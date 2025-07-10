use crate::binary::node::{AttrParser, Node}; // Added AttrParser
use crate::event_bus::EventBus;
use crate::request::IqError; // For send_request_iq
use crate::session_manager::SessionManager;
use crate::store::commands::DeviceCommand;
use crate::store::persistence_manager::PersistenceManager;
use crate::types::events::{
    ClientOutdated, ConnectFailure, ConnectFailureReason, DecryptedMessage, Event, LoggedOut,
    Receipt as EventReceipt, StreamError, StreamReplaced, TempBanReason, TemporaryBan,
}; // Added DecryptedMessage
use crate::types::jid::Jid;
use crate::types::presence::ReceiptType;
use dashmap::DashMap;

use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration as StdDuration;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout; // For send_request_iq // For send_request_iq

pub struct StanzaProcessor {
    pub(crate) stanza_receiver: Mutex<mpsc::Receiver<Node>>,
    pub(crate) session_manager: Arc<SessionManager>,
    pub(crate) persistence_manager: Arc<PersistenceManager>,
    pub(crate) event_bus: Arc<EventBus>,
    pub(crate) response_waiters: Arc<Mutex<HashMap<String, oneshot::Sender<Node>>>>,
    pub(crate) client_is_logged_in: Arc<AtomicBool>,
    pub(crate) client_last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
    pub(crate) client_auto_reconnect_errors: Arc<AtomicU32>,
    pub(crate) connection_manager: Arc<crate::connection_manager::ConnectionManager>,
    pub(crate) chat_locks: Arc<DashMap<Jid, Arc<Mutex<()>>>>,
    unique_id_prefix: String,
    id_counter: Arc<AtomicU64>,
}

impl StanzaProcessor {
    pub fn new(
        stanza_receiver: mpsc::Receiver<Node>,
        session_manager: Arc<SessionManager>,
        persistence_manager: Arc<PersistenceManager>,
        event_bus: Arc<EventBus>,
        response_waiters: Arc<Mutex<HashMap<String, oneshot::Sender<Node>>>>,
        client_is_logged_in: Arc<AtomicBool>,
        client_last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
        client_auto_reconnect_errors: Arc<AtomicU32>,
        connection_manager: Arc<crate::connection_manager::ConnectionManager>,
        unique_id_prefix: String,
        id_counter: Arc<AtomicU64>,
    ) -> Self {
        Self {
            stanza_receiver: Mutex::new(stanza_receiver),
            session_manager,
            persistence_manager,
            event_bus,
            response_waiters,
            client_is_logged_in,
            client_last_successful_connect,
            client_auto_reconnect_errors,
            connection_manager,
            chat_locks: Arc::new(DashMap::new()),
            unique_id_prefix,
            id_counter,
        }
    }

    fn generate_request_id(&self) -> String {
        format!(
            "{}-{}",
            self.unique_id_prefix,
            self.id_counter.fetch_add(1, Ordering::Relaxed)
        )
    }

    pub async fn send_request_iq(
        &self,
        mut node: Node,
        timeout_duration: Option<StdDuration>,
    ) -> Result<Node, IqError> {
        let request_id = match node.attrs.get("id") {
            Some(id) => id.clone(),
            None => {
                let new_id = self.generate_request_id();
                node.attrs.insert("id".to_string(), new_id.clone());
                new_id
            }
        };

        let iq_type = node.attrs.get("type").map(String::as_str);
        if !matches!(iq_type, Some("get") | Some("set")) {
            return Err(IqError::BadRequest(format!(
                "IQ request node must have type 'get' or 'set', found: {:?}",
                iq_type
            )));
        }

        let (tx, rx) = oneshot::channel();
        self.response_waiters
            .lock()
            .await
            .insert(request_id.clone(), tx);

        if let Err(e) = self.connection_manager.send_node(node).await {
            self.response_waiters.lock().await.remove(&request_id);
            return Err(IqError::Socket(format!(
                "Failed to send IQ node via ConnectionManager: {}",
                e
            )));
        }

        let duration = timeout_duration.unwrap_or_else(|| StdDuration::from_secs(30));

        match timeout(duration, rx).await {
            Ok(Ok(response_node)) => {
                if response_node.attrs.get("type").map(String::as_str) == Some("error") {
                    let error_child = response_node.get_optional_child("error");
                    if let Some(err_node) = error_child {
                        let mut parser =
                            crate::binary::attrs::AttrParser::new(err_node.attrs.clone());
                        let code = parser.optional_u64("code").unwrap_or(0) as u16;
                        let text = parser.optional_string("text").unwrap_or_default();
                        return Err(IqError::ServerError { code, text });
                    }
                    return Err(IqError::ServerError {
                        code: 0,
                        text: "Received IQ type error with no <error> child".to_string(),
                    });
                }
                Ok(response_node)
            }
            Ok(Err(_)) => {
                self.response_waiters.lock().await.remove(&request_id);
                Err(IqError::RequestDropped)
            }
            Err(_) => {
                self.response_waiters.lock().await.remove(&request_id);
                Err(IqError::Timeout)
            }
        }
    }

    pub async fn run_processing_loop(self: Arc<Self>) {
        info!("StanzaProcessor: Starting processing loop...");
        loop {
            let node_opt = self.stanza_receiver.lock().await.recv().await;
            match node_opt {
                Some(node) => {
                    let self_clone = self.clone();
                    tokio::spawn(async move {
                        self_clone.process_node(node).await;
                    });
                }
                None => {
                    info!("StanzaProcessor: Node channel closed, exiting processing loop.");
                    break;
                }
            }
        }
        info!("StanzaProcessor: Processing loop stopped.");
    }

    async fn handle_iq_response(&self, node: Node) -> bool {
        if let Some(id) = node.attrs.get("id") {
            if let Some(sender) = self.response_waiters.lock().await.remove(id) {
                if sender.send(node).is_err() {
                    warn!(
                        "Failed to send IQ response to waiter for id {}: receiver dropped",
                        id
                    );
                }
                return true;
            }
        }
        false
    }

    pub async fn process_node(self: &Arc<Self>, node: Node) {
        if node.tag == "iq" {
            if let Some(sync_node) = node.get_optional_child("sync") {
                if let Some(collection_node) = sync_node.get_optional_child("collection") {
                    let name = collection_node.attrs().string("name");
                    debug!(target: "StanzaProcessor/Recv", "Received app state sync response for '{name}' (hiding content).");
                } else {
                    debug!(target: "StanzaProcessor/Recv", "{node}");
                }
            } else {
                debug!(target: "StanzaProcessor/Recv", "{node}");
            }
        } else {
            debug!(target: "StanzaProcessor/Recv", "{node}");
        }

        if node.tag == "iq" && self.handle_iq_response(node.clone()).await {
            return;
        }

        match node.tag.as_str() {
            "success" => self.handle_success(&node).await,
            "failure" => self.handle_connect_failure(&node).await,
            "stream:error" => self.handle_stream_error(&node).await,
            "iq" => {
                if !self.handle_iq(&node).await {
                    warn!(target: "StanzaProcessor", "Received unhandled IQ: {node}");
                }
            }
            "receipt" => self.handle_receipt(&node).await,
            "message" => {
                let self_clone = self.clone();
                let node_clone = node.clone();
                tokio::spawn(async move {
                    let from_jid_str = node_clone.attrs.get("from").cloned().unwrap_or_default();
                    let chat_jid_for_lock: Option<Jid> = from_jid_str.parse().ok();

                    if let Some(jid) = chat_jid_for_lock {
                        let lock = self_clone
                            .chat_locks
                            .entry(jid.clone())
                            .or_insert_with(|| Arc::new(Mutex::new(())))
                            .clone();
                        let _guard = lock.lock().await;

                        match self_clone
                            .session_manager
                            .handle_encrypted_node(node_clone.clone())
                            .await
                        {
                            Ok(Some(decrypted_wa_message)) => {
                                let from_jid: Jid = jid;

                                let event = Event::Message(Arc::new(DecryptedMessage {
                                    info: crate::types::message::MessageInfo {
                                        id: node_clone.attrs.get("id").cloned().unwrap_or_default(),
                                        source: crate::types::message::MessageSource {
                                            chat: from_jid.clone(),
                                            sender: from_jid.clone(),
                                            is_from_me: false,
                                            is_group_message: from_jid.is_group(),
                                            _push_name: None,
                                        },
                                        category: node_clone.attrs.get("category").cloned(),
                                        participant: node_clone
                                            .attrs
                                            .get("participant")
                                            .and_then(|s| s.parse().ok()),
                                        message_type: decrypted_wa_message.message_type_string(),
                                        timestamp: chrono::Utc::now().timestamp() as u64,
                                        ack_level: None,
                                    },
                                    data: decrypted_wa_message,
                                }));
                                self_clone.event_bus.dispatch(Arc::new(event)).await;
                            }
                            Ok(None) => { /* Signal protocol message handled internally */ }
                            Err(e) => {
                                warn!("StanzaProcessor: Error handling encrypted node in SessionManager (with lock for {}): {:?}", jid, e);
                            }
                        }
                    } else {
                        warn!("StanzaProcessor: Could not determine chat JID for message from attribute 'from', processing without lock: {}", node_clone.attrs.get("from").unwrap_or("N/A"));
                        match self_clone
                            .session_manager
                            .handle_encrypted_node(node_clone.clone())
                            .await
                        {
                            Ok(Some(decrypted_wa_message)) => {
                                let from_jid_fallback: Jid = node_clone
                                    .attrs
                                    .get("from")
                                    .and_then(|s| s.parse().ok())
                                    .unwrap_or_else(|| {
                                        Jid::new("unknown", crate::types::jid::Server::User)
                                    });

                                let event = Event::Message(Arc::new(DecryptedMessage {
                                    info: crate::types::message::MessageInfo {
                                        id: node_clone.attrs.get("id").cloned().unwrap_or_default(),
                                        source: crate::types::message::MessageSource {
                                            chat: from_jid_fallback.clone(),
                                            sender: from_jid_fallback.clone(),
                                            is_from_me: false,
                                            is_group_message: from_jid_fallback.is_group(),
                                            _push_name: None,
                                        },
                                        category: node_clone.attrs.get("category").cloned(),
                                        participant: node_clone
                                            .attrs
                                            .get("participant")
                                            .and_then(|s| s.parse().ok()),
                                        message_type: decrypted_wa_message.message_type_string(),
                                        timestamp: chrono::Utc::now().timestamp() as u64,
                                        ack_level: None,
                                    },
                                    data: decrypted_wa_message,
                                }));
                                self_clone.event_bus.dispatch(Arc::new(event)).await;
                            }
                            Ok(None) => { /* Signal protocol message handled internally */ }
                            Err(e) => {
                                warn!("StanzaProcessor: Error handling encrypted node in SessionManager (no lock due to missing JID): {:?}", e);
                            }
                        }
                    }
                });
            }
            "ack" => {}
            _ => {
                warn!(target: "StanzaProcessor", "Received unknown top-level node: {node}");
            }
        }
    }

    async fn handle_iq(self: &Arc<Self>, node: &Node) -> bool {
        if let Some("get") = node.attrs().optional_string("type") {
            if node.get_optional_child("ping").is_some() {
                info!(target: "StanzaProcessor", "Received ping, sending pong.");
                let from_jid_str = node.attrs().string("from");
                let id = node.attrs().string("id");
                let pong = Node {
                    tag: "iq".into(),
                    attrs: [
                        ("to".into(), from_jid_str),
                        ("id".into(), id),
                        ("type".into(), "result".into()),
                    ]
                    .iter()
                    .cloned()
                    .collect(),
                    content: None,
                };
                if let Err(e) = self.connection_manager.send_node(pong).await {
                    warn!("StanzaProcessor: Failed to send pong: {:?}", e);
                }
                return true;
            }
        }
        false
    }

    async fn handle_success(self: &Arc<Self>, node: &Node) {
        info!("StanzaProcessor: Successfully authenticated with WhatsApp servers!");
        self.client_is_logged_in.store(true, Ordering::Relaxed);
        *self.client_last_successful_connect.lock().await = Some(chrono::Utc::now());
        self.client_auto_reconnect_errors
            .store(0, Ordering::Relaxed);

        if let Some(lid_str) = node.attrs.get("lid") {
            if let Ok(lid) = lid_str.parse::<Jid>() {
                let current_device = self.persistence_manager.get_device_snapshot().await;
                if current_device.lid.as_ref() != Some(&lid) {
                    info!(target: "StanzaProcessor", "Updating LID from server to '{}'", lid);
                    self.persistence_manager
                        .process_command(DeviceCommand::SetLid(Some(lid)))
                        .await;
                }
            } else {
                warn!(target: "StanzaProcessor", "Failed to parse LID from success stanza: {}", lid_str);
            }
        } else {
            warn!(target: "StanzaProcessor", "LID not found in <success> stanza.");
        }

        if let Some(push_name_attr) = node.attrs.get("pushname") {
            let new_name = push_name_attr.clone();
            let old_name = self
                .persistence_manager
                .get_device_snapshot()
                .await
                .push_name;

            if old_name != new_name {
                info!(target: "StanzaProcessor", "Updating push name from server to '{}'", new_name);
                self.persistence_manager
                    .process_command(DeviceCommand::SetPushName(new_name.clone()))
                    .await;
                self.event_bus
                    .dispatch(Arc::new(Event::SelfPushNameUpdated(
                        crate::types::events::SelfPushNameUpdated {
                            from_server: true,
                            old_name,
                            new_name,
                        },
                    )))
                    .await;
            }
        }

        self.event_bus
            .dispatch(Arc::new(Event::Connected(
                crate::types::events::Connected {},
            )))
            .await;
    }

    async fn handle_connect_failure(self: &Arc<Self>, node: &Node) {
        let mut attrs = node.attrs();
        let reason_code = attrs.optional_u64("reason").unwrap_or(0) as i32;
        let reason = ConnectFailureReason::from(reason_code);
        let should_log_out = !reason.should_reconnect();

        info!(target: "StanzaProcessor", "Handling connect failure, reason: {:?}, should_log_out: {}", reason, should_log_out);

        if should_log_out {
            self.event_bus
                .dispatch(Arc::new(Event::LoggedOut(LoggedOut {
                    on_connect: true,
                    reason,
                })))
                .await;
        } else if let ConnectFailureReason::TempBanned = reason {
            let ban_code = attrs.optional_u64("code").unwrap_or(0) as i32;
            let expire_secs = attrs.optional_u64("expire").unwrap_or(0);
            let expire_duration =
                chrono::Duration::try_seconds(expire_secs as i64).unwrap_or_default();
            warn!(target: "StanzaProcessor", "Temporary ban connect failure: {node}");
            self.event_bus
                .dispatch(Arc::new(Event::TemporaryBan(TemporaryBan {
                    code: TempBanReason::from(ban_code),
                    expire: expire_duration,
                })))
                .await;
        } else if let ConnectFailureReason::ClientOutdated = reason {
            error!(target: "StanzaProcessor", "Client is outdated and was rejected by server.");
            self.event_bus
                .dispatch(Arc::new(Event::ClientOutdated(ClientOutdated {})))
                .await;
        } else {
            self.event_bus
                .dispatch(Arc::new(Event::ConnectFailure(ConnectFailure {
                    reason,
                    message: attrs.optional_string("message").unwrap_or_default(),
                    raw: Some(node.clone()),
                })))
                .await;
        }
    }

    async fn handle_stream_error(self: &Arc<Self>, node: &Node) {
        self.client_is_logged_in.store(false, Ordering::Relaxed);

        let mut attrs = node.attrs();
        let code = attrs.optional_string("code").unwrap_or_default();
        let conflict_type = node
            .get_optional_child("conflict")
            .map(|n| n.attrs().optional_string("type").unwrap_or_default())
            .unwrap_or_default();

        info!(target: "StanzaProcessor", "Handling stream error, code: '{}', conflict: '{}'", code, conflict_type);

        match (code.as_str(), conflict_type.as_str()) {
            ("401", "device_removed") | (_, "replaced") => {
                let event = if conflict_type == "replaced" {
                    Event::StreamReplaced(StreamReplaced {})
                } else {
                    Event::LoggedOut(LoggedOut {
                        on_connect: false,
                        reason: ConnectFailureReason::LoggedOut,
                    })
                };
                self.event_bus.dispatch(Arc::new(event)).await;
            }
            _ => {
                self.event_bus
                    .dispatch(Arc::new(Event::StreamError(StreamError {
                        code: code.to_string(),
                        raw: Some(node.clone()),
                    })))
                    .await;
            }
        }
    }

    async fn handle_receipt(self: &Arc<Self>, node: &Node) {
        let mut attrs = node.attrs();
        let from = attrs.jid("from");
        let id = attrs.string("id");
        let receipt_type_str = attrs.optional_string("type").unwrap_or("delivery");
        let participant = attrs.optional_jid("participant");

        let receipt_type = ReceiptType::from(receipt_type_str.to_string());
        info!(
            "StanzaProcessor: Received receipt type '{:?}' for message {} from {}",
            receipt_type, id, from
        );

        let sender = if from.is_group() && participant.is_some() {
            participant.unwrap()
        } else {
            from.clone()
        };

        let event_receipt = EventReceipt {
            message_ids: vec![id.clone()],
            source: crate::types::message::MessageSource {
                chat: from.clone(),
                sender: sender.clone(),
                is_from_me: false,
                is_group_message: from.is_group(),
                _push_name: None,
            },
            timestamp: chrono::Utc::now(),
            r#type: receipt_type.clone(),
            message_sender: sender.clone(),
        };

        if receipt_type == ReceiptType::Retry {
            warn!(
                "StanzaProcessor: Retry receipt handling for message {} from {} is TODO.",
                id, from
            );
            self.event_bus
                .dispatch(Arc::new(Event::Receipt(event_receipt)))
                .await;
        } else {
            self.event_bus
                .dispatch(Arc::new(Event::Receipt(event_receipt)))
                .await;
        }
    }
}
