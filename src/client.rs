mod context_impl;

use crate::handshake;
use crate::pair;
use crate::qrcode;
use wacore::xml::DisplayableNode;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::node::Node;

use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager};

use crate::handlers;
use crate::types::events::{ConnectFailureReason, Event};
use crate::types::presence::Presence;

use dashmap::DashMap;

use log::{debug, error, info, warn};

use rand::RngCore;
use scopeguard;
use std::collections::{HashMap, HashSet, VecDeque};
use wacore_binary::jid::Jid;
use wacore_binary::jid::SERVER_JID;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, mpsc};
use tokio::task;
use tokio::time::{Duration, sleep};
use wacore::client::context::GroupInfo;
use waproto::whatsapp as wa;

use crate::socket::{FrameSocket, NoiseSocket, SocketError};

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("client is not connected")]
    NotConnected,
    #[error("socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("client is already connected")]
    AlreadyConnected,
    #[error("client is not logged in")]
    NotLoggedIn,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RecentMessageKey {
    pub to: Jid,
    pub id: String,
}

pub struct Client {
    pub core: wacore::client::CoreClient,

    pub persistence_manager: Arc<PersistenceManager>,
    pub media_conn: Arc<Mutex<Option<crate::mediaconn::MediaConn>>>,

    pub is_logged_in: Arc<AtomicBool>,
    pub(crate) is_connecting: Arc<AtomicBool>,
    pub(crate) is_running: Arc<AtomicBool>,
    pub(crate) shutdown_notifier: Arc<Notify>,

    pub(crate) frame_socket: Arc<Mutex<Option<FrameSocket>>>,
    pub(crate) noise_socket: Arc<Mutex<Option<Arc<NoiseSocket>>>>,
    pub(crate) frames_rx: Arc<Mutex<Option<tokio::sync::mpsc::Receiver<bytes::Bytes>>>>,

    pub(crate) response_waiters:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<wacore_binary::Node>>>>,
    pub(crate) unique_id: String,
    pub(crate) id_counter: Arc<AtomicU64>,

    pub(crate) chat_locks: Arc<DashMap<Jid, Arc<tokio::sync::Mutex<()>>>>,
    pub group_cache: Arc<DashMap<Jid, GroupInfo>>,

    pub(crate) expected_disconnect: Arc<AtomicBool>,

    pub(crate) recent_messages_map: Arc<Mutex<HashMap<RecentMessageKey, Arc<wa::Message>>>>,
    pub(crate) recent_messages_list: Arc<Mutex<VecDeque<RecentMessageKey>>>,

    pub(crate) pending_retries: Arc<Mutex<HashSet<String>>>,

    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>,
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,

    pub(crate) processed_messages_cache: Arc<Mutex<HashSet<RecentMessageKey>>>,

    pub(crate) needs_initial_full_sync: Arc<AtomicBool>,

    pub(crate) test_mode: Arc<AtomicBool>,
    pub(crate) test_network_sender:
        Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<crate::test_network::TestMessage>>>>,
}

impl Client {
    pub async fn new(persistence_manager: Arc<PersistenceManager>) -> Self {
        let mut unique_id_bytes = [0u8; 2];
        rand::rng().fill_bytes(&mut unique_id_bytes);

        let device_snapshot = persistence_manager.get_device_snapshot().await;
        let core = wacore::client::CoreClient::new(device_snapshot.core.clone());

        let processed_messages_cache = {
            let mut cache = HashSet::new();
            for processed_msg in &device_snapshot.core.processed_messages {
                let key = RecentMessageKey {
                    to: processed_msg.to.clone(),
                    id: processed_msg.id.clone(),
                };
                cache.insert(key);
            }
            Arc::new(Mutex::new(cache))
        };

        Self {
            core,
            persistence_manager,
            media_conn: Arc::new(Mutex::new(None)),
            is_logged_in: Arc::new(AtomicBool::new(false)),
            is_connecting: Arc::new(AtomicBool::new(false)),
            is_running: Arc::new(AtomicBool::new(false)),
            shutdown_notifier: Arc::new(Notify::new()),

            frame_socket: Arc::new(Mutex::new(None)),
            noise_socket: Arc::new(Mutex::new(None)),
            frames_rx: Arc::new(Mutex::new(None)),

            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            unique_id: format!("{}.{}", unique_id_bytes[0], unique_id_bytes[1]),
            id_counter: Arc::new(AtomicU64::new(0)),
            chat_locks: Arc::new(DashMap::new()),
            group_cache: Arc::new(DashMap::new()),

            expected_disconnect: Arc::new(AtomicBool::new(false)),

            recent_messages_map: Arc::new(Mutex::new(HashMap::with_capacity(256))),
            recent_messages_list: Arc::new(Mutex::new(VecDeque::with_capacity(256))),
            pending_retries: Arc::new(Mutex::new(HashSet::new())),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),
            processed_messages_cache,

            needs_initial_full_sync: Arc::new(AtomicBool::new(false)),

            test_mode: Arc::new(AtomicBool::new(false)),
            test_network_sender: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn run(self: &Arc<Self>) {
        if self.is_running.swap(true, Ordering::SeqCst) {
            warn!("Client `run` method called while already running.");
            return;
        }
        while self.is_running.load(Ordering::Relaxed) {
            self.expected_disconnect.store(false, Ordering::Relaxed);

            if self.connect().await.is_err() {
                error!("Failed to connect, will retry...");
            } else {
                if self.read_messages_loop().await.is_err() {
                    warn!(
                        "Message loop exited with an error. Will attempt to reconnect if enabled."
                    );
                } else {
                    warn!("Message loop exited gracefully.");
                }

                self.cleanup_connection_state().await;
            }

            if !self.enable_auto_reconnect.load(Ordering::Relaxed) {
                self.is_running.store(false, Ordering::Relaxed);
                break;
            }

            let error_count = self.auto_reconnect_errors.fetch_add(1, Ordering::SeqCst);
            let delay_secs = u64::from(error_count * 2).min(30);
            let delay = Duration::from_secs(delay_secs);
            info!(
                "Will attempt to reconnect in {:?} (attempt {})",
                delay,
                error_count + 1
            );
            tokio::select! {
                _ = sleep(delay) => {},
                _ = self.shutdown_notifier.notified() => {
                    self.is_running.store(false, Ordering::Relaxed);
                    break;
                }
            }
        }
        info!("Client run loop has shut down.");
    }

    pub async fn connect(self: &Arc<Self>) -> Result<(), anyhow::Error> {
        if self.is_connecting.swap(true, Ordering::SeqCst) {
            return Err(ClientError::AlreadyConnected.into());
        }

        let _guard = scopeguard::guard((), |_| {
            self.is_connecting.store(false, Ordering::Relaxed);
        });

        if self.is_connected() {
            return Err(ClientError::AlreadyConnected.into());
        }

        let (mut frame_socket, mut frames_rx) = FrameSocket::new();
        frame_socket.connect().await?;

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let noise_socket =
            handshake::do_handshake(&device_snapshot, &mut frame_socket, &mut frames_rx).await?;

        *self.frame_socket.lock().await = Some(frame_socket);
        *self.frames_rx.lock().await = Some(frames_rx);
        *self.noise_socket.lock().await = Some(noise_socket);

        let client_clone = self.clone();
        task::spawn_local(async move { client_clone.keepalive_loop().await });

        Ok(())
    }

    pub async fn disconnect(&self) {
        info!("Disconnecting client intentionally.");
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.is_running.store(false, Ordering::Relaxed);
        self.shutdown_notifier.notify_waiters();
        if let Some(fs) = self.frame_socket.lock().await.as_mut() {
            fs.close().await;
        }
        self.cleanup_connection_state().await;
    }

    async fn cleanup_connection_state(&self) {
        self.is_logged_in.store(false, Ordering::Relaxed);
        *self.frame_socket.lock().await = None;
        *self.noise_socket.lock().await = None;
        *self.frames_rx.lock().await = None;
    }

    async fn read_messages_loop(self: &Arc<Self>) -> Result<(), anyhow::Error> {
        info!(target: "Client", "Starting message processing loop...");

        let mut rx_guard = self.frames_rx.lock().await;
        let mut frames_rx = rx_guard
            .take()
            .ok_or_else(|| anyhow::anyhow!("Cannot start message loop: not connected"))?;
        drop(rx_guard);

        loop {
            tokio::select! {
                    biased;
                    _ = self.shutdown_notifier.notified() => {
                        info!(target: "Client", "Shutdown signaled. Exiting message loop.");
                        return Ok(());
                    },
                    frame_opt = frames_rx.recv() => {
                        match frame_opt {
                            Some(encrypted_frame) => {
                                self.process_encrypted_frame(&encrypted_frame).await;
                            },
                            None => {
                                self.cleanup_connection_state().await;
                                 if !self.expected_disconnect.load(Ordering::Relaxed) {
                                    self.core.event_bus.dispatch(&Event::Disconnected(crate::types::events::Disconnected));
                                    info!("Socket disconnected unexpectedly.");
                                    return Err(anyhow::anyhow!("Socket disconnected unexpectedly"));
                                } else {
                                    info!("Socket disconnected as expected.");
                                    return Ok(());
                                }
                            }
                    }
                }
            }
        }
    }

    pub async fn has_message_been_processed(&self, key: &RecentMessageKey) -> bool {
        let cache = self.processed_messages_cache.lock().await;
        cache.contains(key)
    }

    pub async fn take_recent_message(&self, to: Jid, id: String) -> Option<Arc<wa::Message>> {
        let key = RecentMessageKey { to, id };
        let mut map_guard = self.recent_messages_map.lock().await;
        if let Some(msg) = map_guard.remove(&key) {
            let mut list_guard = self.recent_messages_list.lock().await;
            list_guard.retain(|k| k != &key);
            Some(msg)
        } else {
            None
        }
    }

    pub async fn mark_message_as_processed(&self, key: RecentMessageKey) {
        let wacore_key = wacore::store::device::ProcessedMessageKey {
            to: key.to.clone(),
            id: key.id.clone(),
        };

        self.persistence_manager
            .process_command(wacore::store::commands::DeviceCommand::AddProcessedMessage(
                wacore_key,
            ))
            .await;
    }

    pub(crate) async fn process_encrypted_frame(self: &Arc<Self>, encrypted_frame: &bytes::Bytes) {
        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
            Some(s) => s,
            None => {
                log::error!("Cannot process frame: not connected (no noise socket)");
                return;
            }
        };

        let decrypted_payload = match noise_socket.decrypt_frame(encrypted_frame) {
            Ok(p) => p,
            Err(e) => {
                log::error!(target: "Client", "Failed to decrypt frame: {e}");
                return;
            }
        };

        let unpacked_data_cow = match wacore_binary::util::unpack(&decrypted_payload) {
            Ok(data) => data,
            Err(e) => {
                log::warn!(target: "Client/Recv", "Failed to decompress frame: {e}");
                return;
            }
        };

        match wacore_binary::marshal::unmarshal_ref(unpacked_data_cow.as_ref()) {
            Ok(node_ref) => {
                let node = node_ref.to_owned();
                self.process_node(&node).await;
            }
            Err(e) => log::warn!(target: "Client/Recv", "Failed to unmarshal node: {e}"),
        };
    }

    pub async fn process_node(self: &Arc<Self>, node: &Node) {
        if node.tag == "iq"
            && let Some(sync_node) = node.get_optional_child("sync")
            && let Some(collection_node) = sync_node.get_optional_child("collection")
        {
            let name = collection_node.attrs().string("name");
            debug!(target: "Client/Recv", "Received app state sync response for '{name}' (hiding content).");
        } else {
            debug!(target: "Client/Recv","{}", DisplayableNode(node));
        }

        if node.tag == "xmlstreamend" {
            warn!(target: "Client", "Received <xmlstreamend/>, treating as disconnect.");
            self.shutdown_notifier.notify_one();
            return;
        }

        if node.tag == "iq" {
            let id_opt = node.attrs.get("id");
            if let Some(id) = id_opt {
                let has_waiter = self.response_waiters.lock().await.contains_key(id);
                if has_waiter && self.handle_iq_response(node.clone()).await {
                    return;
                }
            }
        }

        match node.tag.as_str() {
            "success" => self.handle_success(node).await,
            "failure" => self.handle_connect_failure(node).await,
            "stream:error" => self.handle_stream_error(node).await,
            "ib" => handlers::ib::handle_ib(self.clone(), node).await,
            "iq" => {
                if !self.handle_iq(node).await {
                    warn!(target: "Client", "Received unhandled IQ: {}", DisplayableNode(node));
                }
            }
            "receipt" => self.handle_receipt(node).await,
            "notification" => {
                handlers::notification::handle_notification(self, node).await;
            }
            "call" | "presence" | "chatstate" => self.handle_unimplemented(&node.tag).await,
            "message" => {
                let client_clone = self.clone();
                let node_arc = Arc::new(node.clone());

                task::spawn_local(async move {
                    let info = match client_clone.parse_message_info(&node_arc).await {
                        Ok(info) => info,
                        Err(e) => {
                            log::warn!(
                                "Could not parse message info to acquire lock; dropping message. Error: {e:?}"
                            );
                            return;
                        }
                    };
                    let chat_jid = info.source.chat;

                    let mutex_arc = client_clone
                        .chat_locks
                        .entry(chat_jid)
                        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                        .clone();

                    let _lock_guard = mutex_arc.lock().await;

                    client_clone.handle_encrypted_message(node_arc).await;
                });
            }
            "ack" => {
                info!(target: "Client/Recv", "Received ACK node: {}", DisplayableNode(node));
            }
            _ => {
                warn!(target: "Client", "Received unknown top-level node: {}", DisplayableNode(node));
            }
        }
    }

    async fn handle_unimplemented(&self, tag: &str) {
        warn!(target: "Client", "TODO: Implement handler for <{tag}>");
    }

    pub async fn set_passive(&self, passive: bool) -> Result<(), crate::request::IqError> {
        use crate::request::{InfoQuery, InfoQueryType};
        use SERVER_JID;

        let tag = if passive { "passive" } else { "active" };

        let query = InfoQuery {
            namespace: "passive",
            query_type: InfoQueryType::Set,
            to: SERVER_JID.parse().unwrap(),
            target: None,
            id: None,
            content: Some(wacore_binary::node::NodeContent::Nodes(vec![
                NodeBuilder::new(tag).build(),
            ])),
            timeout: None,
        };

        self.send_iq(query).await.map(|_| ())
    }

    async fn handle_success(self: &Arc<Self>, node: &Node) {
        info!("Successfully authenticated with WhatsApp servers!");
        self.is_logged_in.store(true, Ordering::Relaxed);
        *self.last_successful_connect.lock().await = Some(chrono::Utc::now());
        self.auto_reconnect_errors.store(0, Ordering::Relaxed);

        if let Some(lid_str) = node.attrs.get("lid") {
            if let Ok(lid) = lid_str.parse::<Jid>() {
                let device_snapshot = self.persistence_manager.get_device_snapshot().await;
                if device_snapshot.lid.as_ref() != Some(&lid) {
                    info!(target: "Client", "Updating LID from server to '{lid}'");
                    self.persistence_manager
                        .process_command(DeviceCommand::SetLid(Some(lid)))
                        .await;
                }
            } else {
                warn!(target: "Client", "Failed to parse LID from success stanza: {lid_str}");
            }
        } else {
            warn!(target: "Client", "LID not found in <success> stanza. Group messaging may fail.");
        }

        let client_clone = self.clone();
        task::spawn_local(async move {
            if let Err(e) = client_clone.set_passive(false).await {
                warn!("Failed to send post-connect passive IQ: {e:?}");
            }

            if client_clone
                .needs_initial_full_sync
                .swap(false, Ordering::Relaxed)
            {
                info!("Performing initial full app state sync after pairing.");
                for name in wacore::appstate::keys::ALL_PATCH_NAMES {
                    let client_for_sync = client_clone.clone();
                    task::spawn_local(async move {
                        crate::appstate_sync::app_state_sync(&client_for_sync, name, true).await;
                    });
                }
            }

            if let Err(e) = client_clone.send_presence(Presence::Available).await {
                warn!(
                    "Could not send initial presence: {e:?}. This is expected if push_name is not yet known."
                );
            }

            client_clone
                .core
                .event_bus
                .dispatch(&Event::Connected(crate::types::events::Connected));
        });
    }

    async fn expect_disconnect(&self) {
        self.expected_disconnect.store(true, Ordering::Relaxed);
    }

    async fn handle_stream_error(&self, node: &Node) {
        self.is_logged_in.store(false, Ordering::Relaxed);

        let mut attrs = node.attrs();
        let code = attrs.optional_string("code").unwrap_or("");
        let conflict_type = node
            .get_optional_child("conflict")
            .map(|n| n.attrs().optional_string("type").unwrap_or("").to_string())
            .unwrap_or_default();

        match (code, conflict_type.as_str()) {
            ("515", _) => {
                info!(target: "Client", "Got 515 stream error, server is closing stream. Will auto-reconnect.");
            }
            ("401", "device_removed") | (_, "replaced") => {
                info!(target: "Client", "Got stream error indicating client was removed or replaced. Logging out.");
                self.expect_disconnect().await;
                self.enable_auto_reconnect.store(false, Ordering::Relaxed);

                let event = if conflict_type == "replaced" {
                    Event::StreamReplaced(crate::types::events::StreamReplaced)
                } else {
                    Event::LoggedOut(crate::types::events::LoggedOut {
                        on_connect: false,
                        reason: ConnectFailureReason::LoggedOut,
                    })
                };
                self.core.event_bus.dispatch(&event);
            }
            ("503", _) => {
                info!(target: "Client", "Got 503 service unavailable, will auto-reconnect.");
            }
            _ => {
                error!(target: "Client", "Unknown stream error: {}", DisplayableNode(node));
                self.expect_disconnect().await;
                self.core.event_bus.dispatch(&Event::StreamError(
                    crate::types::events::StreamError {
                        code: code.to_string(),
                        raw: Some(node.clone()),
                    },
                ));
            }
        }

        self.shutdown_notifier.notify_one();
    }

    async fn handle_connect_failure(&self, node: &Node) {
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.shutdown_notifier.notify_one();

        let mut attrs = node.attrs();
        let reason_code = attrs.optional_u64("reason").unwrap_or(0) as i32;
        let reason = ConnectFailureReason::from(reason_code);

        if reason.should_reconnect() {
            self.expected_disconnect.store(false, Ordering::Relaxed);
        } else {
            self.enable_auto_reconnect.store(false, Ordering::Relaxed);
        }

        if reason.is_logged_out() {
            info!(target: "Client", "Got {reason:?} connect failure, logging out.");
            self.core
                .event_bus
                .dispatch(&wacore::types::events::Event::LoggedOut(
                    crate::types::events::LoggedOut {
                        on_connect: true,
                        reason,
                    },
                ));
        } else if let ConnectFailureReason::TempBanned = reason {
            let ban_code = attrs.optional_u64("code").unwrap_or(0) as i32;
            let expire_secs = attrs.optional_u64("expire").unwrap_or(0);
            let expire_duration =
                chrono::Duration::try_seconds(expire_secs as i64).unwrap_or_default();
            warn!(target: "Client", "Temporary ban connect failure: {}", DisplayableNode(node));
            self.core.event_bus.dispatch(&Event::TemporaryBan(
                crate::types::events::TemporaryBan {
                    code: crate::types::events::TempBanReason::from(ban_code),
                    expire: expire_duration,
                },
            ));
        } else if let ConnectFailureReason::ClientOutdated = reason {
            error!(target: "Client", "Client is outdated and was rejected by server.");
            self.core
                .event_bus
                .dispatch(&Event::ClientOutdated(crate::types::events::ClientOutdated));
        } else {
            warn!(target: "Client", "Unknown connect failure: {}", DisplayableNode(node));
            self.core.event_bus.dispatch(&Event::ConnectFailure(
                crate::types::events::ConnectFailure {
                    reason,
                    message: attrs.optional_string("message").unwrap_or("").to_string(),
                    raw: Some(node.clone()),
                },
            ));
        }
    }

    async fn handle_iq(self: &Arc<Self>, node: &Node) -> bool {
        if let Some("get") = node.attrs().optional_string("type")
            && let Some(_ping_node) = node.get_optional_child("ping")
        {
            info!(target: "Client", "Received ping, sending pong.");
            let mut parser = node.attrs();
            let from_jid = parser.jid("from");
            let id = parser.string("id");
            let pong = NodeBuilder::new("iq")
                .attrs([
                    ("to", from_jid.to_string()),
                    ("id", id),
                    ("type", "result".to_string()),
                ])
                .build();
            if let Err(e) = self.send_node(pong).await {
                warn!("Failed to send pong: {e:?}");
            }
            return true;
        }

        if pair::handle_iq(self, node).await {
            return true;
        }

        false
    }

    pub async fn get_qr_channel(
        &self,
    ) -> Result<mpsc::Receiver<qrcode::QrCodeEvent>, qrcode::QrError> {
        qrcode::get_qr_channel_logic(self).await
    }

    pub fn is_connected(&self) -> bool {
        self.noise_socket
            .try_lock()
            .is_ok_and(|guard| guard.is_some())
    }

    pub fn is_logged_in(&self) -> bool {
        self.is_logged_in.load(Ordering::Relaxed)
    }

    pub async fn send_node(&self, node: Node) -> Result<(), ClientError> {
        if self.test_mode.load(Ordering::Relaxed) {
            debug!(target: "Client/Send", "Using test mode for node: {}", DisplayableNode(&node));
            return self.send_node_test_mode(node).await;
        }

        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
            Some(socket) => socket,
            None => return Err(ClientError::NotConnected),
        };

        debug!(target: "Client/Send", "--> {}", DisplayableNode(&node));

        let payload = wacore_binary::marshal::marshal(&node).map_err(|e| {
            error!("Failed to marshal node: {e:?}");
            SocketError::Crypto("Marshal error".to_string())
        })?;

        noise_socket.send_frame(&payload).await.map_err(Into::into)
    }

    pub async fn set_push_name(&self, name: String) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let old_name = device_snapshot.push_name.clone();

        if old_name != name {
            self.persistence_manager
                .process_command(DeviceCommand::SetPushName(name.clone()))
                .await;

            self.core.event_bus.dispatch(&Event::SelfPushNameUpdated(
                crate::types::events::SelfPushNameUpdated {
                    from_server: false,
                    old_name,
                    new_name: name,
                },
            ));
        }
        Ok(())
    }

    pub async fn update_push_name_and_notify(self: &Arc<Self>, new_name: String) {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let old_name = device_snapshot.push_name.clone();

        if old_name == new_name {
            return;
        }

        log::info!("Updating push name from '{}' -> '{}'", old_name, new_name);
        self.persistence_manager
            .process_command(DeviceCommand::SetPushName(new_name.clone()))
            .await;

        self.core.event_bus.dispatch(&Event::SelfPushNameUpdated(
            crate::types::events::SelfPushNameUpdated {
                from_server: true,
                old_name,
                new_name: new_name.clone(),
            },
        ));

        let client_clone = self.clone();
        tokio::task::spawn_local(async move {
            if let Err(e) = client_clone.send_presence(Presence::Available).await {
                log::warn!("Failed to send presence after push name update: {:?}", e);
            } else {
                log::info!("Sent presence after push name update.");
            }
        });
    }

    pub async fn get_push_name(&self) -> String {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        device_snapshot.push_name.clone()
    }

    pub async fn is_ready_for_presence(&self) -> bool {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        device_snapshot.is_ready_for_presence()
    }

    pub async fn get_device_debug_info(&self) -> String {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        format!(
            "Device Debug Info:\n  - JID: {:?}\n  - LID: {:?}\n  - Push Name: '{}'\n  - Has Account: {}\n  - Ready for Presence: {}",
            device_snapshot.id,
            device_snapshot.lid,
            device_snapshot.push_name,
            device_snapshot.account.is_some(),
            device_snapshot.id.is_some() && !device_snapshot.push_name.is_empty()
        )
    }

    pub async fn get_jid(&self) -> Option<Jid> {
        let snapshot = self.persistence_manager.get_device_snapshot().await;
        snapshot.id.clone()
    }

    pub async fn enable_test_mode(
        &self,
        network_sender: tokio::sync::mpsc::UnboundedSender<crate::test_network::TestMessage>,
    ) {
        info!("Enabling test mode for client");
        self.test_mode.store(true, Ordering::Relaxed);
        *self.test_network_sender.lock().await = Some(network_sender);
    }

    async fn send_node_test_mode(&self, node: Node) -> Result<(), ClientError> {
        use crate::test_network::TestMessage;

        debug!(target: "Client/TestSend", "Sending node in test mode: {}", DisplayableNode(&node));

        let sender_guard = self.test_network_sender.lock().await;
        let sender = match sender_guard.as_ref() {
            Some(s) => s,
            None => return Err(ClientError::NotConnected),
        };

        let to_jid = node.attrs.get("to").and_then(|to_str| to_str.parse().ok());

        let from_jid = match self.get_jid().await {
            Some(jid) => jid,
            None => return Err(ClientError::NotLoggedIn),
        };

        let test_message = TestMessage {
            node,
            from: from_jid,
            to: to_jid,
        };

        sender
            .send(test_message)
            .map_err(|_| ClientError::NotConnected)?;
        Ok(())
    }

    pub async fn send_protocol_receipt(
        &self,
        id: String,
        receipt_type: crate::types::presence::ReceiptType,
    ) {
        if id.is_empty() {
            return;
        }
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        if let Some(own_jid) = &device_snapshot.id {
            let node = NodeBuilder::new("receipt")
                .attrs([
                    ("id", id),
                    ("type", format!("{:?}", receipt_type).to_lowercase()),
                    ("to", own_jid.to_non_ad().to_string()),
                ])
                .build();

            if let Err(e) = self.send_node(node).await {
                warn!(
                    "Failed to send protocol receipt of type {:?} for message ID {}: {:?}",
                    receipt_type, self.unique_id, e
                );
            }
        }
    }
}
