use crate::binary::node::Node;
use crate::handshake;
use crate::pair;
use crate::qrcode;
use crate::store;

use crate::handlers;
use crate::types::events::{ConnectFailureReason, Event};
use crate::types::presence::Presence;

use dashmap::DashMap;
use log::{debug, error, info, warn};
use rand::RngCore;
use scopeguard;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use tokio::time::{sleep, Duration};

use crate::socket::{FrameSocket, NoiseSocket, SocketError};
use whatsapp_proto::whatsapp as wa;

pub type EventHandler = Box<dyn Fn(Arc<Event>) + Send + Sync>;
pub(crate) struct WrappedHandler {
    pub(crate) id: usize,
    handler: EventHandler,
}
static NEXT_HANDLER_ID: AtomicUsize = AtomicUsize::new(1);

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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct RecentMessageKey {
    to: crate::types::jid::Jid,
    id: String,
}

pub struct Client {
    pub store: std::sync::Arc<tokio::sync::RwLock<store::Device>>,

    pub media_conn: Arc<Mutex<Option<crate::mediaconn::MediaConn>>>,

    pub(crate) is_logged_in: Arc<AtomicBool>,
    pub(crate) is_connecting: Arc<AtomicBool>,
    pub(crate) is_running: Arc<AtomicBool>,
    pub(crate) shutdown_notifier: Arc<Notify>,

    pub(crate) frame_socket: Arc<Mutex<Option<FrameSocket>>>,
    pub(crate) noise_socket: Arc<Mutex<Option<Arc<NoiseSocket>>>>,
    pub(crate) frames_rx: Arc<Mutex<Option<tokio::sync::mpsc::Receiver<bytes::Bytes>>>>,

    pub(crate) response_waiters:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<crate::binary::Node>>>>,
    pub(crate) unique_id: String,
    pub(crate) id_counter: Arc<AtomicU64>,
    pub(crate) event_handlers: Arc<RwLock<Vec<WrappedHandler>>>,

    /// Manages per-chat locks to allow for concurrent message processing
    /// from different chats while serializing messages within the same chat.
    pub(crate) chat_locks: Arc<DashMap<crate::types::jid::Jid, Arc<tokio::sync::Mutex<()>>>>,

    pub(crate) expected_disconnect: Arc<AtomicBool>,

    pub(crate) recent_messages_map: Arc<Mutex<HashMap<RecentMessageKey, wa::Message>>>,
    pub(crate) recent_messages_list: Arc<Mutex<VecDeque<RecentMessageKey>>>,

    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>,
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
    pub(crate) last_buffer_cleanup: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl Client {
    pub fn new(store: store::Device) -> Self {
        let mut unique_id_bytes = [0u8; 2];
        rand::thread_rng().fill_bytes(&mut unique_id_bytes);

        Self {
            store: std::sync::Arc::new(tokio::sync::RwLock::new(store)),
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
            event_handlers: Arc::new(RwLock::new(Vec::new())),

            // Initialize the per-chat locks map
            chat_locks: Arc::new(DashMap::new()),

            expected_disconnect: Arc::new(AtomicBool::new(false)),

            recent_messages_map: Arc::new(Mutex::new(HashMap::with_capacity(256))),
            recent_messages_list: Arc::new(Mutex::new(VecDeque::with_capacity(256))),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),
            last_buffer_cleanup: Arc::new(Mutex::new(None)),
        }
    }
    /// Placeholder function to get group participants.
    /// A real implementation should fetch this information from the store
    /// where group metadata is persisted.
    pub async fn get_group_participants(
        &self,
        _group_jid: &crate::types::jid::Jid,
    ) -> Result<Vec<crate::types::jid::Jid>, anyhow::Error> {
        // TODO: This is a placeholder. A real implementation should fetch
        // group metadata from the store to get the actual participant list.
        // For now, it includes only the sender to allow testing the flow to yourself.
        let own_jid = self
            .store
            .read()
            .await
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in"))?;
        Ok(vec![own_jid])
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

        let noise_socket =
            handshake::do_handshake(&self.store, &mut frame_socket, &mut frames_rx).await?;

        *self.frame_socket.lock().await = Some(frame_socket);
        *self.frames_rx.lock().await = Some(frames_rx);
        *self.noise_socket.lock().await = Some(noise_socket);

        let client_clone = self.clone();
        tokio::spawn(client_clone.keepalive_loop());

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
                                    self.dispatch_event(Event::Disconnected(crate::types::events::Disconnected)).await;
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

    /// Processes an encrypted frame from the WebSocket.
    /// This is the entry point for all incoming frames after the handshake.
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

        let unpacked_data_cow = match crate::binary::util::unpack(&decrypted_payload) {
            Ok(data) => data,
            Err(e) => {
                log::warn!(target: "Client/Recv", "Failed to decompress frame: {e}");
                return;
            }
        };

        // --- Periodic cleanup of event buffer (every 12 hours) ---
        {
            let mut last_cleanup = self.last_buffer_cleanup.lock().await;
            let now = chrono::Utc::now();
            let needs_cleanup = last_cleanup
                .map(|t| (now - t).num_hours() >= 12)
                .unwrap_or(true);
            if needs_cleanup {
                *last_cleanup = Some(now);
                let client_clone = self.clone();
                tokio::spawn(async move {
                    let backend = client_clone.store.read().await.backend.clone();
                    // Delete entries older than 14 days, similar to whatsmeow
                    let cutoff = chrono::Utc::now() - chrono::Duration::days(14);
                    if let Err(e) = backend.delete_old_buffered_events(cutoff).await {
                        log::warn!("Failed to clean up old event buffer entries: {:?}", e);
                    }
                });
            }
        }

        match crate::binary::unmarshal_ref(unpacked_data_cow.as_ref()) {
            Ok(node_ref) => {
                // Convert to owned only when needed for processing
                let node = node_ref.to_owned();
                self.process_node(node).await;
            }
            Err(e) => log::warn!(target: "Client/Recv", "Failed to unmarshal node: {e}"),
        };
    }

    pub async fn process_node(self: &Arc<Self>, node: Node) {
        if node.tag == "iq" {
            if let Some(sync_node) = node.get_optional_child("sync") {
                if let Some(collection_node) = sync_node.get_optional_child("collection") {
                    let name = collection_node.attrs().string("name");
                    debug!(target: "Client/Recv", "Received app state sync response for '{name}' (hiding content).");
                } else {
                    debug!(target: "Client/Recv", "{node}");
                }
            } else {
                debug!(target: "Client/Recv", "{node}");
            }
        } else {
            debug!(target: "Client/Recv", "{node}");
        }

        if node.tag == "xmlstreamend" {
            warn!(target: "Client", "Received <xmlstreamend/>, treating as disconnect.");
            self.shutdown_notifier.notify_one();
            return;
        }

        if node.tag == "iq" && self.handle_iq_response(node.clone()).await {
            return;
        }

        match node.tag.as_str() {
            "success" => self.handle_success(&node).await,
            "failure" => self.handle_connect_failure(&node).await,
            "stream:error" => self.handle_stream_error(&node).await,
            "ib" => handlers::ib::handle_ib(self.clone(), &node).await,
            "iq" => {
                if !self.handle_iq(&node).await {
                    warn!(target: "Client", "Received unhandled IQ: {node}");
                }
            }
            "receipt" => self.handle_receipt(&node).await,
            "notification" => handlers::notification::handle_notification(self, &node).await,
            "call" | "presence" | "chatstate" => self.handle_unimplemented(&node.tag).await,
            "message" => {
                let client_clone = self.clone();
                let node_clone = node.clone();
                tokio::spawn(async move {
                    // First, parse the message info to get the source chat JID
                    let info = match client_clone.parse_message_info(&node_clone).await {
                        Ok(info) => info,
                        Err(e) => {
                            log::warn!("Could not parse message info to acquire lock: {e:?}");
                            return;
                        }
                    };
                    let chat_jid = info.source.chat;

                    // Acquire a lock for this specific chat.
                    // entry().or_default() gets the existing mutex or creates a new one atomically.
                    let mutex_arc = client_clone
                        .chat_locks
                        .entry(chat_jid)
                        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                        .clone();
                    let _lock_guard = mutex_arc.lock().await;
                    client_clone.handle_encrypted_message(node_clone).await;
                });
            }
            "ack" => {}
            _ => {
                warn!(target: "Client", "Received unknown top-level node: {node}");
            }
        }
    }

    async fn handle_unimplemented(&self, tag: &str) {
        warn!(target: "Client", "TODO: Implement handler for <{tag}>");
    }

    async fn handle_receipt(self: &Arc<Self>, node: &Node) {
        let mut attrs = node.attrs();
        let from = attrs.jid("from");
        let id = attrs.string("id");
        let receipt_type_str = attrs.optional_string("type").unwrap_or("delivery");

        use crate::types::presence::ReceiptType;
        let receipt_type = ReceiptType::from(receipt_type_str.to_string());

        info!("Received receipt type '{receipt_type:?}' for message {id} from {from}");

        let receipt = crate::types::events::Receipt {
            message_ids: vec![id.clone()],
            source: crate::types::message::MessageSource {
                chat: from.clone(),
                sender: from.clone(),
                ..Default::default()
            },
            timestamp: chrono::Utc::now(),
            r#type: receipt_type.clone(),
            message_sender: from.clone(),
        };

        if receipt_type == ReceiptType::Retry {
            let client_clone = Arc::clone(self);
            let node_clone = node.clone();
            tokio::spawn(async move {
                if let Err(e) = client_clone
                    .handle_retry_receipt(&receipt, &node_clone)
                    .await
                {
                    log::warn!(
                        "Failed to handle retry receipt for {}: {e:?}",
                        receipt.message_ids[0]
                    );
                }
            });
        } else {
            self.dispatch_event(Event::Receipt(receipt)).await;
        }
    }

    pub async fn set_passive(&self, passive: bool) -> Result<(), crate::request::IqError> {
        use crate::binary::node::Node;
        use crate::request::{InfoQuery, InfoQueryType};
        use crate::types::jid::SERVER_JID;

        let tag = if passive { "passive" } else { "active" };

        let query = InfoQuery {
            namespace: "passive",
            query_type: InfoQueryType::Set,
            to: SERVER_JID.parse().unwrap(),
            target: None,
            id: None,
            content: Some(crate::binary::node::NodeContent::Nodes(vec![Node {
                tag: tag.to_string(),
                ..Default::default()
            }])),
            timeout: None,
        };

        self.send_iq(query).await.map(|_| ())
    }

    async fn handle_success(self: &Arc<Self>, node: &Node) {
        info!("Successfully authenticated with WhatsApp servers!");
        self.is_logged_in.store(true, Ordering::Relaxed);
        *self.last_successful_connect.lock().await = Some(chrono::Utc::now());
        self.auto_reconnect_errors.store(0, Ordering::Relaxed);

        // Check for `pushname` and update the store if it's different.
        if let Some(push_name) = node.attrs.get("pushname") {
            let new_name = push_name.clone();
            let (needs_update, old_name) = {
                let store = self.store.read().await;
                (store.push_name != new_name, store.push_name.clone())
            };

            if needs_update {
                info!(target: "Client", "Updating push name from server to '{}'", new_name);
                {
                    let mut store = self.store.write().await;
                    store.push_name = new_name.clone();
                } // write lock dropped

                self.dispatch_event(Event::SelfPushNameUpdated(
                    crate::types::events::SelfPushNameUpdated {
                        from_server: true,
                        old_name,
                        new_name,
                    },
                ))
                .await;
            }
        }

        let client_clone = self.clone();
        tokio::spawn(async move {
            // This task runs after successful authentication.
            if let Err(e) = client_clone.set_passive(false).await {
                warn!("Failed to send post-connect passive IQ: {e:?}");
            }

            // Now, attempt to send presence. This might fail if push_name is still empty, which is OK.
            if let Err(e) = client_clone.send_presence(Presence::Available).await {
                warn!("Could not send initial presence: {e:?}. This is expected if push_name is not yet known.");
            }

            client_clone
                .dispatch_event(Event::Connected(crate::types::events::Connected))
                .await;
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
                self.dispatch_event(event).await;
            }
            ("503", _) => {
                info!(target: "Client", "Got 503 service unavailable, will auto-reconnect.");
            }
            _ => {
                error!(target: "Client", "Unknown stream error: {node}");
                self.expect_disconnect().await;
                self.dispatch_event(Event::StreamError(crate::types::events::StreamError {
                    code: code.to_string(),
                    raw: Some(node.clone()),
                }))
                .await;
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
            self.dispatch_event(Event::LoggedOut(crate::types::events::LoggedOut {
                on_connect: true,
                reason,
            }))
            .await;
        } else if let ConnectFailureReason::TempBanned = reason {
            let ban_code = attrs.optional_u64("code").unwrap_or(0) as i32;
            let expire_secs = attrs.optional_u64("expire").unwrap_or(0);
            let expire_duration =
                chrono::Duration::try_seconds(expire_secs as i64).unwrap_or_default();
            warn!(target: "Client", "Temporary ban connect failure: {node}");
            self.dispatch_event(Event::TemporaryBan(crate::types::events::TemporaryBan {
                code: crate::types::events::TempBanReason::from(ban_code),
                expire: expire_duration,
            }))
            .await;
        } else if let ConnectFailureReason::ClientOutdated = reason {
            error!(target: "Client", "Client is outdated and was rejected by server.");
            self.dispatch_event(Event::ClientOutdated(crate::types::events::ClientOutdated))
                .await;
        } else {
            warn!(target: "Client", "Unknown connect failure: {node}");
            self.dispatch_event(Event::ConnectFailure(
                crate::types::events::ConnectFailure {
                    reason,
                    message: attrs.optional_string("message").unwrap_or("").to_string(),
                    raw: Some(node.clone()),
                },
            ))
            .await;
        }
    }

    async fn handle_iq(self: &Arc<Self>, node: &Node) -> bool {
        if let Some("get") = node.attrs().optional_string("type") {
            if let Some(_ping_node) = node.get_optional_child("ping") {
                info!(target: "Client", "Received ping, sending pong.");
                let mut parser = node.attrs();
                let from_jid = parser.jid("from");
                let id = parser.string("id");
                let pong = Node {
                    tag: "iq".into(),
                    attrs: [
                        ("to".into(), from_jid.to_string()),
                        ("id".into(), id),
                        ("type".into(), "result".into()),
                    ]
                    .iter()
                    .cloned()
                    .collect(),
                    content: None,
                };
                if let Err(e) = self.send_node(pong).await {
                    warn!("Failed to send pong: {e:?}");
                }
                return true;
            }
        }

        if pair::handle_iq(self, node).await {
            return true;
        }

        false
    }

    pub(crate) async fn add_event_handler_internal(&self, handler: EventHandler) -> usize {
        let id = NEXT_HANDLER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let wrapped = WrappedHandler { id, handler };
        self.event_handlers.write().await.push(wrapped);
        id
    }

    pub async fn add_event_handler(&self, handler: EventHandler) {
        self.add_event_handler_internal(handler).await;
    }

    pub async fn remove_event_handler(&self, id: usize) -> bool {
        let mut handlers = self.event_handlers.write().await;
        let initial_len = handlers.len();
        handlers.retain(|h| h.id != id);
        handlers.len() < initial_len
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

    pub async fn dispatch_event(&self, event: Event) {
        let event_arc = Arc::new(event);
        let handlers = self.event_handlers.read().await;
        for wrapped in handlers.iter() {
            (wrapped.handler)(event_arc.clone());
        }
    }

    pub async fn send_node(&self, node: Node) -> Result<(), ClientError> {
        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
            Some(socket) => socket,
            None => return Err(ClientError::NotConnected),
        };

        debug!(target: "Client/Send", "{node}");

        let payload = crate::binary::marshal(&node).map_err(|e| {
            error!("Failed to marshal node: {e:?}");
            SocketError::Crypto("Marshal error".to_string())
        })?;

        noise_socket.send_frame(&payload).await.map_err(Into::into)
    }

    pub async fn send_presence(&self, presence: Presence) -> Result<(), anyhow::Error> {
        let store = self.store.read().await;
        debug!(
            "🔍 send_presence called with push_name: '{}'",
            store.push_name
        );
        if store.push_name.is_empty() {
            warn!("❌ Cannot send presence: push_name is empty!");
            return Err(anyhow::anyhow!(
                "Cannot send presence without a push name set"
            ));
        }
        let presence_type = match presence {
            Presence::Available => "available",
            Presence::Unavailable => "unavailable",
        };
        let node = crate::binary::node::Node {
            tag: "presence".to_string(),
            attrs: [
                ("type".to_string(), presence_type.to_string()),
                ("name".to_string(), store.push_name.clone()),
            ]
            .into(),
            content: None,
        };
        drop(store);
        info!(
            "📡 Sending presence stanza: <presence type=\"{}\" name=\"{}\"/>",
            presence_type,
            node.attrs.get("name").unwrap_or(&"".to_string())
        );
        self.send_node(node).await.map_err(|e| e.into())
    }

    /// Sets the push name (display name) for this client.
    /// This name will be sent in presence announcements and shown to other users.
    /// This will trigger a `SelfPushNameUpdated` event, which your application
    /// should handle to persist the new state.
    pub async fn set_push_name(&self, name: String) -> Result<(), anyhow::Error> {
        let (needs_update, old_name) = {
            let store = self.store.read().await;
            (store.push_name != name, store.push_name.clone())
        };

        if needs_update {
            let mut store = self.store.write().await;
            store.push_name = name.clone();
            drop(store);

            self.dispatch_event(Event::SelfPushNameUpdated(
                crate::types::events::SelfPushNameUpdated {
                    from_server: false, // This was a manual call
                    old_name,
                    new_name: name,
                },
            ))
            .await;
        }
        Ok(())
    }

    /// Add a message to the recent message cache (with eviction)
    pub(crate) async fn add_recent_message(
        &self,
        to: crate::types::jid::Jid,
        id: String,
        msg: wa::Message,
    ) {
        const RECENT_MESSAGES_SIZE: usize = 256;
        let key = RecentMessageKey { to, id };
        let mut map_guard = self.recent_messages_map.lock().await;
        let mut list_guard = self.recent_messages_list.lock().await;

        if list_guard.len() >= RECENT_MESSAGES_SIZE {
            if let Some(old_key) = list_guard.pop_front() {
                map_guard.remove(&old_key);
            }
        }
        list_guard.push_back(key.clone());
        map_guard.insert(key, msg);
    }

    /// Retrieve a message from the recent message cache
    pub(crate) async fn get_recent_message(
        &self,
        to: crate::types::jid::Jid,
        id: String,
    ) -> Option<wa::Message> {
        let key = RecentMessageKey { to, id };
        let map_guard = self.recent_messages_map.lock().await;
        map_guard.get(&key).cloned()
    }

    /// Handle retry receipt: clear session and resend original message
    pub(crate) async fn handle_retry_receipt(
        &self,
        receipt: &crate::types::events::Receipt,
        node: &Node,
    ) -> Result<(), anyhow::Error> {
        let retry_child = node
            .get_optional_child("retry")
            .ok_or_else(|| anyhow::anyhow!("<retry> child missing from receipt"))?;

        let message_id = retry_child.attrs().string("id");

        let original_msg = self
            .get_recent_message(receipt.source.chat.clone(), message_id.clone())
            .await
            .ok_or_else(|| {
                anyhow::anyhow!("Could not find message {} in cache for retry", message_id)
            })?;

        let signal_address = crate::signal::address::SignalAddress::new(
            receipt.source.sender.user.clone(),
            receipt.source.sender.device as u32,
        );
        let address_str = signal_address.to_string();
        let store_guard = self.store.read().await;
        let _ = store_guard.backend.delete_session(&address_str).await;
        info!(
            "Deleted session for {} due to retry receipt, will re-establish.",
            receipt.source.sender
        );

        self.send_message(receipt.source.chat.clone(), original_msg)
            .await?;
        Ok(())
    }

    /// Gets the current push name (display name) for this client.
    pub async fn get_push_name(&self) -> String {
        let store = self.store.read().await;
        store.push_name.clone()
    }

    /// Checks if the device has all required information for presence announcements.
    /// Returns true if the device has a JID and push name set.
    pub async fn is_ready_for_presence(&self) -> bool {
        let store = self.store.read().await;
        store.id.is_some() && !store.push_name.is_empty()
    }

    /// Gets diagnostic information about the device state for debugging.
    pub async fn get_device_debug_info(&self) -> String {
        let store = self.store.read().await;
        format!(
            "Device Debug Info:\n  - JID: {:?}\n  - Push Name: '{}'\n  - Has Account: {}\n  - Ready for Presence: {}",
            store.id,
            store.push_name,
            store.account.is_some(),
            store.id.is_some() && !store.push_name.is_empty()
        )
    }

    /// Save the current device state to persistent storage.
    /// This method requires the concrete FileStore type to be passed in.
    pub async fn save_device_state(
        &self,
        file_store: &crate::store::filestore::FileStore,
    ) -> Result<(), anyhow::Error> {
        let store = self.store.read().await;
        file_store
            .save_device_data(&store.to_serializable())
            .await
            .map_err(|e| anyhow::anyhow!("Failed to save device state: {}", e))
    }
}
