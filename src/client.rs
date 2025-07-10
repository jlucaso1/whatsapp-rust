use crate::binary::node::Node;
use crate::handshake;
use crate::pair;
use crate::qrcode;
use crate::signal::address::SignalAddress;
use crate::signal::store::{SenderKeyStore, SessionStore};
use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager}; // Added PersistenceManager and DeviceCommand, removed self // Import required traits

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
    // pub store: std::sync::Arc<tokio::sync::RwLock<store::Device>>, // Replaced with persistence_manager
    pub persistence_manager: Arc<PersistenceManager>,

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

    pub(crate) lid_pn_map: Arc<Mutex<HashMap<crate::types::jid::Jid, crate::types::jid::Jid>>>,

    pub(crate) expected_disconnect: Arc<AtomicBool>,

    pub(crate) recent_messages_map: Arc<Mutex<HashMap<RecentMessageKey, wa::Message>>>,
    pub(crate) recent_messages_list: Arc<Mutex<VecDeque<RecentMessageKey>>>,

    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>,
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
    pub(crate) last_buffer_cleanup: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,
}

impl Client {
    // pub fn new(store: store::Device) -> Self { // Old constructor
    pub fn new(persistence_manager: Arc<PersistenceManager>) -> Self {
        let mut unique_id_bytes = [0u8; 2];
        rand::thread_rng().fill_bytes(&mut unique_id_bytes);

        Self {
            // store: std::sync::Arc::new(tokio::sync::RwLock::new(store)), // Old store
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
            event_handlers: Arc::new(RwLock::new(Vec::new())),

            // Initialize the per-chat locks map
            chat_locks: Arc::new(DashMap::new()),

            lid_pn_map: Arc::new(Mutex::new(HashMap::new())),

            expected_disconnect: Arc::new(AtomicBool::new(false)),

            recent_messages_map: Arc::new(Mutex::new(HashMap::with_capacity(256))),
            recent_messages_list: Arc::new(Mutex::new(VecDeque::with_capacity(256))),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),
            last_buffer_cleanup: Arc::new(Mutex::new(None)),
        }
    }
    // REMOVED: get_group_participants stub. Use query_group_info instead.

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

        // Use persistence_manager to get a device snapshot for handshake
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let noise_socket =
            handshake::do_handshake(&device_snapshot, &mut frame_socket, &mut frames_rx).await?;
        // It's assumed do_handshake might modify the device_snapshot (e.g. JID, account details after pairing)
        // If so, these changes need to be committed back via PersistenceManager commands.
        // For QR pairing, this is handled by QrCodeEvent::Success which should trigger commands.
        // For login, the <success> handler will update the device via commands.

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
                let pm_clone = self.persistence_manager.clone(); // Use persistence_manager
                tokio::spawn(async move {
                    // Access backend through persistence_manager's device's backend
                    // This requires PersistenceManager to expose a way to get the backend,
                    // or for Device to hold an Arc<dyn Backend> that PM initializes.
                    // Assuming Device has `backend: Arc<dyn Backend>`
                    let device_snapshot = pm_clone.get_device_snapshot().await;
                    let backend = device_snapshot.backend.clone();
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
        let participant = attrs.optional_jid("participant");

        use crate::types::presence::ReceiptType;
        let receipt_type = ReceiptType::from(receipt_type_str.to_string());

        info!("Received receipt type '{receipt_type:?}' for message {id} from {from}");

        let sender = if from.is_group() && participant.is_some() {
            participant.unwrap()
        } else {
            from.clone()
        };

        let receipt = crate::types::events::Receipt {
            message_ids: vec![id.clone()],
            source: crate::types::message::MessageSource {
                chat: from.clone(),
                sender: sender.clone(),
                ..Default::default()
            },
            timestamp: chrono::Utc::now(),
            r#type: receipt_type.clone(),
            message_sender: sender.clone(),
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

        // --- MODIFICATION START ---
        // Check for `lid` and update the store. This is crucial for group messaging.
        if let Some(lid_str) = node.attrs.get("lid") {
            if let Ok(lid) = lid_str.parse::<crate::types::jid::Jid>() {
                // Use command to update LID
                let current_device = self.persistence_manager.get_device_snapshot().await;
                if current_device.lid.as_ref() != Some(&lid) {
                    info!(target: "Client", "Updating LID from server to '{}'", lid);
                    self.persistence_manager
                        .process_command(DeviceCommand::SetLid(Some(lid)))
                        .await;
                }
            } else {
                warn!(target: "Client", "Failed to parse LID from success stanza: {}", lid_str);
            }
        } else {
            warn!(target: "Client", "LID not found in <success> stanza. Group messaging may fail.");
        }
        // --- MODIFICATION END ---

        // Check for `pushname` and update the store if it's different.
        if let Some(push_name_attr) = node.attrs.get("pushname") {
            let new_name = push_name_attr.clone();
            let current_device = self.persistence_manager.get_device_snapshot().await;
            let old_name = current_device.push_name.clone();

            if old_name != new_name {
                info!(target: "Client", "Updating push name from server to '{}'", new_name);
                self.persistence_manager
                    .process_command(DeviceCommand::SetPushName(new_name.clone()))
                    .await;

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

        // Update account info if present in success node
        // This part needs to be adapted if `account` is part of the success node attributes or children
        // For example, if it's an attribute:
        // if let Some(account_str) = node.attrs.get("account") { ... parse and update ... }
        // Or if it's a child node:
        // if let Some(account_node) = node.get_optional_child("account") { ... parse and update ... }
        // Assuming AdvSignedDeviceIdentity might come from here or another handshake part
        // For now, this is a placeholder. If login provides AdvSignedDeviceIdentity,
        // it should be processed and a DeviceCommand::SetAccount should be sent.
        // e.g. self.persistence_manager.process_command(DeviceCommand::SetAccount(Some(parsed_account_identity))).await;

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
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        debug!(
            "🔍 send_presence called with push_name: '{}'",
            device_snapshot.push_name
        );
        if device_snapshot.push_name.is_empty() {
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
                ("name".to_string(), device_snapshot.push_name.clone()),
            ]
            .into(),
            content: None,
        };
        // drop(device_snapshot) // Not needed as it's a clone
        info!(
            "📡 Sending presence stanza: <presence type=\"{}\" name=\"{}\"/>",
            presence_type,
            node.attrs.get("name").unwrap_or(&"".to_string())
        );
        self.send_node(node).await.map_err(|e| e.into())
    }

    /// Sets the push name (display name) for this client.
    /// This name will be sent in presence announcements and shown to other users.
    /// This will trigger a `SelfPushNameUpdated` event. The PersistenceManager
    /// will handle saving the state.
    pub async fn set_push_name(&self, name: String) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let old_name = device_snapshot.push_name.clone();

        if old_name != name {
            self.persistence_manager
                .process_command(DeviceCommand::SetPushName(name.clone()))
                .await;

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

        let participant_jid = receipt.source.sender.clone();

        // Check if this is a group message
        if receipt.source.chat.is_group() {
            // For group messages, delete the sender key to force generation of a new one
            // This is the key fix to prevent infinite retry loops
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_lid = device_snapshot
                .lid
                .clone()
                .ok_or_else(|| anyhow::anyhow!("LID missing for group retry handling"))?;

            let sender_address = SignalAddress::new(own_lid.user.clone(), own_lid.device as u32);
            let sender_key_name = crate::signal::sender_key_name::SenderKeyName::new(
                receipt.source.chat.to_string(),
                sender_address.to_string(),
            );

            let device_store = self.persistence_manager.get_device_arc().await;

            // Delete the sender key record to force creation of a new one
            if let Err(e) = device_store.delete_sender_key(&sender_key_name).await {
                log::warn!(
                    "Failed to delete sender key for group {}: {}",
                    receipt.source.chat,
                    e
                );
            } else {
                info!(
                    "Deleted sender key for group {} due to retry receipt from {}",
                    receipt.source.chat, participant_jid
                );
            }

            // Also delete the pairwise session with the participant who sent the retry
            let signal_address = crate::signal::address::SignalAddress::new(
                participant_jid.user.clone(),
                participant_jid.device as u32,
            );

            if let Err(e) = device_store.delete_session(&signal_address).await {
                // It's not a critical error if the session file doesn't exist,
                // especially when dealing with the primary device (:0).
                if let Some(store_err) = e.downcast_ref::<crate::store::error::StoreError>() {
                    if !matches!(store_err, crate::store::error::StoreError::Io(io_err) if io_err.kind() == std::io::ErrorKind::NotFound)
                    {
                        log::warn!("Failed to delete session for {}: {}", signal_address, e);
                    }
                } else {
                    log::warn!("Failed to delete session for {}: {}", signal_address, e);
                }
            } else {
                info!(
                    "Deleted session for {} due to retry receipt",
                    signal_address
                );
            }
        } else {
            // For direct messages, only delete the pairwise session
            let signal_address = crate::signal::address::SignalAddress::new(
                participant_jid.user.clone(),
                participant_jid.device as u32,
            );

            let device_store = self.persistence_manager.get_device_arc().await;
            if let Err(e) = device_store.delete_session(&signal_address).await {
                // It's not a critical error if the session file doesn't exist.
                if let Some(store_err) = e.downcast_ref::<crate::store::error::StoreError>() {
                    if !matches!(store_err, crate::store::error::StoreError::Io(io_err) if io_err.kind() == std::io::ErrorKind::NotFound)
                    {
                        log::warn!("Failed to delete session for {}: {}", signal_address, e);
                    }
                } else {
                    log::warn!("Failed to delete session for {}: {}", signal_address, e);
                }
            } else {
                info!(
                    "Deleted session for {} due to retry receipt",
                    signal_address
                );
            }
        }

        // Resend the original message
        self.send_message_impl(receipt.source.chat.clone(), original_msg, message_id)
            .await?; // Use _impl to send with original ID
        Ok(())
    }

    /// Gets the current push name (display name) for this client.
    pub async fn get_push_name(&self) -> String {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        device_snapshot.push_name.clone()
    }

    /// Checks if the device has all required information for presence announcements.
    /// Returns true if the device has a JID and push name set.
    pub async fn is_ready_for_presence(&self) -> bool {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        device_snapshot.id.is_some() && !device_snapshot.push_name.is_empty()
    }

    /// Gets diagnostic information about the device state for debugging.
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

    // save_device_state is removed as PersistenceManager handles saving.
    // If a manual save is needed, it should be a method on PersistenceManager.

    /// Query group info to get all participant JIDs.
    pub async fn query_group_info(
        &self,
        jid: &crate::types::jid::Jid,
    ) -> Result<Vec<crate::types::jid::Jid>, anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        let query_node = Node {
            tag: "query".to_string(),
            attrs: [("request".to_string(), "interactive".to_string())].into(),
            content: None,
        };
        let iq = crate::request::InfoQuery {
            namespace: "w:g2",
            query_type: crate::request::InfoQueryType::Get,
            to: jid.clone(),
            content: Some(NodeContent::Nodes(vec![query_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let resp_node = self.send_iq(iq).await?;

        let group_node = resp_node
            .get_optional_child("group")
            .ok_or_else(|| anyhow::anyhow!("<group> not found in group info response"))?;

        let mut participants = Vec::new();
        // Lock the map to update it
        let mut lid_pn_map = self.lid_pn_map.lock().await;

        for participant_node in group_node.get_children_by_tag("participant") {
            let mut attrs = participant_node.attrs();
            let participant_jid = attrs.jid("jid");

            // --- MODIFICATION START ---
            if let Some(lid_jid_str) = attrs.optional_string("lid") {
                if !lid_jid_str.is_empty() {
                    if let Ok(lid_jid) = lid_jid_str.parse::<crate::types::jid::Jid>() {
                        log::debug!("Found LID-PN mapping: {} <-> {}", participant_jid, lid_jid);
                        // Store both ways for easy lookup
                        lid_pn_map.insert(participant_jid.clone(), lid_jid.clone());
                        lid_pn_map.insert(lid_jid, participant_jid.clone());
                    }
                }
            }
            // --- MODIFICATION END ---

            if !attrs.ok() {
                log::warn!("Failed to parse participant attrs: {:?}", attrs.errors);
                continue;
            }
            participants.push(participant_jid);
        }

        Ok(participants)
    }

    /// Fetch all devices for the given JIDs using usync IQ.
    pub async fn get_user_devices(
        &self,
        jids: &[crate::types::jid::Jid],
    ) -> Result<Vec<crate::types::jid::Jid>, anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        let mut user_nodes = Vec::new();
        for jid in jids {
            user_nodes.push(Node {
                tag: "user".to_string(),
                attrs: [("jid".to_string(), jid.to_non_ad().to_string())].into(),
                content: None,
            });
        }

        let usync_node = Node {
            tag: "usync".to_string(),
            attrs: [
                ("context".to_string(), "message".to_string()),
                ("index".to_string(), "0".to_string()),
                ("last".to_string(), "true".to_string()),
                ("mode".to_string(), "query".to_string()),
                ("sid".to_string(), self.generate_request_id()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(vec![
                Node {
                    tag: "query".to_string(),
                    attrs: Default::default(),
                    content: Some(NodeContent::Nodes(vec![Node {
                        tag: "devices".to_string(),
                        attrs: [("version".to_string(), "2".to_string())].into(),
                        content: None,
                    }])),
                },
                Node {
                    tag: "list".to_string(),
                    attrs: Default::default(),
                    content: Some(NodeContent::Nodes(user_nodes)),
                },
            ])),
        };

        let iq = crate::request::InfoQuery {
            namespace: "usync",
            query_type: crate::request::InfoQueryType::Get,
            to: crate::types::jid::SERVER_JID.parse().unwrap(),
            content: Some(NodeContent::Nodes(vec![usync_node])),
            id: None,
            target: None,
            timeout: None,
        };

        let resp_node = self.send_iq(iq).await?;

        let list_node = resp_node
            .get_optional_child_by_tag(&["usync", "list"])
            .ok_or_else(|| anyhow::anyhow!("<usync> or <list> not found in usync response"))?;

        let mut all_devices = Vec::new();
        for user_node in list_node.get_children_by_tag("user") {
            let user_jid = user_node.attrs().jid("jid");
            let device_list_node = user_node
                .get_optional_child_by_tag(&["devices", "device-list"])
                .ok_or_else(|| {
                    anyhow::anyhow!(format!("<device-list> not found for user {}", user_jid))
                })?;

            for device_node in device_list_node.get_children_by_tag("device") {
                let device_id_str = device_node.attrs().string("id");
                let device_id: u16 = device_id_str.parse()?;

                let mut device_jid = user_jid.clone();
                device_jid.device = device_id;
                all_devices.push(device_jid);
            }
        }

        Ok(all_devices)
    }
}
