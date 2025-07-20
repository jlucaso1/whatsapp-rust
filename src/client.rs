use crate::binary::node::Node;
use crate::handshake;
use crate::pair;
use crate::qrcode;

use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager}; // Added PersistenceManager and DeviceCommand, removed self // Import required traits

use crate::handlers;
use crate::types::events::{ConnectFailureReason, Event, EventBus};
use crate::types::presence::Presence;

// New modules for refactored logic

use dashmap::DashMap;
use log::{debug, error, info, warn};
use rand::RngCore;
use scopeguard;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use thiserror::Error;
use tokio::sync::{Mutex, Notify, broadcast, mpsc};
use tokio::time::{Duration, sleep};

use crate::socket::{FrameSocket, NoiseSocket, SocketError};
use waproto::whatsapp as wa;

// Macro to generate typed event subscription methods
macro_rules! generate_subscription_methods {
    ($(($method_name:ident, $return_type:ty, $bus_field:ident)),* $(,)?) => {
        $(
            pub fn $method_name(&self) -> broadcast::Receiver<$return_type> {
                self.event_bus.$bus_field.subscribe()
            }
        )*
    };
}

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
    pub to: crate::types::jid::Jid,
    pub id: String,
}

pub struct Client {
    /// Core protocol client (platform-independent)
    pub core: wacore::client::CoreClient,

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
    pub(crate) event_bus: Arc<EventBus>,

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

    /// In-memory cache for fast duplicate message detection
    pub(crate) processed_messages_cache: Arc<Mutex<HashSet<RecentMessageKey>>>,

    /// Test mode fields
    pub(crate) test_mode: Arc<AtomicBool>,
    pub(crate) test_network_sender:
        Arc<Mutex<Option<tokio::sync::mpsc::UnboundedSender<crate::test_network::TestMessage>>>>,
}

impl Client {
    pub async fn new(persistence_manager: Arc<PersistenceManager>) -> Self {
        let mut unique_id_bytes = [0u8; 2];
        rand::rng().fill_bytes(&mut unique_id_bytes);

        // Get initial device state and create core client
        let device_snapshot = persistence_manager.get_device_snapshot().await;
        let core = wacore::client::CoreClient::new(device_snapshot.core.clone());

        // Initialize processed messages cache from device state
        let processed_messages_cache = {
            let mut cache = HashSet::new();
            for processed_msg in &device_snapshot.core.processed_messages {
                // Convert from wacore::ProcessedMessageKey to client::RecentMessageKey
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
            event_bus: Arc::new(EventBus::new()),

            // Initialize the per-chat locks map
            chat_locks: Arc::new(DashMap::new()),

            lid_pn_map: Arc::new(Mutex::new(HashMap::new())),

            expected_disconnect: Arc::new(AtomicBool::new(false)),

            recent_messages_map: Arc::new(Mutex::new(HashMap::with_capacity(256))),
            recent_messages_list: Arc::new(Mutex::new(VecDeque::with_capacity(256))),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),
            processed_messages_cache,

            // Initialize test mode fields
            test_mode: Arc::new(AtomicBool::new(false)),
            test_network_sender: Arc::new(Mutex::new(None)),
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

    /// Checks if a message has already been processed (for deduplication)
    pub async fn has_message_been_processed(&self, key: &RecentMessageKey) -> bool {
        let cache = self.processed_messages_cache.lock().await;
        cache.contains(key)
    }

    /// Marks a message as processed and adds it to both the in-memory cache and persistent storage
    pub async fn mark_message_as_processed(&self, key: RecentMessageKey) {
        // Convert to wacore type and send to persistence manager first
        let wacore_key = wacore::store::device::ProcessedMessageKey {
            to: key.to.clone(),
            id: key.id.clone(),
        };

        self.persistence_manager
            .process_command(wacore::store::commands::DeviceCommand::AddProcessedMessage(
                wacore_key,
            ))
            .await;

        // Rebuild in-memory cache from the updated persistent storage
        // This ensures the cache respects the cap and maintains consistency
        {
            let mut cache = self.processed_messages_cache.lock().await;
            cache.clear();

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            for processed_msg in &device_snapshot.core.processed_messages {
                let key = RecentMessageKey {
                    to: processed_msg.to.clone(),
                    id: processed_msg.id.clone(),
                };
                cache.insert(key);
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
            if let Some(sync_node) = node.get_optional_child("sync")
                && let Some(collection_node) = sync_node.get_optional_child("collection")
            {
                let name = collection_node.attrs().string("name");
                debug!(target: "Client/Recv", "Received app state sync response for '{name}' (hiding content).");
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
        // --- MODIFICATION END ---

        // Check for `pushname` and update the store if it's different.
        if let Some(push_name_attr) = node.attrs.get("pushname") {
            let new_name = push_name_attr.clone();
            let current_device = self.persistence_manager.get_device_snapshot().await;
            let old_name = current_device.push_name.clone();

            if old_name != new_name {
                info!(target: "Client", "Updating push name from server to '{new_name}'");
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
                warn!(
                    "Could not send initial presence: {e:?}. This is expected if push_name is not yet known."
                );
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
        // Send events to their respective typed channels
        // Ignore send errors as they indicate no subscribers, which is expected
        match event {
            Event::Connected(data) => {
                let _ = self.event_bus.connected.send(Arc::new(data));
            }
            Event::Disconnected(data) => {
                let _ = self.event_bus.disconnected.send(Arc::new(data));
            }
            Event::PairSuccess(data) => {
                let _ = self.event_bus.pair_success.send(Arc::new(data));
            }
            Event::PairError(data) => {
                let _ = self.event_bus.pair_error.send(Arc::new(data));
            }
            Event::LoggedOut(data) => {
                let _ = self.event_bus.logged_out.send(Arc::new(data));
            }
            Event::Qr(data) => {
                let _ = self.event_bus.qr.send(Arc::new(data));
            }
            Event::QrScannedWithoutMultidevice(data) => {
                let _ = self
                    .event_bus
                    .qr_scanned_without_multidevice
                    .send(Arc::new(data));
            }
            Event::ClientOutdated(data) => {
                let _ = self.event_bus.client_outdated.send(Arc::new(data));
            }
            Event::Message(msg, info) => {
                let _ = self.event_bus.message.send(Arc::new((msg, info)));
            }
            Event::Receipt(data) => {
                let _ = self.event_bus.receipt.send(Arc::new(data));
            }
            Event::UndecryptableMessage(data) => {
                let _ = self.event_bus.undecryptable_message.send(Arc::new(data));
            }
            Event::Notification(data) => {
                let _ = self.event_bus.notification.send(Arc::new(data));
            }
            Event::ChatPresence(data) => {
                let _ = self.event_bus.chat_presence.send(Arc::new(data));
            }
            Event::Presence(data) => {
                let _ = self.event_bus.presence.send(Arc::new(data));
            }
            Event::PictureUpdate(data) => {
                let _ = self.event_bus.picture_update.send(Arc::new(data));
            }
            Event::UserAboutUpdate(data) => {
                let _ = self.event_bus.user_about_update.send(Arc::new(data));
            }
            Event::JoinedGroup(data) => {
                let _ = self.event_bus.joined_group.send(Arc::new(data));
            }
            Event::GroupInfoUpdate { jid, update } => {
                let _ = self
                    .event_bus
                    .group_info_update
                    .send(Arc::new((jid, update)));
            }
            Event::ContactUpdate(data) => {
                let _ = self.event_bus.contact_update.send(Arc::new(data));
            }
            Event::PushNameUpdate(data) => {
                let _ = self.event_bus.push_name_update.send(Arc::new(data));
            }
            Event::SelfPushNameUpdated(data) => {
                let _ = self.event_bus.self_push_name_updated.send(Arc::new(data));
            }
            Event::PinUpdate(data) => {
                let _ = self.event_bus.pin_update.send(Arc::new(data));
            }
            Event::MuteUpdate(data) => {
                let _ = self.event_bus.mute_update.send(Arc::new(data));
            }
            Event::ArchiveUpdate(data) => {
                let _ = self.event_bus.archive_update.send(Arc::new(data));
            }
            Event::StreamReplaced(data) => {
                let _ = self.event_bus.stream_replaced.send(Arc::new(data));
            }
            Event::TemporaryBan(data) => {
                let _ = self.event_bus.temporary_ban.send(Arc::new(data));
            }
            Event::ConnectFailure(data) => {
                let _ = self.event_bus.connect_failure.send(Arc::new(data));
            }
            Event::StreamError(data) => {
                let _ = self.event_bus.stream_error.send(Arc::new(data));
            }
        }
    }

    // Generate all subscription methods using the macro
    generate_subscription_methods! {
        (subscribe_to_connected, Arc<crate::types::events::Connected>, connected),
        (subscribe_to_disconnected, Arc<crate::types::events::Disconnected>, disconnected),
        (subscribe_to_pair_success, Arc<crate::types::events::PairSuccess>, pair_success),
        (subscribe_to_pair_error, Arc<crate::types::events::PairError>, pair_error),
        (subscribe_to_logged_out, Arc<crate::types::events::LoggedOut>, logged_out),
        (subscribe_to_qr, Arc<crate::types::events::Qr>, qr),
        (subscribe_to_qr_scanned_without_multidevice, Arc<crate::types::events::QrScannedWithoutMultidevice>, qr_scanned_without_multidevice),
        (subscribe_to_client_outdated, Arc<crate::types::events::ClientOutdated>, client_outdated),
        (subscribe_to_messages, Arc<(Box<waproto::whatsapp::Message>, crate::types::message::MessageInfo)>, message),
        (subscribe_to_receipts, Arc<crate::types::events::Receipt>, receipt),
        (subscribe_to_undecryptable_messages, Arc<crate::types::events::UndecryptableMessage>, undecryptable_message),
        (subscribe_to_notifications, Arc<crate::binary::node::Node>, notification),
        (subscribe_to_chat_presence, Arc<crate::types::events::ChatPresenceUpdate>, chat_presence),
        (subscribe_to_presence, Arc<crate::types::events::PresenceUpdate>, presence),
        (subscribe_to_picture_updates, Arc<crate::types::events::PictureUpdate>, picture_update),
        (subscribe_to_user_about_updates, Arc<crate::types::events::UserAboutUpdate>, user_about_update),
        (subscribe_to_joined_groups, Arc<Box<waproto::whatsapp::Conversation>>, joined_group),
        (subscribe_to_group_info_updates, Arc<(crate::types::jid::Jid, Box<waproto::whatsapp::SyncActionValue>)>, group_info_update),
        (subscribe_to_contact_updates, Arc<crate::types::events::ContactUpdate>, contact_update),
        (subscribe_to_push_name_updates, Arc<crate::types::events::PushNameUpdate>, push_name_update),
        (subscribe_to_self_push_name_updated, Arc<crate::types::events::SelfPushNameUpdated>, self_push_name_updated),
        (subscribe_to_pin_updates, Arc<crate::types::events::PinUpdate>, pin_update),
        (subscribe_to_mute_updates, Arc<crate::types::events::MuteUpdate>, mute_update),
        (subscribe_to_archive_updates, Arc<crate::types::events::ArchiveUpdate>, archive_update),
        (subscribe_to_stream_replaced, Arc<crate::types::events::StreamReplaced>, stream_replaced),
        (subscribe_to_temporary_ban, Arc<crate::types::events::TemporaryBan>, temporary_ban),
        (subscribe_to_connect_failure, Arc<crate::types::events::ConnectFailure>, connect_failure),
        (subscribe_to_stream_error, Arc<crate::types::events::StreamError>, stream_error),
    }

    /// Helper method for tests to subscribe to all events
    /// This recreates the old behavior where all events are sent to a single channel
    pub fn subscribe_to_all_events(&self) -> tokio::sync::mpsc::UnboundedReceiver<Event> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        // Helper macro for standard single-value events
        macro_rules! forward_simple_events {
            ($(($method_name:ident, $event_variant:ident)),* $(,)?) => {
                $(
                    {
                        let tx = tx.clone();
                        let mut recv = self.$method_name();
                        tokio::spawn(async move {
                            while let Ok(data) = recv.recv().await {
                                let event = Event::$event_variant((*data).clone());
                                if tx.send(event).is_err() {
                                    break;
                                }
                            }
                        });
                    }
                )*
            };
        }

        // Forward simple events using macro
        forward_simple_events! {
            (subscribe_to_connected, Connected),
            (subscribe_to_disconnected, Disconnected),
            (subscribe_to_pair_success, PairSuccess),
            (subscribe_to_pair_error, PairError),
            (subscribe_to_logged_out, LoggedOut),
            (subscribe_to_qr, Qr),
            (subscribe_to_qr_scanned_without_multidevice, QrScannedWithoutMultidevice),
            (subscribe_to_client_outdated, ClientOutdated),
            (subscribe_to_receipts, Receipt),
            (subscribe_to_undecryptable_messages, UndecryptableMessage),
            (subscribe_to_notifications, Notification),
            (subscribe_to_chat_presence, ChatPresence),
            (subscribe_to_presence, Presence),
            (subscribe_to_picture_updates, PictureUpdate),
            (subscribe_to_user_about_updates, UserAboutUpdate),
            (subscribe_to_joined_groups, JoinedGroup),
            (subscribe_to_contact_updates, ContactUpdate),
            (subscribe_to_push_name_updates, PushNameUpdate),
            (subscribe_to_self_push_name_updated, SelfPushNameUpdated),
            (subscribe_to_pin_updates, PinUpdate),
            (subscribe_to_mute_updates, MuteUpdate),
            (subscribe_to_archive_updates, ArchiveUpdate),
            (subscribe_to_stream_replaced, StreamReplaced),
            (subscribe_to_temporary_ban, TemporaryBan),
            (subscribe_to_connect_failure, ConnectFailure),
            (subscribe_to_stream_error, StreamError),
        }

        // Handle special cases manually for now
        // Messages (tuple data)
        {
            let tx = tx.clone();
            let mut recv = self.subscribe_to_messages();
            tokio::spawn(async move {
                while let Ok(data) = recv.recv().await {
                    let (msg, info) = &*data;
                    let event = Event::Message(msg.clone(), info.clone());
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            });
        }

        // Group info updates (special struct format)
        {
            let tx = tx.clone();
            let mut recv = self.subscribe_to_group_info_updates();
            tokio::spawn(async move {
                while let Ok(data) = recv.recv().await {
                    let (jid, update) = &*data;
                    let event = Event::GroupInfoUpdate {
                        jid: jid.clone(),
                        update: update.clone(),
                    };
                    if tx.send(event).is_err() {
                        break;
                    }
                }
            });
        }

        rx
    }

    pub async fn send_node(&self, node: Node) -> Result<(), ClientError> {
        // Check if we're in test mode first
        if self.test_mode.load(Ordering::Relaxed) {
            debug!(target: "Client/Send", "Using test mode for node: {node}");
            return self.send_node_test_mode(node).await;
        }

        debug!(target: "Client/Send", "Using normal mode for node: {node}");
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
        // In test mode, return mock group participants
        if self.test_mode.load(std::sync::atomic::Ordering::Relaxed) {
            // For test mode, assume the group has all three test clients as participants
            let all_participants = vec![
                "alice.1@lid".parse()?,
                "bob.1@lid".parse()?,
                "charlie.1@lid".parse()?,
            ];

            // Filter out the current client from participants (don't encrypt for yourself)
            let own_jid = self.get_jid().await;
            if let Some(own_jid) = own_jid {
                let filtered_participants: Vec<_> = all_participants
                    .into_iter()
                    .filter(|p| *p != own_jid)
                    .collect();
                return Ok(filtered_participants);
            } else {
                return Ok(all_participants);
            }
        }

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
            if let Some(lid_jid_str) = attrs.optional_string("lid")
                && !lid_jid_str.is_empty()
                && let Ok(lid_jid) = lid_jid_str.parse::<crate::types::jid::Jid>()
            {
                log::debug!("Found LID-PN mapping: {participant_jid} <-> {lid_jid}");
                // Store both ways for easy lookup
                lid_pn_map.insert(participant_jid.clone(), lid_jid.clone());
                lid_pn_map.insert(lid_jid, participant_jid.clone());
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
        // In test mode, return mock devices without making IQ requests
        if self.test_mode.load(Ordering::Relaxed) {
            debug!("get_user_devices: Using test mode, returning mock devices for {jids:?}");
            return Ok(jids.to_vec()); // In test mode, assume each JID is its own device
        }

        debug!("get_user_devices: Using normal mode for {jids:?}");
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
                .ok_or_else(|| anyhow::anyhow!("<device-list> not found for user {user_jid}"))?;

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
    /// Returns the current JID for this client (from device snapshot)
    pub async fn get_jid(&self) -> Option<crate::types::jid::Jid> {
        let snapshot = self.persistence_manager.get_device_snapshot().await;
        snapshot.id.clone()
    }

    /// Test mode methods
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

        debug!(target: "Client/TestSend", "Sending node in test mode: {node}");

        let sender_guard = self.test_network_sender.lock().await;
        let sender = match sender_guard.as_ref() {
            Some(s) => s,
            None => return Err(ClientError::NotConnected), // No test network configured
        };

        // Extract target recipient from the node's "to" attribute if it exists
        let to_jid = node.attrs.get("to").and_then(|to_str| to_str.parse().ok());

        // Get our own JID as the sender
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
}
