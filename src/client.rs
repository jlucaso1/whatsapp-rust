mod context_impl;

use crate::handshake;
use crate::pair;
use anyhow::anyhow;
use dashmap::DashMap;
use rand::RngCore;
use std::collections::{HashMap, HashSet, VecDeque};
use tokio::sync::watch;
use wacore::xml::DisplayableNode;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, JidExt, SERVER_JID};
use wacore_binary::node::Node;

use crate::appstate_sync::AppStateProcessor;
use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager};
use crate::types::enc_handler::EncHandler;
use crate::types::events::{ConnectFailureReason, Event};
use crate::types::presence::Presence;

// keep single DashMap import above

use log::{debug, error, info, warn};

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use thiserror::Error;
use tokio::sync::{Mutex, Notify, RwLock, mpsc, oneshot};
use tokio::time::{Duration, sleep};
use wacore::appstate::patch_decode::WAPatchName;
use wacore::client::context::GroupInfo;
use waproto::whatsapp as wa;

use crate::socket::{FrameSocket, NoiseSocket, SocketError};
use crate::sync_task::MajorSyncTask;

const APP_STATE_KEY_WAIT_TIMEOUT: Duration = Duration::from_secs(15);
const APP_STATE_RETRY_MAX_ATTEMPTS: u32 = 6;

const MAX_POOLED_BUFFER_CAP: usize = 512 * 1024;

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

#[derive(Debug, Clone)]
pub(crate) struct RecentMessageManagerHandle(pub mpsc::Sender<RecentMessageCommand>);

impl RecentMessageManagerHandle {
    pub(crate) async fn send_insert(
        &self,
        key: RecentMessageKey,
        msg: Arc<wa::Message>,
    ) -> Result<(), mpsc::error::SendError<RecentMessageCommand>> {
        self.0.send(RecentMessageCommand::Insert(key, msg)).await
    }

    pub(crate) async fn shutdown(
        &self,
    ) -> Result<(), mpsc::error::SendError<RecentMessageCommand>> {
        self.0.send(RecentMessageCommand::Shutdown).await
    }
}

#[derive(Debug)]
pub enum RecentMessageCommand {
    Insert(RecentMessageKey, Arc<wa::Message>),
    Take(RecentMessageKey, oneshot::Sender<Option<Arc<wa::Message>>>),
    Shutdown,
}

#[derive(Debug, thiserror::Error)]
pub enum RecentMessageError {
    #[error("Manager task unavailable - channel send failed")]
    ManagerUnavailable,
    #[error("Manager task did not respond within timeout")]
    ResponseTimeout,
    #[error("Manager task panicked or was dropped")]
    TaskDropped,
}

#[derive(Clone)]
pub struct PhoneLinkingCache {
    pub jid: Jid,
    pub key_pair: wacore::libsignal::protocol::KeyPair,
    pub linking_code: String,
    pub pairing_ref: String,
}

pub struct Client {
    pub(crate) core: wacore::client::CoreClient,

    pub(crate) persistence_manager: Arc<PersistenceManager>,
    pub(crate) media_conn: Arc<RwLock<Option<crate::mediaconn::MediaConn>>>,

    pub(crate) is_logged_in: Arc<AtomicBool>,
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
    pub device_cache: Arc<DashMap<Jid, (Vec<Jid>, std::time::Instant)>>,

    pub(crate) retried_group_messages: Arc<DashMap<String, ()>>,
    pub(crate) expected_disconnect: Arc<AtomicBool>,

    pub(crate) recent_msg_tx: RecentMessageManagerHandle,

    pub(crate) pending_retries: Arc<Mutex<HashSet<String>>>,

    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>,
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,

    pub(crate) needs_initial_full_sync: Arc<AtomicBool>,

    pub(crate) app_state_processor: Option<AppStateProcessor>,
    pub(crate) app_state_key_requests: Arc<Mutex<HashMap<String, std::time::Instant>>>,
    pub(crate) initial_keys_synced_notifier: Arc<Notify>,
    pub(crate) initial_app_state_keys_received: Arc<AtomicBool>,
    pub(crate) major_sync_task_sender: mpsc::Sender<MajorSyncTask>,
    pub(crate) pairing_cancellation_tx: Arc<Mutex<Option<watch::Sender<()>>>>,

    /// Phone linking cache for pairing code authentication
    pub(crate) phone_linking_cache: Arc<Mutex<Option<PhoneLinkingCache>>>,

    pub(crate) send_buffer_pool: Arc<Mutex<Vec<Vec<u8>>>>,

    /// Custom handlers for encrypted message types
    pub custom_enc_handlers: Arc<DashMap<String, Arc<dyn EncHandler>>>,

    /// Router for dispatching stanzas to their appropriate handlers
    pub(crate) stanza_router: crate::handlers::router::StanzaRouter,

    /// Whether to send ACKs synchronously or in a background task
    pub(crate) synchronous_ack: bool,
}

impl Client {
    pub async fn new(
        persistence_manager: Arc<PersistenceManager>,
    ) -> (Arc<Self>, mpsc::Receiver<MajorSyncTask>) {
        let mut unique_id_bytes = [0u8; 2];
        rand::rng().fill_bytes(&mut unique_id_bytes);

        let device_snapshot = persistence_manager.get_device_snapshot().await;
        let core = wacore::client::CoreClient::new(device_snapshot.core.clone());

        let (tx, rx) = mpsc::channel(32);

        let (recent_tx, mut recent_rx) = mpsc::channel(256);
        let recent_handle = RecentMessageManagerHandle(recent_tx);

        let map_inner = Arc::new(Mutex::new(HashMap::with_capacity(256)));
        let list_inner = Arc::new(Mutex::new(VecDeque::with_capacity(256)));
        let map_clone = map_inner.clone();
        let list_clone = list_inner.clone();
        tokio::spawn(async move {
            while let Some(cmd) = recent_rx.recv().await {
                match cmd {
                    RecentMessageCommand::Insert(key, msg) => {
                        let mut map = map_clone.lock().await;
                        let mut list = list_clone.lock().await;
                        map.insert(key.clone(), msg);
                        list.push_back(key);
                        if list.len() > 256
                            && let Some(old_key) = list.pop_front()
                        {
                            map.remove(&old_key);
                        }
                    }
                    RecentMessageCommand::Take(key, responder) => {
                        let mut map = map_clone.lock().await;
                        let mut list = list_clone.lock().await;
                        let msg = map.remove(&key);
                        list.retain(|k| k != &key);
                        let _ = responder.send(msg);
                    }
                    RecentMessageCommand::Shutdown => {
                        info!("RecentMessageManager shutting down");
                        break;
                    }
                }
            }
        });

        let this = Self {
            core,
            persistence_manager: persistence_manager.clone(),
            media_conn: Arc::new(RwLock::new(None)),
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
            device_cache: Arc::new(DashMap::new()),
            retried_group_messages: Arc::new(DashMap::new()),

            expected_disconnect: Arc::new(AtomicBool::new(false)),

            recent_msg_tx: recent_handle,

            pending_retries: Arc::new(Mutex::new(HashSet::new())),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),

            needs_initial_full_sync: Arc::new(AtomicBool::new(false)),

            app_state_processor: Some(AppStateProcessor::new(persistence_manager.backend())),
            app_state_key_requests: Arc::new(Mutex::new(HashMap::new())),
            initial_keys_synced_notifier: Arc::new(Notify::new()),
            initial_app_state_keys_received: Arc::new(AtomicBool::new(false)),
            major_sync_task_sender: tx,
            pairing_cancellation_tx: Arc::new(Mutex::new(None)),
            phone_linking_cache: Arc::new(Mutex::new(None)),
            send_buffer_pool: Arc::new(Mutex::new(Vec::with_capacity(4))),
            custom_enc_handlers: Arc::new(DashMap::new()),
            stanza_router: Self::create_stanza_router(),
            synchronous_ack: false,
        };

        let arc = Arc::new(this);
        (arc, rx)
    }

    /// Create and configure the stanza router with all the handlers.
    fn create_stanza_router() -> crate::handlers::router::StanzaRouter {
        use crate::handlers::{
            basic::{AckHandler, FailureHandler, StreamErrorHandler, SuccessHandler},
            ib::IbHandler,
            iq::IqHandler,
            message::MessageHandler,
            notification::NotificationHandler,
            receipt::ReceiptHandler,
            router::StanzaRouter,
            unimplemented::UnimplementedHandler,
        };

        let mut router = StanzaRouter::new();

        // Register all handlers
        router.register(Arc::new(MessageHandler::new()));
        router.register(Arc::new(ReceiptHandler::new()));
        router.register(Arc::new(IqHandler::new()));
        router.register(Arc::new(SuccessHandler::new()));
        router.register(Arc::new(FailureHandler::new()));
        router.register(Arc::new(StreamErrorHandler::new()));
        router.register(Arc::new(IbHandler::new()));
        router.register(Arc::new(NotificationHandler::new()));
        router.register(Arc::new(AckHandler::new()));

        // Register unimplemented handlers
        router.register(Arc::new(UnimplementedHandler::for_call()));
        router.register(Arc::new(UnimplementedHandler::for_presence()));
        router.register(Arc::new(UnimplementedHandler::for_chatstate()));

        router
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
        tokio::spawn(async move { client_clone.keepalive_loop().await });

        Ok(())
    }

    pub async fn disconnect(&self) {
        info!("Disconnecting client intentionally.");
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.is_running.store(false, Ordering::Relaxed);
        self.shutdown_notifier.notify_waiters();

        // Shutdown recent message manager
        if let Err(e) = self.recent_msg_tx.shutdown().await {
            warn!("Failed to shutdown recent message manager: {}", e);
        }

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
        self.retried_group_messages.clear();
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

    pub(crate) async fn take_recent_message(
        &self,
        to: Jid,
        id: String,
    ) -> Result<Option<Arc<wa::Message>>, RecentMessageError> {
        let key = RecentMessageKey { to, id };
        let (oneshot_tx, oneshot_rx) = oneshot::channel();

        // Use a timeout to prevent hanging if the task is unresponsive
        if (self
            .recent_msg_tx
            .0
            .send(RecentMessageCommand::Take(key, oneshot_tx))
            .await)
            .is_err()
        {
            return Err(RecentMessageError::ManagerUnavailable);
        }

        // Wait for response with timeout
        match tokio::time::timeout(Duration::from_secs(5), oneshot_rx).await {
            Ok(Ok(msg)) => Ok(msg),
            Ok(Err(_)) => Err(RecentMessageError::TaskDropped),
            Err(_) => Err(RecentMessageError::ResponseTimeout),
        }
    }

    pub(crate) async fn add_recent_message(
        &self,
        to: Jid,
        id: String,
        msg: Arc<wa::Message>,
    ) -> Result<(), RecentMessageError> {
        let key = RecentMessageKey { to, id };
        self.recent_msg_tx
            .send_insert(key, msg)
            .await
            .map_err(|_| RecentMessageError::ManagerUnavailable)
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

    pub(crate) async fn process_node(self: &Arc<Self>, node: &Node) {
        if node.tag == "iq"
            && let Some(sync_node) = node.get_optional_child("sync")
            && let Some(collection_node) = sync_node.get_optional_child("collection")
        {
            let name = collection_node.attrs().string("name");
            info!(target: "Client/Recv", "Received app state sync response for '{name}' (hiding content).");
        } else {
            info!(target: "Client/Recv","{}", DisplayableNode(node));
        }

        // Prepare deferred ACK cancellation flag (sent after dispatch unless cancelled)
        let mut cancelled = false;

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

        // Dispatch to appropriate handler using the router
        if !self
            .stanza_router
            .dispatch(self.clone(), node, &mut cancelled)
            .await
        {
            warn!(target: "Client", "Received unknown top-level node: {}", DisplayableNode(node));
        }

        // Send the deferred ACK if applicable and not cancelled by handler
        if self.should_ack(node) && !cancelled {
            self.maybe_deferred_ack(node).await;
        }
    }

    /// Determine if a node should be acknowledged with <ack/>.
    fn should_ack(&self, node: &Node) -> bool {
        matches!(
            node.tag.as_str(),
            "message" | "receipt" | "notification" | "call"
        ) && node.attrs.contains_key("id")
            && node.attrs.contains_key("from")
    }

    /// Possibly send a deferred ack: either immediately or via spawned task.
    /// Handlers can cancel by setting `cancelled` to true.
    async fn maybe_deferred_ack(self: &Arc<Self>, node: &Node) {
        if self.synchronous_ack {
            if let Err(e) = self.send_ack_for(node).await {
                warn!(target: "Client", "Failed to send ack: {e:?}");
            }
        } else {
            let this = self.clone();
            let node_clone = node.clone();
            tokio::spawn(async move {
                if let Err(e) = this.send_ack_for(&node_clone).await {
                    warn!(target: "Client", "Failed to send ack: {e:?}");
                }
            });
        }
    }

    /// Build and send an <ack/> node corresponding to the given stanza.
    async fn send_ack_for(&self, node: &Node) -> Result<(), ClientError> {
        let id = match node.attrs.get("id") {
            Some(v) => v.clone(),
            None => return Ok(()),
        };
        let from = match node.attrs.get("from") {
            Some(v) => v.clone(),
            None => return Ok(()),
        };
        let participant = node.attrs.get("participant").cloned();
        let typ = if node.tag != "message" {
            node.attrs.get("type").cloned()
        } else {
            None
        };
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("class".to_string(), node.tag.clone());
        attrs.insert("id".to_string(), id);
        attrs.insert("to".to_string(), from);
        if let Some(p) = participant {
            attrs.insert("participant".to_string(), p);
        }
        if let Some(t) = typ {
            attrs.insert("type".to_string(), t);
        }
        let ack = Node {
            tag: "ack".to_string(),
            attrs,
            content: None,
        };
        self.send_node(ack).await
    }

    pub(crate) async fn handle_unimplemented(&self, tag: &str) {
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

    pub(crate) async fn handle_success(self: &Arc<Self>, node: &Node) {
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
        tokio::spawn(async move {
            if let Err(e) = client_clone.set_passive(false).await {
                warn!("Failed to send post-connect passive IQ: {e:?}");
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

            if client_clone.needs_initial_full_sync.load(Ordering::Relaxed) {
                if !client_clone
                    .initial_app_state_keys_received
                    .load(Ordering::Relaxed)
                {
                    info!(target: "Client/AppState", "Waiting for initial app state keys before starting full sync (15s timeout)...");
                    match tokio::time::timeout(
                        APP_STATE_KEY_WAIT_TIMEOUT,
                        client_clone.initial_keys_synced_notifier.notified(),
                    )
                    .await
                    {
                        Ok(_) => {
                            info!(target: "Client/AppState", "Initial app state keys received; proceeding with full sync.")
                        }
                        Err(_) => {
                            warn!(target: "Client/AppState", "Timed out waiting for initial app state keys; continuing anyway (may see 'app state key not found' warnings).")
                        }
                    }
                } else {
                    info!(target: "Client/AppState", "Initial app state keys already present; starting full sync immediately.");
                }
                let names = [
                    WAPatchName::CriticalBlock,
                    WAPatchName::CriticalUnblockLow,
                    WAPatchName::RegularLow,
                    WAPatchName::RegularHigh,
                    WAPatchName::Regular,
                ];
                for name in names {
                    if let Err(e) = client_clone.fetch_app_state_with_retry(name).await {
                        warn!(
                            "Failed to full sync app state {:?} after retry logic: {e}",
                            name
                        );
                    }
                }
                client_clone
                    .needs_initial_full_sync
                    .store(false, Ordering::Relaxed);
            }
        });
    }

    async fn fetch_app_state_with_retry(&self, name: WAPatchName) -> anyhow::Result<()> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            let res = self.process_app_state_sync_task(name, true).await;
            match res {
                Ok(()) => return Ok(()),
                Err(e) => {
                    let es = e.to_string();
                    if es.contains("app state key not found") && attempt == 1 {
                        if !self.initial_app_state_keys_received.load(Ordering::Relaxed) {
                            info!(target: "Client/AppState", "App state key missing for {:?}; waiting up to 10s for key share then retrying", name);
                            if tokio::time::timeout(
                                Duration::from_secs(10),
                                self.initial_keys_synced_notifier.notified(),
                            )
                            .await
                            .is_err()
                            {
                                warn!(target: "Client/AppState", "Timeout waiting for key share for {:?}; retrying anyway", name);
                            }
                        }
                        continue;
                    }
                    if es.contains("database is locked") && attempt < APP_STATE_RETRY_MAX_ATTEMPTS {
                        let backoff = Duration::from_millis(200 * attempt as u64 + 150);
                        warn!(target: "Client/AppState", "Attempt {} for {:?} failed due to locked DB; backing off {:?} and retrying", attempt, name, backoff);
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    pub(crate) async fn process_app_state_sync_task(
        &self,
        name: WAPatchName,
        full_sync: bool,
    ) -> anyhow::Result<()> {
        let backend = self.persistence_manager.backend();
        let mut full_sync = full_sync;

        let mut state = backend.get_app_state_version(name.as_str()).await?;
        if state.version == 0 {
            full_sync = true;
        }

        let mut has_more = true;
        let want_snapshot = full_sync;

        if has_more {
            debug!(target: "Client/AppState", "Fetching app state patch batch: name={:?} want_snapshot={want_snapshot} version={} full_sync={} has_more_previous={}", name, state.version, full_sync, has_more);

            let mut collection_builder = NodeBuilder::new("collection")
                .attr("name", name.as_str())
                .attr(
                    "return_snapshot",
                    if want_snapshot { "true" } else { "false" },
                );
            if !want_snapshot {
                collection_builder = collection_builder.attr("version", state.version.to_string());
            }
            let sync_node = NodeBuilder::new("sync")
                .children([collection_builder.build()])
                .build();
            let iq = crate::request::InfoQuery {
                namespace: "w:sync:app:state",
                query_type: crate::request::InfoQueryType::Set,
                to: SERVER_JID.parse().unwrap(),
                target: None,
                id: None,
                content: Some(wacore_binary::node::NodeContent::Nodes(vec![sync_node])),
                timeout: None,
            };

            let resp = self.send_iq(iq).await?;
            debug!(target: "Client/AppState", "Received IQ response for {:?}; decoding patches", name);

            let _decode_start = std::time::Instant::now();
            let pre_downloaded_snapshot: Option<Vec<u8>> =
                match wacore::appstate::patch_decode::parse_patch_list(&resp) {
                    Ok(pl) => {
                        debug!(target: "Client/AppState", "Parsed patch list for {:?}: has_snapshot_ref={} has_more_patches={}", name, pl.snapshot_ref.is_some(), pl.has_more_patches);
                        if let Some(ext) = &pl.snapshot_ref {
                            match self.download(ext).await {
                                Ok(bytes) => Some(bytes),
                                Err(e) => {
                                    warn!("Failed to download external snapshot: {e}");
                                    None
                                }
                            }
                        } else {
                            None
                        }
                    }
                    Err(_) => None,
                };

            let download = |_: &wa::ExternalBlobReference| -> anyhow::Result<Vec<u8>> {
                if let Some(bytes) = &pre_downloaded_snapshot {
                    Ok(bytes.clone())
                } else {
                    Err(anyhow::anyhow!("snapshot not pre-downloaded"))
                }
            };

            if let Some(proc) = &self.app_state_processor {
                let (mutations, new_state, list) =
                    proc.decode_patch_list(&resp, &download, true).await?;
                let decode_elapsed = _decode_start.elapsed();
                if decode_elapsed.as_millis() > 500 {
                    debug!(target: "Client/AppState", "Patch decode for {:?} took {:?}", name, decode_elapsed);
                }

                let missing = proc.get_missing_key_ids(&list).await.unwrap_or_default();
                if !missing.is_empty() {
                    let mut to_request: Vec<Vec<u8>> = Vec::new();
                    let mut guard = self.app_state_key_requests.lock().await;
                    let now = std::time::Instant::now();
                    for key_id in missing {
                        let hex_id = hex::encode(&key_id);
                        let should = guard
                            .get(&hex_id)
                            .map(|t| t.elapsed() > std::time::Duration::from_secs(24 * 3600))
                            .unwrap_or(true);
                        if should {
                            guard.insert(hex_id, now);
                            to_request.push(key_id);
                        }
                    }
                    drop(guard);
                    if !to_request.is_empty() {
                        self.request_app_state_keys(&to_request).await;
                    }
                }

                for m in mutations {
                    debug!(target: "Client/AppState", "Dispatching mutation kind={} index_len={} full_sync={}", m.index.first().map(|s| s.as_str()).unwrap_or(""), m.index.len(), full_sync);
                    self.dispatch_app_state_mutation(&m, full_sync).await;
                }

                state = new_state;
                has_more = list.has_more_patches;
                debug!(target: "Client/AppState", "After processing batch name={:?} has_more={has_more}", name);
            }
        }

        backend
            .set_app_state_version(name.as_str(), state.clone())
            .await?;

        debug!(target: "Client/AppState", "Completed and saved app state sync for {:?} (final version={})", name, state.version);
        Ok(())
    }

    #[allow(dead_code)]
    async fn request_app_state_keys(&self, raw_key_ids: &[Vec<u8>]) {
        if raw_key_ids.is_empty() {
            return;
        }
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = match device_snapshot.pn.clone() {
            Some(j) => j,
            None => return,
        };
        let key_ids: Vec<wa::message::AppStateSyncKeyId> = raw_key_ids
            .iter()
            .map(|k| wa::message::AppStateSyncKeyId {
                key_id: Some(k.clone()),
            })
            .collect();
        let msg = wa::Message {
            protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                r#type: Some(wa::message::protocol_message::Type::AppStateSyncKeyRequest as i32),
                app_state_sync_key_request: Some(wa::message::AppStateSyncKeyRequest { key_ids }),
                ..Default::default()
            })),
            ..Default::default()
        };
        if let Err(e) = self
            .send_message_impl(
                own_jid,
                Arc::new(msg),
                Some(self.generate_message_id().await),
                true,
                false,
                None,
            )
            .await
        {
            warn!("Failed to send app state key request: {e}");
        }
    }

    #[allow(dead_code)]
    async fn dispatch_app_state_mutation(
        &self,
        m: &crate::appstate_sync::Mutation,
        full_sync: bool,
    ) {
        use wacore::types::events::{
            ArchiveUpdate, ContactUpdate, Event, MarkChatAsReadUpdate, MuteUpdate, PinUpdate,
        };
        if m.operation != wa::syncd_mutation::SyncdOperation::Set {
            return;
        }
        if m.index.is_empty() {
            return;
        }
        let kind = &m.index[0];
        let ts = m
            .action_value
            .as_ref()
            .and_then(|v| v.timestamp)
            .unwrap_or(0);
        let time = chrono::DateTime::from_timestamp_millis(ts).unwrap_or_else(chrono::Utc::now);
        let jid = if m.index.len() > 1 {
            m.index[1].parse().unwrap_or_default()
        } else {
            Jid::default()
        };
        match kind.as_str() {
            "setting_pushName" => {
                if let Some(val) = &m.action_value
                    && let Some(act) = &val.push_name_setting
                    && let Some(new_name) = &act.name
                {
                    let new_name = new_name.clone();
                    let bus = self.core.event_bus.clone();

                    let snapshot = self.persistence_manager.get_device_snapshot().await;
                    let old = snapshot.push_name.clone();
                    if old != new_name {
                        info!(target: "Client/AppState", "Persisting push name from app state mutation: '{}' (old='{}')", new_name, old);
                        self.persistence_manager
                            .process_command(DeviceCommand::SetPushName(new_name.clone()))
                            .await;
                        bus.dispatch(&Event::SelfPushNameUpdated(
                            crate::types::events::SelfPushNameUpdated {
                                from_server: true,
                                old_name: old,
                                new_name: new_name.clone(),
                            },
                        ));
                    } else {
                        debug!(target: "Client/AppState", "Push name mutation received but name unchanged: '{}'", new_name);
                    }
                }
            }
            "mute" => {
                if let Some(val) = &m.action_value
                    && let Some(act) = &val.mute_action
                {
                    self.core.event_bus.dispatch(&Event::MuteUpdate(MuteUpdate {
                        jid,
                        timestamp: time,
                        action: Box::new(*act),
                        from_full_sync: full_sync,
                    }));
                }
            }
            "pin" | "pin_v1" => {
                if let Some(val) = &m.action_value
                    && let Some(act) = &val.pin_action
                {
                    self.core.event_bus.dispatch(&Event::PinUpdate(PinUpdate {
                        jid,
                        timestamp: time,
                        action: Box::new(*act),
                        from_full_sync: full_sync,
                    }));
                }
            }
            "archive" => {
                if let Some(val) = &m.action_value
                    && let Some(act) = &val.archive_chat_action
                {
                    self.core
                        .event_bus
                        .dispatch(&Event::ArchiveUpdate(ArchiveUpdate {
                            jid,
                            timestamp: time,
                            action: Box::new(act.clone()),
                            from_full_sync: full_sync,
                        }));
                }
            }
            "contact" => {
                if let Some(val) = &m.action_value
                    && let Some(act) = &val.contact_action
                {
                    self.core
                        .event_bus
                        .dispatch(&Event::ContactUpdate(ContactUpdate {
                            jid,
                            timestamp: time,
                            action: Box::new(act.clone()),
                            from_full_sync: full_sync,
                        }));
                }
            }
            "mark_chat_as_read" | "markChatAsRead" => {
                if let Some(val) = &m.action_value
                    && let Some(act) = &val.mark_chat_as_read_action
                {
                    self.core.event_bus.dispatch(&Event::MarkChatAsReadUpdate(
                        MarkChatAsReadUpdate {
                            jid,
                            timestamp: time,
                            action: Box::new(act.clone()),
                            from_full_sync: full_sync,
                        },
                    ));
                }
            }
            _ => {}
        }
    }

    async fn expect_disconnect(&self) {
        self.expected_disconnect.store(true, Ordering::Relaxed);
    }

    pub(crate) async fn handle_stream_error(&self, node: &Node) {
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

    pub(crate) async fn handle_connect_failure(&self, node: &Node) {
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

    pub(crate) async fn handle_iq(self: &Arc<Self>, node: &Node) -> bool {
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

    pub fn is_connected(&self) -> bool {
        self.noise_socket
            .try_lock()
            .is_ok_and(|guard| guard.is_some())
    }

    pub fn is_logged_in(&self) -> bool {
        self.is_logged_in.load(Ordering::Relaxed)
    }

    /// Get access to the PersistenceManager for this client.
    /// This is useful for multi-account scenarios to get the device ID.
    pub fn persistence_manager(&self) -> Arc<PersistenceManager> {
        self.persistence_manager.clone()
    }

    pub async fn edit_message(
        &self,
        to: Jid,
        original_id: String,
        new_content: wa::Message,
    ) -> Result<String, anyhow::Error> {
        let own_jid = self
            .get_pn()
            .await
            .ok_or_else(|| anyhow!("Not logged in"))?;

        let edit_container_message = wa::Message {
            edited_message: Some(Box::new(wa::message::FutureProofMessage {
                message: Some(Box::new(wa::Message {
                    protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                        key: Some(wa::MessageKey {
                            remote_jid: Some(to.to_string()),
                            from_me: Some(true),
                            id: Some(original_id.clone()),
                            participant: if to.is_group() {
                                Some(own_jid.to_non_ad().to_string())
                            } else {
                                None
                            },
                        }),
                        r#type: Some(wa::message::protocol_message::Type::MessageEdit as i32),
                        edited_message: Some(Box::new(new_content)),
                        timestamp_ms: Some(chrono::Utc::now().timestamp_millis()),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
            })),
            ..Default::default()
        };

        self.send_message_impl(
            to,
            Arc::new(edit_container_message),
            Some(original_id.clone()),
            false,
            false,
            Some(crate::types::message::EditAttribute::MessageEdit),
        )
        .await?;

        Ok(original_id)
    }

    pub async fn send_node(&self, node: Node) -> Result<(), ClientError> {
        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
            Some(socket) => socket,
            None => return Err(ClientError::NotConnected),
        };

        info!(target: "Client/Send", "{}", DisplayableNode(&node));
        let mut pool_guard = self.send_buffer_pool.lock().await;
        let mut plaintext_buf = pool_guard.pop().unwrap_or_else(|| Vec::with_capacity(1024));
        let mut encrypted_buf = pool_guard.pop().unwrap_or_else(|| Vec::with_capacity(1024));
        drop(pool_guard);

        plaintext_buf.clear();
        encrypted_buf.clear();

        if let Err(e) = wacore_binary::marshal::marshal_to(&node, &mut plaintext_buf) {
            error!("Failed to marshal node: {e:?}");
            let mut g = self.send_buffer_pool.lock().await;
            g.push(plaintext_buf);
            g.push(encrypted_buf);
            return Err(SocketError::Crypto("Marshal error".to_string()).into());
        }

        let send_res = noise_socket
            .encrypt_and_send(plaintext_buf, encrypted_buf)
            .await;

        let plaintext_buf = match send_res {
            Ok(buf) => buf,
            Err(e) => {
                return Err(e.into());
            }
        };

        let mut g = self.send_buffer_pool.lock().await;
        if plaintext_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
            g.push(plaintext_buf);
        }
        g.push(Vec::new());
        Ok(())
    }

    pub(crate) async fn update_push_name_and_notify(self: &Arc<Self>, new_name: String) {
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
        tokio::spawn(async move {
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

    pub async fn get_pn(&self) -> Option<Jid> {
        let snapshot = self.persistence_manager.get_device_snapshot().await;
        snapshot.pn.clone()
    }

    pub async fn get_lid(&self) -> Option<Jid> {
        let snapshot = self.persistence_manager.get_device_snapshot().await;
        snapshot.lid.clone()
    }

    pub(crate) async fn send_protocol_receipt(
        &self,
        id: String,
        receipt_type: crate::types::presence::ReceiptType,
    ) {
        if id.is_empty() {
            return;
        }
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        if let Some(own_jid) = &device_snapshot.pn {
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

    /// Generates a pairing code that can be used to link to a phone without scanning a QR code.
    ///
    /// You must connect the client normally before calling this (which means you'll also receive a QR code
    /// event, but that can be ignored when doing code pairing). You should also wait for `*events.Connected` before
    /// calling this to ensure the connection is fully established. If using `Client::connect()`, wait for
    /// the first item in the channel. Alternatively, sleeping for a second after calling connect will probably work too.
    ///
    /// The exact expiry of pairing codes is unknown, but QR codes are always generated and the login websocket is closed
    /// after the QR codes run out, which means there's a 160-second time limit. It is recommended to generate the pairing
    /// code immediately after connecting to the websocket to have the maximum time.
    ///
    /// The client_type parameter must be one of the PairClientType constants, but which one doesn't matter.
    /// The client_display_name must be formatted as `Browser (OS)`, and only common browsers/OSes are allowed
    /// (the server will validate it and return 400 if it's wrong).
    ///
    /// See https://faq.whatsapp.com/1324084875126592 for more info
    pub async fn pair_phone(
        &self,
        phone: String,
        show_push_notification: bool,
        client_type: PairClientType,
        client_display_name: String,
    ) -> Result<String, anyhow::Error> {
        if self.phone_linking_cache.lock().await.is_some() {
            return Err(anyhow::anyhow!("Pairing already in progress"));
        }

        // Clean phone number - remove non-digits
        let phone = phone
            .chars()
            .filter(|c| c.is_ascii_digit())
            .collect::<String>();
        if phone.len() <= 6 {
            return Err(anyhow::anyhow!("Phone number too short"));
        }
        if phone.starts_with('0') {
            return Err(anyhow::anyhow!(
                "Phone number should not start with 0 (use international format)"
            ));
        }

        let jid = format!("{}@s.whatsapp.net", phone).parse::<Jid>()?;

        // Generate ephemeral key pair and linking code using wacore utilities
        let (ephemeral_key_pair, ephemeral_key, encoded_linking_code) =
            wacore::pair::PairUtils::generate_companion_ephemeral_key()?;

        // Send IQ request
        let link_code_companion_reg = NodeBuilder::new("link_code_companion_reg")
            .attr("jid", jid.to_string())
            .attr("stage", "companion_hello")
            .attr(
                "should_show_push_notification",
                if show_push_notification {
                    "true"
                } else {
                    "false"
                },
            )
            .children(vec![
                NodeBuilder::new("link_code_pairing_wrapped_companion_ephemeral_pub")
                    .bytes(ephemeral_key)
                    .build(),
                NodeBuilder::new("companion_server_auth_key_pub")
                    .bytes(
                        self.core
                            .device
                            .noise_key
                            .public_key
                            .public_key_bytes()
                            .to_vec(),
                    )
                    .build(),
                NodeBuilder::new("companion_platform_id")
                    .bytes(vec![b'0' + (client_type as u8)])
                    .build(),
                NodeBuilder::new("companion_platform_display")
                    .bytes(client_display_name)
                    .build(),
                NodeBuilder::new("link_code_pairing_nonce")
                    .bytes(vec![0])
                    .build(),
            ])
            .build();

        let resp = self
            .send_iq(crate::request::InfoQuery {
                namespace: "md",
                query_type: crate::request::InfoQueryType::Set,
                to: "s.whatsapp.net".parse().unwrap(),
                target: None,
                id: None,
                content: Some(wacore_binary::node::NodeContent::Nodes(vec![
                    link_code_companion_reg,
                ])),
                timeout: None,
            })
            .await?;

        // Extract pairing reference from response
        let link_code_companion_regs = resp.get_children_by_tag("link_code_companion_reg");
        if link_code_companion_regs.is_empty() {
            return Err(anyhow::anyhow!(
                "No link_code_companion_reg found in response"
            ));
        }
        let link_code_companion_reg = &link_code_companion_regs[0];
        let pairing_ref_nodes =
            link_code_companion_reg.get_children_by_tag("link_code_pairing_ref");
        if pairing_ref_nodes.is_empty() {
            return Err(anyhow::anyhow!(
                "No link_code_pairing_ref found in response"
            ));
        }
        let pairing_ref_node = &pairing_ref_nodes[0];
        let pairing_ref = match &pairing_ref_node.content {
            Some(wacore_binary::node::NodeContent::Bytes(bytes)) => {
                String::from_utf8(bytes.clone())?
            }
            _ => return Err(anyhow::anyhow!("Unexpected pairing ref content type")),
        };

        // Store pairing state
        *self.phone_linking_cache.lock().await = Some(PhoneLinkingCache {
            jid,
            key_pair: ephemeral_key_pair,
            linking_code: encoded_linking_code.clone(),
            pairing_ref,
        });

        // Return formatted pairing code (XXXX-XXXX)
        Ok(format!(
            "{}-{}",
            &encoded_linking_code[0..4],
            &encoded_linking_code[4..8]
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairClientType {
    Unknown = 0,
    Chrome = 1,
    Edge = 2,
    Firefox = 3,
    IE = 4,
    Opera = 5,
    Safari = 6,
    Electron = 7,
    UWP = 8,
    OtherWebClient = 9,
}

impl From<PairClientType> for i32 {
    fn from(client_type: PairClientType) -> i32 {
        client_type as i32
    }
}
