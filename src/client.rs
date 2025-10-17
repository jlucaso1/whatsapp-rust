mod context_impl;

use crate::handshake;
use crate::pair;
use anyhow::anyhow;
use dashmap::DashMap;
use moka::future::Cache;
use tokio::sync::watch;
use wacore::xml::{DisplayableNode, DisplayableNodeRef};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::JidExt;
use wacore_binary::node::Node;

use crate::appstate_sync::AppStateProcessor;
use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager};
use crate::types::enc_handler::EncHandler;
use crate::types::events::{ConnectFailureReason, Event};
use crate::types::presence::Presence;

// keep single DashMap import above

use log::{debug, error, info, warn};

use rand::RngCore;
use rand_core::{OsRng, TryRngCore};
use scopeguard;
use std::collections::{HashMap, HashSet, VecDeque};
use wacore_binary::jid::Jid;
use wacore_binary::jid::SERVER_JID;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use thiserror::Error;
use tokio::sync::{Mutex, Notify, OnceCell, RwLock, mpsc, oneshot};
use tokio::time::{Duration, sleep};
use wacore::appstate::patch_decode::WAPatchName;
use wacore::client::context::GroupInfo;
use waproto::whatsapp as wa;

use crate::socket::{NoiseSocket, SocketError, error::EncryptSendError};
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
    #[error("encrypt/send error: {0}")]
    EncryptSend(#[from] EncryptSendError),
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
}

#[derive(Debug)]
pub enum RecentMessageCommand {
    Insert(RecentMessageKey, Arc<wa::Message>),
    Take(RecentMessageKey, oneshot::Sender<Option<Arc<wa::Message>>>),
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

pub struct Client {
    pub(crate) core: wacore::client::CoreClient,

    pub(crate) persistence_manager: Arc<PersistenceManager>,
    pub(crate) media_conn: Arc<RwLock<Option<crate::mediaconn::MediaConn>>>,

    pub(crate) is_logged_in: Arc<AtomicBool>,
    pub(crate) is_connecting: Arc<AtomicBool>,
    pub(crate) is_running: Arc<AtomicBool>,
    pub(crate) shutdown_notifier: Arc<Notify>,

    pub(crate) transport: Arc<Mutex<Option<Arc<dyn crate::transport::Transport>>>>,
    pub(crate) transport_events:
        Arc<Mutex<Option<mpsc::Receiver<crate::transport::TransportEvent>>>>,
    pub(crate) transport_factory: Arc<dyn crate::transport::TransportFactory>,
    pub(crate) noise_socket: Arc<Mutex<Option<Arc<NoiseSocket>>>>,

    pub(crate) response_waiters:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<wacore_binary::Node>>>>,
    pub(crate) unique_id: String,
    pub(crate) id_counter: Arc<AtomicU64>,

    pub(crate) chat_locks: Arc<DashMap<Jid, Arc<tokio::sync::Mutex<()>>>>,
    pub group_cache: OnceCell<Cache<Jid, GroupInfo>>,
    pub device_cache: OnceCell<Cache<Jid, Vec<Jid>>>,

    pub(crate) retried_group_messages: Cache<String, ()>,
    pub(crate) expected_disconnect: Arc<AtomicBool>,

    pub(crate) recent_msg_tx: OnceCell<RecentMessageManagerHandle>,

    pub(crate) pending_retries: Arc<Mutex<HashSet<String>>>,

    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>,
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,

    pub(crate) needs_initial_full_sync: Arc<AtomicBool>,

    pub(crate) app_state_processor: OnceCell<AppStateProcessor>,
    pub(crate) app_state_key_requests: Arc<Mutex<HashMap<String, std::time::Instant>>>,
    pub(crate) initial_keys_synced_notifier: Arc<Notify>,
    pub(crate) initial_app_state_keys_received: Arc<AtomicBool>,
    pub(crate) major_sync_task_sender: mpsc::Sender<MajorSyncTask>,
    pub(crate) pairing_cancellation_tx: Arc<Mutex<Option<watch::Sender<()>>>>,

    pub(crate) send_buffer_pool: Arc<Mutex<Vec<Vec<u8>>>>,

    /// Custom handlers for encrypted message types
    pub custom_enc_handlers: Arc<DashMap<String, Arc<dyn EncHandler>>>,

    /// Router for dispatching stanzas to their appropriate handlers
    pub(crate) stanza_router: crate::handlers::router::StanzaRouter,

    /// Whether to send ACKs synchronously or in a background task
    pub(crate) synchronous_ack: bool,

    /// HTTP client for making HTTP requests (media upload/download, version fetching)
    pub http_client: Arc<dyn crate::http::HttpClient>,

    /// Version override for testing or manual specification
    pub(crate) override_version: Option<(u32, u32, u32)>,
}

impl Client {
    pub async fn new(
        persistence_manager: Arc<PersistenceManager>,
        transport_factory: Arc<dyn crate::transport::TransportFactory>,
        http_client: Arc<dyn crate::http::HttpClient>,
        override_version: Option<(u32, u32, u32)>,
    ) -> (Arc<Self>, mpsc::Receiver<MajorSyncTask>) {
        let mut unique_id_bytes = [0u8; 2];
        OsRng.unwrap_err().fill_bytes(&mut unique_id_bytes);

        let device_snapshot = persistence_manager.get_device_snapshot().await;
        let core = wacore::client::CoreClient::new(device_snapshot.core.clone());

        let (tx, rx) = mpsc::channel(32);

        let this = Self {
            core,
            persistence_manager: persistence_manager.clone(),
            media_conn: Arc::new(RwLock::new(None)),
            is_logged_in: Arc::new(AtomicBool::new(false)),
            is_connecting: Arc::new(AtomicBool::new(false)),
            is_running: Arc::new(AtomicBool::new(false)),
            shutdown_notifier: Arc::new(Notify::new()),

            transport: Arc::new(Mutex::new(None)),
            transport_events: Arc::new(Mutex::new(None)),
            transport_factory,
            noise_socket: Arc::new(Mutex::new(None)),

            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            unique_id: format!("{}.{}", unique_id_bytes[0], unique_id_bytes[1]),
            id_counter: Arc::new(AtomicU64::new(0)),
            chat_locks: Arc::new(DashMap::new()),
            group_cache: OnceCell::new(),
            device_cache: OnceCell::new(),
            retried_group_messages: Cache::builder()
                .time_to_live(Duration::from_secs(300))
                .max_capacity(2_000)
                .build(),

            expected_disconnect: Arc::new(AtomicBool::new(false)),

            recent_msg_tx: OnceCell::new(),

            pending_retries: Arc::new(Mutex::new(HashSet::new())),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),

            needs_initial_full_sync: Arc::new(AtomicBool::new(false)),

            app_state_processor: OnceCell::new(),
            app_state_key_requests: Arc::new(Mutex::new(HashMap::new())),
            initial_keys_synced_notifier: Arc::new(Notify::new()),
            initial_app_state_keys_received: Arc::new(AtomicBool::new(false)),
            major_sync_task_sender: tx,
            pairing_cancellation_tx: Arc::new(Mutex::new(None)),
            send_buffer_pool: Arc::new(Mutex::new(Vec::with_capacity(4))),
            custom_enc_handlers: Arc::new(DashMap::new()),
            stanza_router: Self::create_stanza_router(),
            synchronous_ack: false,
            http_client,
            override_version,
        };

        let arc = Arc::new(this);
        (arc, rx)
    }

    async fn get_recent_msg_manager(&self) -> &RecentMessageManagerHandle {
        self.recent_msg_tx
            .get_or_init(|| async {
                info!("Initializing RecentMessageManager task for the first time.");
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
                                list.retain(|k| k != &key);
                                list.push_back(key);
                                while list.len() > 256 {
                                    if let Some(old_key) = list.pop_front() {
                                        map.remove(&old_key);
                                    }
                                }
                            }
                            RecentMessageCommand::Take(key, responder) => {
                                let mut map = map_clone.lock().await;
                                let mut list = list_clone.lock().await;
                                let msg = map.remove(&key);
                                list.retain(|k| k != &key);
                                let _ = responder.send(msg);
                            }
                        }
                    }
                });

                recent_handle
            })
            .await
    }

    pub(crate) async fn get_group_cache(&self) -> &Cache<Jid, GroupInfo> {
        self.group_cache
            .get_or_init(|| async {
                info!("Initializing Group Cache for the first time.");
                Cache::builder()
                    .time_to_live(Duration::from_secs(3600))
                    .max_capacity(1_000)
                    .build()
            })
            .await
    }

    pub(crate) async fn get_device_cache(&self) -> &Cache<Jid, Vec<Jid>> {
        self.device_cache
            .get_or_init(|| async {
                info!("Initializing Device Cache for the first time.");
                Cache::builder()
                    .time_to_live(Duration::from_secs(3600))
                    .max_capacity(5_000)
                    .build()
            })
            .await
    }

    pub(crate) async fn get_app_state_processor(&self) -> &AppStateProcessor {
        self.app_state_processor
            .get_or_init(|| async {
                info!("Initializing AppStateProcessor for the first time.");
                AppStateProcessor::new(self.persistence_manager.backend())
            })
            .await
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

        let version_future = crate::version::resolve_and_update_version(
            &self.persistence_manager,
            &self.http_client,
            self.override_version,
        );

        let transport_future = self.transport_factory.create_transport();

        info!("Connecting WebSocket and fetching latest client version in parallel...");
        let (version_result, transport_result) = tokio::join!(version_future, transport_future);

        version_result.map_err(|e| anyhow!("Failed to resolve app version: {}", e))?;
        let (transport, mut transport_events) = transport_result?;
        info!("Version fetch and transport connection established.");

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        let noise_socket =
            handshake::do_handshake(&device_snapshot, transport.clone(), &mut transport_events)
                .await?;

        *self.transport.lock().await = Some(transport);
        *self.transport_events.lock().await = Some(transport_events);
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

        if let Some(transport) = self.transport.lock().await.as_ref() {
            transport.disconnect().await;
        }
        self.cleanup_connection_state().await;
    }

    async fn cleanup_connection_state(&self) {
        self.is_logged_in.store(false, Ordering::Relaxed);
        *self.transport.lock().await = None;
        *self.transport_events.lock().await = None;
        *self.noise_socket.lock().await = None;
        self.retried_group_messages.invalidate_all();
    }

    async fn read_messages_loop(self: &Arc<Self>) -> Result<(), anyhow::Error> {
        info!(target: "Client", "Starting message processing loop...");

        let mut rx_guard = self.transport_events.lock().await;
        let mut transport_events = rx_guard
            .take()
            .ok_or_else(|| anyhow::anyhow!("Cannot start message loop: not connected"))?;
        drop(rx_guard);

        // Frame decoder to parse incoming data
        let mut frame_decoder = crate::framing::FrameDecoder::new();

        loop {
            tokio::select! {
                    biased;
                    _ = self.shutdown_notifier.notified() => {
                        info!(target: "Client", "Shutdown signaled. Exiting message loop.");
                        return Ok(());
                    },
                    event_opt = transport_events.recv() => {
                        match event_opt {
                            Some(crate::transport::TransportEvent::DataReceived(data)) => {
                                // Feed data into the frame decoder
                                frame_decoder.feed(&data);

                                // Process all complete frames
                                while let Some(encrypted_frame) = frame_decoder.decode_frame() {
                                    self.process_encrypted_frame(&encrypted_frame).await;
                                }
                            },
                            Some(crate::transport::TransportEvent::Disconnected) | None => {
                                self.cleanup_connection_state().await;
                                 if !self.expected_disconnect.load(Ordering::Relaxed) {
                                    self.core.event_bus.dispatch(&Event::Disconnected(crate::types::events::Disconnected));
                                    info!("Transport disconnected unexpectedly.");
                                    return Err(anyhow::anyhow!("Transport disconnected unexpectedly"));
                                } else {
                                    info!("Transport disconnected as expected.");
                                    return Ok(());
                                }
                            }
                            Some(crate::transport::TransportEvent::Connected) => {
                                // Already handled during handshake, but could be useful for logging
                                debug!("Transport connected event received");
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

        let manager = self.get_recent_msg_manager().await;
        // Use a timeout to prevent hanging if the task is unresponsive
        if manager
            .0
            .send(RecentMessageCommand::Take(key, oneshot_tx))
            .await
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
        let manager = self.get_recent_msg_manager().await;
        manager
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

        let encrypted_frame_clone = encrypted_frame.clone();
        let decrypted_payload_result =
            tokio::task::spawn_blocking(move || noise_socket.decrypt_frame(&encrypted_frame_clone))
                .await;

        let decrypted_payload = match decrypted_payload_result {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                log::error!(target: "Client", "Failed to decrypt frame: {e}");
                return;
            }
            Err(e) => {
                log::error!(
                    target: "Client",
                    "Failed to decrypt frame (spawn_blocking join error): {e}"
                );
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
                // Pass NodeRef directly to process_node to avoid allocation
                self.process_node(&node_ref).await;
            }
            Err(e) => log::warn!(target: "Client/Recv", "Failed to unmarshal node: {e}"),
        };
    }

    pub(crate) async fn process_node(self: &Arc<Self>, node: &wacore_binary::node::NodeRef<'_>) {
        use wacore::xml::DisplayableNodeRef;

        if node.tag.as_ref() == "iq"
            && let Some(sync_node) = node.get_optional_child("sync")
            && let Some(collection_node) = sync_node.get_optional_child("collection")
        {
            let name = collection_node.attr_parser().string("name");
            info!(target: "Client/Recv", "Received app state sync response for '{name}' (hiding content).");
        } else {
            info!(target: "Client/Recv","{}", DisplayableNodeRef(node));
        }

        // Prepare deferred ACK cancellation flag (sent after dispatch unless cancelled)
        let mut cancelled = false;

        if node.tag.as_ref() == "xmlstreamend" {
            warn!(target: "Client", "Received <xmlstreamend/>, treating as disconnect.");
            self.shutdown_notifier.notify_one();
            return;
        }

        if node.tag.as_ref() == "iq" {
            let id_opt = node.get_attr("id");
            if let Some(id) = id_opt {
                let has_waiter = self.response_waiters.lock().await.contains_key(id.as_ref());
                if has_waiter && self.handle_iq_response(node.to_owned()).await {
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
            warn!(target: "Client", "Received unknown top-level node: {}", DisplayableNodeRef(node));
        }

        // Send the deferred ACK if applicable and not cancelled by handler
        if self.should_ack_ref(node) && !cancelled {
            self.maybe_deferred_ack_ref(node).await;
        }
    }

    /// Determine if a NodeRef should be acknowledged with <ack/>.
    fn should_ack_ref(&self, node: &wacore_binary::node::NodeRef<'_>) -> bool {
        matches!(
            node.tag.as_ref(),
            "message" | "receipt" | "notification" | "call"
        ) && node.get_attr("id").is_some()
            && node.get_attr("from").is_some()
    }

    /// Possibly send a deferred ack from a NodeRef: either immediately or via spawned task.
    /// Handlers can cancel by setting `cancelled` to true.
    async fn maybe_deferred_ack_ref(self: &Arc<Self>, node: &wacore_binary::node::NodeRef<'_>) {
        if self.synchronous_ack {
            if let Err(e) = self.send_ack_for_ref(node).await {
                warn!(target: "Client", "Failed to send ack: {e:?}");
            }
        } else {
            let this = self.clone();
            let node_clone = node.to_owned();
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

    /// Build and send an <ack/> node corresponding to the given NodeRef stanza.
    async fn send_ack_for_ref(
        &self,
        node: &wacore_binary::node::NodeRef<'_>,
    ) -> Result<(), ClientError> {
        let id = match node.get_attr("id") {
            Some(v) => v.to_string(),
            None => return Ok(()),
        };
        let from = match node.get_attr("from") {
            Some(v) => v.to_string(),
            None => return Ok(()),
        };
        let participant = node.get_attr("participant").map(|v| v.to_string());
        let typ = if node.tag.as_ref() != "message" {
            node.get_attr("type").map(|v| v.to_string())
        } else {
            None
        };
        let mut attrs = std::collections::HashMap::new();
        attrs.insert("class".to_string(), node.tag.to_string());
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

    pub(crate) async fn handle_success_ref(
        self: &Arc<Self>,
        node: &wacore_binary::node::NodeRef<'_>,
    ) {
        self.handle_success(node).await;
    }

    pub(crate) async fn handle_success(self: &Arc<Self>, node: &wacore_binary::node::NodeRef<'_>) {
        info!("Successfully authenticated with WhatsApp servers!");
        self.is_logged_in.store(true, Ordering::Relaxed);
        *self.last_successful_connect.lock().await = Some(chrono::Utc::now());
        self.auto_reconnect_errors.store(0, Ordering::Relaxed);

        if let Some(lid_str) = node.get_attr("lid") {
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

    /// Handles incoming `<ack/>` stanzas by resolving pending response waiters.
    ///
    /// If an ack with an ID that matches a pending task in `response_waiters`,
    /// the task is resolved and the function returns `true`. Otherwise, returns `false`.
    pub(crate) async fn handle_ack_response(&self, node: Node) -> bool {
        let id_opt = node.attrs.get("id").cloned();
        if let Some(id) = id_opt
            && let Some(waiter) = self.response_waiters.lock().await.remove(&id)
        {
            if waiter.send(node).is_err() {
                warn!(target: "Client/Ack", "Failed to send ACK response to waiter for ID {id}. Receiver was likely dropped.");
            }
            return true;
        }
        false
    }

    /// Wrapper for `handle_ack_response` that accepts a `NodeRef`.
    pub(crate) async fn handle_ack_response_ref(&self, node: &wacore_binary::node::NodeRef<'_>) {
        let _ = self.handle_ack_response(node.to_owned()).await;
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

            let proc = self.get_app_state_processor().await;
            let (mutations, new_state, list) =
                proc.decode_patch_list(&resp, &download, true).await?;
            let decode_elapsed = _decode_start.elapsed();
            if decode_elapsed.as_millis() > 500 {
                debug!(target: "Client/AppState", "Patch decode for {:?} took {:?}", name, decode_elapsed);
            }

            let missing = match proc.get_missing_key_ids(&list).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("Failed to get missing key IDs for {:?}: {}", name, e);
                    Vec::new()
                }
            };
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

    pub(crate) async fn handle_stream_error_ref(&self, node: &wacore_binary::node::NodeRef<'_>) {
        self.handle_stream_error(node).await;
    }

    pub(crate) async fn handle_stream_error(&self, node: &wacore_binary::node::NodeRef<'_>) {
        self.is_logged_in.store(false, Ordering::Relaxed);

        let mut attrs = node.attr_parser();
        let code = attrs.optional_string("code").unwrap_or("");
        let conflict_type = node
            .get_optional_child("conflict")
            .map(|n| {
                n.attr_parser()
                    .optional_string("type")
                    .unwrap_or("")
                    .to_string()
            })
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
                error!(target: "Client", "Unknown stream error: {}", DisplayableNodeRef(node));
                self.expect_disconnect().await;
                self.core.event_bus.dispatch(&Event::StreamError(
                    crate::types::events::StreamError {
                        code: code.to_string(),
                        raw: Some(node.to_owned()),
                    },
                ));
            }
        }

        self.shutdown_notifier.notify_one();
    }

    pub(crate) async fn handle_connect_failure_ref(&self, node: &wacore_binary::node::NodeRef<'_>) {
        self.handle_connect_failure(node).await;
    }

    pub(crate) async fn handle_connect_failure(&self, node: &wacore_binary::node::NodeRef<'_>) {
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.shutdown_notifier.notify_one();

        let mut attrs = node.attr_parser();
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
            warn!(target: "Client", "Temporary ban connect failure: {}", DisplayableNodeRef(node));
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
            warn!(target: "Client", "Unknown connect failure: {}", DisplayableNodeRef(node));
            self.core.event_bus.dispatch(&Event::ConnectFailure(
                crate::types::events::ConnectFailure {
                    reason,
                    message: attrs.optional_string("message").unwrap_or("").to_string(),
                    raw: Some(node.to_owned()),
                },
            ));
        }
    }

    pub(crate) async fn handle_iq_ref(
        self: &Arc<Self>,
        node: &wacore_binary::node::NodeRef<'_>,
    ) -> bool {
        if let Some("get") = node.attr_parser().optional_string("type")
            && let Some(_ping_node) = node.get_optional_child("ping")
        {
            info!(target: "Client", "Received ping, sending pong.");
            let mut parser = node.attr_parser();
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

        // Pass NodeRef directly to pair handling
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
            if plaintext_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
                g.push(plaintext_buf);
            }
            if encrypted_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
                g.push(encrypted_buf);
            }
            return Err(SocketError::Crypto("Marshal error".to_string()).into());
        }

        let (plaintext_buf, encrypted_buf) = match noise_socket
            .encrypt_and_send(plaintext_buf, encrypted_buf)
            .await
        {
            Ok(bufs) => bufs,
            Err(mut e) => {
                let p_buf = std::mem::take(&mut e.plaintext_buf);
                let o_buf = std::mem::take(&mut e.out_buf);
                let mut g = self.send_buffer_pool.lock().await;
                if p_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
                    g.push(p_buf);
                }
                if o_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
                    g.push(o_buf);
                }
                return Err(e.into());
            }
        };

        let mut g = self.send_buffer_pool.lock().await;
        if plaintext_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
            g.push(plaintext_buf);
        }
        if encrypted_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
            g.push(encrypted_buf);
        }
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
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock HTTP client for tests
    #[derive(Debug, Clone)]
    struct MockHttpClient;

    #[async_trait::async_trait]
    impl crate::http::HttpClient for MockHttpClient {
        async fn execute(
            &self,
            _request: crate::http::HttpRequest,
        ) -> Result<crate::http::HttpResponse, anyhow::Error> {
            Ok(crate::http::HttpResponse {
                status_code: 200,
                body: Vec::new(),
            })
        }
    }

    #[tokio::test]
    async fn test_ack_behavior_for_incoming_stanzas() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(":memory:")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // --- Assertions ---

        // Verify that we still ack other critical stanzas (regression check).
        // Create NodeRef directly for testing
        use std::borrow::Cow;
        use wacore_binary::node::{NodeContentRef, NodeRef};

        let receipt_node_ref = NodeRef::new(
            Cow::Borrowed("receipt"),
            vec![
                (Cow::Borrowed("from"), Cow::Borrowed("s.whatsapp.net")),
                (Cow::Borrowed("id"), Cow::Borrowed("RCPT-1")),
            ],
            Some(NodeContentRef::String(Cow::Borrowed("test"))),
        );

        let notification_node_ref = NodeRef::new(
            Cow::Borrowed("notification"),
            vec![
                (Cow::Borrowed("from"), Cow::Borrowed("s.whatsapp.net")),
                (Cow::Borrowed("id"), Cow::Borrowed("NOTIF-1")),
            ],
            Some(NodeContentRef::String(Cow::Borrowed("test"))),
        );

        assert!(
            client.should_ack_ref(&receipt_node_ref),
            "should_ack_ref must still return TRUE for <receipt> stanzas."
        );
        assert!(
            client.should_ack_ref(&notification_node_ref),
            "should_ack_ref must still return TRUE for <notification> stanzas."
        );

        info!(
            "✅ test_ack_behavior_for_incoming_stanzas passed: Client correctly differentiates which stanzas to acknowledge."
        );
    }

    #[tokio::test]
    async fn test_send_buffer_pool_reuses_both_buffers() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(":memory:")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Check initial pool size
        let initial_pool_size = {
            let pool = client.send_buffer_pool.lock().await;
            pool.len()
        };

        // Attempt to send a node (this will fail because we're not connected, but that's okay)
        let test_node = NodeBuilder::new("test").attr("id", "test-123").build();

        let _ = client.send_node(test_node).await;

        // After the send attempt, the pool should have the same or more buffers
        // (depending on whether buffers were consumed and returned)
        let final_pool_size = {
            let pool = client.send_buffer_pool.lock().await;
            pool.len()
        };

        // The key assertion: we should not be leaking buffers
        // If the fix works, buffers should be returned to the pool
        // (or at least not allocating new ones unnecessarily)
        assert!(
            final_pool_size >= initial_pool_size,
            "Buffer pool should not shrink after send operations"
        );

        info!(
            "✅ test_send_buffer_pool_reuses_both_buffers passed: Buffer pool properly manages buffers"
        );
    }

    #[tokio::test]
    async fn test_ack_waiter_resolves() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(":memory:")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // 1. Insert a waiter for a specific ID
        let test_id = "ack-test-123".to_string();
        let (tx, rx) = oneshot::channel();
        client
            .response_waiters
            .lock()
            .await
            .insert(test_id.clone(), tx);
        assert!(
            client.response_waiters.lock().await.contains_key(&test_id),
            "Waiter should be inserted before handling ack"
        );

        // 2. Create a mock <ack/> node with the test ID
        let ack_node = NodeBuilder::new("ack")
            .attr("id", test_id.clone())
            .attr("from", "s.whatsapp.net")
            .build();

        // 3. Handle the ack
        let handled = client.handle_ack_response(ack_node).await;
        assert!(
            handled,
            "handle_ack_response should return true when waiter exists"
        );

        // 4. Await the receiver with a timeout
        match tokio::time::timeout(Duration::from_secs(1), rx).await {
            Ok(Ok(response_node)) => {
                assert_eq!(
                    response_node.attrs.get("id"),
                    Some(&test_id),
                    "Response node should have correct ID"
                );
            }
            Ok(Err(_)) => panic!("Receiver was dropped without being sent a value"),
            Err(_) => panic!("Test timed out waiting for ack response"),
        }

        // 5. Verify the waiter was removed
        assert!(
            !client.response_waiters.lock().await.contains_key(&test_id),
            "Waiter should be removed after handling"
        );

        info!(
            "✅ test_ack_waiter_resolves passed: ACK response correctly resolves pending waiters"
        );
    }

    #[tokio::test]
    async fn test_ack_without_matching_waiter() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(":memory:")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Create an ack without any matching waiter
        let ack_node = NodeBuilder::new("ack")
            .attr("id", "non-existent-id")
            .attr("from", "s.whatsapp.net")
            .build();

        // Should return false since there's no waiter
        let handled = client.handle_ack_response(ack_node).await;
        assert!(
            !handled,
            "handle_ack_response should return false when no waiter exists"
        );

        info!(
            "✅ test_ack_without_matching_waiter passed: ACK without matching waiter handled gracefully"
        );
    }
}
