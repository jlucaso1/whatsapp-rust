mod context_impl;
mod device_registry;
mod lid_pn;
mod sender_keys;
mod sessions;

use crate::handshake;
use crate::lid_pn_cache::LidPnCache;
use crate::pair;
use anyhow::{Result, anyhow};
use dashmap::DashMap;
use indexmap::IndexMap;
use moka::future::Cache;
use tokio::sync::watch;
use wacore::xml::DisplayableNode;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::JidExt;
use wacore_binary::node::Node;

use crate::appstate_sync::AppStateProcessor;
use crate::jid_utils::server_jid;
use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager};
use crate::types::enc_handler::EncHandler;
use crate::types::events::{ConnectFailureReason, Event};

use log::{debug, error, info, warn};

use rand::RngCore;
use scopeguard;
use std::collections::{HashMap, HashSet};
use wacore_binary::jid::Jid;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use thiserror::Error;
use tokio::sync::{Mutex, Notify, OnceCell, RwLock, mpsc};
use tokio::time::{Duration, sleep};
use wacore::appstate::patch_decode::WAPatchName;
use wacore::client::context::GroupInfo;
use waproto::whatsapp as wa;

use crate::socket::{NoiseSocket, SocketError, error::EncryptSendError};
use crate::sync_task::MajorSyncTask;

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

/// Key for looking up recent messages for retry functionality.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RecentMessageKey {
    pub to: Jid,
    pub id: String,
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
        Arc<Mutex<Option<async_channel::Receiver<crate::transport::TransportEvent>>>>,
    pub(crate) transport_factory: Arc<dyn crate::transport::TransportFactory>,
    pub(crate) noise_socket: Arc<Mutex<Option<Arc<NoiseSocket>>>>,

    pub(crate) response_waiters:
        Arc<Mutex<HashMap<String, tokio::sync::oneshot::Sender<wacore_binary::Node>>>>,
    pub(crate) unique_id: String,
    pub(crate) id_counter: Arc<AtomicU64>,

    /// Per-device session locks for Signal protocol operations.
    /// Prevents race conditions when multiple messages from the same sender
    /// are processed concurrently across different chats.
    /// Keys are Signal protocol address strings (e.g., "user@s.whatsapp.net:0")
    /// to match the SignalProtocolStoreAdapter's internal locking.
    pub(crate) session_locks: Cache<String, Arc<tokio::sync::Mutex<()>>>,

    /// Per-chat message queues for sequential message processing.
    /// Prevents race conditions where a later message is processed before
    /// the PreKey message that establishes the Signal session.
    pub(crate) message_queues: Cache<String, mpsc::Sender<Arc<Node>>>,

    /// Cache for LID to Phone Number mappings (bidirectional).
    /// When we receive a message with sender_lid/sender_pn attributes, we store the mapping here.
    /// This allows us to reuse existing LID-based sessions when sending replies.
    /// The cache is backed by persistent storage and warmed up on client initialization.
    pub(crate) lid_pn_cache: Arc<LidPnCache>,

    /// Per-chat mutex for serializing message enqueue operations.
    /// This ensures messages are enqueued in the order they arrive,
    /// preventing race conditions during queue initialization.
    pub(crate) message_enqueue_locks: Cache<String, Arc<tokio::sync::Mutex<()>>>,

    pub group_cache: OnceCell<Cache<Jid, GroupInfo>>,
    pub device_cache: OnceCell<Cache<Jid, Vec<Jid>>>,

    pub(crate) retried_group_messages: Cache<String, ()>,
    pub(crate) expected_disconnect: Arc<AtomicBool>,

    /// Connection generation counter - incremented on each new connection.
    /// Used to detect stale post-login tasks from previous connections.
    pub(crate) connection_generation: Arc<AtomicU64>,

    /// Cache for recent messages (serialized bytes) for retry functionality.
    /// Uses moka cache with TTL and max capacity for automatic eviction.
    pub(crate) recent_messages: Cache<RecentMessageKey, Vec<u8>>,

    pub(crate) pending_retries: Arc<Mutex<HashSet<String>>>,

    /// Track retry attempts per message to prevent infinite retry loops.
    /// Key: "{chat}:{msg_id}:{sender}", Value: retry count
    /// Matches WhatsApp Web's MAX_RETRY = 5 behavior.
    pub(crate) message_retry_counts: Cache<String, u8>,

    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>,
    pub last_successful_connect: Arc<Mutex<Option<chrono::DateTime<chrono::Utc>>>>,

    pub(crate) needs_initial_full_sync: Arc<AtomicBool>,

    pub(crate) app_state_processor: OnceCell<AppStateProcessor>,
    pub(crate) app_state_key_requests: Arc<Mutex<HashMap<String, std::time::Instant>>>,
    pub(crate) initial_keys_synced_notifier: Arc<Notify>,
    pub(crate) initial_app_state_keys_received: Arc<AtomicBool>,

    /// Notifier for when offline sync (ib offline stanza) is received.
    /// WhatsApp Web waits for this before sending passive tasks (prekey upload, active IQ, presence).
    pub(crate) offline_sync_notifier: Arc<Notify>,
    /// Flag indicating offline sync has completed (received ib offline stanza).
    pub(crate) offline_sync_completed: Arc<AtomicBool>,
    /// Notifier for when the noise socket is established (before login).
    /// Use this to wait for the socket to be ready for sending messages.
    pub(crate) socket_ready_notifier: Arc<Notify>,
    /// Notifier for when the client is fully connected and logged in.
    /// Triggered after Event::Connected is dispatched.
    pub(crate) connected_notifier: Arc<Notify>,
    pub(crate) major_sync_task_sender: mpsc::Sender<MajorSyncTask>,
    pub(crate) pairing_cancellation_tx: Arc<Mutex<Option<watch::Sender<()>>>>,

    /// State machine for pair code authentication flow.
    /// Tracks the pending pair code request and ephemeral keys.
    pub(crate) pair_code_state: Arc<Mutex<wacore::pair_code::PairCodeState>>,

    /// Pool for reusing plaintext marshal buffers.
    /// Note: encrypted buffers are not pooled since they're moved to transport (zero-copy).
    pub(crate) plaintext_buffer_pool: Arc<Mutex<Vec<Vec<u8>>>>,

    /// Custom handlers for encrypted message types
    pub custom_enc_handlers: Arc<DashMap<String, Arc<dyn EncHandler>>>,

    /// Cache for pending PDO (Peer Data Operation) requests.
    /// Maps message cache keys (chat:id) to pending request info.
    pub(crate) pdo_pending_requests: Cache<String, crate::pdo::PendingPdoRequest>,

    /// LRU cache for device registry (matches WhatsApp Web's 5000 entry limit).
    /// Maps user ID to DeviceListRecord for fast device existence checks.
    /// Backed by persistent storage.
    pub(crate) device_registry_cache: Cache<String, wacore::store::traits::DeviceListRecord>,

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
        rand::rng().fill_bytes(&mut unique_id_bytes);

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

            session_locks: Cache::builder()
                .time_to_live(Duration::from_secs(300)) // 5 minute TTL
                .max_capacity(10_000) // Limit to 10k concurrent sessions
                .build(),
            message_queues: Cache::builder()
                .time_to_live(Duration::from_secs(300)) // Idle queues expire after 5 mins
                .max_capacity(10_000) // Limit to 10k concurrent chats
                .build(),
            lid_pn_cache: Arc::new(LidPnCache::new()),
            message_enqueue_locks: Cache::builder()
                .time_to_live(Duration::from_secs(300))
                .max_capacity(10_000)
                .build(),
            group_cache: OnceCell::new(),
            device_cache: OnceCell::new(),
            retried_group_messages: Cache::builder()
                .time_to_live(Duration::from_secs(300))
                .max_capacity(2_000)
                .build(),

            expected_disconnect: Arc::new(AtomicBool::new(false)),
            connection_generation: Arc::new(AtomicU64::new(0)),

            // Recent messages cache for retry functionality
            // TTL of 5 minutes (retries don't happen after that)
            // Max 1000 messages to bound memory usage
            recent_messages: Cache::builder()
                .time_to_live(Duration::from_secs(300))
                .max_capacity(1_000)
                .build(),

            pending_retries: Arc::new(Mutex::new(HashSet::new())),

            // Retry count tracking cache for preventing infinite retry loops.
            // TTL of 5 minutes to match retry functionality, max 5000 entries.
            message_retry_counts: Cache::builder()
                .time_to_live(Duration::from_secs(300))
                .max_capacity(5_000)
                .build(),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),
            last_successful_connect: Arc::new(Mutex::new(None)),

            needs_initial_full_sync: Arc::new(AtomicBool::new(false)),

            app_state_processor: OnceCell::new(),
            app_state_key_requests: Arc::new(Mutex::new(HashMap::new())),
            initial_keys_synced_notifier: Arc::new(Notify::new()),
            initial_app_state_keys_received: Arc::new(AtomicBool::new(false)),
            offline_sync_notifier: Arc::new(Notify::new()),
            offline_sync_completed: Arc::new(AtomicBool::new(false)),
            socket_ready_notifier: Arc::new(Notify::new()),
            connected_notifier: Arc::new(Notify::new()),
            major_sync_task_sender: tx,
            pairing_cancellation_tx: Arc::new(Mutex::new(None)),
            pair_code_state: Arc::new(Mutex::new(wacore::pair_code::PairCodeState::default())),
            plaintext_buffer_pool: Arc::new(Mutex::new(Vec::with_capacity(4))),
            custom_enc_handlers: Arc::new(DashMap::new()),
            pdo_pending_requests: crate::pdo::new_pdo_cache(),
            device_registry_cache: Cache::builder()
                .max_capacity(5_000) // Match WhatsApp Web's 5000 entry limit
                .time_to_live(Duration::from_secs(3600)) // 1 hour TTL
                .build(),
            stanza_router: Self::create_stanza_router(),
            synchronous_ack: false,
            http_client,
            override_version,
        };

        let arc = Arc::new(this);

        // Warm up the LID-PN cache from persistent storage
        let warm_up_arc = arc.clone();
        tokio::spawn(async move {
            if let Err(e) = warm_up_arc.warm_up_lid_pn_cache().await {
                warn!("Failed to warm up LID-PN cache: {e}");
            }
        });

        // Start background task to clean up stale device registry entries
        let cleanup_arc = arc.clone();
        tokio::spawn(async move {
            cleanup_arc.device_registry_cleanup_loop().await;
        });

        (arc, rx)
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
        router.register(Arc::new(MessageHandler));
        router.register(Arc::new(ReceiptHandler));
        router.register(Arc::new(IqHandler));
        router.register(Arc::new(SuccessHandler));
        router.register(Arc::new(FailureHandler));
        router.register(Arc::new(StreamErrorHandler));
        router.register(Arc::new(IbHandler));
        router.register(Arc::new(NotificationHandler));
        router.register(Arc::new(AckHandler));

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
                } else if self.expected_disconnect.load(Ordering::Relaxed) {
                    debug!("Message loop exited gracefully (expected disconnect).");
                } else {
                    info!("Message loop exited gracefully.");
                }

                self.cleanup_connection_state().await;
            }

            if !self.enable_auto_reconnect.load(Ordering::Relaxed) {
                info!("Auto-reconnect disabled, shutting down.");
                self.is_running.store(false, Ordering::Relaxed);
                break;
            }

            // If this was an expected disconnect (e.g., 515 after pairing), reconnect immediately
            if self.expected_disconnect.load(Ordering::Relaxed) {
                self.auto_reconnect_errors.store(0, Ordering::Relaxed);
                info!("Expected disconnect (e.g., 515), reconnecting immediately...");
                continue;
            }

            let error_count = self.auto_reconnect_errors.fetch_add(1, Ordering::SeqCst);
            let delay_secs = u64::from(error_count * 2).min(30);
            let delay = Duration::from_secs(delay_secs);
            info!(
                "Will attempt to reconnect in {:?} (attempt {})",
                delay,
                error_count + 1
            );
            sleep(delay).await;
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

        // Reset login state for new connection attempt. This ensures that
        // handle_success will properly process the <success> stanza even if
        // a previous connection's post-login task bailed out early.
        self.is_logged_in.store(false, Ordering::Relaxed);
        self.offline_sync_completed.store(false, Ordering::Relaxed);

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

        // Notify waiters that socket is ready (before login)
        self.socket_ready_notifier.notify_waiters();

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
        // Reset offline sync state for next connection
        self.offline_sync_completed.store(false, Ordering::Relaxed);
    }

    async fn read_messages_loop(self: &Arc<Self>) -> Result<(), anyhow::Error> {
        info!(target: "Client", "Starting message processing loop...");

        let mut rx_guard = self.transport_events.lock().await;
        let transport_events = rx_guard
            .take()
            .ok_or_else(|| anyhow::anyhow!("Cannot start message loop: not connected"))?;
        drop(rx_guard);

        // Frame decoder to parse incoming data
        let mut frame_decoder = wacore::framing::FrameDecoder::new();

        loop {
            tokio::select! {
                    biased;
                    _ = self.shutdown_notifier.notified() => {
                        info!(target: "Client", "Shutdown signaled in message loop. Exiting message loop.");
                        return Ok(());
                    },
                    event_result = transport_events.recv() => {
                        match event_result {
                            Ok(crate::transport::TransportEvent::DataReceived(data)) => {
                                // Feed data into the frame decoder
                                frame_decoder.feed(&data);

                                // Process all complete frames
                                // Note: Frame decryption must be sequential (noise protocol counter),
                                // but we spawn node processing concurrently after decryption
                                while let Some(encrypted_frame) = frame_decoder.decode_frame() {
                                    // Decrypt the frame synchronously (required for noise counter ordering)
                                    if let Some(node) = self.decrypt_frame(&encrypted_frame).await {
                                        // Handle critical nodes synchronously to avoid race conditions.
                                        // <success> must be processed inline to ensure is_logged_in state
                                        // is set before checking expected_disconnect or spawning other tasks.
                                        let is_critical = matches!(node.tag.as_str(), "success" | "failure" | "stream:error");

                                        if is_critical {
                                            // Process critical nodes inline
                                            self.process_decrypted_node(node).await;
                                        } else {
                                            // Spawn non-critical node processing as a separate task
                                            // to allow concurrent handling (Signal protocol work, etc.)
                                            let client = self.clone();
                                            tokio::spawn(async move {
                                                client.process_decrypted_node(node).await;
                                            });
                                        }
                                    }

                                    // Check if we should exit after processing (e.g., after 515 stream error)
                                    if self.expected_disconnect.load(Ordering::Relaxed) {
                                        info!(target: "Client", "Expected disconnect signaled during frame processing. Exiting message loop.");
                                        return Ok(());
                                    }
                                }
                            },
                            Ok(crate::transport::TransportEvent::Disconnected) | Err(_) => {
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
                            Ok(crate::transport::TransportEvent::Connected) => {
                                // Already handled during handshake, but could be useful for logging
                                debug!("Transport connected event received");
                            }
                    }
                }
            }
        }
    }

    /// Decrypt a frame and return the parsed node.
    /// This must be called sequentially due to noise protocol counter requirements.
    pub(crate) async fn decrypt_frame(
        self: &Arc<Self>,
        encrypted_frame: &bytes::Bytes,
    ) -> Option<wacore_binary::node::Node> {
        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
            Some(s) => s,
            None => {
                log::error!("Cannot process frame: not connected (no noise socket)");
                return None;
            }
        };

        let decrypted_payload = match noise_socket.decrypt_frame(encrypted_frame) {
            Ok(p) => p,
            Err(e) => {
                log::error!(target: "Client", "Failed to decrypt frame: {e}");
                return None;
            }
        };

        let unpacked_data_cow = match wacore_binary::util::unpack(&decrypted_payload) {
            Ok(data) => data,
            Err(e) => {
                log::warn!(target: "Client/Recv", "Failed to decompress frame: {e}");
                return None;
            }
        };

        match wacore_binary::marshal::unmarshal_ref(unpacked_data_cow.as_ref()) {
            Ok(node_ref) => Some(node_ref.to_owned()),
            Err(e) => {
                log::warn!(target: "Client/Recv", "Failed to unmarshal node: {e}");
                None
            }
        }
    }

    /// Process an already-decrypted node.
    /// This can be spawned concurrently since it doesn't depend on noise protocol state.
    /// The node is wrapped in Arc to avoid cloning when passing through handlers.
    pub(crate) async fn process_decrypted_node(self: &Arc<Self>, node: wacore_binary::node::Node) {
        // Wrap in Arc once - all handlers will share this same allocation
        let node_arc = Arc::new(node);
        self.process_node(node_arc).await;
    }

    /// Process a node wrapped in Arc. Handlers receive the Arc and can share/store it cheaply.
    pub(crate) async fn process_node(self: &Arc<Self>, node: Arc<Node>) {
        use wacore::xml::DisplayableNode;

        if node.tag.as_str() == "iq"
            && let Some(sync_node) = node.get_optional_child("sync")
            && let Some(collection_node) = sync_node.get_optional_child("collection")
        {
            let name = collection_node.attrs().string("name");
            info!(target: "Client/Recv", "Received app state sync response for '{name}' (hiding content).");
        } else {
            info!(target: "Client/Recv","{}", DisplayableNode(&node));
        }

        // Prepare deferred ACK cancellation flag (sent after dispatch unless cancelled)
        let mut cancelled = false;

        if node.tag.as_str() == "xmlstreamend" {
            if self.expected_disconnect.load(Ordering::Relaxed) {
                debug!(target: "Client", "Received <xmlstreamend/>, expected disconnect.");
            } else {
                warn!(target: "Client", "Received <xmlstreamend/>, treating as disconnect.");
            }
            self.shutdown_notifier.notify_waiters();
            return;
        }

        if node.tag.as_str() == "iq" {
            let id_opt = node.attrs.get("id");
            if let Some(id) = id_opt {
                let has_waiter = self.response_waiters.lock().await.contains_key(id.as_str());
                if has_waiter && self.handle_iq_response(Arc::clone(&node)).await {
                    return;
                }
            }
        }

        // Dispatch to appropriate handler using the router
        // Clone Arc (cheap - just reference count) not the Node itself
        if !self
            .stanza_router
            .dispatch(self.clone(), Arc::clone(&node), &mut cancelled)
            .await
        {
            warn!(target: "Client", "Received unknown top-level node: {}", DisplayableNode(&node));
        }

        // Send the deferred ACK if applicable and not cancelled by handler
        if self.should_ack(&node) && !cancelled {
            self.maybe_deferred_ack(node).await;
        }
    }

    /// Determine if a Node should be acknowledged with <ack/>.
    fn should_ack(&self, node: &Node) -> bool {
        matches!(
            node.tag.as_str(),
            "message" | "receipt" | "notification" | "call"
        ) && node.attrs.contains_key("id")
            && node.attrs.contains_key("from")
    }

    /// Possibly send a deferred ack: either immediately or via spawned task.
    /// Handlers can cancel by setting `cancelled` to true.
    /// Uses Arc<Node> to avoid cloning when spawning the async task.
    async fn maybe_deferred_ack(self: &Arc<Self>, node: Arc<Node>) {
        if self.synchronous_ack {
            if let Err(e) = self.send_ack_for(&node).await {
                warn!(target: "Client", "Failed to send ack: {e:?}");
            }
        } else {
            let this = self.clone();
            // Node is already in Arc - just clone the Arc (cheap), not the Node
            tokio::spawn(async move {
                if let Err(e) = this.send_ack_for(&node).await {
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
        let mut attrs = IndexMap::new();
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
        use crate::request::InfoQuery;

        let tag = if passive { "passive" } else { "active" };

        let query = InfoQuery::set(
            "passive",
            server_jid(),
            Some(wacore_binary::node::NodeContent::Nodes(vec![
                NodeBuilder::new(tag).build(),
            ])),
        );

        self.send_iq(query).await.map(|_| ())
    }

    pub async fn clean_dirty_bits(
        &self,
        type_: &str,
        timestamp: Option<&str>,
    ) -> Result<(), ClientError> {
        let id = self.generate_request_id();
        let mut clean_builder = NodeBuilder::new("clean").attr("type", type_);
        if let Some(ts) = timestamp {
            clean_builder = clean_builder.attr("timestamp", ts);
        }

        let node = NodeBuilder::new("iq")
            .attr("to", server_jid().to_string())
            .attr("type", "set")
            .attr("xmlns", "urn:xmpp:whatsapp:dirty")
            .attr("id", id)
            .children([clean_builder.build()])
            .build();

        self.send_node(node).await
    }

    pub async fn fetch_props(&self) -> Result<(), crate::request::IqError> {
        use crate::request::InfoQuery;

        debug!(target: "Client", "Fetching properties (props)...");

        let props_node = NodeBuilder::new("props")
            .attr("protocol", "2")
            .attr("hash", "") // TODO: load hash from persistence
            .build();

        let iq = InfoQuery::get(
            "w",
            server_jid(),
            Some(wacore_binary::node::NodeContent::Nodes(vec![props_node])),
        );

        self.send_iq(iq).await.map(|_| ())
    }

    pub async fn fetch_privacy_settings(&self) -> Result<(), crate::request::IqError> {
        use crate::request::InfoQuery;

        debug!(target: "Client", "Fetching privacy settings...");

        let iq = InfoQuery::get(
            "privacy",
            server_jid(),
            Some(wacore_binary::node::NodeContent::Nodes(vec![
                NodeBuilder::new("privacy").build(),
            ])),
        );

        self.send_iq(iq).await.map(|_| ())
    }

    pub async fn send_digest_key_bundle(&self) -> Result<(), crate::request::IqError> {
        use crate::request::InfoQuery;

        debug!(target: "Client", "Sending digest key bundle...");

        let digest_node = NodeBuilder::new("digest").build();
        let iq = InfoQuery::get(
            "encrypt",
            server_jid(),
            Some(wacore_binary::node::NodeContent::Nodes(vec![digest_node])),
        );

        self.send_iq(iq).await.map(|_| ())
    }

    pub(crate) async fn handle_success(self: &Arc<Self>, node: &wacore_binary::node::Node) {
        // Skip processing if an expected disconnect is pending (e.g., 515 received).
        // This prevents race conditions where a spawned success handler runs after
        // cleanup_connection_state has already reset is_logged_in.
        if self.expected_disconnect.load(Ordering::Relaxed) {
            debug!(target: "Client", "Ignoring <success> stanza: expected disconnect pending");
            return;
        }

        // Guard against multiple <success> stanzas (WhatsApp may send more than one during
        // routing/reconnection). Only process the first one per connection.
        if self.is_logged_in.swap(true, Ordering::SeqCst) {
            debug!(target: "Client", "Ignoring duplicate <success> stanza (already logged in)");
            return;
        }

        // Increment connection generation to invalidate any stale post-login tasks
        // from previous connections (e.g., during 515 reconnect cycles).
        let current_generation = self.connection_generation.fetch_add(1, Ordering::SeqCst) + 1;

        info!(
            "Successfully authenticated with WhatsApp servers! (gen={})",
            current_generation
        );
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
        let task_generation = current_generation;
        tokio::spawn(async move {
            // Macro to check if this task is still valid (connection hasn't been replaced)
            macro_rules! check_generation {
                () => {
                    if client_clone.connection_generation.load(Ordering::SeqCst) != task_generation
                    {
                        debug!("Post-login task cancelled: connection generation changed");
                        return;
                    }
                };
            }

            info!(target: "Client", "Starting post-login initialization sequence (gen={})...", task_generation);

            let mut force_initial_sync = false;
            let device_snapshot = client_clone.persistence_manager.get_device_snapshot().await;
            if device_snapshot.push_name.is_empty() {
                const DEFAULT_PUSH_NAME: &str = "WhatsApp Rust";
                warn!(
                    target: "Client",
                    "Push name is empty! Setting default to '{DEFAULT_PUSH_NAME}' to allow presence."
                );
                client_clone
                    .persistence_manager
                    .process_command(DeviceCommand::SetPushName(DEFAULT_PUSH_NAME.to_string()))
                    .await;
                force_initial_sync = true;
            }

            // Check connection before network operations.
            // During pairing, a 515 disconnect happens quickly after success,
            // so the socket may already be gone.
            if !client_clone.is_connected() {
                debug!(
                    "Skipping post-login init: connection closed (likely pairing phase reconnect)"
                );
                return;
            }

            // === Establish session with primary phone for PDO ===
            // This must happen BEFORE we exit passive mode (before offline messages arrive).
            // PDO needs a session with device 0 to request decrypted content from our phone.
            // Matches WhatsApp Web's bootstrapDeviceCapabilities() pattern.
            check_generation!();
            if let Err(e) = client_clone
                .establish_primary_phone_session_immediate()
                .await
            {
                warn!(target: "Client/PDO", "Failed to establish session with primary phone on login: {:?}", e);
                // Don't fail login - PDO will retry via ensure_e2e_sessions fallback
            }

            // === Send active IQ ===
            // The server sends <ib><offline count="X"/></ib> AFTER we exit passive mode.
            // This matches WhatsApp Web's behavior: sendPassiveModeProtocol("active") first,
            // then wait for offlineDeliveryEnd.
            check_generation!();
            if let Err(e) = client_clone.set_passive(false).await {
                warn!("Failed to send post-connect active IQ: {e:?}");
            }

            // === Wait for offline sync to complete ===
            // The server sends <ib><offline count="X"/></ib> after we exit passive mode.
            // Use a timeout to handle cases where the server doesn't send offline ib
            // (e.g., during initial pairing or if there are no offline messages).
            const OFFLINE_SYNC_TIMEOUT_SECS: u64 = 5;

            if !client_clone.offline_sync_completed.load(Ordering::Relaxed) {
                info!(target: "Client", "Waiting for offline sync to complete (up to {}s)...", OFFLINE_SYNC_TIMEOUT_SECS);
                let wait_result = tokio::time::timeout(
                    Duration::from_secs(OFFLINE_SYNC_TIMEOUT_SECS),
                    client_clone.offline_sync_notifier.notified(),
                )
                .await;

                // Check if connection was replaced while waiting
                check_generation!();

                if wait_result.is_err() {
                    info!(target: "Client", "Offline sync wait timed out, proceeding with passive tasks");
                } else {
                    info!(target: "Client", "Offline sync completed, proceeding with passive tasks");
                }
            }

            // === Passive Tasks (mimics WhatsApp Web's PassiveTaskManager) ===
            // These tasks run after offline delivery ends.

            check_generation!();
            if let Err(e) = client_clone.upload_pre_keys().await {
                warn!("Failed to upload pre-keys during startup: {e:?}");
            }

            // Re-check connection and generation before sending presence
            check_generation!();
            if !client_clone.is_connected() {
                debug!("Skipping presence: connection closed");
                return;
            }

            // Send presence (like WhatsApp Web's sendPresenceAvailable after passive tasks)
            if let Err(e) = client_clone.presence().set_available().await {
                warn!("Failed to send initial presence: {e:?}");
            } else {
                info!("Initial presence sent successfully.");
            }

            // === End of Passive Tasks ===

            check_generation!();

            // Background initialization queries (can run in parallel, non-blocking)
            let bg_client = client_clone.clone();
            let bg_generation = task_generation;
            tokio::spawn(async move {
                // Check connection and generation before starting background queries
                if bg_client.connection_generation.load(Ordering::SeqCst) != bg_generation {
                    debug!("Skipping background init queries: connection generation changed");
                    return;
                }
                if !bg_client.is_connected() {
                    debug!("Skipping background init queries: connection closed");
                    return;
                }

                info!(
                    target: "Client",
                    "Sending background initialization queries (Props, Blocklist, Privacy, Digest)..."
                );

                let props_fut = bg_client.fetch_props();
                let binding = bg_client.blocking();
                let blocklist_fut = binding.get_blocklist();
                let privacy_fut = bg_client.fetch_privacy_settings();
                let digest_fut = bg_client.send_digest_key_bundle();

                let (r_props, r_block, r_priv, r_digest) =
                    tokio::join!(props_fut, blocklist_fut, privacy_fut, digest_fut);

                if let Err(e) = r_props {
                    warn!("Background init: Failed to fetch props: {e:?}");
                }
                if let Err(e) = r_block {
                    warn!("Background init: Failed to fetch blocklist: {e:?}");
                }
                if let Err(e) = r_priv {
                    warn!("Background init: Failed to fetch privacy settings: {e:?}");
                }
                if let Err(e) = r_digest {
                    warn!("Background init: Failed to send digest: {e:?}");
                }
            });

            client_clone
                .core
                .event_bus
                .dispatch(&Event::Connected(crate::types::events::Connected));
            client_clone.connected_notifier.notify_waiters();

            check_generation!();

            let flag_set = client_clone.needs_initial_full_sync.load(Ordering::Relaxed);
            if flag_set || force_initial_sync {
                info!(
                    target: "Client/AppState",
                    "Starting Initial App State Sync (flag_set={flag_set}, force={force_initial_sync})"
                );

                if !client_clone
                    .initial_app_state_keys_received
                    .load(Ordering::Relaxed)
                {
                    info!(
                        target: "Client/AppState",
                        "Waiting up to 5s for app state keys..."
                    );
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        client_clone.initial_keys_synced_notifier.notified(),
                    )
                    .await;

                    // Check if connection was replaced while waiting
                    check_generation!();
                }

                let sync_client = client_clone.clone();
                let sync_generation = task_generation;
                tokio::spawn(async move {
                    let names = [
                        WAPatchName::CriticalBlock,
                        WAPatchName::CriticalUnblockLow,
                        WAPatchName::RegularLow,
                        WAPatchName::RegularHigh,
                        WAPatchName::Regular,
                    ];

                    for name in names {
                        // Check generation before each sync to avoid racing with new connections
                        if sync_client.connection_generation.load(Ordering::SeqCst)
                            != sync_generation
                        {
                            debug!("App state sync cancelled: connection generation changed");
                            return;
                        }

                        if let Err(e) = sync_client.fetch_app_state_with_retry(name).await {
                            warn!("Failed to full sync app state {:?}: {e}", name);
                        }
                    }

                    sync_client
                        .needs_initial_full_sync
                        .store(false, Ordering::Relaxed);
                    info!(target: "Client/AppState", "Initial App State Sync Completed.");
                });
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

        let mut state = backend.get_version(name.as_str()).await?;
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
                to: server_jid(),
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
                let mut to_request: Vec<Vec<u8>> = Vec::with_capacity(missing.len());
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

        backend.set_version(name.as_str(), state.clone()).await?;

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
                &msg,
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

    pub(crate) async fn handle_stream_error(&self, node: &wacore_binary::node::Node) {
        self.is_logged_in.store(false, Ordering::Relaxed);

        let mut attrs = node.attrs();
        let code = attrs.optional_string("code").unwrap_or("");
        let conflict_type = node
            .get_optional_child("conflict")
            .map(|n| n.attrs().optional_string("type").unwrap_or("").to_string())
            .unwrap_or_default();

        match (code, conflict_type.as_str()) {
            ("515", _) => {
                // 515 is expected during registration/pairing phase - server closes stream after pairing
                info!(target: "Client", "Got 515 stream error, server is closing stream. Will auto-reconnect.");
                self.expect_disconnect().await;
                // Proactively disconnect transport since server may not close the connection
                // Clone the transport Arc before spawning to avoid holding the lock
                let transport_opt = self.transport.lock().await.clone();
                if let Some(transport) = transport_opt {
                    // Spawn disconnect in background so we don't block the message loop
                    tokio::spawn(async move {
                        info!(target: "Client", "Disconnecting transport after 515");
                        transport.disconnect().await;
                    });
                }
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

        info!(target: "Client", "Notifying shutdown from stream error handler");
        self.shutdown_notifier.notify_waiters();
    }

    pub(crate) async fn handle_connect_failure(&self, node: &wacore_binary::node::Node) {
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.shutdown_notifier.notify_waiters();

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

    pub(crate) async fn handle_iq(self: &Arc<Self>, node: &wacore_binary::node::Node) -> bool {
        if let Some("get") = node.attrs.get("type").map(|s| s.as_str())
            && node.get_optional_child("ping").is_some()
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

        // Pass Node directly to pair handling
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

    /// Waits for the noise socket to be established.
    ///
    /// Returns `Ok(())` when the socket is ready, or `Err` on timeout.
    /// This is useful for code that needs to send messages before login,
    /// such as requesting a pair code during initial pairing.
    ///
    /// If the socket is already connected, returns immediately.
    pub async fn wait_for_socket(&self, timeout: std::time::Duration) -> Result<(), anyhow::Error> {
        // Fast path: already connected
        if self.is_connected() {
            return Ok(());
        }

        // Register waiter and re-check to avoid race condition:
        // If socket becomes ready between checks, the notified future captures it.
        let notified = self.socket_ready_notifier.notified();
        if self.is_connected() {
            return Ok(());
        }

        tokio::time::timeout(timeout, notified)
            .await
            .map_err(|_| anyhow::anyhow!("Timeout waiting for socket"))
    }

    /// Waits for the client to establish a connection and complete login.
    ///
    /// Returns `Ok(())` when connected, or `Err` on timeout.
    /// This is useful for code that needs to run after connection is established
    /// and authentication is complete.
    ///
    /// If the client is already connected and logged in, returns immediately.
    pub async fn wait_for_connected(
        &self,
        timeout: std::time::Duration,
    ) -> Result<(), anyhow::Error> {
        // Fast path: already connected and logged in
        if self.is_connected() && self.is_logged_in() {
            return Ok(());
        }

        // Register waiter and re-check to avoid race condition:
        // If connection completes between checks, the notified future captures it.
        let notified = self.connected_notifier.notified();
        if self.is_connected() && self.is_logged_in() {
            return Ok(());
        }

        tokio::time::timeout(timeout, notified)
            .await
            .map_err(|_| anyhow::anyhow!("Timeout waiting for connection"))
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
            &edit_container_message,
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

        let mut plaintext_buf = {
            let mut pool = self.plaintext_buffer_pool.lock().await;
            pool.pop().unwrap_or_else(|| Vec::with_capacity(1024))
        };
        plaintext_buf.clear();

        if let Err(e) = wacore_binary::marshal::marshal_to(&node, &mut plaintext_buf) {
            error!("Failed to marshal node: {e:?}");
            let mut pool = self.plaintext_buffer_pool.lock().await;
            if plaintext_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
                pool.push(plaintext_buf);
            }
            return Err(SocketError::Crypto("Marshal error".to_string()).into());
        }

        // Size based on plaintext + encryption overhead (16 byte tag + 3 byte frame header)
        let encrypted_buf = Vec::with_capacity(plaintext_buf.len() + 32);

        let (plaintext_buf, _) = match noise_socket
            .encrypt_and_send(plaintext_buf, encrypted_buf)
            .await
        {
            Ok(bufs) => bufs,
            Err(mut e) => {
                let p_buf = std::mem::take(&mut e.plaintext_buf);
                let mut pool = self.plaintext_buffer_pool.lock().await;
                if p_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
                    pool.push(p_buf);
                }
                return Err(e.into());
            }
        };

        let mut pool = self.plaintext_buffer_pool.lock().await;
        if plaintext_buf.capacity() <= MAX_POOLED_BUFFER_CAP {
            pool.push(plaintext_buf);
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
            if let Err(e) = client_clone.presence().set_available().await {
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

    // get_phone_number_from_lid is in client/lid_pn.rs

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
            let type_str = match receipt_type {
                crate::types::presence::ReceiptType::HistorySync => "hist_sync",
                crate::types::presence::ReceiptType::Read => "read",
                crate::types::presence::ReceiptType::ReadSelf => "read-self",
                crate::types::presence::ReceiptType::Delivered => "delivery",
                crate::types::presence::ReceiptType::Played => "played",
                crate::types::presence::ReceiptType::PlayedSelf => "played-self",
                crate::types::presence::ReceiptType::Inactive => "inactive",
                crate::types::presence::ReceiptType::PeerMsg => "peer_msg",
                crate::types::presence::ReceiptType::Sender => "sender",
                crate::types::presence::ReceiptType::ServerError => "server-error",
                crate::types::presence::ReceiptType::Retry => "retry",
                crate::types::presence::ReceiptType::Other(ref s) => s.as_str(),
            };

            let node = NodeBuilder::new("receipt")
                .attrs([
                    ("id", id),
                    ("type", type_str.to_string()),
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
    use crate::lid_pn_cache::LearningSource;
    use crate::test_utils::MockHttpClient;
    use tokio::sync::oneshot;
    use wacore_binary::jid::SERVER_JID;

    #[tokio::test]
    async fn test_ack_behavior_for_incoming_stanzas() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(":memory:")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // --- Assertions ---

        // Verify that we still ack other critical stanzas (regression check).
        use indexmap::IndexMap;
        use wacore_binary::node::{Node, NodeContent};

        let mut receipt_attrs = IndexMap::new();
        receipt_attrs.insert("from".to_string(), "@s.whatsapp.net".to_string());
        receipt_attrs.insert("id".to_string(), "RCPT-1".to_string());
        let receipt_node = Node::new(
            "receipt",
            receipt_attrs,
            Some(NodeContent::String("test".to_string())),
        );

        let mut notification_attrs = IndexMap::new();
        notification_attrs.insert("from".to_string(), "@s.whatsapp.net".to_string());
        notification_attrs.insert("id".to_string(), "NOTIF-1".to_string());
        let notification_node = Node::new(
            "notification",
            notification_attrs,
            Some(NodeContent::String("test".to_string())),
        );

        assert!(
            client.should_ack(&receipt_node),
            "should_ack must still return TRUE for <receipt> stanzas."
        );
        assert!(
            client.should_ack(&notification_node),
            "should_ack must still return TRUE for <notification> stanzas."
        );

        info!(
            "✅ test_ack_behavior_for_incoming_stanzas passed: Client correctly differentiates which stanzas to acknowledge."
        );
    }

    #[tokio::test]
    async fn test_plaintext_buffer_pool_reuses_buffers() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(":memory:")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Check initial pool size
        let initial_pool_size = {
            let pool = client.plaintext_buffer_pool.lock().await;
            pool.len()
        };

        // Attempt to send a node (this will fail because we're not connected, but that's okay)
        let test_node = NodeBuilder::new("test").attr("id", "test-123").build();

        let _ = client.send_node(test_node).await;

        // After the send attempt, the pool should have the same or more buffers
        // (depending on whether buffers were consumed and returned)
        let final_pool_size = {
            let pool = client.plaintext_buffer_pool.lock().await;
            pool.len()
        };

        assert!(
            final_pool_size >= initial_pool_size,
            "Plaintext buffer pool should not shrink after send operations"
        );

        info!(
            "✅ test_plaintext_buffer_pool_reuses_buffers passed: Buffer pool properly manages plaintext buffers"
        );
    }

    #[tokio::test]
    async fn test_ack_waiter_resolves() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(":memory:")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
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
            .attr("from", SERVER_JID)
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
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
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
            .attr("from", SERVER_JID)
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

    /// Test that the lid_pn_cache correctly stores and retrieves LID mappings.
    ///
    /// This is critical for the LID-PN session mismatch fix. When we receive a message
    /// with sender_lid, we cache the phone->LID mapping so that when sending replies,
    /// we can reuse the existing LID session instead of creating a new PN session.
    #[tokio::test]
    async fn test_lid_pn_cache_basic_operations() {
        let backend = Arc::new(
            crate::store::SqliteStore::new("file:memdb_lid_cache_basic?mode=memory&cache=shared")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Initially, the cache should be empty for a phone number
        let phone = "559980000001";
        let lid = "100000012345678";

        assert!(
            client.lid_pn_cache.get_current_lid(phone).await.is_none(),
            "Cache should be empty initially"
        );

        // Insert a phone->LID mapping using add_lid_pn_mapping
        client
            .add_lid_pn_mapping(lid, phone, LearningSource::Usync)
            .await
            .expect("Failed to persist LID-PN mapping in tests");

        // Verify we can retrieve it (phone -> LID lookup)
        let cached_lid = client.lid_pn_cache.get_current_lid(phone).await;
        assert!(cached_lid.is_some(), "Cache should contain the mapping");
        assert_eq!(
            cached_lid.expect("cache should have LID"),
            lid,
            "Cached LID should match what we inserted"
        );

        // Verify reverse lookup works (LID -> phone)
        let cached_phone = client.lid_pn_cache.get_phone_number(lid).await;
        assert!(cached_phone.is_some(), "Reverse lookup should work");
        assert_eq!(
            cached_phone.expect("reverse lookup should return phone"),
            phone,
            "Cached phone should match what we inserted"
        );

        // Verify a different phone number returns None
        assert!(
            client
                .lid_pn_cache
                .get_current_lid("559980000002")
                .await
                .is_none(),
            "Different phone number should not have a mapping"
        );

        info!("✅ test_lid_pn_cache_basic_operations passed: LID-PN cache works correctly");
    }

    /// Test that the lid_pn_cache respects timestamp-based conflict resolution.
    ///
    /// When a phone number has multiple LIDs, the most recent one should be returned.
    #[tokio::test]
    async fn test_lid_pn_cache_timestamp_resolution() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(
                "file:memdb_lid_cache_timestamp?mode=memory&cache=shared",
            )
            .await
            .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let phone = "559980000001";
        let lid_old = "100000012345678";
        let lid_new = "100000087654321";

        // Insert initial mapping
        client
            .add_lid_pn_mapping(lid_old, phone, LearningSource::Usync)
            .await
            .expect("Failed to persist LID-PN mapping in tests");

        assert_eq!(
            client
                .lid_pn_cache
                .get_current_lid(phone)
                .await
                .expect("cache should have LID"),
            lid_old,
            "Initial LID should be stored"
        );

        // Small delay to ensure different timestamp
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // Add new mapping with newer timestamp
        client
            .add_lid_pn_mapping(lid_new, phone, LearningSource::PeerPnMessage)
            .await
            .expect("Failed to persist LID-PN mapping in tests");

        assert_eq!(
            client
                .lid_pn_cache
                .get_current_lid(phone)
                .await
                .expect("cache should have newer LID"),
            lid_new,
            "Newer LID should be returned for phone lookup"
        );

        // Both LIDs should still resolve to the same phone
        assert_eq!(
            client
                .lid_pn_cache
                .get_phone_number(lid_old)
                .await
                .expect("reverse lookup should return phone"),
            phone,
            "Old LID should still map to phone"
        );
        assert_eq!(
            client
                .lid_pn_cache
                .get_phone_number(lid_new)
                .await
                .expect("reverse lookup should return phone"),
            phone,
            "New LID should also map to phone"
        );

        info!(
            "✅ test_lid_pn_cache_timestamp_resolution passed: Timestamp-based resolution works correctly"
        );
    }

    /// Test that get_lid_for_phone (from SendContextResolver) returns the cached value.
    ///
    /// This is the method used by wacore::send to look up LID mappings when encrypting.
    #[tokio::test]
    async fn test_get_lid_for_phone_via_send_context_resolver() {
        use wacore::client::context::SendContextResolver;

        let backend = Arc::new(
            crate::store::SqliteStore::new("file:memdb_get_lid_for_phone?mode=memory&cache=shared")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let phone = "559980000001";
        let lid = "100000012345678";

        // Before caching, should return None
        assert!(
            client.get_lid_for_phone(phone).await.is_none(),
            "get_lid_for_phone should return None before caching"
        );

        // Cache the mapping using add_lid_pn_mapping
        client
            .add_lid_pn_mapping(lid, phone, LearningSource::Usync)
            .await
            .expect("Failed to persist LID-PN mapping in tests");

        // Now it should return the LID
        let result = client.get_lid_for_phone(phone).await;
        assert!(
            result.is_some(),
            "get_lid_for_phone should return Some after caching"
        );
        assert_eq!(
            result.expect("get_lid_for_phone should return Some"),
            lid,
            "get_lid_for_phone should return the cached LID"
        );

        info!(
            "✅ test_get_lid_for_phone_via_send_context_resolver passed: SendContextResolver correctly returns cached LID"
        );
    }

    // =========================================================================
    // PDO Session Establishment Timing Tests
    // =========================================================================
    // These tests verify the critical timing behavior for PDO:
    // - Session with device 0 must be established BEFORE offline messages arrive
    // - ensure_e2e_sessions() waits for offline sync (for normal message sending)
    // - establish_primary_phone_session_immediate() does NOT wait (for login)
    // =========================================================================

    /// Test that wait_for_offline_delivery_end returns immediately when the flag is already set.
    #[tokio::test]
    async fn test_wait_for_offline_delivery_end_returns_immediately_when_flag_set() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(
                "file:memdb_offline_sync_flag_set?mode=memory&cache=shared",
            )
            .await
            .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Set the flag to true (simulating offline sync completed)
        client
            .offline_sync_completed
            .store(true, std::sync::atomic::Ordering::Relaxed);

        // This should return immediately (not wait 10 seconds)
        let start = std::time::Instant::now();
        client.wait_for_offline_delivery_end().await;
        let elapsed = start.elapsed();

        // Should complete in < 100ms (not 10 second timeout)
        assert!(
            elapsed.as_millis() < 100,
            "wait_for_offline_delivery_end should return immediately when flag is set, took {:?}",
            elapsed
        );

        info!("✅ test_wait_for_offline_delivery_end_returns_immediately_when_flag_set passed");
    }

    /// Test that wait_for_offline_delivery_end times out when the flag is NOT set.
    /// This verifies the 10-second timeout is working.
    #[tokio::test]
    async fn test_wait_for_offline_delivery_end_times_out_when_flag_not_set() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(
                "file:memdb_offline_sync_timeout?mode=memory&cache=shared",
            )
            .await
            .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Flag is false by default, so we need to use a shorter timeout for the test
        // We'll verify behavior by using tokio timeout
        let start = std::time::Instant::now();

        // Use a short timeout to test the behavior without waiting 10 seconds
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            client.wait_for_offline_delivery_end(),
        )
        .await;

        let elapsed = start.elapsed();

        // The wait should NOT complete immediately - it should timeout
        // (because the flag is false and no one is notifying)
        assert!(
            result.is_err(),
            "wait_for_offline_delivery_end should not return immediately when flag is false"
        );
        assert!(
            elapsed.as_millis() >= 95, // Allow small timing variance
            "Should have waited for the timeout duration, took {:?}",
            elapsed
        );

        info!("✅ test_wait_for_offline_delivery_end_times_out_when_flag_not_set passed");
    }

    /// Test that wait_for_offline_delivery_end returns when notified.
    #[tokio::test]
    async fn test_wait_for_offline_delivery_end_returns_on_notify() {
        let backend = Arc::new(
            crate::store::SqliteStore::new("file:memdb_offline_notify?mode=memory&cache=shared")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let client_clone = client.clone();

        // Spawn a task that will notify after 50ms
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            client_clone.offline_sync_notifier.notify_waiters();
        });

        let start = std::time::Instant::now();
        client.wait_for_offline_delivery_end().await;
        let elapsed = start.elapsed();

        // Should complete around 50ms (when notified), not 10 seconds
        assert!(
            elapsed.as_millis() < 200,
            "wait_for_offline_delivery_end should return when notified, took {:?}",
            elapsed
        );
        assert!(
            elapsed.as_millis() >= 45, // Should have waited for the notify
            "Should have waited for the notify, only took {:?}",
            elapsed
        );

        info!("✅ test_wait_for_offline_delivery_end_returns_on_notify passed");
    }

    /// Test that the offline_sync_completed flag starts as false.
    #[tokio::test]
    async fn test_offline_sync_flag_initially_false() {
        let backend = Arc::new(
            crate::store::SqliteStore::new(
                "file:memdb_offline_flag_initial?mode=memory&cache=shared",
            )
            .await
            .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // The flag should be false initially
        assert!(
            !client
                .offline_sync_completed
                .load(std::sync::atomic::Ordering::Relaxed),
            "offline_sync_completed should be false when Client is first created"
        );

        info!("✅ test_offline_sync_flag_initially_false passed");
    }

    /// Test the complete offline sync lifecycle:
    /// 1. Flag starts false
    /// 2. Flag is set true after IB offline stanza
    /// 3. Notify is called
    #[tokio::test]
    async fn test_offline_sync_lifecycle() {
        use std::sync::atomic::Ordering;

        let backend = Arc::new(
            crate::store::SqliteStore::new("file:memdb_offline_lifecycle?mode=memory&cache=shared")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // 1. Initially false
        assert!(!client.offline_sync_completed.load(Ordering::Relaxed));

        // 2. Spawn a waiter
        let client_waiter = client.clone();
        let waiter_handle = tokio::spawn(async move {
            client_waiter.wait_for_offline_delivery_end().await;
            true // Return that we completed
        });

        // Give the waiter time to start waiting
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;

        // Verify waiter hasn't completed yet
        assert!(
            !waiter_handle.is_finished(),
            "Waiter should still be waiting"
        );

        // 3. Simulate IB handler behavior (set flag and notify)
        client.offline_sync_completed.store(true, Ordering::Relaxed);
        client.offline_sync_notifier.notify_waiters();

        // 4. Waiter should complete
        let result = tokio::time::timeout(std::time::Duration::from_millis(100), waiter_handle)
            .await
            .expect("Waiter should complete after notify")
            .expect("Waiter task should not panic");

        assert!(result, "Waiter should have completed successfully");
        assert!(client.offline_sync_completed.load(Ordering::Relaxed));

        info!("✅ test_offline_sync_lifecycle passed");
    }

    /// Test that establish_primary_phone_session_immediate returns error when no PN is set.
    /// This verifies the "not logged in" guard works.
    #[tokio::test]
    async fn test_establish_primary_phone_session_fails_without_pn() {
        let backend = Arc::new(
            crate::store::SqliteStore::new("file:memdb_no_pn?mode=memory&cache=shared")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // No PN set, so this should fail
        let result = client.establish_primary_phone_session_immediate().await;

        assert!(
            result.is_err(),
            "establish_primary_phone_session_immediate should fail when no PN is set"
        );

        let error_msg = result.unwrap_err().to_string();
        assert!(
            error_msg.contains("Not logged in"),
            "Error should mention 'Not logged in', got: {}",
            error_msg
        );

        info!("✅ test_establish_primary_phone_session_fails_without_pn passed");
    }

    /// Test that ensure_e2e_sessions waits for offline sync to complete.
    /// This is the CRITICAL difference between ensure_e2e_sessions and
    /// establish_primary_phone_session_immediate.
    #[tokio::test]
    async fn test_ensure_e2e_sessions_waits_for_offline_sync() {
        use std::sync::atomic::Ordering;
        use wacore_binary::jid::Jid;

        let backend = Arc::new(
            crate::store::SqliteStore::new("file:memdb_ensure_e2e_waits?mode=memory&cache=shared")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Flag is false (offline sync not complete)
        assert!(!client.offline_sync_completed.load(Ordering::Relaxed));

        // Call ensure_e2e_sessions with an empty list (so it returns early after the wait)
        // This lets us test the waiting behavior without needing network
        let client_clone = client.clone();
        let ensure_handle = tokio::spawn(async move {
            // Start with some JIDs - but since we're testing the wait, we use empty
            // to avoid needing actual session establishment
            client_clone.ensure_e2e_sessions(vec![]).await
        });

        // Wait a bit - ensure_e2e_sessions should return immediately for empty list
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert!(
            ensure_handle.is_finished(),
            "ensure_e2e_sessions should return immediately for empty JID list"
        );

        // Now test with actual JIDs - it should wait for offline sync
        let client_clone = client.clone();
        let test_jid = Jid::pn("559999999999");
        let ensure_handle = tokio::spawn(async move {
            // This will wait for offline sync before proceeding
            let start = std::time::Instant::now();
            let _ = client_clone.ensure_e2e_sessions(vec![test_jid]).await;
            start.elapsed()
        });

        // Give it a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        // It should still be waiting (offline sync not complete)
        assert!(
            !ensure_handle.is_finished(),
            "ensure_e2e_sessions should be waiting for offline sync"
        );

        // Now complete offline sync
        client.offline_sync_completed.store(true, Ordering::Relaxed);
        client.offline_sync_notifier.notify_waiters();

        // Now it should complete (might fail on session establishment, but that's ok)
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), ensure_handle).await;

        assert!(
            result.is_ok(),
            "ensure_e2e_sessions should complete after offline sync"
        );

        info!("✅ test_ensure_e2e_sessions_waits_for_offline_sync passed");
    }

    /// Integration test: Verify that the immediate session establishment does NOT
    /// wait for offline sync. This is critical for PDO to work during offline sync.
    ///
    /// The flow is:
    /// 1. Login -> establish_primary_phone_session_immediate() is called
    /// 2. This should NOT wait for offline sync (flag is false at this point)
    /// 3. After session is established, offline messages arrive
    /// 4. When decryption fails, PDO can immediately send to device 0
    #[tokio::test]
    async fn test_immediate_session_does_not_wait_for_offline_sync() {
        use std::sync::atomic::Ordering;
        use wacore_binary::jid::Jid;

        let backend = Arc::new(
            crate::store::SqliteStore::new("file:memdb_immediate_no_wait?mode=memory&cache=shared")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend.clone())
                .await
                .expect("persistence manager should initialize"),
        );

        // Set a PN so establish_primary_phone_session_immediate doesn't fail early
        pm.modify_device(|device| {
            device.pn = Some(Jid::pn("559999999999"));
        })
        .await;

        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Flag is false (offline sync not complete - simulating login state)
        assert!(!client.offline_sync_completed.load(Ordering::Relaxed));

        // Call establish_primary_phone_session_immediate
        // It should NOT wait for offline sync - it should proceed immediately
        let start = std::time::Instant::now();

        // Note: This will fail because we can't actually fetch prekeys in tests,
        // but the important thing is that it doesn't WAIT for offline sync
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client.establish_primary_phone_session_immediate(),
        )
        .await;

        let elapsed = start.elapsed();

        // The call should complete (or fail) quickly, NOT wait for 10 second timeout
        assert!(
            result.is_ok(),
            "establish_primary_phone_session_immediate should not wait for offline sync, timed out"
        );

        // It should complete in < 500ms (not 10 second wait)
        assert!(
            elapsed.as_millis() < 500,
            "establish_primary_phone_session_immediate should not wait, took {:?}",
            elapsed
        );

        // The actual result might be an error (no network), but that's fine
        // The important thing is it didn't wait for offline sync
        info!(
            "establish_primary_phone_session_immediate completed in {:?} (result: {:?})",
            elapsed,
            result.unwrap().is_ok()
        );

        info!("✅ test_immediate_session_does_not_wait_for_offline_sync passed");
    }
}
