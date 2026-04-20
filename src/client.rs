mod context_impl;
mod device_registry;
mod lid_pn;
mod sender_keys;
mod sessions;

use crate::cache::Cache;
use crate::cache_store::TypedCache;
use crate::handshake;
use crate::lid_pn_cache::LidPnCache;
use crate::pair;
use anyhow::{Result, anyhow};
use futures::FutureExt;
#[cfg(test)]
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};

use wacore::xml::{DisplayableNode, DisplayableNodeRef};
use wacore_binary::JidExt;
use wacore_binary::Node;
use wacore_binary::builder::NodeBuilder;
#[cfg(test)]
use wacore_binary::{Attrs, NodeValue};

use crate::appstate_sync::AppStateProcessor;
use crate::handlers::chatstate::ChatStateEvent;
use crate::jid_utils::server_jid;
use crate::store::{commands::DeviceCommand, persistence_manager::PersistenceManager};
use crate::types::enc_handler::EncHandler;
use crate::types::events::{ConnectFailureReason, Event};

use log::{debug, error, info, trace, warn};

use rand::{Rng, RngExt};
use scopeguard;
use wacore_binary::Jid;

use portable_atomic::AtomicU64;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

/// Filter for matching incoming stanzas (nodes) by tag and attributes.
///
/// Used with [`Client::wait_for_node`] to wait for specific stanzas.
/// Zero-cost when no waiters are active (single atomic load per node).
///
/// # Example
/// ```ignore
/// // Wait for a w:gp2 notification from a specific group
/// let waiter = client.wait_for_node(
///     NodeFilter::tag("notification")
///         .attr("type", "w:gp2")
///         .attr("from", "group@g.us"),
/// );
/// // ... trigger the action ...
/// let node = waiter.await?;
/// ```
#[derive(Debug, Clone)]
pub struct NodeFilter {
    tag: String,
    attrs: Vec<(String, String)>,
}

impl NodeFilter {
    /// Create a filter matching nodes with the given tag.
    pub fn tag(tag: impl Into<String>) -> Self {
        Self {
            tag: tag.into(),
            attrs: Vec::new(),
        }
    }

    /// Add an attribute constraint. All attributes must match.
    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.attrs.push((key.into(), value.into()));
        self
    }

    /// Shorthand for `.attr("from", jid.to_string())`.
    pub fn from_jid(self, jid: &Jid) -> Self {
        self.attr("from", jid.to_string())
    }

    fn matches(&self, node: &wacore_binary::NodeRef<'_>) -> bool {
        node.tag == self.tag.as_str()
            && self.attrs.iter().all(|(k, v)| {
                node.get_attr(k.as_str())
                    .is_some_and(|attr| attr.as_str() == v.as_str())
            })
    }
}

struct NodeWaiter {
    filter: NodeFilter,
    tx: futures::channel::oneshot::Sender<Arc<wacore_binary::OwnedNodeRef>>,
}

struct SentNodeWaiter {
    filter: NodeFilter,
    tx: futures::channel::oneshot::Sender<Arc<Node>>,
}

fn resolve_waiters(
    waiters_mutex: &std::sync::Mutex<Vec<NodeWaiter>>,
    counter: &AtomicUsize,
    node: &Arc<wacore_binary::OwnedNodeRef>,
) {
    let nr = node.get();
    let mut waiters = waiters_mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let mut i = 0;
    while i < waiters.len() {
        if waiters[i].tx.is_canceled() {
            waiters.swap_remove(i);
            counter.fetch_sub(1, Ordering::Release);
        } else if waiters[i].filter.matches(nr) {
            let w = waiters.swap_remove(i);
            counter.fetch_sub(1, Ordering::Release);
            let _ = w.tx.send(Arc::clone(node));
        } else {
            i += 1;
        }
    }
}

use async_lock::Mutex;
use async_lock::RwLock;
use std::time::Duration;
use thiserror::Error;

use wacore::appstate::patch_decode::WAPatchName;
use wacore::client::context::GroupInfo;
use wacore::runtime::timeout as rt_timeout;
use waproto::whatsapp as wa;

use crate::cache_config::CacheConfig;
use crate::socket::{NoiseSocket, SocketError, error::EncryptSendError};
use crate::sync_task::MajorSyncTask;
use wacore::runtime::Runtime;

/// Type alias for chatstate event handler functions.
type ChatStateHandler = Arc<dyn Fn(ChatStateEvent) + Send + Sync>;

/// Per-chat lane for sequential message processing. Combines the enqueue lock
/// and queue sender into a single cached entry (one lookup instead of two).
/// Keyed by `Jid` to avoid per-message `to_string()` allocation.
#[derive(Clone)]
pub(crate) struct ChatLane {
    pub enqueue_lock: Arc<async_lock::Mutex<()>>,
    pub queue_tx: async_channel::Sender<Arc<wacore_binary::OwnedNodeRef>>,
}

const APP_STATE_RETRY_MAX_ATTEMPTS: u32 = 6;

/// WA Web: MQTT `MqttProtocolClient.connect()` uses `CONNECT_TIMEOUT = 20s`,
/// DGW `connectTimeoutMs` defaults to `20000ms`.
const TRANSPORT_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);

/// Snapshot of internal collection sizes for memory leak detection.
///
/// All counts are approximate (moka caches may have pending evictions).
/// Call [`Client::memory_diagnostics`] to obtain a snapshot.
///
/// Requires the `debug-diagnostics` feature.
#[cfg(feature = "debug-diagnostics")]
#[derive(Debug, Clone)]
pub struct MemoryDiagnostics {
    // -- Moka caches (TTL/capacity-bounded) --
    pub group_cache: u64,
    pub device_registry_cache: u64,
    pub lid_pn_lid_entries: u64,
    pub lid_pn_pn_entries: u64,
    pub recent_messages: u64,
    pub sender_key_device_cache: u64,
    pub message_retry_counts: u64,
    pub pdo_pending_requests: u64,
    // -- Moka caches (capacity-only, no TTL) --
    pub session_locks: u64,
    pub chat_lanes: u64,
    // -- Unbounded collections --
    pub response_waiters: usize,
    pub node_waiters: usize,
    pub pending_retries: usize,
    pub presence_subscriptions: usize,
    pub app_state_key_requests: usize,
    pub app_state_syncing: usize,
    pub signal_cache_sessions: usize,
    pub signal_cache_identities: usize,
    pub signal_cache_sender_keys: usize,
    // -- Misc --
    pub chatstate_handlers: usize,
    pub custom_enc_handlers: usize,
}

#[cfg(feature = "debug-diagnostics")]
impl std::fmt::Display for MemoryDiagnostics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Memory Diagnostics ===")?;
        writeln!(f, "--- Moka caches (TTL-bounded) ---")?;
        writeln!(f, "  group_cache:            {}", self.group_cache)?;
        writeln!(
            f,
            "  device_registry_cache:  {}",
            self.device_registry_cache
        )?;
        writeln!(f, "  lid_pn (lid):           {}", self.lid_pn_lid_entries)?;
        writeln!(f, "  lid_pn (pn):            {}", self.lid_pn_pn_entries)?;
        writeln!(f, "  recent_messages:        {}", self.recent_messages)?;
        writeln!(
            f,
            "  sk_device_cache:        {}",
            self.sender_key_device_cache
        )?;
        writeln!(f, "  message_retry_counts:   {}", self.message_retry_counts)?;
        writeln!(f, "  pdo_pending_requests:   {}", self.pdo_pending_requests)?;
        writeln!(f, "--- Moka caches (capacity-only) ---")?;
        writeln!(f, "  session_locks:          {}", self.session_locks)?;
        writeln!(f, "  chat_lanes:             {}", self.chat_lanes)?;
        writeln!(f, "--- Unbounded collections ---")?;
        writeln!(f, "  response_waiters:       {}", self.response_waiters)?;
        writeln!(f, "  node_waiters:           {}", self.node_waiters)?;
        writeln!(f, "  pending_retries:        {}", self.pending_retries)?;
        writeln!(
            f,
            "  presence_subscriptions: {}",
            self.presence_subscriptions
        )?;
        writeln!(
            f,
            "  app_state_key_requests: {}",
            self.app_state_key_requests
        )?;
        writeln!(f, "  app_state_syncing:      {}", self.app_state_syncing)?;
        writeln!(
            f,
            "  signal_sessions:        {}",
            self.signal_cache_sessions
        )?;
        writeln!(
            f,
            "  signal_identities:      {}",
            self.signal_cache_identities
        )?;
        writeln!(
            f,
            "  signal_sender_keys:     {}",
            self.signal_cache_sender_keys
        )?;
        writeln!(f, "--- Misc ---")?;
        writeln!(f, "  chatstate_handlers:     {}", self.chatstate_handlers)?;
        writeln!(f, "  custom_enc_handlers:    {}", self.custom_enc_handlers)?;
        Ok(())
    }
}

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

impl ClientError {
    pub fn is_transport_unavailable(&self) -> bool {
        match self {
            ClientError::NotConnected => true,
            ClientError::EncryptSend(e) => e.is_transport_unavailable(),
            _ => false,
        }
    }
}

use wacore::types::message::ChatMessageId;

/// Metrics for tracking offline sync progress
#[derive(Debug)]
pub(crate) struct OfflineSyncMetrics {
    pub active: AtomicBool,
    pub total_messages: AtomicUsize,
    pub processed_messages: AtomicUsize,
    // Using simple std Mutex for timestamp as it's rarely contended and non-async
    pub start_time: std::sync::Mutex<Option<wacore::time::Instant>>,
}

pub struct Client {
    pub(crate) runtime: Arc<dyn Runtime>,
    pub(crate) core: wacore::client::CoreClient,

    pub(crate) persistence_manager: Arc<PersistenceManager>,
    pub(crate) media_conn: Arc<RwLock<Option<crate::mediaconn::MediaConn>>>,

    pub(crate) is_logged_in: Arc<AtomicBool>,
    pub(crate) is_connecting: Arc<AtomicBool>,
    pub(crate) is_running: Arc<AtomicBool>,
    /// Whether the noise socket is established (connected to WhatsApp servers).
    /// Uses an AtomicBool instead of probing the noise_socket mutex to avoid
    /// TOCTOU races where `try_lock()` fails due to contention, not disconnection.
    is_connected: Arc<AtomicBool>,
    /// Terminal shutdown (process-wide). Fired ONLY by `disconnect()`.
    /// Long-lived subscribers that must outlive reconnect cycles (saver,
    /// device registry cleanup) subscribe here.
    pub(crate) shutdown_notifier: wacore::runtime::ShutdownNotifier,

    /// Per-connection shutdown. Replaced with a fresh notifier on every new
    /// connection; fired on cleanup_connection_state / stream end / stream
    /// error / connect_failure / disconnect. Per-connection subscribers
    /// (keepalive, request waiters, read loop, offline flush) observe this.
    pub(crate) connection_shutdown: std::sync::Mutex<wacore::runtime::ShutdownNotifier>,
    /// Timestamp (ms since UNIX epoch) of the last received WebSocket data.
    /// Updated on every `DataReceived` transport event.
    /// WA Web: `parseAndHandleStanza` → `deadSocketTimer.cancel()`.
    pub(crate) last_data_received_ms: Arc<AtomicU64>,
    /// Timestamp (ms since UNIX epoch) of the last sent WebSocket data.
    /// Updated on every `send_node` call.
    /// WA Web: `callStanza` → `deadSocketTimer.onOrBefore(deadSocketTime)`.
    pub(crate) last_data_sent_ms: Arc<AtomicU64>,

    pub(crate) transport: Arc<Mutex<Option<Arc<dyn crate::transport::Transport>>>>,
    pub(crate) transport_events:
        Arc<Mutex<Option<async_channel::Receiver<crate::transport::TransportEvent>>>>,
    pub(crate) transport_factory: Arc<dyn crate::transport::TransportFactory>,
    pub(crate) noise_socket: Arc<Mutex<Option<Arc<NoiseSocket>>>>,

    pub(crate) response_waiters: Arc<
        Mutex<HashMap<String, futures::channel::oneshot::Sender<Arc<wacore_binary::OwnedNodeRef>>>>,
    >,

    /// Generic node waiters for waiting on specific stanzas by tag/attributes.
    /// Uses std::sync::Mutex (not tokio) since the critical section is trivial.
    /// Guarded by `node_waiter_count` for zero-cost when no waiters are active.
    node_waiters: std::sync::Mutex<Vec<NodeWaiter>>,
    node_waiter_count: AtomicUsize,
    /// Waiters for raw outgoing nodes before encryption.
    sent_node_waiters: std::sync::Mutex<Vec<SentNodeWaiter>>,
    sent_node_waiter_count: AtomicUsize,

    pub(crate) unique_id: String,
    pub(crate) id_counter: Arc<AtomicU64>,

    pub(crate) unified_session: crate::unified_session::UnifiedSessionManager,

    /// In-memory cache for Signal protocol state (sessions, identities, sender keys).
    /// Matches WhatsApp Web's SignalStoreCache pattern: crypto ops read/write this cache,
    /// and DB writes are deferred to flush() after each message is processed.
    pub(crate) signal_cache: Arc<crate::store::signal_cache::SignalStoreCache>,

    /// Limits message processing concurrency (1 permit during offline sync, N after).
    /// Wrapped in Mutex to allow replacing on reconnect.
    pub(crate) message_processing_semaphore: std::sync::Mutex<Arc<async_lock::Semaphore>>,
    /// Bumped on every semaphore swap so stale Arc clones are rejected.
    pub(crate) message_semaphore_generation: Arc<AtomicU64>,

    /// Per-device session locks for Signal protocol operations.
    /// Prevents race conditions when multiple messages from the same sender
    /// are processed concurrently across different chats.
    /// Keys are Signal protocol address strings (e.g., "user@s.whatsapp.net:0")
    /// to match the SignalProtocolStoreAdapter's internal locking.
    pub(crate) session_locks: Cache<String, Arc<async_lock::Mutex<()>>>,

    /// Per-chat lane combining enqueue lock + message queue into a single cached entry.
    /// One cache lookup instead of two per incoming message.
    pub(crate) chat_lanes: Cache<Jid, ChatLane>,

    /// Cache for LID to Phone Number mappings (bidirectional).
    /// When we receive a message with sender_lid/sender_pn attributes, we store the mapping here.
    /// This allows us to reuse existing LID-based sessions when sending replies.
    /// The cache is backed by persistent storage and warmed up on client initialization.
    pub(crate) lid_pn_cache: Arc<LidPnCache>,
    pub(crate) ab_props: Arc<wacore::store::ab_props::AbPropsCache>,

    pub group_cache: async_lock::Mutex<Option<Arc<TypedCache<Jid, GroupInfo>>>>,

    pub(crate) expected_disconnect: Arc<AtomicBool>,
    /// Set by `reconnect()` to suppress the "Message loop exited with an error" warning.
    /// Unlike `expected_disconnect`, this does NOT skip the reconnect backoff.
    pub(crate) intentional_reconnect: AtomicBool,

    /// Connection generation counter - incremented on each new connection.
    /// Used to detect stale post-login tasks from previous connections.
    pub(crate) connection_generation: Arc<AtomicU64>,

    /// Cache for recent messages (serialized bytes) for retry functionality.
    /// Uses moka cache with TTL and max capacity for automatic eviction.
    pub(crate) recent_messages: Cache<ChatMessageId, Vec<u8>>,

    pub(crate) sender_key_device_cache: crate::sender_key_device_cache::SenderKeyDeviceCache,

    pub(crate) pending_device_sync: crate::pending_device_sync::PendingDeviceSync,

    pub(crate) pending_retries: Arc<std::sync::Mutex<HashSet<String>>>,

    /// Track retry attempts per message to prevent infinite retry loops.
    /// Key: "{chat}:{msg_id}:{sender}", Value: retry count
    /// Matches WhatsApp Web's MAX_RETRY = 5 behavior.
    pub(crate) message_retry_counts: Cache<String, u8>,

    pub enable_auto_reconnect: Arc<AtomicBool>,
    pub auto_reconnect_errors: Arc<AtomicU32>,

    pub(crate) needs_initial_full_sync: Arc<AtomicBool>,

    pub(crate) app_state_processor: async_lock::Mutex<Option<Arc<AppStateProcessor>>>,
    pub(crate) app_state_key_requests: Arc<Mutex<HashMap<String, wacore::time::Instant>>>,
    /// Tracks collections currently being synced to prevent duplicate sync tasks.
    /// Matches WA Web's in-flight tracking set in WAWebSyncdCollectionsStateMachine.
    pub(crate) app_state_syncing: Arc<Mutex<HashSet<WAPatchName>>>,
    pub(crate) initial_keys_synced_notifier: Arc<event_listener::Event>,
    pub(crate) initial_app_state_keys_received: Arc<AtomicBool>,

    /// Prevents concurrent prekey upload operations (matches WA Web's dedup set in `handlePreKeyLow`).
    pub(crate) prekey_upload_lock: Arc<async_lock::Mutex<()>>,
    /// Notifier for when offline sync (ib offline stanza) is received.
    /// WhatsApp Web waits for this before sending passive tasks (prekey upload, active IQ, presence).
    pub(crate) offline_sync_notifier: Arc<event_listener::Event>,
    /// Flag indicating offline sync has completed (received ib offline stanza).
    pub(crate) offline_sync_completed: Arc<AtomicBool>,
    /// Number of history sync tasks currently queued or running.
    pub(crate) history_sync_tasks_in_flight: Arc<AtomicUsize>,
    /// Notifier triggered when history sync work becomes idle.
    pub(crate) history_sync_idle_notifier: Arc<event_listener::Event>,
    /// Flushed by `disconnect()`/`reconnect()` before tearing down the transport
    /// so in-flight delivery receipts aren't dropped with `NotConnected`
    /// (issue #571).
    pub(crate) outbound_flush: Arc<crate::flush_scope::FlushScope>,
    /// Contacts with active presence subscriptions that must be re-subscribed on reconnect.
    pub(crate) presence_subscriptions: Arc<async_lock::Mutex<HashSet<Jid>>>,
    /// Metrics for granular offline sync logging
    pub(crate) offline_sync_metrics: Arc<OfflineSyncMetrics>,
    /// Notifier for when the noise socket is established (before login).
    /// Use this to wait for the socket to be ready for sending messages.
    pub(crate) socket_ready_notifier: Arc<event_listener::Event>,
    /// Set to `true` only when `dispatch_connected()` fires (after critical sync
    /// completes). Reset on each new connection attempt. Used by
    /// `wait_for_connected()` to avoid a false-positive fast path when the
    /// client is logged in but critical app state hasn't synced yet.
    pub(crate) is_ready: Arc<AtomicBool>,
    /// Notifier for when the client is fully connected and logged in.
    /// Triggered after Event::Connected is dispatched.
    pub(crate) connected_notifier: Arc<event_listener::Event>,
    pub(crate) major_sync_task_sender: async_channel::Sender<MajorSyncTask>,
    pub(crate) pairing_cancellation_tx: Arc<Mutex<Option<async_channel::Sender<()>>>>,

    /// State machine for pair code authentication flow.
    /// Tracks the pending pair code request and ephemeral keys.
    pub(crate) pair_code_state: Arc<Mutex<wacore::pair_code::PairCodeState>>,

    /// Custom handlers for encrypted message types
    pub custom_enc_handlers: Arc<async_lock::RwLock<HashMap<String, Arc<dyn EncHandler>>>>,

    /// Chat state (typing indicator) handlers registered by external consumers.
    /// Each handler receives a `ChatStateEvent` describing the chat, optional participant and state.
    pub(crate) chatstate_handlers: Arc<RwLock<Vec<ChatStateHandler>>>,

    pub(crate) pdo_pending_requests:
        Cache<wacore::types::message::ChatMessageId, crate::pdo::PendingPdoRequest>,

    /// LRU cache for device registry (matches WhatsApp Web's 5000 entry limit).
    /// Maps user ID to DeviceListRecord for fast device existence checks.
    /// Backed by persistent storage.
    pub(crate) device_registry_cache: TypedCache<String, wacore::store::traits::DeviceListRecord>,

    /// Router for dispatching stanzas to their appropriate handlers
    pub(crate) stanza_router: crate::handlers::router::StanzaRouter,

    /// Whether to send ACKs synchronously or in a background task
    pub(crate) synchronous_ack: bool,

    /// HTTP client for making HTTP requests (media upload/download, version fetching)
    pub http_client: Arc<dyn crate::http::HttpClient>,

    /// Version override for testing or manual specification
    pub(crate) override_version: Option<(u32, u32, u32)>,

    /// When true, history sync notifications are acknowledged but not downloaded
    /// or processed. Set via `BotBuilder::skip_history_sync()`.
    pub(crate) skip_history_sync: AtomicBool,

    /// Cache configuration for TTL and capacity of all caches.
    /// Stored for use by lazily-initialized caches (group_cache).
    pub(crate) cache_config: CacheConfig,

    /// Weak self-reference for spawning background tasks from `&self` methods.
    /// Initialized after `Arc::new(this)` in the constructor.
    pub(crate) self_weak: std::sync::OnceLock<std::sync::Weak<Client>>,

    /// Holds the background saver's AbortHandle so the task lifetime follows
    /// `Arc<Client>` ref count instead of the Bot wrapper's. Set once by
    /// `Bot::build`; on Client drop (last Arc), the handle drops and the saver
    /// is aborted.
    pub(crate) saver_handle: std::sync::OnceLock<wacore::runtime::AbortHandle>,

    /// When true, emit `Event::RawNode` for every decoded stanza before router dispatch.
    /// Default false — only enable when external consumers need raw protocol access.
    raw_node_forwarding: AtomicBool,
}

impl Client {
    pub fn shutdown_signal(&self) -> wacore::runtime::ShutdownSignal {
        self.shutdown_notifier.subscribe()
    }

    pub(crate) fn connection_shutdown_signal(&self) -> wacore::runtime::ShutdownSignal {
        self.connection_shutdown
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .subscribe()
    }

    /// Fire the per-connection shutdown. Per-connection subscribers exit;
    /// the terminal shutdown_notifier is untouched so reconnects still work.
    pub(crate) fn notify_connection_shutdown(&self) {
        self.connection_shutdown
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .notify();
    }

    /// Reset the per-connection notifier. Call at the start of each new
    /// connection so subscribers registered afterwards see a fresh signal.
    /// The previous notifier's subscribers have already been woken (either
    /// by notify on disconnect, or by falling out of scope).
    pub(crate) fn reset_connection_shutdown(&self) {
        *self
            .connection_shutdown
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = wacore::runtime::ShutdownNotifier::new();
    }

    /// Read the current semaphore generation and Arc atomically under the mutex.
    pub(crate) fn read_message_semaphore(&self) -> (u64, Arc<async_lock::Semaphore>) {
        let guard = match self.message_processing_semaphore.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        (
            self.message_semaphore_generation.load(Ordering::SeqCst),
            guard.clone(),
        )
    }

    /// Replace the message processing semaphore and bump the generation counter.
    ///
    /// Both operations happen under the same mutex hold so readers always see
    /// a consistent (generation, Arc) pair. Must be called from a non-async
    /// context or inside a scoped block (MutexGuard is !Send).
    pub(crate) fn swap_message_semaphore(&self, permits: usize) {
        let mut guard = match self.message_processing_semaphore.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Arc::new(async_lock::Semaphore::new(permits));
        self.message_semaphore_generation
            .fetch_add(1, Ordering::SeqCst);
    }

    fn should_downgrade_sync_error(&self, err: &anyhow::Error) -> bool {
        if self.is_shutting_down() {
            return true;
        }

        matches!(
            err.downcast_ref::<crate::request::IqError>(),
            Some(
                crate::request::IqError::NotConnected
                    | crate::request::IqError::InternalChannelClosed
            )
        )
    }

    /// Log a sync error, downgrading to debug level during shutdown/disconnect.
    fn log_sync_error(&self, context: &str, err: &anyhow::Error) {
        if self.should_downgrade_sync_error(err) {
            debug!("Skipping {context} during shutdown: {err}");
        } else {
            warn!("Failed {context}: {err}");
        }
    }

    /// Returns `true` when the client has completed its full startup:
    /// transport connected, server authenticated, and critical app state synced.
    /// This is the condition `wait_for_connected` uses to resolve.
    fn is_fully_ready(&self) -> bool {
        self.is_connected() && self.is_logged_in() && self.is_ready.load(Ordering::Relaxed)
    }

    /// Dispatch the Connected event and notify waiters.
    fn dispatch_connected(&self) {
        self.is_ready.store(true, Ordering::Relaxed);
        self.core
            .event_bus
            .dispatch(Event::Connected(crate::types::events::Connected));
        self.connected_notifier.notify(usize::MAX);
    }

    /// Enable or disable skipping of history sync notifications at runtime.
    ///
    /// When enabled, the client will acknowledge incoming history sync
    /// notifications but will not download or process the data.
    pub fn set_skip_history_sync(&self, enabled: bool) {
        self.skip_history_sync.store(enabled, Ordering::Relaxed);
    }

    /// Public entry point for processing [`MajorSyncTask`] from the sync channel.
    pub async fn process_sync_task(self: &Arc<Self>, task: crate::sync_task::MajorSyncTask) {
        match task {
            crate::sync_task::MajorSyncTask::HistorySync {
                message_id,
                notification,
            } => {
                self.process_history_sync_task(message_id, *notification)
                    .await;
                self.finish_history_sync_task();
            }
            crate::sync_task::MajorSyncTask::AppStateSync { name, full_sync } => {
                if let Err(e) = self.process_app_state_sync_task(name, full_sync).await {
                    log::warn!("App state sync task for {name:?} failed: {e}");
                }
            }
        }
    }

    /// Returns `true` if history sync notifications are currently being skipped.
    pub fn skip_history_sync_enabled(&self) -> bool {
        self.skip_history_sync.load(Ordering::Relaxed)
    }

    pub(crate) fn is_shutting_down(&self) -> bool {
        self.expected_disconnect.load(Ordering::Relaxed) || !self.is_running.load(Ordering::Relaxed)
    }

    /// Create a new `Client` with default cache configuration.
    ///
    /// This is the standard constructor. Use [`Client::new_with_cache_config`]
    /// if you need to customise cache TTL / capacity.
    pub async fn new(
        runtime: Arc<dyn Runtime>,
        persistence_manager: Arc<PersistenceManager>,
        transport_factory: Arc<dyn crate::transport::TransportFactory>,
        http_client: Arc<dyn crate::http::HttpClient>,
        override_version: Option<(u32, u32, u32)>,
    ) -> (Arc<Self>, async_channel::Receiver<MajorSyncTask>) {
        Self::new_with_cache_config(
            runtime,
            persistence_manager,
            transport_factory,
            http_client,
            override_version,
            CacheConfig::default(),
        )
        .await
    }

    /// Create a new `Client` with a custom [`CacheConfig`].
    pub async fn new_with_cache_config(
        runtime: Arc<dyn Runtime>,
        persistence_manager: Arc<PersistenceManager>,
        transport_factory: Arc<dyn crate::transport::TransportFactory>,
        http_client: Arc<dyn crate::http::HttpClient>,
        override_version: Option<(u32, u32, u32)>,
        cache_config: CacheConfig,
    ) -> (Arc<Self>, async_channel::Receiver<MajorSyncTask>) {
        let mut unique_id_bytes = [0u8; 2];
        rand::make_rng::<rand::rngs::StdRng>().fill_bytes(&mut unique_id_bytes);

        let device_snapshot = persistence_manager.get_device_snapshot().await;
        let core = wacore::client::CoreClient::new(device_snapshot.core.clone());

        let (tx, rx) = async_channel::bounded(32);

        let this = Self {
            runtime: runtime.clone(),
            core,
            persistence_manager: persistence_manager.clone(),
            media_conn: Arc::new(RwLock::new(None)),
            is_logged_in: Arc::new(AtomicBool::new(false)),
            is_connecting: Arc::new(AtomicBool::new(false)),
            is_running: Arc::new(AtomicBool::new(false)),
            is_connected: Arc::new(AtomicBool::new(false)),
            shutdown_notifier: wacore::runtime::ShutdownNotifier::new(),
            connection_shutdown: std::sync::Mutex::new(wacore::runtime::ShutdownNotifier::new()),
            last_data_received_ms: Arc::new(AtomicU64::new(0)),
            last_data_sent_ms: Arc::new(AtomicU64::new(0)),

            transport: Arc::new(Mutex::new(None)),
            transport_events: Arc::new(Mutex::new(None)),
            transport_factory,
            noise_socket: Arc::new(Mutex::new(None)),

            response_waiters: Arc::new(Mutex::new(HashMap::new())),
            node_waiters: std::sync::Mutex::new(Vec::new()),
            node_waiter_count: AtomicUsize::new(0),
            sent_node_waiters: std::sync::Mutex::new(Vec::new()),
            sent_node_waiter_count: AtomicUsize::new(0),
            unique_id: format!("{}.{}", unique_id_bytes[0], unique_id_bytes[1]),
            id_counter: Arc::new(AtomicU64::new(0)),
            unified_session: crate::unified_session::UnifiedSessionManager::new(),

            signal_cache: Arc::new(crate::store::signal_cache::SignalStoreCache::new()),
            message_processing_semaphore: std::sync::Mutex::new(Arc::new(
                async_lock::Semaphore::new(1),
            )),
            message_semaphore_generation: Arc::new(AtomicU64::new(0)),
            // Coordination caches: capacity-only eviction, no TTL/TTI.
            // These hold live mutexes and channel senders; time-based eviction
            // while tasks hold references would silently break serialisation.
            session_locks: Cache::builder()
                .max_capacity(cache_config.session_locks_capacity.max(1))
                .build(),
            chat_lanes: Cache::builder()
                .max_capacity(cache_config.chat_lanes_capacity.max(1))
                .build(),
            lid_pn_cache: Arc::new(LidPnCache::with_config(
                &cache_config.lid_pn_cache,
                cache_config.cache_stores.lid_pn_cache.clone(),
            )),
            ab_props: Arc::new(wacore::store::ab_props::AbPropsCache::new()),
            group_cache: async_lock::Mutex::new(None),

            expected_disconnect: Arc::new(AtomicBool::new(false)),
            intentional_reconnect: AtomicBool::new(false),
            connection_generation: Arc::new(AtomicU64::new(0)),

            recent_messages: cache_config.recent_messages.build_with_ttl(),

            sender_key_device_cache: crate::sender_key_device_cache::SenderKeyDeviceCache::new(
                &cache_config.sender_key_devices_cache,
            ),

            pending_device_sync: crate::pending_device_sync::PendingDeviceSync::new(),

            pending_retries: Arc::new(std::sync::Mutex::new(HashSet::new())),

            message_retry_counts: cache_config.message_retry_counts.build_with_ttl(),

            offline_sync_metrics: Arc::new(OfflineSyncMetrics {
                active: AtomicBool::new(false),
                total_messages: AtomicUsize::new(0),
                processed_messages: AtomicUsize::new(0),
                start_time: std::sync::Mutex::new(None),
            }),

            enable_auto_reconnect: Arc::new(AtomicBool::new(true)),
            auto_reconnect_errors: Arc::new(AtomicU32::new(0)),

            needs_initial_full_sync: Arc::new(AtomicBool::new(false)),

            app_state_processor: async_lock::Mutex::new(None),
            app_state_key_requests: Arc::new(Mutex::new(HashMap::new())),
            app_state_syncing: Arc::new(Mutex::new(HashSet::new())),
            initial_keys_synced_notifier: Arc::new(event_listener::Event::new()),
            initial_app_state_keys_received: Arc::new(AtomicBool::new(false)),
            prekey_upload_lock: Arc::new(async_lock::Mutex::new(())),
            offline_sync_notifier: Arc::new(event_listener::Event::new()),
            offline_sync_completed: Arc::new(AtomicBool::new(false)),
            history_sync_tasks_in_flight: Arc::new(AtomicUsize::new(0)),
            history_sync_idle_notifier: Arc::new(event_listener::Event::new()),
            outbound_flush: Arc::new(crate::flush_scope::FlushScope::new()),
            presence_subscriptions: Arc::new(async_lock::Mutex::new(HashSet::new())),
            socket_ready_notifier: Arc::new(event_listener::Event::new()),
            is_ready: Arc::new(AtomicBool::new(false)),
            connected_notifier: Arc::new(event_listener::Event::new()),
            major_sync_task_sender: tx,
            pairing_cancellation_tx: Arc::new(Mutex::new(None)),
            pair_code_state: Arc::new(Mutex::new(wacore::pair_code::PairCodeState::default())),
            custom_enc_handlers: Arc::new(async_lock::RwLock::new(HashMap::new())),
            chatstate_handlers: Arc::new(RwLock::new(Vec::new())),
            pdo_pending_requests: cache_config.pdo_pending_requests.build_with_ttl(),
            device_registry_cache: cache_config.device_registry_cache.build_typed_ttl(
                cache_config.cache_stores.device_registry_cache.clone(),
                "device_registry",
            ),
            stanza_router: Self::create_stanza_router(),
            synchronous_ack: false,
            http_client,
            override_version,
            skip_history_sync: AtomicBool::new(false),
            cache_config,
            self_weak: std::sync::OnceLock::new(),
            saver_handle: std::sync::OnceLock::new(),
            raw_node_forwarding: AtomicBool::new(false),
        };

        let arc = Arc::new(this);
        let _ = arc.self_weak.set(Arc::downgrade(&arc));

        // Warm up the LID-PN cache from persistent storage
        let warm_up_arc = arc.clone();
        arc.runtime
            .spawn(Box::pin(async move {
                if let Err(e) = warm_up_arc.warm_up_lid_pn_cache().await {
                    warn!("Failed to warm up LID-PN cache: {e}");
                }
            }))
            .detach();

        // Start background task to clean up stale device registry entries
        let cleanup_arc = arc.clone();
        arc.runtime
            .spawn(Box::pin(async move {
                cleanup_arc.device_registry_cleanup_loop().await;
            }))
            .detach();

        (arc, rx)
    }

    pub(crate) async fn get_group_cache(&self) -> Arc<TypedCache<Jid, GroupInfo>> {
        let mut guard = self.group_cache.lock().await;
        if let Some(cache) = guard.as_ref() {
            return cache.clone();
        }
        debug!("Initializing Group Cache for the first time.");
        let cache = Arc::new(
            self.cache_config
                .group_cache
                .build_typed_ttl(self.cache_config.cache_stores.group_cache.clone(), "group"),
        );
        *guard = Some(cache.clone());
        cache
    }

    pub(crate) async fn get_app_state_processor(&self) -> Arc<AppStateProcessor> {
        let mut guard = self.app_state_processor.lock().await;
        if let Some(proc) = guard.as_ref() {
            return proc.clone();
        }
        debug!("Initializing AppStateProcessor for the first time.");
        let proc = Arc::new(AppStateProcessor::new(
            self.persistence_manager.backend(),
            self.runtime.clone(),
        ));
        *guard = Some(proc.clone());
        proc
    }

    /// Create and configure the stanza router with all the handlers.
    fn create_stanza_router() -> crate::handlers::router::StanzaRouter {
        use crate::handlers::{
            basic::{AckHandler, FailureHandler, StreamErrorHandler, SuccessHandler},
            chatstate::ChatstateHandler,
            ib::IbHandler,
            iq::IqHandler,
            message::MessageHandler,
            notification::NotificationHandler,
            receipt::ReceiptHandler,
            router::StanzaRouter,
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
        router.register(Arc::new(ChatstateHandler));

        router.register(Arc::new(crate::handlers::call::CallHandler));

        // Register unimplemented handlers
        router.register(Arc::new(crate::handlers::presence::PresenceHandler));

        router
    }

    /// Registers an external event handler to the core event bus.
    pub fn register_handler(&self, handler: Arc<dyn wacore::types::events::EventHandler>) {
        self.core.event_bus.add_handler(handler);
    }

    /// Enable or disable raw node forwarding.
    /// When enabled, `Event::RawNode` is emitted for every decoded stanza before
    /// the stanza router dispatches it. Only enable when external consumers need
    /// raw protocol access (e.g. voice call stanzas).
    pub fn set_raw_node_forwarding(&self, enabled: bool) {
        self.raw_node_forwarding.store(enabled, Ordering::Relaxed);
    }

    /// Build a [`SignalProtocolStoreAdapter`] from the current device state and signal cache.
    pub(crate) async fn signal_adapter(
        &self,
    ) -> crate::store::signal_adapter::SignalProtocolStoreAdapter {
        let device_store = self.persistence_manager.get_device_arc().await;
        self.signal_adapter_from(device_store)
    }

    /// Build a [`SignalProtocolStoreAdapter`] from a pre-fetched device arc.
    pub(crate) fn signal_adapter_from(
        &self,
        device_store: Arc<async_lock::RwLock<crate::store::Device>>,
    ) -> crate::store::signal_adapter::SignalProtocolStoreAdapter {
        crate::store::signal_adapter::SignalProtocolStoreAdapter::new(
            device_store,
            self.signal_cache.clone(),
        )
    }

    /// Get the per-address session mutex from the lock cache.
    pub(crate) async fn session_lock_for(
        &self,
        signal_addr_str: &str,
    ) -> Arc<async_lock::Mutex<()>> {
        self.session_locks
            .get_with_by_ref(signal_addr_str, async {
                Arc::new(async_lock::Mutex::new(()))
            })
            .await
    }

    /// Get the active noise socket, or error if not connected.
    pub(crate) async fn get_noise_socket(
        &self,
    ) -> Result<Arc<crate::socket::noise_socket::NoiseSocket>, ClientError> {
        self.noise_socket
            .lock()
            .await
            .clone()
            .ok_or(ClientError::NotConnected)
    }

    /// Send pre-marshaled plaintext bytes through the noise socket.
    ///
    /// The bytes must be a valid WABinary-marshaled stanza (as produced by
    /// `wacore_binary::marshal::marshal_to`). Sending malformed data will
    /// cause the server to close the connection.
    ///
    /// This bypasses node logging and `sent_node_waiter` resolution — use
    /// [`send_node`](Client::send_node) for normal stanza sending.
    pub async fn send_raw_bytes(&self, plaintext: Vec<u8>) -> Result<(), ClientError> {
        let noise_socket = self.get_noise_socket().await?;
        noise_socket
            .encrypt_and_send(bytes::Bytes::from(plaintext))
            .await?;
        self.last_data_sent_ms
            .store(wacore::time::now_millis().max(0) as u64, Ordering::Relaxed);
        Ok(())
    }

    /// Register a chatstate handler which will be invoked when a `<chatstate>` stanza is received.
    ///
    /// The handler receives a `ChatStateEvent` with the parsed chat state information.
    pub async fn register_chatstate_handler(
        &self,
        handler: Arc<dyn Fn(ChatStateEvent) + Send + Sync>,
    ) {
        self.chatstate_handlers.write().await.push(handler);
    }

    /// Dispatch a parsed chatstate stanza to registered handlers.
    ///
    /// Called by `ChatstateHandler` after parsing the incoming stanza.
    pub(crate) async fn dispatch_chatstate_event(
        &self,
        stanza: wacore::iq::chatstate::ChatstateStanza,
    ) {
        use wacore::iq::chatstate::{ChatstateSource, ReceivedChatState};
        use wacore::types::events::ChatPresenceUpdate;
        use wacore::types::message::MessageSource;
        use wacore::types::presence::{ChatPresence, ChatPresenceMedia};

        // Dispatch via event bus
        let (chat, sender, is_group) = match &stanza.source {
            ChatstateSource::User { from } => (from.clone(), from.clone(), false),
            ChatstateSource::Group { from, participant } => {
                (from.clone(), participant.clone(), true)
            }
        };

        let (state, media) = match stanza.state {
            ReceivedChatState::Typing => (ChatPresence::Composing, ChatPresenceMedia::Text),
            ReceivedChatState::RecordingAudio => {
                (ChatPresence::Composing, ChatPresenceMedia::Audio)
            }
            ReceivedChatState::Idle => (ChatPresence::Paused, ChatPresenceMedia::Text),
        };

        self.core
            .event_bus
            .dispatch(Event::ChatPresence(ChatPresenceUpdate {
                source: MessageSource {
                    chat,
                    sender,
                    is_from_me: false,
                    is_group,
                    addressing_mode: None,
                    sender_alt: None,
                    recipient_alt: None,
                    broadcast_list_owner: None,
                    recipient: None,
                },
                state,
                media,
            }));

        // Invoke legacy callback handlers
        let event = ChatStateEvent::from_stanza(stanza);
        let handlers = self.chatstate_handlers.read().await.clone();
        for handler in handlers {
            let event_clone = event.clone();
            self.runtime
                .spawn(Box::pin(async move {
                    (handler)(event_clone);
                }))
                .detach();
        }
    }

    pub async fn run(self: &Arc<Self>) {
        if self.is_running.swap(true, Ordering::SeqCst) {
            warn!("Client `run` method called while already running.");
            return;
        }
        while self.is_running.load(Ordering::Relaxed) {
            self.expected_disconnect.store(false, Ordering::Relaxed);

            if let Err(connect_err) = self.connect().await {
                let is_transient = connect_err
                    .downcast_ref::<crate::handshake::HandshakeError>()
                    .is_some_and(|e| e.is_transient());
                if is_transient {
                    debug!("Transient connect failure, will retry: {connect_err:#}");
                } else {
                    error!("Failed to connect: {connect_err:#}. Will retry...");
                }
            } else {
                let unexpected_disconnect = if self.read_messages_loop().await.is_err() {
                    // Check intentional_reconnect AFTER read loop exits — reconnect()
                    // sets this flag while the loop is running, so it must be read here.
                    if self.expected_disconnect.load(Ordering::Relaxed)
                        || self.intentional_reconnect.swap(false, Ordering::Relaxed)
                    {
                        debug!("Message loop exited during expected disconnect.");
                        false
                    } else {
                        warn!(
                            "Message loop exited with an error. Will attempt to reconnect if enabled."
                        );
                        true
                    }
                } else if self.expected_disconnect.load(Ordering::Relaxed) {
                    debug!("Message loop exited gracefully (expected disconnect).");
                    false
                } else {
                    info!("Message loop exited gracefully.");
                    false
                };

                self.cleanup_connection_state().await;

                // Dispatch after cleanup so handlers see cleared connection state.
                if unexpected_disconnect {
                    self.core
                        .event_bus
                        .dispatch(Event::Disconnected(crate::types::events::Disconnected));
                }
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
            // WA Web: Fibonacci backoff with 10% jitter, max 900s.
            // algo: { type: "fibonacci", first: 1000, second: 1000 }
            // jitter: 0.1, max: 9e5
            let delay = fibonacci_backoff(error_count);
            info!(
                "Will attempt to reconnect in {:?} (attempt {})",
                delay,
                error_count + 1
            );
            self.runtime.sleep(delay).await;
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
        self.is_ready.store(false, Ordering::Relaxed);
        self.is_connected.store(false, Ordering::Relaxed);
        self.offline_sync_completed.store(false, Ordering::Relaxed);

        // WA Web: both MQTT and DGW transports use a 20s connect timeout.
        // Without this, a dead network blocks on the OS TCP SYN timeout (~60-75s).
        // Version fetch is also wrapped so a hung HTTP request doesn't block connect().
        let version_future = rt_timeout(
            &*self.runtime,
            TRANSPORT_CONNECT_TIMEOUT,
            crate::version::resolve_and_update_version(
                &self.persistence_manager,
                &self.http_client,
                self.override_version,
            ),
        );
        let transport_future = rt_timeout(
            &*self.runtime,
            TRANSPORT_CONNECT_TIMEOUT,
            self.transport_factory.create_transport(),
        );

        debug!("Connecting WebSocket and fetching latest client version in parallel...");
        let (version_result, transport_result) = futures::join!(version_future, transport_future);

        version_result
            .map_err(|_| anyhow!("Version fetch timed out after {TRANSPORT_CONNECT_TIMEOUT:?}"))?
            .map_err(|e| anyhow!("Failed to resolve app version: {}", e))?;
        let (transport, mut transport_events) = transport_result.map_err(|_| {
            anyhow!("Transport connect timed out after {TRANSPORT_CONNECT_TIMEOUT:?}")
        })??;
        debug!("Version fetch and transport connection established.");

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        let noise_socket = match handshake::do_handshake(
            self.runtime.clone(),
            &device_snapshot,
            transport.clone(),
            &mut transport_events,
        )
        .await
        {
            Ok(socket) => socket,
            Err(e) => {
                transport.disconnect().await;
                return Err(e.into());
            }
        };

        // Fresh per-connection shutdown so subscribers registered during this
        // connection see a clean signal; the previous notifier was already
        // fired on the prior cleanup_connection_state.
        self.reset_connection_shutdown();

        *self.transport.lock().await = Some(transport);
        *self.transport_events.lock().await = Some(transport_events);
        *self.noise_socket.lock().await = Some(noise_socket);
        self.is_connected.store(true, Ordering::Release);

        // Notify waiters that socket is ready (before login)
        self.socket_ready_notifier.notify(usize::MAX);

        let client_clone = self.clone();
        self.runtime
            .spawn(Box::pin(async move { client_clone.keepalive_loop().await }))
            .detach();

        Ok(())
    }

    /// Deregister this companion device and disconnect.
    /// Does NOT wipe stored keys. Delete the storage backend to fully clear credentials.
    pub async fn logout(self: &Arc<Self>) -> Result<()> {
        use wacore::iq::devices::RemoveCompanionDeviceSpec;

        self.enable_auto_reconnect.store(false, Ordering::Relaxed);

        if self.is_connected()
            && let Ok(jid) = self.require_pn().await
            && let Err(e) = self.execute(RemoveCompanionDeviceSpec::new(&jid)).await
        {
            warn!("Failed to send logout IQ: {e}");
        }

        self.disconnect().await;

        self.core
            .event_bus
            .dispatch(Event::LoggedOut(crate::types::events::LoggedOut {
                on_connect: false,
                reason: ConnectFailureReason::LoggedOut,
            }));

        Ok(())
    }

    pub async fn disconnect(self: &Arc<Self>) {
        use wacore::time::Instant;

        info!("Disconnecting client intentionally.");
        let t_total = Instant::now();

        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.is_running.store(false, Ordering::Relaxed);
        self.shutdown_notifier.notify();
        // Stop the read loop first so no new stanzas enter the pipeline while
        // we're flushing receipts (issue #571).
        self.notify_connection_shutdown();

        let t = Instant::now();
        self.outbound_flush
            .flush(&*self.runtime, std::time::Duration::from_secs(5))
            .await;
        log::debug!(target: "Client/Disconnect", "outbound_flush drained in {:?}", t.elapsed());

        let t = Instant::now();
        if let Err(e) = self.persistence_manager.flush().await {
            log::error!("Failed to flush device state during disconnect: {e}");
        }
        log::debug!(target: "Client/Disconnect", "persistence flushed in {:?}", t.elapsed());

        let t = Instant::now();
        if let Some(transport) = self.transport.lock().await.as_ref() {
            log::debug!(target: "Client/Disconnect", "transport lock acquired in {:?}", t.elapsed());
            let t_d = Instant::now();
            transport.disconnect().await;
            log::debug!(target: "Client/Disconnect", "transport.disconnect() returned in {:?}", t_d.elapsed());
        } else {
            log::debug!(target: "Client/Disconnect", "no transport present (lock in {:?})", t.elapsed());
        }

        let t = Instant::now();
        self.cleanup_connection_state().await;
        log::debug!(target: "Client/Disconnect", "cleanup_connection_state in {:?}", t.elapsed());

        log::debug!(target: "Client/Disconnect", "disconnect complete in {:?}", t_total.elapsed());
    }

    /// Backoff step used by [`reconnect()`] to create an offline window.
    ///
    /// `fibonacci_backoff(RECONNECT_BACKOFF_STEP)` determines the delay before
    /// the run loop re-connects.  This must be longer than the mock server's
    /// chatstate TTL (`CHATSTATE_TTL_SECS=3`) so TTL-expiry tests pass.
    ///
    /// Sequence: fib(0)=1s, fib(1)=1s, fib(2)=2s, fib(3)=3s, **fib(4)=5s**.
    pub const RECONNECT_BACKOFF_STEP: u32 = 4;

    /// Drop the current connection and trigger the auto-reconnect loop.
    ///
    /// Unlike [`disconnect`], this does **not** stop the run loop. The client
    /// will reconnect automatically using the same persisted identity/store,
    /// just as it would after a network interruption. Use
    /// [`wait_for_connected`] to wait for the new connection to be ready.
    ///
    /// This is useful for:
    /// - Handling network changes (e.g., Wi-Fi → cellular)
    /// - Forcing a fresh server session
    /// - Testing offline message delivery
    pub async fn reconnect(self: &Arc<Self>) {
        use wacore::time::Instant;

        info!("Reconnecting: dropping transport for auto-reconnect.");
        let t_total = Instant::now();

        self.intentional_reconnect.store(true, Ordering::Relaxed);
        self.auto_reconnect_errors
            .store(Self::RECONNECT_BACKOFF_STEP, Ordering::Relaxed);
        self.notify_connection_shutdown();

        let t = Instant::now();
        self.outbound_flush
            .flush(&*self.runtime, std::time::Duration::from_secs(2))
            .await;
        log::debug!(target: "Client/Reconnect", "outbound_flush drained in {:?}", t.elapsed());

        let t = Instant::now();
        if let Some(transport) = self.transport.lock().await.as_ref() {
            log::debug!(target: "Client/Reconnect", "transport lock acquired in {:?}", t.elapsed());
            let t_d = Instant::now();
            transport.disconnect().await;
            log::debug!(target: "Client/Reconnect", "transport.disconnect() returned in {:?}", t_d.elapsed());
        }

        log::debug!(target: "Client/Reconnect", "reconnect teardown complete in {:?}", t_total.elapsed());
    }

    /// Drop the current connection and reconnect immediately with no delay.
    ///
    /// Unlike [`reconnect`], which introduces a deliberate offline window,
    /// this method sets the `expected_disconnect` flag so the run loop
    /// skips the backoff delay and reconnects as fast as possible.
    pub async fn reconnect_immediately(self: &Arc<Self>) {
        use wacore::time::Instant;

        info!("Reconnecting immediately (expected disconnect).");
        let t_total = Instant::now();

        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.notify_connection_shutdown();

        let t = Instant::now();
        self.outbound_flush
            .flush(&*self.runtime, std::time::Duration::from_secs(2))
            .await;
        log::debug!(target: "Client/Reconnect", "outbound_flush drained in {:?}", t.elapsed());

        let t = Instant::now();
        if let Some(transport) = self.transport.lock().await.as_ref() {
            log::debug!(target: "Client/Reconnect", "transport lock acquired in {:?}", t.elapsed());
            let t_d = Instant::now();
            transport.disconnect().await;
            log::debug!(target: "Client/Reconnect", "transport.disconnect() returned in {:?}", t_d.elapsed());
        }

        log::debug!(target: "Client/Reconnect", "reconnect_immediately teardown complete in {:?}", t_total.elapsed());
    }

    async fn cleanup_connection_state(&self) {
        // Note: node_waiters are intentionally NOT cleared here — they are
        // cross-connection (callers may register a waiter before an action that
        // completes on a subsequent connection, e.g. after 515 reconnect).
        // sent_node_waiters ARE cleared because they match pre-encryption
        // outgoing stanzas, which are transport-scoped.
        self.clear_sent_node_waiters();
        self.is_logged_in.store(false, Ordering::Relaxed);
        self.is_ready.store(false, Ordering::Relaxed);
        // Signal the keepalive loop (and any other per-connection tasks) to
        // exit promptly. Without this, a stale keepalive loop can overlap
        // with the next one after reconnect. Uses the PER-CONNECTION signal
        // so the terminal shutdown_notifier stays clean for reconnects.
        self.notify_connection_shutdown();
        // Take + disconnect the transport so the underlying socket is closed
        // even when cleanup_connection_state runs on a path other than
        // `Client::disconnect()` (e.g. the run loop calling this after
        // graceful message-loop exit triggered by the shutdown signal).
        // Without this, a concurrent user-initiated disconnect can race the
        // run loop: run loop wins, clears transport to None, user's
        // `disconnect()` then sees None and skips transport teardown,
        // leaving the socket un-closed (observed empirically with 3+
        // concurrent `disconnect()` calls on a single-threaded executor).
        // `transport.disconnect()` is expected to be idempotent so it's fine
        // if `Client::disconnect()` also calls it on the same transport.
        if let Some(transport) = self.transport.lock().await.take() {
            transport.disconnect().await;
        }
        *self.transport_events.lock().await = None;
        *self.noise_socket.lock().await = None;
        // Clear is_connected AFTER noise_socket is None, so no task can see
        // is_connected==true with a cleared socket. send_node() independently
        // checks the socket, but this ordering avoids a confusing state window.
        self.is_connected.store(false, Ordering::Release);
        // Drop per-chat lanes so workers exit via channel close.
        self.chat_lanes.invalidate_all();
        // Clear pending retries so stale keys from detached scopeguard
        // cleanup don't suppress the first retry after reconnect.
        self.pending_retries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clear();
        // Clear signal cache so stale state doesn't leak across connections
        self.signal_cache.clear().await;
        // Reset semaphore to 1 permit for next offline sync.
        self.swap_message_semaphore(1);
        // Reset dead-socket timestamps so stale values from the previous
        // connection don't trigger an immediate reconnect on the next one.
        self.last_data_received_ms.store(0, Ordering::Relaxed);
        self.last_data_sent_ms.store(0, Ordering::Relaxed);
        self.pending_device_sync.clear().await;
        // Reset offline sync state for next connection
        self.offline_sync_completed.store(false, Ordering::Relaxed);
        self.offline_sync_metrics
            .active
            .store(false, Ordering::Release);
        self.offline_sync_metrics
            .total_messages
            .store(0, Ordering::Release);
        self.offline_sync_metrics
            .processed_messages
            .store(0, Ordering::Release);
        match self.offline_sync_metrics.start_time.lock() {
            Ok(mut guard) => *guard = None,
            Err(poison) => *poison.into_inner() = None,
        }
        self.history_sync_tasks_in_flight
            .store(0, Ordering::Relaxed);
        self.history_sync_idle_notifier.notify(usize::MAX);
        // Drain all pending IQ waiters so they fail fast with InternalChannelClosed
        // instead of hanging until the 75s timeout.
        let mut waiters_map = self.response_waiters.lock().await;
        let waiter_count = waiters_map.len();
        // Replace with new map to release backing storage; old senders drop here,
        // causing receivers to get RecvError → IqError::InternalChannelClosed
        *waiters_map = HashMap::new();
        drop(waiters_map);
        if waiter_count > 0 {
            debug!(
                "Dropping {} orphaned IQ response waiter(s) on disconnect",
                waiter_count
            );
        }

        // Clear app state tracking maps to prevent unbounded growth across reconnections.
        // Replace with new collections to release backing storage.
        *self.app_state_key_requests.lock().await = HashMap::new();
        *self.app_state_syncing.lock().await = HashSet::new();

        // Drop stale media connection (auth tokens become invalid on reconnect)
        *self.media_conn.write().await = None;

        // Clear app state key cache — keys will be re-fetched from DB on demand
        if let Some(proc) = self.app_state_processor.lock().await.as_ref() {
            proc.clear_key_cache().await;
        }
    }

    /// Returns a snapshot of all internal collection sizes for memory leak detection.
    ///
    /// Moka caches report approximate counts (pending evictions may not be reflected).
    /// Call `run_pending_tasks()` on individual caches first if you need exact counts.
    ///
    /// Requires the `debug-diagnostics` feature.
    #[cfg(feature = "debug-diagnostics")]
    pub async fn memory_diagnostics(&self) -> MemoryDiagnostics {
        let (sig_sessions, sig_identities, sig_sender_keys) =
            self.signal_cache.entry_counts().await;
        let (lid_lid, lid_pn) = self.lid_pn_cache.entry_counts();
        let pending_retries_count = self
            .pending_retries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len();

        MemoryDiagnostics {
            group_cache: self
                .group_cache
                .lock()
                .await
                .as_ref()
                .map_or(0, |c| c.entry_count()),
            device_registry_cache: self.device_registry_cache.entry_count(),
            lid_pn_lid_entries: lid_lid,
            lid_pn_pn_entries: lid_pn,
            recent_messages: self.recent_messages.entry_count(),
            sender_key_device_cache: self.sender_key_device_cache.entry_count(),
            message_retry_counts: self.message_retry_counts.entry_count(),
            pdo_pending_requests: self.pdo_pending_requests.entry_count(),
            session_locks: self.session_locks.entry_count(),
            chat_lanes: self.chat_lanes.entry_count(),
            response_waiters: self.response_waiters.lock().await.len(),
            node_waiters: self.node_waiter_count.load(Ordering::Relaxed),
            pending_retries: pending_retries_count,
            presence_subscriptions: self.presence_subscriptions.lock().await.len(),
            app_state_key_requests: self.app_state_key_requests.lock().await.len(),
            app_state_syncing: self.app_state_syncing.lock().await.len(),
            signal_cache_sessions: sig_sessions,
            signal_cache_identities: sig_identities,
            signal_cache_sender_keys: sig_sender_keys,
            chatstate_handlers: self.chatstate_handlers.read().await.len(),
            custom_enc_handlers: self.custom_enc_handlers.read().await.len(),
        }
    }

    /// Flush the in-memory signal cache to the database backend.
    /// Called after each message is decrypted or after encryption operations.
    pub(crate) async fn flush_signal_cache(&self) -> Result<(), anyhow::Error> {
        let device = self.persistence_manager.get_device_arc().await;
        let device_guard = device.read().await;
        self.signal_cache
            .flush(&*device_guard.backend)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to flush signal cache: {e}"))
    }

    /// [`flush_signal_cache`](Self::flush_signal_cache) with error logging instead of propagation.
    pub(crate) async fn flush_signal_cache_logged(&self, context: &str, id: Option<&str>) {
        if let Err(e) = self.flush_signal_cache().await {
            if let Some(id) = id {
                log::error!("Failed to flush signal cache ({context} {id}): {e:?}");
            } else {
                log::error!("Failed to flush signal cache ({context}): {e:?}");
            }
        }
    }

    async fn read_messages_loop(self: &Arc<Self>) -> Result<(), anyhow::Error> {
        debug!("Starting message processing loop...");

        let mut rx_guard = self.transport_events.lock().await;
        let transport_events = rx_guard
            .take()
            .ok_or_else(|| anyhow::anyhow!("Cannot start message loop: not connected"))?;
        drop(rx_guard);

        // Frame decoder to parse incoming data
        let mut frame_decoder = wacore::framing::FrameDecoder::new();
        let shutdown = self.connection_shutdown_signal();

        loop {
            futures::select_biased! {
                    _ = wacore::runtime::wait_for_shutdown(&shutdown).fuse() => {
                        debug!("Shutdown signaled in message loop. Exiting message loop.");
                        return Ok(());
                    },
                    event_result = transport_events.recv().fuse() => {
                        match event_result {
                            Ok(crate::transport::TransportEvent::DataReceived(data)) => {
                                // Update dead-socket timer (WA Web: deadSocketTimer reset)
                                self.last_data_received_ms.store(
                                    wacore::time::now_millis().max(0) as u64,
                                    Ordering::Relaxed,
                                );

                                // Feed data into the frame decoder
                                frame_decoder.feed(&data);

                                // Process all complete frames.
                                // Frame decryption must be sequential (noise protocol counter),
                                // but we spawn node processing concurrently after decryption.
                                let mut frames_in_batch: u32 = 0;

                                while let Some(encrypted_frame) = frame_decoder.decode_frame() {
                                    // Decrypt the frame synchronously (required for noise counter ordering)
                                    if let Some(node) = self.decrypt_frame(encrypted_frame).await {
                                        // Determine processing mode for this node:
                                        // - Critical nodes (success/failure/stream:error): inline, required for state
                                        // - Message nodes: inline, preserves arrival order for per-chat queues
                                        //   (MessageHandler just enqueues + ACKs, heavy crypto runs in workers)
                                        // - ib (in-band): inline, ensures offline sync tracking (expected count)
                                        //   is set up before offline messages are processed
                                        // - Everything else: spawned concurrently for parallelism
                                        let process_inline = matches!(
                                            node.tag(),
                                            "success" | "failure" | "stream:error" | "message" | "ib"
                                        );

                                        if process_inline {
                                            self.process_decrypted_node(node).await;
                                        } else {
                                            let client = self.clone();
                                            self.runtime.spawn(Box::pin(async move {
                                                client.process_decrypted_node(node).await;
                                            })).detach();
                                        }
                                    }

                                    // Check if we should exit after processing (e.g., after 515 stream error)
                                    if self.expected_disconnect.load(Ordering::Relaxed) {
                                        debug!("Expected disconnect signaled during frame processing. Exiting message loop.");
                                        return Ok(());
                                    }

                                    // Cooperative yield — frequency and behavior are runtime-defined.
                                    frames_in_batch += 1;
                                    if frames_in_batch.is_multiple_of(self.runtime.yield_frequency())
                                        && let Some(yield_fut) = self.runtime.yield_now()
                                    {
                                        yield_fut.await;
                                    }
                                }

                                // Refresh timestamp after processing the entire batch so
                                // the keepalive loop sees the batch completion time, not
                                // just the arrival time. Prevents stale reads when a
                                // large batch (e.g. offline sync) takes seconds to drain.
                                if frames_in_batch > 1 {
                                    self.last_data_received_ms.store(
                                        wacore::time::now_millis().max(0) as u64,
                                        Ordering::Relaxed,
                                    );
                                }
                            },
                            Ok(crate::transport::TransportEvent::Disconnected) | Err(_) => {
                                if !self.expected_disconnect.load(Ordering::Relaxed) {
                                    debug!("Transport disconnected unexpectedly.");
                                    return Err(anyhow::anyhow!("Transport disconnected unexpectedly"));
                                } else {
                                    debug!("Transport disconnected as expected.");
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

    /// Decrypt a frame and return the parsed node as a zero-copy OwnedNodeRef.
    /// This must be called sequentially due to noise protocol counter requirements.
    pub(crate) async fn decrypt_frame(
        self: &Arc<Self>,
        encrypted_frame: bytes::BytesMut,
    ) -> Option<wacore_binary::OwnedNodeRef> {
        let noise_socket = match self.get_noise_socket().await {
            Ok(s) => s,
            Err(_) => {
                log::error!("Cannot process frame: not connected (no noise socket)");
                return None;
            }
        };

        let decrypted_payload = match noise_socket.decrypt_frame(encrypted_frame) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Failed to decrypt frame: {e}");
                return None;
            }
        };

        let buffer = match wacore_binary::util::unpack_bytes(decrypted_payload) {
            Ok(data) => data,
            Err(e) => {
                log::warn!(target: "Client/Recv", "Failed to decompress frame: {e}");
                return None;
            }
        };

        match wacore_binary::OwnedNodeRef::new(buffer) {
            Ok(owned) => Some(owned),
            Err(e) => {
                log::warn!(target: "Client/Recv", "Failed to unmarshal node: {e}");
                None
            }
        }
    }

    /// Process an already-decrypted node.
    /// This can be spawned concurrently since it doesn't depend on noise protocol state.
    /// The node is wrapped in Arc to avoid cloning when passing through handlers.
    pub(crate) async fn process_decrypted_node(
        self: &Arc<Self>,
        node: wacore_binary::OwnedNodeRef,
    ) {
        // Wrap in Arc once - all handlers will share this same allocation
        let node_arc = Arc::new(node);
        self.process_node(node_arc).await;
    }

    /// Process a node wrapped in Arc. Handlers receive the Arc and can share/store it cheaply.
    pub(crate) async fn process_node(self: &Arc<Self>, node: Arc<wacore_binary::OwnedNodeRef>) {
        use wacore::xml::DisplayableNodeRef;
        let nr = node.get();

        // --- Offline Sync Tracking ---
        if nr.tag.as_ref() == "ib" {
            // Check for offline_preview child to get expected count
            if let Some(preview) = nr.get_optional_child("offline_preview") {
                let count: usize = preview
                    .get_attr("count")
                    .map(|v| v.as_str())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);

                if count == 0 {
                    self.offline_sync_metrics
                        .active
                        .store(false, Ordering::Release);
                    debug!(target: "Client/OfflineSync", "Sync COMPLETED: 0 items.");
                } else {
                    // Use stronger memory ordering for state transitions
                    self.offline_sync_metrics
                        .total_messages
                        .store(count, Ordering::Release);
                    self.offline_sync_metrics
                        .processed_messages
                        .store(0, Ordering::Release);
                    self.offline_sync_metrics
                        .active
                        .store(true, Ordering::Release);
                    match self.offline_sync_metrics.start_time.lock() {
                        Ok(mut guard) => *guard = Some(wacore::time::Instant::now()),
                        Err(poison) => *poison.into_inner() = Some(wacore::time::Instant::now()),
                    }
                    debug!(target: "Client/OfflineSync", "Sync STARTED: Expecting {} items.", count);
                }
            } else if self.offline_sync_metrics.active.load(Ordering::Acquire)
                && nr.get_optional_child("offline").is_some()
            {
                // Handle end marker: <ib><offline count="N"/> signals sync completion
                // Only <ib> with an <offline> child is a real end marker.
                // Other <ib> children (thread_metadata, edge_routing, dirty) are NOT end markers.
                let processed = self
                    .offline_sync_metrics
                    .processed_messages
                    .load(Ordering::Acquire);
                let elapsed = match self.offline_sync_metrics.start_time.lock() {
                    Ok(guard) => guard.map(|t| t.elapsed()).unwrap_or_default(),
                    Err(poison) => poison.into_inner().map(|t| t.elapsed()).unwrap_or_default(),
                };
                debug!(target: "Client/OfflineSync", "Sync COMPLETED: End marker received. Processed {} items in {:.2?}.", processed, elapsed);
                self.offline_sync_metrics
                    .active
                    .store(false, Ordering::Release);
            }
        }

        // Track progress if active
        if self.offline_sync_metrics.active.load(Ordering::Acquire) {
            // Check for 'offline' attribute on relevant stanzas
            if nr.get_attr("offline").is_some() {
                let processed = self
                    .offline_sync_metrics
                    .processed_messages
                    .fetch_add(1, Ordering::Release)
                    + 1;
                let total = self
                    .offline_sync_metrics
                    .total_messages
                    .load(Ordering::Acquire);

                if processed.is_multiple_of(50) || processed == total {
                    trace!(target: "Client/OfflineSync", "Sync Progress: {}/{}", processed, total);
                }

                if processed >= total {
                    let elapsed = match self.offline_sync_metrics.start_time.lock() {
                        Ok(guard) => guard.map(|t| t.elapsed()).unwrap_or_default(),
                        Err(poison) => poison.into_inner().map(|t| t.elapsed()).unwrap_or_default(),
                    };
                    debug!(target: "Client/OfflineSync", "Sync COMPLETED: Processed {} items in {:.2?}.", processed, elapsed);
                    self.offline_sync_metrics
                        .active
                        .store(false, Ordering::Release);
                }
            }
        }
        // --- End Tracking ---

        if nr.tag.as_ref() == "iq"
            && let Some(sync_node) = nr.get_optional_child("sync")
            && let Some(collection_node) = sync_node.get_optional_child("collection")
        {
            let name = collection_node.attrs().optional_string("name");
            let name = name.as_deref().unwrap_or("<unknown>");
            debug!(target: "Client/Recv", "Received app state sync response for '{name}' (hiding content).");
        } else {
            debug!(target: "Client/Recv","{}", DisplayableNodeRef(nr));
        }

        // Prepare deferred ACK cancellation flag (sent after dispatch unless cancelled)
        let mut cancelled = false;

        // Emit raw node before any early returns so all decoded stanzas
        // (including IQ responses and xmlstreamend) reach external observers
        if self.raw_node_forwarding.load(Ordering::Relaxed) {
            self.core
                .event_bus
                .dispatch(Event::RawNode(Arc::clone(&node)));
        }

        if nr.tag.as_ref() == "xmlstreamend" {
            if self.expected_disconnect.load(Ordering::Relaxed) {
                debug!("Received <xmlstreamend/>, expected disconnect.");
            } else {
                warn!("Received <xmlstreamend/>, treating as disconnect.");
            }
            self.notify_connection_shutdown();
            return;
        }

        // Check generic node waiters (zero-cost when none registered)
        if self.node_waiter_count.load(Ordering::Acquire) > 0 {
            self.resolve_node_waiters(&node);
        }

        if nr.tag.as_ref() == "iq"
            && let Some(id) = nr.get_attr("id").map(|v| v.as_str())
        {
            // Single lock acquisition: try to remove the waiter directly.
            let waiter = self.response_waiters.lock().await.remove(id.as_ref());
            if let Some(waiter) = waiter {
                if waiter.send(Arc::clone(&node)).is_err() {
                    warn!(target: "Client/IQ", "Failed to send IQ response to waiter. Receiver was likely dropped.");
                }
                return;
            }
        }

        // Dispatch to appropriate handler using the router
        // Clone Arc (cheap - just reference count) not the Node itself
        if !self
            .stanza_router
            .dispatch(self.clone(), Arc::clone(&node), &mut cancelled)
            .await
        {
            warn!(
                "Received unknown top-level node: {}",
                DisplayableNodeRef(nr)
            );
        }

        // Send the deferred ACK if applicable and not cancelled by handler
        if self.should_ack(nr) && !cancelled {
            self.maybe_deferred_ack(node).await;
        }
    }

    /// Determine if a node should be acknowledged with <ack/>.
    fn should_ack(&self, node: &wacore_binary::NodeRef<'_>) -> bool {
        matches!(
            node.tag.as_ref(),
            "message" | "receipt" | "notification" | "call"
        ) && node.get_attr("id").is_some()
            && node.get_attr("from").is_some()
    }

    /// Possibly send a deferred ack: either immediately or via spawned task.
    /// Handlers can cancel by setting `cancelled` to true.
    /// Uses Arc<OwnedNodeRef> to avoid cloning when spawning the async task.
    async fn maybe_deferred_ack(self: &Arc<Self>, node: Arc<wacore_binary::OwnedNodeRef>) {
        if self.synchronous_ack {
            if let Err(e) = self.send_ack_for(node.get()).await
                && !e.is_transport_unavailable()
            {
                warn!("Failed to send ack: {e:?}");
            }
        } else {
            let this = self.clone();
            self.runtime
                .spawn(Box::pin(async move {
                    if let Err(e) = this.send_ack_for(node.get()).await
                        && !e.is_transport_unavailable()
                    {
                        warn!("Failed to send ack: {e:?}");
                    }
                }))
                .detach();
        }
    }

    /// Build and send an <ack/> node corresponding to the given stanza.
    async fn send_ack_for(&self, node: &wacore_binary::NodeRef<'_>) -> Result<(), ClientError> {
        if self.expected_disconnect.load(Ordering::Relaxed) {
            return Ok(());
        }
        if !self.is_connected() {
            return Err(ClientError::NotConnected);
        }
        let own_pn = self.get_pn().await;
        let buf = match encode_ack_bytes(node, own_pn.as_ref()) {
            Ok(Some(buf)) => buf,
            Ok(None) => return Ok(()),
            Err(e) => {
                log::warn!("Failed to encode ack: {e}");
                return Ok(());
            }
        };
        self.send_raw_bytes(buf).await
    }

    pub(crate) async fn handle_unimplemented(&self, tag: &str) {
        log::debug!("Unhandled stanza: <{tag}>");
    }

    pub async fn set_passive(&self, passive: bool) -> Result<(), crate::request::IqError> {
        use wacore::iq::passive::PassiveModeSpec;
        self.execute(PassiveModeSpec::new(passive)).await
    }

    pub async fn clean_dirty_bits(
        &self,
        bit: wacore::iq::dirty::DirtyBit,
    ) -> Result<(), crate::request::IqError> {
        use wacore::iq::dirty::CleanDirtyBitsSpec;

        let spec = CleanDirtyBitsSpec::single(bit);
        self.execute(spec).await
    }

    pub async fn fetch_props(&self) -> Result<(), crate::request::IqError> {
        use wacore::iq::props::PropsSpec;
        use wacore::store::commands::DeviceCommand;

        let stored_hash = self
            .persistence_manager
            .get_device_snapshot()
            .await
            .props_hash
            .clone();

        // Deltas only contain changed props, so they're invalid against an empty cache.
        let spec = match &stored_hash {
            Some(hash) if self.ab_props.is_seeded() => {
                debug!("Fetching props with hash for delta update...");
                PropsSpec::with_hash(hash)
            }
            _ => {
                debug!("Fetching props (full)...");
                PropsSpec::new()
            }
        };

        let response = self.execute(spec).await?;

        if response.delta_update {
            debug!(
                "Props delta update received ({} changed props)",
                response.experiment_props.len()
            );
        } else {
            debug!(
                "Props full update received ({} props, hash={:?})",
                response.experiment_props.len(),
                response.hash
            );
        }

        self.ab_props
            .apply_props(response.delta_update, response.experiment_props.into_iter())
            .await;

        if let Some(new_hash) = response.hash {
            self.persistence_manager
                .process_command(DeviceCommand::SetPropsHash(Some(new_hash)))
                .await;
        }

        Ok(())
    }

    pub(crate) fn ab_props(&self) -> &wacore::store::ab_props::AbPropsCache {
        &self.ab_props
    }

    pub async fn fetch_privacy_settings(
        &self,
    ) -> Result<wacore::iq::privacy::PrivacySettingsResponse, crate::request::IqError> {
        use wacore::iq::privacy::PrivacySettingsSpec;

        debug!("Fetching privacy settings...");

        self.execute(PrivacySettingsSpec::new()).await
    }

    /// Set a privacy setting.
    ///
    /// Use [`PrivacyCategory::is_valid_value`] to check valid combinations.
    ///
    /// # Example
    /// ```ignore
    /// use wacore::iq::privacy::{PrivacyCategory, PrivacyValue};
    /// client.set_privacy_setting(PrivacyCategory::Last, PrivacyValue::Contacts).await?;
    /// ```
    pub async fn set_privacy_setting(
        &self,
        category: wacore::iq::privacy::PrivacyCategory,
        value: wacore::iq::privacy::PrivacyValue,
    ) -> Result<wacore::iq::privacy::SetPrivacySettingResponse, crate::request::IqError> {
        use wacore::iq::privacy::SetPrivacySettingSpec;
        self.execute(SetPrivacySettingSpec::new(category, value))
            .await
    }

    /// Set a privacy setting to `contact_blacklist` with a disallowed list update.
    ///
    /// Only `Last`, `Profile`, `Status`, `GroupAdd` support disallowed lists.
    /// Returns the server's updated dhash for use in subsequent updates.
    pub async fn set_privacy_disallowed_list(
        &self,
        category: wacore::iq::privacy::PrivacyCategory,
        update: wacore::iq::privacy::DisallowedListUpdate,
    ) -> Result<wacore::iq::privacy::SetPrivacySettingResponse, crate::request::IqError> {
        use wacore::iq::privacy::SetPrivacySettingSpec;
        self.execute(SetPrivacySettingSpec::with_disallowed_list(
            category, update,
        ))
        .await
    }

    /// Set the default disappearing messages duration (seconds). Pass 0 to disable.
    pub async fn set_default_disappearing_mode(
        &self,
        duration: u32,
    ) -> Result<(), crate::request::IqError> {
        use wacore::iq::privacy::SetDefaultDisappearingModeSpec;
        self.execute(SetDefaultDisappearingModeSpec::new(duration))
            .await
    }

    /// Get business profile for a WhatsApp Business account.
    pub async fn get_business_profile(
        &self,
        jid: &wacore_binary::Jid,
    ) -> Result<Option<wacore::iq::business::BusinessProfile>, crate::request::IqError> {
        use wacore::iq::business::BusinessProfileSpec;
        self.execute(BusinessProfileSpec::new(jid)).await
    }

    /// Reject an incoming call. Fire-and-forget — no server response is expected.
    pub async fn reject_call(
        &self,
        call_id: &str,
        call_from: &wacore_binary::Jid,
    ) -> Result<(), anyhow::Error> {
        anyhow::ensure!(!call_id.is_empty(), "call_id cannot be empty");
        let id = self.generate_request_id();

        let stanza = wacore_binary::builder::NodeBuilder::new("call")
            .attr("to", call_from)
            .attr("id", id)
            .children([wacore_binary::builder::NodeBuilder::new("reject")
                .attr("call-id", call_id)
                .attr("call-creator", call_from)
                .attr("count", "0")
                .build()])
            .build();

        self.send_node(stanza).await?;
        Ok(())
    }

    pub async fn send_digest_key_bundle(&self) -> Result<(), crate::request::IqError> {
        use wacore::iq::prekeys::DigestKeyBundleSpec;

        debug!("Sending digest key bundle...");

        self.execute(DigestKeyBundleSpec::new()).await.map(|_| ())
    }

    pub(crate) async fn handle_success(self: &Arc<Self>, node: &wacore_binary::NodeRef<'_>) {
        // Skip processing if an expected disconnect is pending (e.g., 515 received).
        // This prevents race conditions where a spawned success handler runs after
        // cleanup_connection_state has already reset is_logged_in.
        if self.expected_disconnect.load(Ordering::Relaxed) {
            debug!("Ignoring <success> stanza: expected disconnect pending");
            return;
        }

        // Guard against multiple <success> stanzas (WhatsApp may send more than one during
        // routing/reconnection). Only process the first one per connection.
        if self.is_logged_in.swap(true, Ordering::SeqCst) {
            debug!("Ignoring duplicate <success> stanza (already logged in)");
            return;
        }

        // Increment connection generation to invalidate any stale post-login tasks
        // from previous connections (e.g., during 515 reconnect cycles).
        let current_generation = self.connection_generation.fetch_add(1, Ordering::SeqCst) + 1;

        info!(
            "Successfully authenticated with WhatsApp servers! (gen={})",
            current_generation
        );
        self.auto_reconnect_errors.store(0, Ordering::Relaxed);

        self.update_server_time_offset(node);

        // Extract LID from the node before spawning (node isn't Send).
        let lid_from_server = match node.get_attr("lid") {
            Some(lid_value) => match lid_value.to_jid() {
                Some(lid) => Some(lid),
                None => {
                    warn!("Failed to parse LID from success stanza: {lid_value}");
                    None
                }
            },
            None => {
                warn!("LID not found in <success> stanza. Group messaging may fail.");
                None
            }
        };

        let client_clone = self.clone();
        let task_generation = current_generation;
        self.runtime.spawn(Box::pin(async move {
            // Update LID if changed (moved here to avoid blocking the read loop
            // on Device snapshot + write lock).
            if let Some(lid) = lid_from_server {
                let device_snapshot =
                    client_clone.persistence_manager.get_device_snapshot().await;
                if device_snapshot.lid.as_ref() != Some(&lid) {
                    debug!("Updating LID from server to '{lid}'");
                    client_clone
                        .persistence_manager
                        .process_command(DeviceCommand::SetLid(Some(lid)))
                        .await;
                }
            }
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

            debug!(
                "Starting post-login initialization sequence (gen={})...",
                task_generation
            );

            // Check if we need initial app state sync (empty pushname indicates fresh pairing
            // where pushname will come from app state sync's setting_pushName mutation)
            let device_snapshot = client_clone.persistence_manager.get_device_snapshot().await;
            let needs_pushname_from_sync = device_snapshot.push_name.is_empty();
            if needs_pushname_from_sync {
                debug!("Push name is empty - will be set from app state sync (setting_pushName)");
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

            check_generation!();
            client_clone.send_unified_session().await;

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

            // Sync own device list so DM fan-out includes all companions
            check_generation!();
            if let Err(e) = client_clone.sync_own_device_list().await {
                client_clone.log_sync_error("sync own device list", &e);
            }

            check_generation!();
            if !client_clone.is_connected() {
                debug!("Skipping passive tasks: connection closed");
                return;
            }
            if let Err(e) = client_clone.upload_pre_keys_at_login().await
                && !client_clone.is_shutting_down()
            {
                warn!("Failed to upload pre-keys during startup: {e:?}");
            }

            // === Send active IQ ===
            // The server sends <ib><offline count="X"/></ib> AFTER we exit passive mode.
            // This matches WhatsApp Web's behavior: executePassiveTasks() -> sendPassiveModeProtocol("active")
            check_generation!();
            if !client_clone.is_connected() {
                debug!("Skipping active IQ: connection closed");
                return;
            }
            if let Err(e) = client_clone.set_passive(false).await
                && !client_clone.is_shutting_down()
            {
                warn!("Failed to send post-connect active IQ: {e:?}");
            }

            // === Wait for offline sync to complete ===
            // The server sends <ib><offline count="X"/></ib> after we exit passive mode.
            client_clone.wait_for_offline_delivery_end().await;

            // Check if connection was replaced while waiting
            check_generation!();

            // Re-check connection and generation before sending presence
            check_generation!();
            if !client_clone.is_connected() {
                debug!("Skipping presence: connection closed");
                return;
            }

            // Background initialization queries (can run in parallel, non-blocking)
            let bg_client = client_clone.clone();
            let bg_generation = task_generation;
            client_clone.runtime.spawn(Box::pin(async move {
                // Check connection and generation before starting background queries
                if bg_client.connection_generation.load(Ordering::SeqCst) != bg_generation {
                    debug!("Skipping background init queries: connection generation changed");
                    return;
                }
                if !bg_client.is_connected() {
                    debug!("Skipping background init queries: connection closed");
                    return;
                }

                debug!(
                    "Sending background initialization queries (Props, Blocklist, Privacy, Digest)..."
                );

                let props_fut = bg_client.fetch_props();
                let binding = bg_client.blocking();
                let blocklist_fut = binding.get_blocklist();
                let privacy_fut = bg_client.fetch_privacy_settings();
                let digest_fut = bg_client.validate_digest_key();

                let (r_props, r_block, r_priv, r_digest) =
                    futures::join!(props_fut, blocklist_fut, privacy_fut, digest_fut);

                // Suppress warnings if connection closed while queries were in-flight
                if !bg_client.is_shutting_down() {
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
                        warn!("Background init: Failed to validate digest key: {e:?}");
                    }
                }

                // Prune expired tcTokens on connect (matches WhatsApp Web's PrivacyTokenJob)
                if let Err(e) = bg_client.tc_token().prune_expired().await
                    && !bg_client.is_shutting_down()
                {
                    warn!("Background init: Failed to prune expired tc_tokens: {e:?}");
                }
            })).detach();

            check_generation!();

            let flag_set = client_clone.needs_initial_full_sync.load(Ordering::Relaxed);
            let needs_initial_sync = flag_set || needs_pushname_from_sync;

            if needs_initial_sync {
                // === Fresh pairing path ===
                // Like WhatsApp Web's syncCriticalData(): await critical collections before
                // dispatching Connected, so blocklist/privacy settings are applied first.
                debug!(
                    target: "Client/AppState",
                    "Starting Initial App State Sync (flag_set={flag_set}, needs_pushname={needs_pushname_from_sync})"
                );

                if !client_clone
                    .initial_app_state_keys_received
                    .load(Ordering::Relaxed)
                {
                    debug!(
                        target: "Client/AppState",
                        "Waiting up to 5s for app state keys..."
                    );
                    let _ = rt_timeout(
                        &*client_clone.runtime,
                        Duration::from_secs(5),
                        client_clone.initial_keys_synced_notifier.listen(),
                    )
                    .await;

                    // Check if connection was replaced while waiting
                    check_generation!();
                }

                // Start the critical sync timeout timer matching WhatsApp Web's
                // WAWebSyncBootstrap.$15 (setSyncDCriticalDataSyncTimeout).
                // WhatsApp Web uses 180s and calls socketLogout(SyncdTimeout) if
                // the critical data hasn't synced by then.
                const CRITICAL_SYNC_TIMEOUT_SECS: u64 = 180;
                let timeout_client = client_clone.clone();
                let timeout_generation = task_generation;
                let timeout_rt = client_clone.runtime.clone();
                let critical_sync_timeout_handle = timeout_rt.spawn(Box::pin(async move {
                    timeout_client.runtime.sleep(Duration::from_secs(CRITICAL_SYNC_TIMEOUT_SECS)).await;
                    // Check generation — if connection was replaced, this timeout is stale
                    if timeout_client.connection_generation.load(Ordering::SeqCst)
                        != timeout_generation
                    {
                        return;
                    }
                    // Matches WhatsApp Web's $16(): check if SettingPushName was synced.
                    // If push_name is still empty after 180s, critical sync failed.
                    let push_name = timeout_client.get_push_name().await;
                    if push_name.is_empty() {
                        warn!(
                            target: "Client/AppState",
                            "Critical app state sync timed out after {CRITICAL_SYNC_TIMEOUT_SECS}s \
                             (push_name not synced). Reconnecting to retry."
                        );
                        // WhatsApp Web does socketLogout here which clears device identity.
                        // We reconnect instead — preserving credentials and keeping the
                        // run loop active so auto-reconnect can retry the sync.
                        timeout_client.reconnect_immediately().await;
                    } else {
                        debug!(
                            target: "Client/AppState",
                            "Critical sync timeout fired but push_name was already synced"
                        );
                    }
                }));

                // Await critical collections via batched IQ before dispatching Connected.
                check_generation!();
                match client_clone
                    .sync_collections_batched(vec![
                        WAPatchName::CriticalBlock,
                        WAPatchName::CriticalUnblockLow,
                    ])
                    .await
                {
                    Ok(()) => {
                        // Critical sync completed — cancel the timeout timer
                        critical_sync_timeout_handle.abort();

                        check_generation!();

                        client_clone
                            .resubscribe_presence_subscriptions(task_generation)
                            .await;

                        check_generation!();

                        // Dispatch Connected after critical sync completes.
                        // Presence is NOT sent here — WhatsApp Web sends presence from the
                        // setting_pushName mutation handler (WAWebPushNameSync), not from
                        // criticalSyncDone. Our setting_pushName handler already does this.
                        client_clone.dispatch_connected();
                    }
                    Err(e) => {
                        client_clone.log_sync_error("critical app state sync", &e);
                        // Don't abort the timeout or dispatch Connected — the sync failed,
                        // so the timeout watchdog should remain active to force a reconnect
                        // if needed. Return early to avoid emitting a spurious Connected event.
                        return;
                    }
                }

                // Spawn remaining non-critical collections in background
                let sync_client = client_clone.clone();
                let sync_generation = task_generation;
                client_clone.runtime.spawn(Box::pin(async move {
                    if sync_client.connection_generation.load(Ordering::SeqCst) != sync_generation {
                        debug!("App state sync cancelled: connection generation changed");
                        return;
                    }

                    if let Err(e) = sync_client
                        .sync_collections_batched(vec![
                            WAPatchName::RegularLow,
                            WAPatchName::RegularHigh,
                            WAPatchName::Regular,
                        ])
                        .await
                    {
                        sync_client.log_sync_error("non-critical app state sync", &e);
                    }

                    sync_client
                        .needs_initial_full_sync
                        .store(false, Ordering::Relaxed);
                    debug!(target: "Client/AppState", "Initial App State Sync Completed.");
                })).detach();
            } else {
                // === Reconnection path ===
                // Pushname is already known, send presence and Connected immediately.
                let device_snapshot = client_clone.persistence_manager.get_device_snapshot().await;
                if !device_snapshot.push_name.is_empty() {
                    if let Err(e) = client_clone.presence().set_available().await {
                        warn!("Failed to send initial presence: {e:?}");
                    } else {
                        debug!("Initial presence sent successfully.");
                    }
                }

                client_clone
                    .resubscribe_presence_subscriptions(task_generation)
                    .await;

                // Re-check generation after awaits to avoid dispatching Connected
                // for an outdated connection that was replaced mid-await.
                check_generation!();

                client_clone.dispatch_connected();
            }
        })).detach();
    }

    /// Handles incoming `<ack/>` stanzas by resolving pending response waiters.
    ///
    /// If an ack with an ID that matches a pending task in `response_waiters`,
    /// the task is resolved and the function returns `true`. Otherwise, returns `false`.
    pub(crate) async fn handle_ack_response(&self, node: &wacore_binary::NodeRef<'_>) -> bool {
        // Surface privacy-token nack codes for diagnosability
        if let Some(error_code) = node.get_attr("error") {
            let code = error_code.as_str();
            let id = node.get_attr("id").map(|v| v.as_str().into_owned());
            match code.as_ref() {
                "463" => {
                    warn!(
                        target: "Client/Ack",
                        "Received 463 (MissingTcToken) nack for msg {:?}. \
                         The recipient requires a valid tctoken or cstoken. \
                         This may indicate a reachout timelock on the account.",
                        id
                    );
                }
                "479" => {
                    warn!(
                        target: "Client/Ack",
                        "Received 479 (SmaxInvalid) nack for msg {:?}. \
                         A stanza field has an incorrect format (e.g. wrong JID format or content type).",
                        id
                    );
                }
                _ => {}
            }
        }

        let id_opt = node.get_attr("id").map(|v| v.as_str().into_owned());
        if let Some(id) = id_opt
            && let Some(waiter) = self.response_waiters.lock().await.remove(&id)
        {
            // ACK responses are infrequent; re-encode into OwnedNodeRef for the channel.
            // marshal_ref prepends a leading 0x00 format byte; OwnedNodeRef::new expects raw
            // protocol bytes without it, matching what unpack() produces from the network.
            match wacore_binary::marshal::marshal_ref(node)
                .and_then(|bytes| wacore_binary::OwnedNodeRef::new(bytes[1..].to_vec()))
            {
                Ok(onr) => {
                    if waiter.send(Arc::new(onr)).is_err() {
                        warn!(target: "Client/Ack", "Failed to send ACK response to waiter for ID {id}. Receiver was likely dropped.");
                    }
                }
                Err(e) => {
                    warn!(target: "Client/Ack", "Failed to re-encode ACK node for waiter: {e}");
                }
            }
            return true;
        }
        false
    }

    pub(crate) async fn fetch_app_state_with_retry(&self, name: WAPatchName) -> anyhow::Result<()> {
        // In-flight dedup: skip if this collection is already being synced.
        // Matches WA Web's WAWebSyncdCollectionsStateMachine which tracks in-flight syncs
        // and queues new requests to a pending set.
        {
            let mut syncing = self.app_state_syncing.lock().await;
            if !syncing.insert(name) {
                debug!(target: "Client/AppState", "Skipping sync for {:?}: already in flight", name);
                return Ok(());
            }
        }

        let result = self.fetch_app_state_with_retry_inner(name).await;

        // Always remove from in-flight set when done
        self.app_state_syncing.lock().await.remove(&name);

        result
    }

    async fn fetch_app_state_with_retry_inner(&self, name: WAPatchName) -> anyhow::Result<()> {
        let mut attempt = 0u32;
        loop {
            attempt += 1;
            // full_sync=false lets process_app_state_sync_task auto-detect:
            // version 0 → snapshot (full sync), version > 0 → incremental patches.
            // Matches WA Web which only requests snapshot when version is undefined.
            let res = self.process_app_state_sync_task(name, false).await;
            match res {
                Ok(()) => return Ok(()),
                Err(e) => {
                    if e.downcast_ref::<crate::appstate_sync::AppStateSyncError>()
                        .is_some_and(|ase| {
                            matches!(ase, crate::appstate_sync::AppStateSyncError::KeyNotFound(_))
                        })
                        && attempt == 1
                    {
                        if !self.initial_app_state_keys_received.load(Ordering::Relaxed) {
                            debug!(target: "Client/AppState", "App state key missing for {:?}; waiting up to 10s for key share then retrying", name);
                            if rt_timeout(
                                &*self.runtime,
                                Duration::from_secs(10),
                                self.initial_keys_synced_notifier.listen(),
                            )
                            .await
                            .is_err()
                            {
                                warn!(target: "Client/AppState", "Timeout waiting for key share for {:?}; retrying anyway", name);
                            }
                        }
                        continue;
                    }
                    let is_db_locked = e.downcast_ref::<wacore::store::error::StoreError>()
                        .is_some_and(|se| matches!(se, wacore::store::error::StoreError::Database(msg) if msg.contains("locked") || msg.contains("busy")))
                        || e.downcast_ref::<crate::appstate_sync::AppStateSyncError>()
                            .is_some_and(|ase| matches!(ase, crate::appstate_sync::AppStateSyncError::Store(wacore::store::error::StoreError::Database(msg)) if msg.contains("locked") || msg.contains("busy")));
                    if is_db_locked && attempt < APP_STATE_RETRY_MAX_ATTEMPTS {
                        let backoff = Duration::from_millis(200 * attempt as u64 + 150);
                        warn!(target: "Client/AppState", "Attempt {} for {:?} failed due to locked DB; backing off {:?} and retrying", attempt, name, backoff);
                        self.runtime.sleep(backoff).await;
                        continue;
                    }
                    return Err(e);
                }
            }
        }
    }

    /// Sync multiple collections in a single IQ request, re-fetching those with `has_more_patches`.
    /// Matches WA Web's `serverSync()` outer loop (`3JJWKHeu5-P.js:54278-54305`).
    /// Max 5 iterations (WA Web's `C=5` constant).
    pub(crate) async fn sync_collections_batched(
        &self,
        collections: Vec<WAPatchName>,
    ) -> anyhow::Result<()> {
        if collections.is_empty() {
            return Ok(());
        }

        // In-flight dedup: filter out collections already being synced
        let pending = {
            let mut syncing = self.app_state_syncing.lock().await;
            let mut filtered = Vec::with_capacity(collections.len());
            for name in collections {
                if syncing.insert(name) {
                    filtered.push(name);
                } else {
                    debug!(target: "Client/AppState", "Skipping {:?} in batch: already in flight", name);
                }
            }
            filtered
        };

        if pending.is_empty() {
            return Ok(());
        }

        // Track all collections for cleanup
        let all_collections: Vec<WAPatchName> = pending.clone();

        let result = self.sync_collections_batched_inner(pending).await;

        // Always clean up in-flight set
        {
            let mut syncing = self.app_state_syncing.lock().await;
            for name in &all_collections {
                syncing.remove(name);
            }
        }

        result
    }

    async fn sync_collections_batched_inner(
        &self,
        mut pending: Vec<WAPatchName>,
    ) -> anyhow::Result<()> {
        use wacore::appstate::patch_decode::CollectionSyncError;
        const MAX_ITERATIONS: usize = 5;
        let mut iteration = 0;

        while !pending.is_empty() && iteration < MAX_ITERATIONS {
            iteration += 1;
            debug!(
                target: "Client/AppState",
                "Batched sync iteration {}/{}: {:?}",
                iteration, MAX_ITERATIONS, pending
            );

            let backend = self.persistence_manager.backend();

            // Build multi-collection IQ, tracking which collections need a snapshot
            let mut collection_nodes = Vec::with_capacity(pending.len());
            let mut was_snapshot = std::collections::HashSet::new();
            for &name in &pending {
                let state = backend.get_version(name.as_str()).await?;
                let want_snapshot = state.version == 0;
                if want_snapshot {
                    was_snapshot.insert(name);
                }
                let mut builder = NodeBuilder::new("collection")
                    .attr("name", name.as_str())
                    .attr(
                        "return_snapshot",
                        if want_snapshot { "true" } else { "false" },
                    );
                if !want_snapshot {
                    builder = builder.attr("version", state.version.to_string());
                }
                collection_nodes.push(builder.build());
            }

            let sync_node = NodeBuilder::new("sync").children(collection_nodes).build();
            let iq = crate::request::InfoQuery {
                namespace: "w:sync:app:state",
                query_type: crate::request::InfoQueryType::Set,
                to: server_jid().clone(),
                target: None,
                id: None,
                content: Some(wacore_binary::NodeContent::Nodes(vec![sync_node])),
                timeout: Some(Duration::from_secs(30)),
            };

            let resp = self.send_iq(iq).await?;

            // Pre-download all external blobs for all collections in the response
            let mut pre_downloaded: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();

            if let Ok(patch_lists) =
                wacore::appstate::patch_decode::parse_patch_lists_ref(resp.get())
            {
                for pl in &patch_lists {
                    // Download external snapshot
                    if let Some(ext) = &pl.snapshot_ref
                        && let Some(path) = &ext.direct_path
                    {
                        match self.download(ext).await {
                            Ok(bytes) => {
                                pre_downloaded.insert(path.clone(), bytes);
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to download external snapshot for {:?}: {e}",
                                    pl.name
                                );
                            }
                        }
                    }

                    // Download external mutations
                    for patch in &pl.patches {
                        if let Some(ext) = &patch.external_mutations
                            && let Some(path) = &ext.direct_path
                        {
                            match self.download(ext).await {
                                Ok(bytes) => {
                                    pre_downloaded.insert(path.clone(), bytes);
                                }
                                Err(e) => {
                                    let v =
                                        patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);
                                    warn!(
                                        "Failed to download external mutations for patch v{}: {e}",
                                        v
                                    );
                                }
                            }
                        }
                    }
                }
            }

            let download = |ext: &wa::ExternalBlobReference| -> anyhow::Result<Vec<u8>> {
                if let Some(path) = &ext.direct_path {
                    if let Some(bytes) = pre_downloaded.get(path) {
                        Ok(bytes.clone())
                    } else {
                        Err(anyhow::anyhow!(
                            "external blob not pre-downloaded: {}",
                            path
                        ))
                    }
                } else {
                    Err(anyhow::anyhow!("external blob has no directPath"))
                }
            };

            // Parse and process all collections from the response
            let proc = self.get_app_state_processor().await;
            let results = proc
                .decode_multi_patch_list_ref(resp.get(), &download, true)
                .await?;

            let mut needs_refetch = Vec::new();

            for (mutations, new_state, list) in results {
                let name = list.name;

                // Handle per-collection errors
                if let Some(ref err) = list.error {
                    match err {
                        CollectionSyncError::Conflict { has_more } => {
                            if *has_more {
                                // ConflictHasMore: server has more patches, must refetch.
                                warn!(target: "Client/AppState", "Collection {:?} conflict (has_more=true), will refetch", name);
                                needs_refetch.push(name);
                            } else {
                                // Conflict without has_more: WA Web treats this as success
                                // when there are no pending mutations to push (which is
                                // always the case for us since we don't push app state).
                                debug!(target: "Client/AppState", "Collection {:?} conflict (has_more=false), treating as success (no pending mutations)", name);
                            }
                            continue;
                        }
                        CollectionSyncError::Fatal { code, text } => {
                            warn!(target: "Client/AppState", "Collection {:?} fatal error {}: {}", name, code, text);
                            continue;
                        }
                        CollectionSyncError::Retry { code, text } => {
                            warn!(target: "Client/AppState", "Collection {:?} retryable error {}: {}, will refetch", name, code, text);
                            needs_refetch.push(name);
                            continue;
                        }
                    }
                }

                // Handle missing keys
                let missing = match proc.get_missing_key_ids(&list).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!("Failed to get missing key IDs for {:?}: {}", name, e);
                        Vec::new()
                    }
                };
                self.request_missing_keys_with_dedup(missing).await;

                // full_sync is true only when this collection had a snapshot
                // (version was 0 before sync). This prevents server_sync-triggered
                // incremental syncs from being incorrectly marked as full syncs.
                let full_sync = was_snapshot.contains(&name);
                for m in mutations {
                    self.dispatch_app_state_mutation(&m, full_sync).await;
                }

                // Save version
                backend
                    .set_version(name.as_str(), new_state.clone())
                    .await?;

                // Check if this collection needs more patches
                if list.has_more_patches {
                    needs_refetch.push(name);
                }

                debug!(
                    target: "Client/AppState",
                    "Batched sync: {:?} done (version={}, has_more={})",
                    name, new_state.version, list.has_more_patches
                );
            }

            pending = needs_refetch;
        }

        if !pending.is_empty() {
            warn!(
                target: "Client/AppState",
                "Batched sync: max iterations ({}) reached for {:?}",
                MAX_ITERATIONS, pending
            );
        }

        Ok(())
    }

    pub(crate) async fn process_app_state_sync_task(
        &self,
        name: WAPatchName,
        full_sync: bool,
    ) -> anyhow::Result<()> {
        if self.is_shutting_down() {
            debug!(target: "Client/AppState", "Skipping app state sync task {:?}: client is shutting down", name);
            return Ok(());
        }

        let backend = self.persistence_manager.backend();
        let mut full_sync = full_sync;

        let mut state = backend.get_version(name.as_str()).await?;
        if state.version == 0 {
            full_sync = true;
        }

        let mut has_more = true;
        let mut want_snapshot = full_sync;
        // Safety cap to prevent infinite loops if the server keeps returning
        // has_more_patches=true without advancing the version (WA Web uses 500).
        const MAX_PAGINATION_ITERATIONS: u32 = 500;
        let mut iteration = 0u32;

        while has_more {
            if self.is_shutting_down() {
                debug!(target: "Client/AppState", "Stopping app state sync task {:?}: shutdown detected", name);
                break;
            }
            iteration += 1;
            if iteration > MAX_PAGINATION_ITERATIONS {
                warn!(target: "Client/AppState", "App state sync for {:?} exceeded {} iterations, aborting", name, MAX_PAGINATION_ITERATIONS);
                break;
            }
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
                to: server_jid().clone(),
                target: None,
                id: None,
                content: Some(wacore_binary::NodeContent::Nodes(vec![sync_node])),
                timeout: None,
            };

            let resp = self.send_iq(iq).await?;
            if self.is_shutting_down() {
                debug!(target: "Client/AppState", "Discarding app state sync response for {:?}: shutdown detected", name);
                break;
            }
            debug!(target: "Client/AppState", "Received IQ response for {:?}; decoding patches", name);

            let _decode_start = wacore::time::Instant::now();

            // Pre-download all external blobs (snapshot and patch mutations)
            // We use directPath as the key to identify each blob
            let mut pre_downloaded: std::collections::HashMap<String, Vec<u8>> =
                std::collections::HashMap::new();

            if let Ok(pl) = wacore::appstate::patch_decode::parse_patch_list_ref(resp.get()) {
                debug!(target: "Client/AppState", "Parsed patch list for {:?}: has_snapshot_ref={} has_more_patches={} patches_count={}",
                    name, pl.snapshot_ref.is_some(), pl.has_more_patches, pl.patches.len());

                // Download external snapshot if present
                if let Some(ext) = &pl.snapshot_ref
                    && let Some(path) = &ext.direct_path
                {
                    match self.download(ext).await {
                        Ok(bytes) => {
                            debug!(target: "Client/AppState", "Downloaded external snapshot ({} bytes)", bytes.len());
                            pre_downloaded.insert(path.clone(), bytes);
                        }
                        Err(e) => {
                            warn!("Failed to download external snapshot: {e}");
                        }
                    }
                }

                // Download external mutations for each patch that has them
                for patch in &pl.patches {
                    if let Some(ext) = &patch.external_mutations
                        && let Some(path) = &ext.direct_path
                    {
                        let patch_version =
                            patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);
                        match self.download(ext).await {
                            Ok(bytes) => {
                                debug!(target: "Client/AppState", "Downloaded external mutations for patch v{} ({} bytes)", patch_version, bytes.len());
                                pre_downloaded.insert(path.clone(), bytes);
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to download external mutations for patch v{}: {e}",
                                    patch_version
                                );
                            }
                        }
                    }
                }
            }

            let download = |ext: &wa::ExternalBlobReference| -> anyhow::Result<Vec<u8>> {
                if let Some(path) = &ext.direct_path {
                    if let Some(bytes) = pre_downloaded.get(path) {
                        Ok(bytes.clone())
                    } else {
                        Err(anyhow::anyhow!(
                            "external blob not pre-downloaded: {}",
                            path
                        ))
                    }
                } else {
                    Err(anyhow::anyhow!("external blob has no directPath"))
                }
            };

            let proc = self.get_app_state_processor().await;
            let (mutations, new_state, list) = proc
                .decode_patch_list_ref(resp.get(), &download, true)
                .await?;
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
            self.request_missing_keys_with_dedup(missing).await;

            for m in mutations {
                debug!(target: "Client/AppState", "Dispatching mutation kind={} index_len={} full_sync={}", m.index.first().map(|s| s.as_str()).unwrap_or(""), m.index.len(), full_sync);
                self.dispatch_app_state_mutation(&m, full_sync).await;
            }

            state = new_state;
            has_more = list.has_more_patches;
            // After the first batch, never request a snapshot again — only incremental patches.
            want_snapshot = false;
            debug!(target: "Client/AppState", "After processing batch name={:?} has_more={has_more} new_version={}", name, state.version);
        }

        backend.set_version(name.as_str(), state.clone()).await?;

        debug!(target: "Client/AppState", "Completed and saved app state sync for {:?} (final version={})", name, state.version);
        Ok(())
    }

    /// Request missing app-state keys with dedup stamps.
    /// On send failure, removes stamps so keys can be retried next sync.
    async fn request_missing_keys_with_dedup(&self, missing: Vec<Vec<u8>>) {
        if missing.is_empty() {
            return;
        }
        let mut to_request: Vec<Vec<u8>> = Vec::with_capacity(missing.len());
        let mut guard = self.app_state_key_requests.lock().await;
        let now = wacore::time::Instant::now();
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
        guard.retain(|_, t| t.elapsed() < std::time::Duration::from_secs(24 * 3600));
        drop(guard);
        if !to_request.is_empty()
            && let Err(e) = self.request_app_state_keys(&to_request).await
        {
            warn!("Failed to send app state key request: {e}");
            let mut guard = self.app_state_key_requests.lock().await;
            for key_id in &to_request {
                guard.remove(&hex::encode(key_id));
            }
        }
    }

    async fn request_app_state_keys(&self, raw_key_ids: &[Vec<u8>]) -> Result<(), anyhow::Error> {
        if raw_key_ids.is_empty() {
            return Ok(());
        }
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = match device_snapshot.pn.clone() {
            Some(j) => j,
            None => {
                return Err(anyhow::anyhow!(
                    "no own JID available for app-state key request"
                ));
            }
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
        self.send_message_impl(
            own_jid,
            &msg,
            Some(self.generate_message_id().await),
            true,
            false,
            None,
            vec![],
        )
        .await?;
        Ok(())
    }

    /// Send an app state patch to the server for a given collection.
    ///
    /// Builds the IQ stanza and sends it. Returns the updated hash state.
    pub(crate) async fn send_app_state_patch(
        &self,
        collection_name: &str,
        mutations: Vec<wa::SyncdMutation>,
    ) -> Result<()> {
        let proc = self.get_app_state_processor().await;
        let (patch_bytes, base_version) = proc.build_patch(collection_name, mutations).await?;

        let collection_node = NodeBuilder::new("collection")
            .attr("name", collection_name)
            .attr("version", base_version.to_string())
            .attr("return_snapshot", "false")
            .children([NodeBuilder::new("patch").bytes(patch_bytes).build()])
            .build();
        let sync_node = NodeBuilder::new("sync").children([collection_node]).build();
        let iq = crate::request::InfoQuery {
            namespace: "w:sync:app:state",
            query_type: crate::request::InfoQueryType::Set,
            to: server_jid().clone(),
            target: None,
            id: None,
            content: Some(wacore_binary::NodeContent::Nodes(vec![sync_node])),
            timeout: None,
        };

        self.send_iq(iq).await?;

        // Re-sync to get the latest state from the server after our patch was accepted.
        // This matches whatsmeow's behavior: fetchAppState after successful send.
        if let Ok(patch_name) = collection_name.parse::<WAPatchName>()
            && let Err(e) = self.fetch_app_state_with_retry(patch_name).await
        {
            log::warn!("Failed to re-sync {collection_name} after patch send: {e}");
        }

        Ok(())
    }

    async fn dispatch_app_state_mutation(
        &self,
        m: &crate::appstate_sync::Mutation,
        full_sync: bool,
    ) {
        use wacore::types::events::Event;

        if m.index.is_empty() {
            return;
        }

        // NCT salt sync — handles both "set" (store salt) and "remove" (clear salt).
        // Source: WAWebNctSaltSync, syncd collection RegularHigh, action "nct_salt_sync".
        if m.index[0] == "nct_salt_sync" {
            if m.operation == wa::syncd_mutation::SyncdOperation::Remove {
                debug!(target: "Client/AppState", "Removing NCT salt via app state sync");
                self.persistence_manager
                    .process_command(DeviceCommand::SetNctSalt(None))
                    .await;
            } else if let Some(val) = &m.action_value
                && let Some(act) = &val.nct_salt_sync_action
                && let Some(salt) = &act.salt
            {
                if salt.is_empty() {
                    warn!(target: "Client/AppState", "nct_salt_sync mutation has empty salt, ignoring");
                } else {
                    debug!(target: "Client/AppState", "Stored NCT salt via app state sync ({} bytes)", salt.len());
                    self.persistence_manager
                        .process_command(DeviceCommand::SetNctSalt(Some(salt.clone())))
                        .await;
                }
            } else {
                warn!(target: "Client/AppState", "nct_salt_sync mutation missing salt in action value");
            }
            return;
        }

        // All remaining mutations only care about Set operations
        if m.operation != wa::syncd_mutation::SyncdOperation::Set {
            return;
        }

        // Delegate chat-related mutations (mute, pin, archive, star, contact, etc.)
        if crate::features::chat_actions::dispatch_chat_mutation(&self.core.event_bus, m, full_sync)
        {
            return;
        }

        // Handle client-internal mutations that need persistence/presence access
        if m.index[0] == "setting_pushName"
            && let Some(val) = &m.action_value
            && let Some(act) = &val.push_name_setting
            && let Some(new_name) = &act.name
        {
            let new_name = new_name.clone();
            let bus = self.core.event_bus.clone();

            let snapshot = self.persistence_manager.get_device_snapshot().await;
            let old = snapshot.push_name.clone();
            if old != new_name {
                debug!(target: "Client/AppState", "Persisting push name from app state mutation: '{}' (old='{}')", new_name, old);
                self.persistence_manager
                    .process_command(DeviceCommand::SetPushName(new_name.clone()))
                    .await;
                bus.dispatch(Event::SelfPushNameUpdated(
                    crate::types::events::SelfPushNameUpdated {
                        from_server: true,
                        old_name: old.clone(),
                        new_name: new_name.clone(),
                    },
                ));

                // WhatsApp Web sends presence immediately when receiving pushname
                if old.is_empty() && !new_name.is_empty() {
                    debug!(target: "Client/AppState", "Sending presence after receiving initial pushname from app state sync");
                    if let Err(e) = self.presence().set_available().await {
                        warn!(target: "Client/AppState", "Failed to send presence after pushname sync: {e:?}");
                    }
                }
            } else {
                debug!(target: "Client/AppState", "Push name mutation received but name unchanged: '{}'", new_name);
            }
        }
    }

    pub(crate) async fn handle_stream_error(&self, node: &wacore_binary::NodeRef<'_>) {
        self.is_logged_in.store(false, Ordering::Relaxed);

        let mut attrs = node.attrs();
        let code_cow = attrs.optional_string("code");
        let code = code_cow.as_deref().unwrap_or("");
        let conflict_type = node
            .get_optional_child("conflict")
            .map(|n| {
                n.attrs()
                    .optional_string("type")
                    .as_deref()
                    .unwrap_or("")
                    .to_string()
            })
            .unwrap_or_default();

        // Whether to proactively disconnect the transport after handling.
        let mut should_disconnect = false;

        if !conflict_type.is_empty() {
            info!(
                "Got stream error indicating client was removed or replaced (conflict={}). Logging out.",
                conflict_type
            );
            self.expected_disconnect.store(true, Ordering::Relaxed);
            self.enable_auto_reconnect.store(false, Ordering::Relaxed);

            let event = if conflict_type == "replaced" {
                Event::StreamReplaced(crate::types::events::StreamReplaced)
            } else {
                Event::LoggedOut(crate::types::events::LoggedOut {
                    on_connect: false,
                    reason: ConnectFailureReason::LoggedOut,
                })
            };
            self.core.event_bus.dispatch(event);
            should_disconnect = true;
        } else {
            match code {
                "515" => {
                    info!(
                        "Got 515 stream error, server is closing stream (expected after pairing). Will auto-reconnect."
                    );
                    self.expected_disconnect.store(true, Ordering::Relaxed);
                    should_disconnect = true;
                }
                "516" => {
                    info!("Got 516 stream error (device removed). Logging out.");
                    self.expected_disconnect.store(true, Ordering::Relaxed);
                    self.enable_auto_reconnect.store(false, Ordering::Relaxed);
                    self.core.event_bus.dispatch(Event::LoggedOut(
                        crate::types::events::LoggedOut {
                            on_connect: false,
                            reason: ConnectFailureReason::LoggedOut,
                        },
                    ));
                    should_disconnect = true;
                }
                "401" => {
                    info!("Got 401 stream error (unauthorized). Logging out.");
                    self.expected_disconnect.store(true, Ordering::Relaxed);
                    self.enable_auto_reconnect.store(false, Ordering::Relaxed);
                    self.core.event_bus.dispatch(Event::LoggedOut(
                        crate::types::events::LoggedOut {
                            on_connect: false,
                            reason: ConnectFailureReason::LoggedOut,
                        },
                    ));
                    should_disconnect = true;
                }
                "409" => {
                    info!("Got 409 stream error (conflict). Another session replaced this one.");
                    self.expected_disconnect.store(true, Ordering::Relaxed);
                    self.enable_auto_reconnect.store(false, Ordering::Relaxed);
                    self.core
                        .event_bus
                        .dispatch(Event::StreamReplaced(crate::types::events::StreamReplaced));
                    should_disconnect = true;
                }
                "429" => {
                    warn!(
                        "Got 429 stream error (rate limited). Will auto-reconnect with extended backoff."
                    );
                    self.auto_reconnect_errors.fetch_add(5, Ordering::Relaxed);
                }
                "503" => {
                    info!("Got 503 service unavailable, will auto-reconnect.");
                }
                _ => {
                    error!("Unknown stream error: {}", DisplayableNodeRef(node));
                    self.expected_disconnect.store(true, Ordering::Relaxed);
                    self.core.event_bus.dispatch(Event::StreamError(
                        crate::types::events::StreamError {
                            code: code.to_string(),
                            raw: Some(node.to_owned()),
                        },
                    ));
                }
            }
        }

        // Single transport lock acquisition for all branches that need disconnect.
        if should_disconnect {
            let transport_opt = self.transport.lock().await.clone();
            if let Some(transport) = transport_opt {
                self.runtime
                    .spawn(Box::pin(async move {
                        transport.disconnect().await;
                    }))
                    .detach();
            }
        }

        info!("Notifying connection shutdown from stream error handler");
        self.notify_connection_shutdown();
    }

    pub(crate) async fn handle_connect_failure(&self, node: &wacore_binary::NodeRef<'_>) {
        self.expected_disconnect.store(true, Ordering::Relaxed);
        self.notify_connection_shutdown();

        let mut attrs = node.attrs();
        let reason_code = attrs.optional_u64("reason").unwrap_or(0) as i32;
        let reason = ConnectFailureReason::from(reason_code);

        if reason.should_reconnect() {
            self.expected_disconnect.store(false, Ordering::Relaxed);
        } else {
            self.enable_auto_reconnect.store(false, Ordering::Relaxed);
        }

        if reason.is_logged_out() {
            info!("Got {reason:?} connect failure, logging out.");
            self.core
                .event_bus
                .dispatch(wacore::types::events::Event::LoggedOut(
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
            warn!(
                "Temporary ban connect failure: {}",
                DisplayableNodeRef(node)
            );
            self.core
                .event_bus
                .dispatch(Event::TemporaryBan(crate::types::events::TemporaryBan {
                    code: crate::types::events::TempBanReason::from(ban_code),
                    expire: expire_duration,
                }));
        } else if let ConnectFailureReason::ClientOutdated = reason {
            error!("Client is outdated and was rejected by server.");
            self.core
                .event_bus
                .dispatch(Event::ClientOutdated(crate::types::events::ClientOutdated));
        } else {
            warn!("Unknown connect failure: {}", DisplayableNodeRef(node));
            self.core.event_bus.dispatch(Event::ConnectFailure(
                crate::types::events::ConnectFailure {
                    reason,
                    message: attrs
                        .optional_string("message")
                        .as_deref()
                        .unwrap_or("")
                        .to_string(),
                    raw: Some(node.to_owned()),
                },
            ));
        }
    }

    pub(crate) async fn handle_iq(self: &Arc<Self>, node: &wacore_binary::NodeRef<'_>) -> bool {
        if node.get_attr("type").is_some_and(|s| s.as_str() == "get")
            && (node.get_optional_child("ping").is_some()
                || node
                    .get_attr("xmlns")
                    .is_some_and(|s| s.as_str() == "urn:xmpp:ping"))
        {
            debug!("Received ping, sending pong.");
            let mut parser = node.attrs();
            let from_jid = parser.jid("from");
            let id = parser.optional_string("id").map(|s| s.to_string());
            let pong = build_pong(from_jid.to_string(), id.as_deref());
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
        self.is_connected.load(Ordering::Acquire)
    }

    pub fn is_logged_in(&self) -> bool {
        self.is_logged_in.load(Ordering::Relaxed)
    }

    /// Register a waiter for an incoming node matching the given filter.
    ///
    /// Returns a receiver that resolves when a matching node arrives.
    /// The waiter starts buffering immediately, so register it **before**
    /// performing the action that triggers the expected node.
    ///
    /// When multiple waiters match the same node, each matching waiter
    /// receives a clone of the node (broadcast within a single resolve pass).
    ///
    /// # Example
    /// ```ignore
    /// let waiter = client.wait_for_node(
    ///     NodeFilter::tag("notification").attr("type", "w:gp2"),
    /// );
    /// client.groups().add_participants(&group_jid, &[jid_c]).await?;
    /// let node = waiter.await.expect("notification arrived");
    /// ```
    pub fn wait_for_node(
        &self,
        filter: NodeFilter,
    ) -> futures::channel::oneshot::Receiver<Arc<wacore_binary::OwnedNodeRef>> {
        let (tx, rx) = futures::channel::oneshot::channel();
        self.node_waiter_count.fetch_add(1, Ordering::Release);
        let mut waiters = self
            .node_waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        waiters.push(NodeWaiter { filter, tx });
        rx
    }

    /// Register a waiter for an outgoing node before it is encrypted and sent.
    ///
    /// This is intended for tests and diagnostics that need to inspect the raw
    /// stanza built by the client, such as asserting whether `<tctoken>` or
    /// `<cstoken>` was attached.
    pub fn wait_for_sent_node(
        &self,
        filter: NodeFilter,
    ) -> futures::channel::oneshot::Receiver<Arc<Node>> {
        let (tx, rx) = futures::channel::oneshot::channel();
        self.sent_node_waiter_count.fetch_add(1, Ordering::Release);
        let mut waiters = self
            .sent_node_waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        waiters.push(SentNodeWaiter { filter, tx });
        rx
    }

    /// Check pending node waiters against an incoming node.
    /// Only called when `node_waiter_count > 0`.
    fn resolve_node_waiters(&self, node: &Arc<wacore_binary::OwnedNodeRef>) {
        resolve_waiters(&self.node_waiters, &self.node_waiter_count, node);
    }

    fn resolve_sent_node_waiters(&self, node: &Arc<Node>) {
        let nr = node.as_node_ref();
        let mut waiters = self
            .sent_node_waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut i = 0;
        while i < waiters.len() {
            if waiters[i].tx.is_canceled() {
                waiters.swap_remove(i);
                self.sent_node_waiter_count.fetch_sub(1, Ordering::Release);
            } else if waiters[i].filter.matches(&nr) {
                let w = waiters.swap_remove(i);
                self.sent_node_waiter_count.fetch_sub(1, Ordering::Release);
                let _ = w.tx.send(Arc::clone(node));
            } else {
                i += 1;
            }
        }
    }

    fn clear_sent_node_waiters(&self) {
        let mut waiters = self
            .sent_node_waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let count = waiters.len();
        if count > 0 {
            waiters.clear();
            self.sent_node_waiter_count
                .fetch_sub(count, Ordering::Release);
        }
    }

    pub(crate) fn update_server_time_offset(&self, node: &wacore_binary::NodeRef<'_>) {
        self.unified_session.update_server_time_offset(node);
    }

    pub(crate) async fn send_unified_session(&self) {
        if !self.is_connected() {
            debug!(target: "Client/UnifiedSession", "Skipping: not connected");
            return;
        }

        let Some((node, _sequence)) = self.unified_session.prepare_send().await else {
            return;
        };

        if let Err(e) = self.send_node(node).await {
            debug!(target: "Client/UnifiedSession", "Send failed: {e}");
            self.unified_session.clear_last_sent().await;
        }
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
        let notified = self.socket_ready_notifier.listen();
        if self.is_connected() {
            return Ok(());
        }

        rt_timeout(&*self.runtime, timeout, notified)
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
        // Fast path: fully ready (connected + logged in + critical sync done).
        if self.is_fully_ready() {
            return Ok(());
        }

        // Register waiter and re-check to avoid TOCTOU race:
        // dispatch_connected() could fire between the check above and notified() registration.
        let notified = self.connected_notifier.listen();
        if self.is_fully_ready() {
            return Ok(());
        }

        rt_timeout(&*self.runtime, timeout, notified)
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
        original_id: impl Into<String>,
        new_content: wa::Message,
    ) -> Result<String, anyhow::Error> {
        let original_id = original_id.into();

        // WhatsApp Web uses getMeUserLidOrJidForChat(chat, EditMessage) which
        // returns LID for LID-addressing groups and PN otherwise.
        let participant = if to.is_group() {
            Some(
                self.get_own_jid_for_group(&to)
                    .await?
                    .to_non_ad()
                    .to_string(),
            )
        } else {
            if self.get_pn().await.is_none() {
                return Err(anyhow::Error::from(ClientError::NotLoggedIn));
            }
            None
        };

        let edit_container_message = wa::Message {
            edited_message: Some(Box::new(wa::message::FutureProofMessage {
                message: Some(Box::new(wa::Message {
                    protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                        key: Some(wa::MessageKey {
                            remote_jid: Some(to.to_string()),
                            from_me: Some(true),
                            id: Some(original_id.clone()),
                            participant,
                        }),
                        r#type: Some(wa::message::protocol_message::Type::MessageEdit as i32),
                        edited_message: Some(Box::new(new_content)),
                        timestamp_ms: Some(wacore::time::now_millis()),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
            })),
            ..Default::default()
        };

        // Use a new stanza ID instead of reusing the original message ID.
        // The original message ID is already embedded in protocolMessage.key.id
        // inside the encrypted payload. Reusing it as the outer stanza ID causes
        // the server to deduplicate against the original message and silently
        // drop the edit.
        self.send_message_impl(
            to,
            &edit_container_message,
            None,
            false,
            false,
            Some(crate::types::message::EditAttribute::MessageEdit),
            vec![],
        )
        .await?;

        Ok(original_id)
    }

    /// Send a server-side reaction (used by both newsletter and status reactions).
    pub(crate) async fn send_server_reaction(
        &self,
        to: &Jid,
        server_id: u64,
        reaction: &str,
    ) -> Result<(), anyhow::Error> {
        let request_id = self.generate_message_id().await;

        let stanza = NodeBuilder::new("message")
            .attr("to", to)
            .attr("type", "reaction")
            .attr("id", &request_id)
            .attr("server_id", server_id.to_string())
            .children([NodeBuilder::new("reaction").attr("code", reaction).build()])
            .build();

        self.send_node(stanza).await?;
        Ok(())
    }

    pub async fn send_node(&self, node: Node) -> Result<(), ClientError> {
        debug!(target: "Client/Send", "{}", DisplayableNode(&node));
        if self.sent_node_waiter_count.load(Ordering::Acquire) > 0 {
            self.resolve_sent_node_waiters(&Arc::new(node.clone()));
        }

        let plaintext_buf = wacore_binary::marshal::marshal_auto(&node).map_err(|e| {
            error!("Failed to marshal node: {e:?}");
            SocketError::Crypto("Marshal error".to_string())
        })?;

        self.send_raw_bytes(plaintext_buf).await
    }

    /// Register a oneshot waiter for a server ack by message ID.
    /// Returns the receiver — caller sends the node separately and awaits this in background.
    pub(crate) async fn register_ack_waiter(
        &self,
        message_id: &str,
    ) -> futures::channel::oneshot::Receiver<std::sync::Arc<wacore_binary::OwnedNodeRef>> {
        let (tx, rx) = futures::channel::oneshot::channel();
        self.response_waiters
            .lock()
            .await
            .insert(message_id.to_string(), tx);
        rx
    }

    pub(crate) async fn update_push_name_and_notify(self: &Arc<Self>, new_name: String) {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let old_name = device_snapshot.push_name.clone();

        if old_name == new_name {
            return;
        }

        log::debug!("Updating push name from '{}' -> '{}'", old_name, new_name);
        self.persistence_manager
            .process_command(DeviceCommand::SetPushName(new_name.clone()))
            .await;

        self.core.event_bus.dispatch(Event::SelfPushNameUpdated(
            crate::types::events::SelfPushNameUpdated {
                from_server: true,
                old_name,
                new_name: new_name.clone(),
            },
        ));

        let client_clone = self.clone();
        self.runtime
            .spawn(Box::pin(async move {
                if let Err(e) = client_clone.presence().set_available().await {
                    log::warn!("Failed to send presence after push name update: {:?}", e);
                } else {
                    log::debug!("Sent presence after push name update.");
                }
            }))
            .detach();
    }

    pub async fn get_push_name(&self) -> String {
        self.persistence_manager
            .get_device_arc()
            .await
            .read()
            .await
            .push_name
            .clone()
    }

    pub async fn get_pn(&self) -> Option<Jid> {
        self.persistence_manager
            .get_device_arc()
            .await
            .read()
            .await
            .pn
            .clone()
    }

    pub async fn get_lid(&self) -> Option<Jid> {
        self.persistence_manager
            .get_device_arc()
            .await
            .read()
            .await
            .lid
            .clone()
    }

    pub(crate) async fn require_pn(&self) -> Result<Jid> {
        self.get_pn().await.ok_or(ClientError::NotLoggedIn.into())
    }

    /// Resolve our own JID for a group, respecting its addressing mode.
    ///
    /// Returns LID for LID-addressing groups, PN otherwise.
    /// Matches WhatsApp Web's `getMeUserLidOrJidForChat`.
    pub(crate) async fn get_own_jid_for_group(
        &self,
        group_jid: &Jid,
    ) -> Result<Jid, anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_pn = device_snapshot
            .pn
            .clone()
            .ok_or_else(|| anyhow::Error::from(ClientError::NotLoggedIn))?;

        let addressing_mode = self
            .groups()
            .query_info(group_jid)
            .await
            .map(|info| info.addressing_mode)
            .unwrap_or(crate::types::message::AddressingMode::Pn);

        Ok(match addressing_mode {
            crate::types::message::AddressingMode::Lid => {
                device_snapshot.lid.clone().unwrap_or(own_pn)
            }
            crate::types::message::AddressingMode::Pn => own_pn,
        })
    }

    /// Creates a normalized ChatMessageId by resolving PN to LID JIDs.
    pub(crate) async fn make_chat_message_id(&self, chat: &Jid, id: &str) -> ChatMessageId {
        // Resolve chat JID to LID if possible
        let chat = self.resolve_encryption_jid(chat).await;

        ChatMessageId {
            chat,
            id: id.to_owned(),
        }
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
                crate::types::presence::ReceiptType::EncRekeyRetry => "enc_rekey_retry",
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

/// Builds a pong response node for a server-initiated ping.
///
/// Matches WhatsApp Web (`WAWebCommsHandleStanza`): only includes `id`
/// when the server ping carried one.
fn build_pong(to: String, id: Option<&str>) -> wacore_binary::Node {
    let mut builder = NodeBuilder::new("iq").attr("to", to).attr("type", "result");
    if let Some(id) = id {
        builder = builder.attr("id", id);
    }
    builder.build()
}

/// Build an `<ack/>` for the given stanza, matching WA Web / whatsmeow behavior:
///
/// - `class` = original stanza tag
/// - `id`, `to` (flipped from `from`), `participant` copied from original
/// - `from` = own device PN, only for message acks
/// - `type` echoed for non-message stanzas (whatsmeow: `node.Tag != "message"`),
///   except `notification type="encrypt"` with `<identity/>` child (WA Web drops type there).
///
/// For receipt acks, WA Web uses `MAYBE_CUSTOM_STRING(ackString)` where
/// `ackString = maybeAttrString("type")` — so `type` is only included when
/// explicitly present on the incoming receipt (delivery receipts normally
/// have no type attribute, meaning the ack also has no type).
/// Encode an ack stanza directly to bytes, bypassing Node + marshal_auto.
/// Acks are the most frequent outbound stanza (~1 per inbound message).
fn encode_ack_bytes(
    node: &wacore_binary::NodeRef<'_>,
    own_device_pn: Option<&Jid>,
) -> Result<Option<Vec<u8>>, wacore_binary::error::BinaryError> {
    use wacore_binary::encoder::{ByteWriter, EncodeNode, Encoder};

    let Some(id_val) = node.get_attr("id") else {
        return Ok(None);
    };
    let Some(from_val) = node.get_attr("from") else {
        return Ok(None);
    };
    let participant_val = node.get_attr("participant");
    let tag = node.tag.as_ref();

    let typ_val = if tag != "message" && !is_encrypt_identity_notification(node) {
        node.get_attr("type")
    } else {
        None
    };

    let include_from = tag == "message" && own_device_pn.is_some();

    // Count attrs: class + id + to + optional(from, participant, type)
    let attr_count = 3
        + usize::from(include_from)
        + usize::from(participant_val.is_some())
        + usize::from(typ_val.is_some());

    struct AckNode<'a> {
        id: &'a wacore_binary::node::ValueRef<'a>,
        from: &'a wacore_binary::node::ValueRef<'a>,
        participant: Option<&'a wacore_binary::node::ValueRef<'a>>,
        typ: Option<&'a wacore_binary::node::ValueRef<'a>>,
        own_pn: Option<&'a Jid>,
        tag_str: &'a str,
        attr_count: usize,
    }

    impl EncodeNode for AckNode<'_> {
        fn tag(&self) -> &str {
            "ack"
        }
        fn attrs_len(&self) -> usize {
            self.attr_count
        }
        fn has_content(&self) -> bool {
            false
        }
        fn encode_attrs<'a, W: ByteWriter>(
            &self,
            enc: &mut Encoder<'a, W>,
        ) -> wacore_binary::Result<()> {
            enc.write_string("class")?;
            enc.write_string(self.tag_str)?;
            enc.write_string("id")?;
            self.id.encode_value(enc)?;
            enc.write_string("to")?;
            self.from.encode_value(enc)?;
            if let Some(pn) = self.own_pn {
                enc.write_string("from")?;
                enc.write_jid_owned(pn)?;
            }
            if let Some(p) = self.participant {
                enc.write_string("participant")?;
                p.encode_value(enc)?;
            }
            if let Some(t) = self.typ {
                enc.write_string("type")?;
                t.encode_value(enc)?;
            }
            Ok(())
        }
        fn encode_content<'a, W: ByteWriter>(
            &self,
            _enc: &mut Encoder<'a, W>,
        ) -> wacore_binary::Result<()> {
            Ok(())
        }
    }

    let ack = AckNode {
        id: id_val,
        from: from_val,
        participant: participant_val,
        typ: typ_val,
        own_pn: if include_from { own_device_pn } else { None },
        tag_str: tag,
        attr_count,
    };

    let mut buf = Vec::with_capacity(64);
    let mut encoder = Encoder::new_vec(&mut buf)?;
    encoder.write_node(&ack)?;
    Ok(Some(buf))
}

/// Build an ack Node (used in tests for structure verification).
#[cfg(test)]
fn build_ack_node(node: &wacore_binary::NodeRef<'_>, own_device_pn: Option<&Jid>) -> Option<Node> {
    let id = node.get_attr("id")?.to_node_value();
    let from = node.get_attr("from")?.to_node_value();
    let participant = node.get_attr("participant").map(|v| v.to_node_value());
    let tag = node.tag.as_ref();
    let typ = if tag != "message" && !is_encrypt_identity_notification(node) {
        node.get_attr("type").map(|v| v.to_node_value())
    } else {
        None
    };
    let mut attrs = Attrs::with_capacity(6);
    attrs.insert("class", NodeValue::from(tag));
    attrs.insert("id", id);
    attrs.insert("to", from);
    if tag == "message"
        && let Some(own_device_pn) = own_device_pn
    {
        attrs.insert("from", NodeValue::Jid(own_device_pn.clone()));
    }
    if let Some(p) = participant {
        attrs.insert("participant", p);
    }
    if let Some(t) = typ {
        attrs.insert("type", t);
    }
    Some(Node {
        tag: Cow::Borrowed("ack"),
        attrs,
        content: None,
    })
}

/// WA Web omits `type` when ACKing `<notification type="encrypt"><identity/></notification>`.
fn is_encrypt_identity_notification(node: &wacore_binary::NodeRef<'_>) -> bool {
    node.tag == "notification"
        && node
            .get_attr("type")
            .is_some_and(|v| v.as_str() == "encrypt")
        && node.get_optional_child("identity").is_some()
}

/// Computes a reconnect delay matching WhatsApp Web's Fibonacci backoff:
/// `{ algo: { type: "fibonacci", first: 1000, second: 1000 }, jitter: 0.1, max: 9e5 }`
///
/// Sequence: 1s, 1s, 2s, 3s, 5s, 8s, 13s, 21s, 34s, 55s, 89s, 144s, ... capped at 900s.
/// Each value gets ±10% random jitter.
fn fibonacci_backoff(attempt: u32) -> Duration {
    const MAX_MS: u64 = 900_000; // WA Web: 9e5

    let mut a: u64 = 1000;
    let mut b: u64 = 1000;
    for _ in 0..attempt {
        let next = a.saturating_add(b).min(MAX_MS);
        a = b;
        b = next;
    }
    let base = a.min(MAX_MS);

    // ±10% jitter (WA Web: jitter: 0.1)
    let jitter_range = base / 10;
    let jitter = if jitter_range > 0 {
        rand::make_rng::<rand::rngs::StdRng>().random_range(0..=(jitter_range * 2)) as i64
            - jitter_range as i64
    } else {
        0
    };
    let ms = (base as i64 + jitter).max(0) as u64;
    Duration::from_millis(ms)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lid_pn_cache::LearningSource;
    use crate::test_utils::MockHttpClient;
    use futures::channel::oneshot;
    use wacore_binary::SERVER_JID;

    #[tokio::test]
    async fn test_ack_behavior_for_incoming_stanzas() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // --- Assertions ---

        // Verify that we still ack other critical stanzas (regression check).
        use wacore_binary::{Attrs, Node, NodeContent};

        let mut receipt_attrs = Attrs::new();
        receipt_attrs.insert("from".to_string(), "@s.whatsapp.net".to_string());
        receipt_attrs.insert("id".to_string(), "RCPT-1".to_string());
        let receipt_node = Node::new(
            "receipt",
            receipt_attrs,
            Some(NodeContent::String("test".into())),
        );

        let mut notification_attrs = Attrs::new();
        notification_attrs.insert("from".to_string(), "@s.whatsapp.net".to_string());
        notification_attrs.insert("id".to_string(), "NOTIF-1".to_string());
        let notification_node = Node::new(
            "notification",
            notification_attrs,
            Some(NodeContent::String("test".into())),
        );

        assert!(
            client.should_ack(&receipt_node.as_node_ref()),
            "should_ack must still return TRUE for <receipt> stanzas."
        );
        assert!(
            client.should_ack(&notification_node.as_node_ref()),
            "should_ack must still return TRUE for <notification> stanzas."
        );

        info!(
            "✅ test_ack_behavior_for_incoming_stanzas passed: Client correctly differentiates which stanzas to acknowledge."
        );
    }

    #[tokio::test]
    async fn test_ack_waiter_resolves() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
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
        let handled = client.handle_ack_response(&ack_node.as_node_ref()).await;
        assert!(
            handled,
            "handle_ack_response should return true when waiter exists"
        );

        // 4. Await the receiver with a timeout
        match tokio::time::timeout(Duration::from_secs(1), rx).await {
            Ok(Ok(response_node)) => {
                assert!(
                    response_node
                        .get()
                        .get_attr("id")
                        .is_some_and(|v| v.as_str() == test_id.as_str()),
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
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
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
        let handled = client.handle_ack_response(&ack_node.as_node_ref()).await;
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
            Arc::new(crate::runtime_impl::TokioRuntime),
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
            Arc::new(crate::runtime_impl::TokioRuntime),
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
            Arc::new(crate::runtime_impl::TokioRuntime),
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
            Arc::new(crate::runtime_impl::TokioRuntime),
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
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Flag is false by default, so use a short timeout and verify the helper
        // marks the sync complete on timeout.
        let start = std::time::Instant::now();
        client
            .wait_for_offline_delivery_end_with_timeout(std::time::Duration::from_millis(50))
            .await;

        let elapsed = start.elapsed();
        // Count available permits by trying to acquire non-blockingly
        let semaphore = match client.message_processing_semaphore.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let mut guards = Vec::new();
        while let Some(guard) = semaphore.try_acquire() {
            guards.push(guard);
        }
        let permits = guards.len();
        drop(guards);

        assert!(
            elapsed.as_millis() >= 45, // Allow small timing variance
            "Should have waited for the configured timeout duration, took {:?}",
            elapsed
        );
        assert!(
            client
                .offline_sync_completed
                .load(std::sync::atomic::Ordering::Relaxed),
            "wait_for_offline_delivery_end should mark offline sync complete on timeout"
        );
        assert_eq!(
            permits, 64,
            "timeout completion should restore parallel permits"
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
            Arc::new(crate::runtime_impl::TokioRuntime),
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
            client_clone.offline_sync_notifier.notify(usize::MAX);
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
            Arc::new(crate::runtime_impl::TokioRuntime),
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
            Arc::new(crate::runtime_impl::TokioRuntime),
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
        client.offline_sync_notifier.notify(usize::MAX);

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
            Arc::new(crate::runtime_impl::TokioRuntime),
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

        let err = result.unwrap_err();
        assert!(
            err.downcast_ref::<ClientError>()
                .is_some_and(|e| matches!(e, ClientError::NotLoggedIn)),
            "Error should be ClientError::NotLoggedIn, got: {}",
            err
        );

        info!("✅ test_establish_primary_phone_session_fails_without_pn passed");
    }

    /// Test that ensure_e2e_sessions waits for offline sync to complete.
    /// This is the CRITICAL difference between ensure_e2e_sessions and
    /// establish_primary_phone_session_immediate.
    #[tokio::test]
    async fn test_ensure_e2e_sessions_waits_for_offline_sync() {
        use std::sync::atomic::Ordering;
        use wacore_binary::Jid;

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
            Arc::new(crate::runtime_impl::TokioRuntime),
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
            client_clone.ensure_e2e_sessions(&[]).await
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
            let _ = client_clone.ensure_e2e_sessions(&[test_jid]).await;
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
        client.offline_sync_notifier.notify(usize::MAX);

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
        use wacore_binary::Jid;

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
            Arc::new(crate::runtime_impl::TokioRuntime),
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

    /// Integration test: Verify that establish_primary_phone_session_immediate
    /// skips establishment when a session already exists.
    ///
    /// This is the CRITICAL fix for MAC verification failures:
    /// - BUG (before fix): Called process_prekey_bundle() unconditionally,
    ///   replacing the existing session with a new one
    /// - RESULT: Remote device still uses old session state, causing MAC failures
    #[tokio::test]
    async fn test_establish_session_skips_when_exists() {
        use wacore::libsignal::protocol::SessionRecord;
        use wacore::libsignal::store::SessionStore;
        use wacore::types::jid::JidExt;
        use wacore_binary::Jid;

        let backend = Arc::new(
            crate::store::SqliteStore::new("file:memdb_skip_existing?mode=memory&cache=shared")
                .await
                .expect("Failed to create in-memory backend for test"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend.clone())
                .await
                .expect("persistence manager should initialize"),
        );

        // Set a PN so the function doesn't fail early
        let own_pn = Jid::pn("559999999999");
        pm.modify_device(|device| {
            device.pn = Some(own_pn.clone());
        })
        .await;

        // Pre-populate a session for the primary phone JID (device 0)
        let primary_phone_jid = own_pn.with_device(0);
        let signal_addr = primary_phone_jid.to_protocol_address();

        // Create a dummy session record
        let dummy_session = SessionRecord::new_fresh();
        {
            let device_arc = pm.get_device_arc().await;
            let device = device_arc.read().await;
            device
                .store_session(&signal_addr, &dummy_session)
                .await
                .expect("Failed to store test session");

            // Verify session exists
            let exists = device
                .contains_session(&signal_addr)
                .await
                .expect("Failed to check session");
            assert!(exists, "Session should exist after store");
        }

        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Call establish_primary_phone_session_immediate
        // It should return Ok(()) immediately without fetching prekeys
        let result = client.establish_primary_phone_session_immediate().await;

        assert!(
            result.is_ok(),
            "establish_primary_phone_session_immediate should succeed when session exists"
        );

        // Verify the session was NOT replaced (still has the same record)
        // This is the critical assertion - if session was replaced, it would cause MAC failures
        {
            let device_arc = pm.get_device_arc().await;
            let device = device_arc.read().await;
            let exists = device
                .contains_session(&signal_addr)
                .await
                .expect("Failed to check session");
            assert!(exists, "Session should still exist after the call");
        }

        info!("✅ test_establish_session_skips_when_exists passed");
    }

    /// Integration test: Verify that the session check prevents MAC failures
    /// by documenting the exact control flow that caused the bug.
    #[test]
    fn test_mac_failure_prevention_flow_documentation() {
        // Simulate the decision logic
        fn should_establish_session(
            check_result: Result<bool, &'static str>,
        ) -> Result<bool, String> {
            match check_result {
                Ok(true) => Ok(false), // Session exists → DON'T establish
                Ok(false) => Ok(true), // No session → establish
                Err(e) => Err(format!("Cannot verify session: {}", e)), // Fail-safe
            }
        }

        // Test Case 1: Session exists → skip (prevents MAC failure)
        let result = should_establish_session(Ok(true));
        assert_eq!(result, Ok(false), "Should skip when session exists");

        // Test Case 2: No session → establish
        let result = should_establish_session(Ok(false));
        assert_eq!(result, Ok(true), "Should establish when no session");

        // Test Case 3: Check fails → error (fail-safe)
        let result = should_establish_session(Err("database error"));
        assert!(result.is_err(), "Should fail when check fails");

        info!("✅ test_mac_failure_prevention_flow_documentation passed");
    }

    #[test]
    fn test_unified_session_id_calculation() {
        // Test the mathematical calculation of the unified session ID.
        // Formula: (now_ms + server_offset_ms + 3_days_ms) % 7_days_ms

        const DAY_MS: i64 = 24 * 60 * 60 * 1000;
        const WEEK_MS: i64 = 7 * DAY_MS;
        const OFFSET_MS: i64 = 3 * DAY_MS;

        // Helper function matching the implementation
        fn calculate_session_id(now_ms: i64, server_offset_ms: i64) -> i64 {
            let adjusted_now = now_ms + server_offset_ms;
            (adjusted_now + OFFSET_MS) % WEEK_MS
        }

        // Test 1: Zero offset
        let now_ms = 1706000000000_i64; // Some arbitrary timestamp
        let id = calculate_session_id(now_ms, 0);
        assert!(
            (0..WEEK_MS).contains(&id),
            "Session ID should be in [0, WEEK_MS)"
        );

        // Test 2: Positive server offset (server is ahead)
        let id_with_positive_offset = calculate_session_id(now_ms, 5000);
        assert!(
            (0..WEEK_MS).contains(&id_with_positive_offset),
            "Session ID should be in [0, WEEK_MS)"
        );
        // The ID should be different from zero offset (unless wrap-around)
        // Not testing exact value as it depends on the offset

        // Test 3: Negative server offset (server is behind)
        let id_with_negative_offset = calculate_session_id(now_ms, -5000);
        assert!(
            (0..WEEK_MS).contains(&id_with_negative_offset),
            "Session ID should be in [0, WEEK_MS)"
        );

        // Test 4: Verify modulo wrap-around
        // If adjusted_now + OFFSET_MS >= WEEK_MS, it should wrap
        let wrap_test_now = WEEK_MS - OFFSET_MS + 1000; // Should produce small result
        let wrapped_id = calculate_session_id(wrap_test_now, 0);
        assert_eq!(wrapped_id, 1000, "Should wrap around correctly");

        // Test 5: Edge case - at exact boundary
        let boundary_now = WEEK_MS - OFFSET_MS;
        let boundary_id = calculate_session_id(boundary_now, 0);
        assert_eq!(boundary_id, 0, "At exact boundary should be 0");
    }

    #[tokio::test]
    async fn test_server_time_offset_extraction() {
        use wacore_binary::builder::NodeBuilder;

        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Initially, offset should be 0
        assert_eq!(
            client.unified_session.server_time_offset_ms(),
            0,
            "Initial offset should be 0"
        );

        // Create a node with a 't' attribute
        let server_time = wacore::time::now_secs() + 10; // Server is 10 seconds ahead
        let node = NodeBuilder::new("success")
            .attr("t", server_time.to_string())
            .build();

        // Update the offset
        client.update_server_time_offset(&node.as_node_ref());

        // The offset should be approximately 10 * 1000 = 10000 ms
        // Allow some tolerance for timing differences during the test
        let offset = client.unified_session.server_time_offset_ms();
        assert!(
            (offset - 10000).abs() < 1000, // Allow 1 second tolerance
            "Offset should be approximately 10000ms, got {}",
            offset
        );

        // Test with no 't' attribute - should not change offset
        let node_no_t = NodeBuilder::new("success").build();
        client.update_server_time_offset(&node_no_t.as_node_ref());
        let offset_after = client.unified_session.server_time_offset_ms();
        assert!(
            (offset_after - offset).abs() < 100, // Should be same (or very close)
            "Offset should not change when 't' is missing"
        );

        // Test with invalid 't' attribute - should not change offset
        let node_invalid = NodeBuilder::new("success")
            .attr("t", "not_a_number")
            .build();
        client.update_server_time_offset(&node_invalid.as_node_ref());
        let offset_after_invalid = client.unified_session.server_time_offset_ms();
        assert!(
            (offset_after_invalid - offset).abs() < 100,
            "Offset should not change when 't' is invalid"
        );

        // Test with negative/zero 't' - should not change offset
        let node_zero = NodeBuilder::new("success").attr("t", "0").build();
        client.update_server_time_offset(&node_zero.as_node_ref());
        let offset_after_zero = client.unified_session.server_time_offset_ms();
        assert!(
            (offset_after_zero - offset).abs() < 100,
            "Offset should not change when 't' is 0"
        );

        info!("✅ test_server_time_offset_extraction passed");
    }

    #[tokio::test]
    async fn test_unified_session_manager_integration() {
        // Test the unified session manager through the client

        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Initially, sequence should be 0
        assert_eq!(
            client.unified_session.sequence(),
            0,
            "Initial sequence should be 0"
        );

        // Duplicate prevention depends on the session ID staying the same between calls.
        // Since the session ID is millisecond-based, use a retry loop to handle
        // the rare case where we cross a millisecond boundary between calls.
        loop {
            client.unified_session.reset().await;

            let result = client.unified_session.prepare_send().await;
            assert!(result.is_some(), "First send should succeed");
            let (node, seq) = result.unwrap();
            assert_eq!(node.tag, "ib", "Should be an IB stanza");
            assert_eq!(seq, 1, "First sequence should be 1 (pre-increment)");
            assert_eq!(client.unified_session.sequence(), 1);

            let result2 = client.unified_session.prepare_send().await;
            if result2.is_none() {
                // Duplicate was prevented within the same millisecond
                assert_eq!(client.unified_session.sequence(), 1);
                break;
            }
            // Millisecond boundary crossed, retry
            tokio::task::yield_now().await;
        }

        // Clear last sent and try again - sequence resets on "new" session ID
        client.unified_session.clear_last_sent().await;
        let result3 = client.unified_session.prepare_send().await;
        assert!(result3.is_some(), "Should succeed after clearing");
        let (_, seq3) = result3.unwrap();
        assert_eq!(seq3, 1, "Sequence resets when session ID changes");
        assert_eq!(client.unified_session.sequence(), 1);

        info!("✅ test_unified_session_manager_integration passed");
    }

    #[test]
    fn test_unified_session_protocol_node() {
        // Test the type-safe protocol node implementation
        use wacore::ib::{IbStanza, UnifiedSession};
        use wacore::protocol::ProtocolNode;

        // Create a unified session
        let session = UnifiedSession::new("123456789");
        assert_eq!(session.id, "123456789");
        assert_eq!(session.tag(), "unified_session");

        // Convert to node
        let node = session.into_node();
        assert_eq!(node.tag, "unified_session");
        assert!(node.attrs.get("id").is_some_and(|v| v == "123456789"));

        // Create an IB stanza
        let stanza = IbStanza::unified_session(UnifiedSession::new("987654321"));
        assert_eq!(stanza.tag(), "ib");

        // Convert to node and verify structure
        let ib_node = stanza.into_node();
        assert_eq!(ib_node.tag, "ib");
        let children = ib_node.children().expect("IB stanza should have children");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "unified_session");
        assert!(
            children[0]
                .attrs
                .get("id")
                .is_some_and(|v| v == "987654321")
        );

        info!("✅ test_unified_session_protocol_node passed");
    }

    fn node_to_owned_ref(node: Node) -> Arc<wacore_binary::OwnedNodeRef> {
        crate::test_utils::node_to_owned_ref(&node)
    }

    /// Helper to create a test client for offline sync tests
    async fn create_offline_sync_test_client() -> Arc<Client> {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;
        client
    }

    #[tokio::test]
    async fn test_ib_thread_metadata_does_not_end_sync() {
        let client = create_offline_sync_test_client().await;
        client
            .offline_sync_metrics
            .active
            .store(true, Ordering::Release);

        let node = NodeBuilder::new("ib")
            .children([NodeBuilder::new("thread_metadata")
                .children([NodeBuilder::new("item").build()])
                .build()])
            .build();

        client.process_node(node_to_owned_ref(node)).await;
        assert!(
            client.offline_sync_metrics.active.load(Ordering::Acquire),
            "<ib><thread_metadata> should NOT end offline sync"
        );
    }

    #[tokio::test]
    async fn test_ib_edge_routing_does_not_end_sync() {
        let client = create_offline_sync_test_client().await;
        client
            .offline_sync_metrics
            .active
            .store(true, Ordering::Release);

        let node = NodeBuilder::new("ib")
            .children([NodeBuilder::new("edge_routing")
                .children([NodeBuilder::new("routing_info")
                    .bytes(vec![1, 2, 3])
                    .build()])
                .build()])
            .build();

        client.process_node(node_to_owned_ref(node)).await;
        assert!(
            client.offline_sync_metrics.active.load(Ordering::Acquire),
            "<ib><edge_routing> should NOT end offline sync"
        );
    }

    #[tokio::test]
    async fn test_ib_dirty_does_not_end_sync() {
        let client = create_offline_sync_test_client().await;
        client
            .offline_sync_metrics
            .active
            .store(true, Ordering::Release);

        let node = NodeBuilder::new("ib")
            .children([NodeBuilder::new("dirty")
                .attr("type", "groups")
                .attr("timestamp", "1234")
                .build()])
            .build();

        client.process_node(node_to_owned_ref(node)).await;
        assert!(
            client.offline_sync_metrics.active.load(Ordering::Acquire),
            "<ib><dirty> should NOT end offline sync"
        );
    }

    #[tokio::test]
    async fn test_ib_offline_child_ends_sync() {
        let client = create_offline_sync_test_client().await;
        client
            .offline_sync_metrics
            .active
            .store(true, Ordering::Release);
        client
            .offline_sync_metrics
            .total_messages
            .store(301, Ordering::Release);

        let node = NodeBuilder::new("ib")
            .children([NodeBuilder::new("offline").attr("count", "301").build()])
            .build();

        client.process_node(node_to_owned_ref(node)).await;
        assert!(
            !client.offline_sync_metrics.active.load(Ordering::Acquire),
            "<ib><offline count='301'/> should end offline sync"
        );
    }

    #[tokio::test]
    async fn test_ib_offline_preview_starts_sync() {
        let client = create_offline_sync_test_client().await;

        let node = NodeBuilder::new("ib")
            .children([NodeBuilder::new("offline_preview")
                .attr("count", "301")
                .attr("message", "168")
                .attr("notification", "62")
                .attr("receipt", "68")
                .attr("appdata", "0")
                .build()])
            .build();

        client.process_node(node_to_owned_ref(node)).await;
        assert!(
            client.offline_sync_metrics.active.load(Ordering::Acquire),
            "offline_preview with count>0 should activate sync"
        );
        assert_eq!(
            client
                .offline_sync_metrics
                .total_messages
                .load(Ordering::Acquire),
            301
        );
    }

    #[tokio::test]
    async fn test_offline_message_increments_processed() {
        let client = create_offline_sync_test_client().await;
        client
            .offline_sync_metrics
            .active
            .store(true, Ordering::Release);
        client
            .offline_sync_metrics
            .total_messages
            .store(100, Ordering::Release);

        let node = NodeBuilder::new("message")
            .attr("offline", "1")
            .attr("from", "5551234567@s.whatsapp.net")
            .attr("id", "TEST123")
            .attr("t", "1772884671")
            .attr("type", "text")
            .build();

        client.process_node(node_to_owned_ref(node)).await;
        assert_eq!(
            client
                .offline_sync_metrics
                .processed_messages
                .load(Ordering::Acquire),
            1,
            "offline message should increment processed count"
        );
    }

    // ---------------------------------------------------------------
    // Server-initiated ping detection tests
    //
    // The WhatsApp server can send pings in two formats:
    //
    // 1. Child-element format (legacy/whatsmeow style):
    //    <iq type="get" from="s.whatsapp.net" id="...">
    //      <ping/>
    //    </iq>
    //
    // 2. xmlns-attribute format (real WhatsApp Web format):
    //    <iq from="s.whatsapp.net" t="..." type="get" xmlns="urn:xmpp:ping"/>
    //    This is a self-closing tag with NO child elements.
    //    Verified against captured WhatsApp Web JS (WAWebCommsHandleStanza):
    //      if (t.xmlns === "urn:xmpp:ping") return wap("iq", { type: "result", to: t.from });
    //
    // Both must be recognized and answered with a pong, otherwise the
    // server considers the client dead and stops responding to keepalive
    // pings — causing a timeout cascade and forced reconnect.
    // ---------------------------------------------------------------

    #[tokio::test]
    async fn test_handle_iq_ping_with_child_element() {
        // Format 1: <iq type="get"><ping/></iq> — the legacy format with a <ping> child node.
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let ping_node = NodeBuilder::new("iq")
            .attr("type", "get")
            .attr("from", SERVER_JID)
            .attr("id", "ping-child-1")
            .children([NodeBuilder::new("ping").build()])
            .build();

        let handled = client.handle_iq(&ping_node.as_node_ref()).await;
        assert!(
            handled,
            "handle_iq must recognize ping with <ping> child element"
        );
    }

    #[tokio::test]
    async fn test_handle_iq_ping_with_xmlns_attribute() {
        // Format 2: <iq type="get" xmlns="urn:xmpp:ping"/> — the real WhatsApp Web format.
        // This is a self-closing IQ with NO children, only an xmlns attribute.
        // The server sends this format; failing to respond causes keepalive timeout cascade.
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let ping_node = NodeBuilder::new("iq")
            .attr("type", "get")
            .attr("from", SERVER_JID)
            .attr("id", "ping-xmlns-1")
            .attr("xmlns", "urn:xmpp:ping")
            .build();

        let handled = client.handle_iq(&ping_node.as_node_ref()).await;
        assert!(
            handled,
            "handle_iq must recognize ping with xmlns=\"urn:xmpp:ping\" attribute (no children)"
        );
    }

    #[tokio::test]
    async fn test_handle_iq_ping_with_both_child_and_xmlns() {
        // Edge case: node has BOTH a <ping> child AND xmlns="urn:xmpp:ping".
        // Should still be handled (OR condition).
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let ping_node = NodeBuilder::new("iq")
            .attr("type", "get")
            .attr("from", SERVER_JID)
            .attr("id", "ping-both-1")
            .attr("xmlns", "urn:xmpp:ping")
            .children([NodeBuilder::new("ping").build()])
            .build();

        let handled = client.handle_iq(&ping_node.as_node_ref()).await;
        assert!(
            handled,
            "handle_iq must handle ping with both child and xmlns"
        );
    }

    #[tokio::test]
    async fn test_handle_iq_non_ping_returns_false() {
        // A type="get" IQ without ping child or xmlns should NOT be handled as ping.
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let non_ping_node = NodeBuilder::new("iq")
            .attr("type", "get")
            .attr("from", SERVER_JID)
            .attr("id", "not-a-ping")
            .attr("xmlns", "some:other:namespace")
            .build();

        let handled = client.handle_iq(&non_ping_node.as_node_ref()).await;
        assert!(
            !handled,
            "handle_iq must NOT treat non-ping xmlns as a ping"
        );
    }

    #[tokio::test]
    async fn test_handle_iq_ping_wrong_type_returns_false() {
        // xmlns="urn:xmpp:ping" but type="result" (not "get") — should NOT be handled as ping.
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let result_node = NodeBuilder::new("iq")
            .attr("type", "result")
            .attr("from", SERVER_JID)
            .attr("id", "ping-result-1")
            .attr("xmlns", "urn:xmpp:ping")
            .build();

        let handled = client.handle_iq(&result_node.as_node_ref()).await;
        assert!(
            !handled,
            "handle_iq must NOT respond to type=\"result\" even with ping xmlns"
        );
    }

    // ── build_pong tests ──────────────────────────────────────────────

    #[test]
    fn test_build_pong_with_id() {
        let pong = build_pong("s.whatsapp.net".to_string(), Some("ping-123"));
        assert!(
            pong.attrs.get("id").is_some_and(|v| v == "ping-123"),
            "pong should include id when server ping has one"
        );
        assert!(pong.attrs.get("type").is_some_and(|v| v == "result"));
        assert!(pong.attrs.get("to").is_some_and(|v| v == "s.whatsapp.net"));
    }

    #[test]
    fn test_build_pong_without_id() {
        let pong = build_pong("s.whatsapp.net".to_string(), None);
        assert!(
            !pong.attrs.contains_key("id"),
            "pong should NOT include id when server ping has none"
        );
        assert!(pong.attrs.get("type").is_some_and(|v| v == "result"));
    }

    #[test]
    fn test_encrypt_identity_notification_omits_type() {
        let node = NodeBuilder::new("notification")
            .attr("from", "186303081611421@lid")
            .attr("id", "4128735301")
            .attr("type", "encrypt")
            .children([NodeBuilder::new("identity").build()])
            .build();

        assert!(
            is_encrypt_identity_notification(&node.as_node_ref()),
            "identity-change notification ACK must omit type to match WA Web"
        );
    }

    #[test]
    fn test_device_notification_is_not_encrypt_identity() {
        let node = NodeBuilder::new("notification")
            .attr("from", "186303081611421@lid")
            .attr("id", "269488578")
            .attr("type", "devices")
            .children([NodeBuilder::new("remove").build()])
            .build();

        assert!(
            !is_encrypt_identity_notification(&node.as_node_ref()),
            "device notification is not an encrypt+identity notification"
        );
    }

    #[test]
    fn test_build_ack_node_for_message_omits_type_includes_from() {
        // Whatsmeow: message acks do NOT echo type (node.Tag != "message" guard).
        // They DO include `from` with own device PN.
        let incoming = NodeBuilder::new("message")
            .attr("from", "120363161500776365@g.us")
            .attr("id", "A5791A5392EF60E3FB0670098DE010D4")
            .attr("type", "text")
            .attr("participant", "181531758878822@lid")
            .build();
        let own_device_pn: Jid = "155500012345:48@s.whatsapp.net"
            .parse()
            .expect("own device PN JID should parse");

        let ack = build_ack_node(&incoming.as_node_ref(), Some(&own_device_pn))
            .expect("message ack should be buildable");

        assert_eq!(ack.tag, "ack");
        // Use PartialEq<str> on NodeValue — works for both String and Jid variants
        // without allocation, so tests don't depend on internal representation.
        assert!(ack.attrs.get("class").is_some_and(|v| v == "message"));
        assert!(
            ack.attrs
                .get("to")
                .is_some_and(|v| v == "120363161500776365@g.us")
        );
        assert!(
            ack.attrs
                .get("from")
                .is_some_and(|v| v == "155500012345:48@s.whatsapp.net")
        );
        assert!(
            ack.attrs
                .get("participant")
                .is_some_and(|v| v == "181531758878822@lid")
        );
        assert!(
            !ack.attrs.contains_key("type"),
            "message ACK must NOT echo type (matches whatsmeow behavior)"
        );
    }

    #[test]
    fn test_build_ack_node_for_identity_change_omits_type_and_from() {
        let incoming = NodeBuilder::new("notification")
            .attr("from", "186303081611421@lid")
            .attr("id", "4128735301")
            .attr("type", "encrypt")
            .children([NodeBuilder::new("identity").build()])
            .build();
        let own_device_pn: Jid = "155500012345:48@s.whatsapp.net"
            .parse()
            .expect("own device PN JID should parse");

        let ack = build_ack_node(&incoming.as_node_ref(), Some(&own_device_pn))
            .expect("notification ack should be buildable");

        assert!(ack.attrs.get("class").is_some_and(|v| v == "notification"));
        assert!(
            !ack.attrs.contains_key("type"),
            "identity-change notification ACK must omit type"
        );
        assert!(
            !ack.attrs.contains_key("from"),
            "notification ACKs should not include our device PN"
        );
    }

    #[test]
    fn test_build_ack_node_for_receipt_with_type_echoes_type() {
        // Receipt acks should echo the type attribute when present (e.g. "read", "played").
        let incoming = NodeBuilder::new("receipt")
            .attr("from", "156535032389744@lid")
            .attr("id", "RCPT-WITH-TYPE")
            .attr("type", "read")
            .build();
        let own_device_pn: Jid = "155500012345:48@s.whatsapp.net"
            .parse()
            .expect("own device PN JID should parse");

        let ack = build_ack_node(&incoming.as_node_ref(), Some(&own_device_pn))
            .expect("receipt ack should be buildable");

        assert!(ack.attrs.get("class").is_some_and(|v| v == "receipt"));
        assert!(
            ack.attrs.get("type").is_some_and(|v| v == "read"),
            "receipt ACK must echo the type attribute when present"
        );
        assert!(
            !ack.attrs.contains_key("from"),
            "receipt ACKs should not include our device PN"
        );
    }

    #[test]
    fn test_build_ack_node_for_receipt_without_type_omits_type() {
        // Delivery receipts have no type attribute — the ack must also omit it.
        // Sending type="delivery" in the ack causes stream:error disconnections.
        let incoming = NodeBuilder::new("receipt")
            .attr("from", "156535032389744@lid")
            .attr("id", "RCPT-NO-TYPE")
            .build();
        let own_device_pn: Jid = "155500012345:48@s.whatsapp.net"
            .parse()
            .expect("own device PN JID should parse");

        let ack = build_ack_node(&incoming.as_node_ref(), Some(&own_device_pn))
            .expect("receipt ack should be buildable");

        assert!(ack.attrs.get("class").is_some_and(|v| v == "receipt"));
        assert!(
            !ack.attrs.contains_key("type"),
            "receipt ACK must NOT contain type when the incoming receipt has no type attribute"
        );
        assert!(
            !ack.attrs.contains_key("from"),
            "receipt ACKs should not include our device PN"
        );
    }

    /// Smoke test: server ping with xmlns but no id attribute is handled.
    #[tokio::test]
    async fn test_handle_iq_ping_without_id() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Server ping without id — real format observed in production logs
        let ping_node = NodeBuilder::new("iq")
            .attr("type", "get")
            .attr("from", SERVER_JID)
            .attr("xmlns", "urn:xmpp:ping")
            .build();

        let handled = client.handle_iq(&ping_node.as_node_ref()).await;
        assert!(
            handled,
            "handle_iq must recognize ping without id attribute"
        );
    }

    // ── fibonacci_backoff tests ────────────────────────────────────────

    #[test]
    fn test_fibonacci_backoff_sequence() {
        // WA Web: first=1000, second=1000 → 1,1,2,3,5,8,13,21,34,55,89,144...s
        // We test base values without jitter by checking the range (±10%).
        let expected_base_ms = [1000, 1000, 2000, 3000, 5000, 8000, 13000, 21000];
        for (attempt, &base) in expected_base_ms.iter().enumerate() {
            let delay = fibonacci_backoff(attempt as u32);
            let ms = delay.as_millis() as u64;
            let low = base - base / 10;
            let high = base + base / 10;
            assert!(
                ms >= low && ms <= high,
                "attempt {attempt}: expected {low}..={high}ms, got {ms}ms"
            );
        }
    }

    #[test]
    fn test_fibonacci_backoff_max_900s() {
        // After many attempts, should cap at 900s (±10%)
        let delay = fibonacci_backoff(100);
        let ms = delay.as_millis() as u64;
        assert!(
            ms <= 990_000,
            "should never exceed 900s + 10% jitter, got {ms}ms"
        );
        assert!(
            ms >= 810_000,
            "should be at least 900s - 10% jitter, got {ms}ms"
        );
    }

    #[test]
    fn test_fibonacci_backoff_first_attempt_is_1s() {
        let delay = fibonacci_backoff(0);
        let ms = delay.as_millis() as u64;
        assert!(
            (900..=1100).contains(&ms),
            "first attempt should be ~1s (±10%), got {ms}ms"
        );
    }

    // ── stream error tests ─────────────────────────────────────────────

    #[tokio::test]
    async fn test_stream_error_401_disables_reconnect() {
        let client = create_offline_sync_test_client().await;
        let node = NodeBuilder::new("stream:error").attr("code", "401").build();
        client.handle_stream_error(&node.as_node_ref()).await;
        assert!(
            !client.enable_auto_reconnect.load(Ordering::Relaxed),
            "401 should disable auto-reconnect"
        );
    }

    #[tokio::test]
    async fn test_stream_error_409_disables_reconnect() {
        let client = create_offline_sync_test_client().await;
        let node = NodeBuilder::new("stream:error").attr("code", "409").build();
        client.handle_stream_error(&node.as_node_ref()).await;
        assert!(
            !client.enable_auto_reconnect.load(Ordering::Relaxed),
            "409 should disable auto-reconnect"
        );
    }

    #[tokio::test]
    async fn test_stream_error_429_keeps_reconnect_with_backoff() {
        let client = create_offline_sync_test_client().await;
        let before = client.auto_reconnect_errors.load(Ordering::Relaxed);
        let node = NodeBuilder::new("stream:error").attr("code", "429").build();
        client.handle_stream_error(&node.as_node_ref()).await;
        assert!(
            client.enable_auto_reconnect.load(Ordering::Relaxed),
            "429 should keep auto-reconnect enabled"
        );
        let after = client.auto_reconnect_errors.load(Ordering::Relaxed);
        assert_eq!(
            after,
            before + 5,
            "429 should increase backoff by exactly 5: before={before}, after={after}"
        );
    }

    #[tokio::test]
    async fn test_stream_error_503_keeps_reconnect() {
        let client = create_offline_sync_test_client().await;
        let node = NodeBuilder::new("stream:error").attr("code", "503").build();
        client.handle_stream_error(&node.as_node_ref()).await;
        assert!(
            client.enable_auto_reconnect.load(Ordering::Relaxed),
            "503 should keep auto-reconnect enabled"
        );
    }

    #[tokio::test]
    async fn test_custom_cache_config_is_respected() {
        use crate::cache_config::{CacheConfig, CacheEntryConfig};
        use std::time::Duration;

        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );

        let custom_config = CacheConfig {
            group_cache: CacheEntryConfig::new(Some(Duration::from_secs(60)), 10),
            device_registry_cache: CacheEntryConfig::new(Some(Duration::from_secs(60)), 10),
            ..CacheConfig::default()
        };

        // Verify that constructing a client with a custom config does not panic
        // and the client is usable.
        let (client, _rx) = Client::new_with_cache_config(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
            custom_config,
        )
        .await;

        assert!(!client.is_logged_in());
    }

    /// Proves that `is_connected()` no longer gives false negatives under mutex
    /// contention. Before the fix, `try_lock()` would fail when another task held
    /// the noise_socket mutex, causing `is_connected()` to return `false` even
    /// though the connection was alive — silently dropping receipt acks.
    ///
    /// This test sets up a real NoiseSocket (same as socket unit tests) so it
    /// accurately models the pre-fix scenario: socket is Some + mutex is held
    /// by another task = old is_connected() returned false.
    #[tokio::test]
    async fn test_is_connected_not_affected_by_mutex_contention() {
        use crate::socket::NoiseSocket;
        use wacore::handshake::NoiseCipher;

        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Initially not connected
        assert!(!client.is_connected(), "should start disconnected");

        // Simulate a real connection: create a NoiseSocket and store it
        let transport: Arc<dyn crate::transport::Transport> =
            Arc::new(crate::transport::mock::MockTransport);
        let key = [0u8; 32];
        let write_key = NoiseCipher::new(&key).expect("valid key");
        let read_key = NoiseCipher::new(&key).expect("valid key");
        let noise_socket = NoiseSocket::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            transport,
            write_key,
            read_key,
        );
        *client.noise_socket.lock().await = Some(Arc::new(noise_socket));
        client.is_connected.store(true, Ordering::Release);

        assert!(client.is_connected(), "should report connected");

        // Hold the noise_socket mutex — this used to make is_connected() return
        // false via try_lock() even though the socket was Some(...)
        let _guard = client.noise_socket.lock().await;
        assert!(
            client.is_connected(),
            "is_connected() must return true even while noise_socket mutex is held"
        );
    }

    /// Verifies that `send_ack_for` returns an error (not silent Ok) when
    /// disconnected. This ensures the caller's `warn!` fires so dropped acks
    /// are visible in logs.
    #[tokio::test]
    async fn test_send_ack_for_returns_error_when_disconnected() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Not connected — send_ack_for should return Err, not Ok
        let receipt = NodeBuilder::new("receipt")
            .attr("from", "120363040237990503@g.us")
            .attr("id", "TEST-RECEIPT-ID")
            .attr("participant", "236395184570386@lid")
            .build();

        let result = client.send_ack_for(&receipt.as_node_ref()).await;
        assert!(
            matches!(result, Err(ClientError::NotConnected)),
            "send_ack_for must return Err(NotConnected) when disconnected, got: {result:?}"
        );
    }

    /// Verifies that `send_ack_for` returns Ok when expected_disconnect is set,
    /// since this is an intentional shutdown path.
    #[tokio::test]
    async fn test_send_ack_for_returns_ok_on_expected_disconnect() {
        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        // Set expected disconnect — send_ack_for should gracefully return Ok
        client.expected_disconnect.store(true, Ordering::Relaxed);

        let receipt = NodeBuilder::new("receipt")
            .attr("from", "120363040237990503@g.us")
            .attr("id", "TEST-RECEIPT-ID")
            .build();

        let result = client.send_ack_for(&receipt.as_node_ref()).await;
        assert!(
            result.is_ok(),
            "send_ack_for should return Ok during expected disconnect"
        );
    }

    // Per-connection notify must NOT set the terminal sticky flag; if it did,
    // every reconnect would instantly abort subscribers registered on the
    // terminal signal. Regression guard for the CI breakage observed on PR #560.
    #[tokio::test]
    async fn per_connection_notify_leaves_terminal_signal_untouched() {
        let client = crate::test_utils::create_test_client().await;

        client.notify_connection_shutdown();

        assert!(
            !client.shutdown_signal().is_fired(),
            "terminal shutdown must stay clean when only per-connection fires"
        );
    }

    // Subscribers registered AFTER a reset must not see the previous
    // notifier's fired state. This is the core property that makes reconnect
    // work: after cleanup_connection_state notifies the per-connection
    // signal, the next connection replaces it with a fresh one.
    #[tokio::test]
    async fn reset_gives_fresh_per_connection_notifier() {
        let client = crate::test_utils::create_test_client().await;

        client.notify_connection_shutdown();
        assert!(
            client.connection_shutdown_signal().is_fired(),
            "subscriber BEFORE reset sees the notify on the current notifier"
        );

        client.reset_connection_shutdown();

        assert!(
            !client.connection_shutdown_signal().is_fired(),
            "subscribers AFTER reset must NOT see the previous notifier's state"
        );
    }

    // Capture-once regression guard: a ShutdownSignal captured before a reset
    // must keep observing the pre-reset fired state. Without this, a
    // reconnect after the old notifier is replaced in the Mutex would
    // strand long-lived tasks (e.g. keepalive) on a new notifier they
    // never registered for. See keepalive_loop which captures its signal
    // once at task startup.
    #[tokio::test]
    async fn captured_signal_keeps_observing_old_notifier_after_reset() {
        let client = crate::test_utils::create_test_client().await;

        let captured = client.connection_shutdown_signal();
        client.notify_connection_shutdown();
        client.reset_connection_shutdown();

        assert!(
            captured.is_fired(),
            "captured signal must retain the pre-reset notifier's fired state"
        );
    }

    // Terminal disconnect() must also wake per-connection subscribers via
    // cleanup_connection_state, so keepalive/request/read loop exit promptly.
    #[tokio::test]
    async fn terminal_disconnect_propagates_to_per_connection_signal() {
        let client = crate::test_utils::create_test_client().await;
        let conn_signal = client.connection_shutdown_signal();

        client.disconnect().await;

        assert!(
            conn_signal.is_fired(),
            "disconnect must fire per-connection via cleanup_connection_state"
        );
        assert!(
            client.shutdown_signal().is_fired(),
            "disconnect must also fire terminal"
        );
    }
}
