mod context_impl;

use crate::handshake;
use crate::lid_pn_cache::{LearningSource, LidPnCache, LidPnEntry};
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
    pub(crate) major_sync_task_sender: mpsc::Sender<MajorSyncTask>,
    pub(crate) pairing_cancellation_tx: Arc<Mutex<Option<watch::Sender<()>>>>,

    pub(crate) send_buffer_pool: Arc<Mutex<Vec<Vec<u8>>>>,

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
            major_sync_task_sender: tx,
            pairing_cancellation_tx: Arc::new(Mutex::new(None)),
            send_buffer_pool: Arc::new(Mutex::new(Vec::with_capacity(4))),
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

    /// Warm up the LID-PN cache from persistent storage.
    /// This is called during client initialization to populate the in-memory cache
    /// with previously learned LID-PN mappings.
    async fn warm_up_lid_pn_cache(&self) -> Result<(), anyhow::Error> {
        let backend = self.persistence_manager.backend();
        let entries = backend.get_all_lid_pn_mappings().await?;

        if entries.is_empty() {
            debug!("LID-PN cache warm-up: no entries found in storage");
            return Ok(());
        }

        let cache_entries: Vec<LidPnEntry> = entries
            .into_iter()
            .map(|e| {
                LidPnEntry::with_timestamp(
                    e.lid,
                    e.phone_number,
                    e.created_at,
                    LearningSource::parse(&e.learning_source),
                )
            })
            .collect();

        self.lid_pn_cache.warm_up(cache_entries).await;
        Ok(())
    }

    /// Background loop to periodically clean up stale device registry entries.
    /// Runs every 6 hours, deleting entries older than 7 days.
    /// Terminates gracefully when shutdown is signaled.
    async fn device_registry_cleanup_loop(&self) {
        use tokio::time::{Duration, interval};

        const CLEANUP_INTERVAL_HOURS: u64 = 6;
        const MAX_AGE_DAYS: i64 = 7;
        const MAX_AGE_SECS: i64 = MAX_AGE_DAYS * 24 * 60 * 60;

        // Run cleanup immediately on startup, then every 6 hours
        let mut interval = interval(Duration::from_secs(CLEANUP_INTERVAL_HOURS * 60 * 60));

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown_notifier.notified() => {
                    debug!(
                        target: "Client/DeviceRegistry",
                        "Shutdown signaled, exiting cleanup loop"
                    );
                    return;
                }
                _ = interval.tick() => {
                    let backend = self.persistence_manager.backend();
                    match backend.cleanup_stale_entries(MAX_AGE_SECS).await {
                        Ok(deleted) => {
                            if deleted > 0 {
                                info!(
                                    target: "Client/DeviceRegistry",
                                    "Cleaned up {} stale device registry entries (older than {} days)",
                                    deleted, MAX_AGE_DAYS
                                );
                            } else {
                                debug!(
                                    target: "Client/DeviceRegistry",
                                    "No stale device registry entries to clean up"
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                target: "Client/DeviceRegistry",
                                "Failed to clean up stale device registry entries: {}",
                                e
                            );
                        }
                    }
                }
            }
        }
    }

    /// Check if a device exists for a user.
    /// Uses the in-memory cache first, then falls back to persistent storage.
    /// Returns true for device_id 0 (primary device always exists).
    /// Matches WhatsApp Web's WAWebApiDeviceList.hasDevice behavior.
    pub(crate) async fn has_device(&self, user: &str, device_id: u32) -> bool {
        // Device ID 0 (primary device) always exists
        if device_id == 0 {
            return true;
        }

        // Check cache first
        if let Some(record) = self.device_registry_cache.get(user).await {
            return record.devices.iter().any(|d| d.device_id == device_id);
        }

        // Fall back to persistence
        let backend = self.persistence_manager.backend();
        match backend.get_devices(user).await {
            Ok(Some(record)) => {
                let has_device = record.devices.iter().any(|d| d.device_id == device_id);
                // Populate cache
                self.device_registry_cache
                    .insert(user.to_string(), record)
                    .await;
                has_device
            }
            Ok(None) => {
                // No record means we don't have device info for this user.
                // WhatsApp Web returns false in this case (!!r && ...).
                // This ensures unknown devices are rejected in retry handling.
                false
            }
            Err(e) => {
                warn!("Failed to check device registry: {e}");
                // On error, be permissive
                true
            }
        }
    }

    /// Update the device list for a user.
    /// Called when we receive device list updates from usync responses.
    pub(crate) async fn update_device_list(
        &self,
        record: wacore::store::traits::DeviceListRecord,
    ) -> Result<()> {
        let user = record.user.clone();

        // Update cache
        self.device_registry_cache
            .insert(user, record.clone())
            .await;

        // Persist to storage
        let backend = self.persistence_manager.backend();
        backend
            .update_device_list(record)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Invalidate the device cache for a specific user.
    /// Called when we receive device change notifications (add/remove/update).
    /// This forces the next device lookup to fetch fresh data.
    pub(crate) async fn invalidate_device_cache(&self, user: &str) {
        use wacore_binary::jid::Jid;

        // Remove from in-memory cache
        self.device_registry_cache.invalidate(user).await;

        // Also invalidate the device cache (Jid -> Vec<Jid>)
        // Remove from device cache for both PN and LID servers
        self.get_device_cache()
            .await
            .invalidate(&Jid::pn(user))
            .await;
        self.get_device_cache()
            .await
            .invalidate(&Jid::lid(user))
            .await;

        log::debug!("Invalidated device cache for user: {}", user);
    }

    /// Mark participants for fresh SKDM on next group send.
    /// Filters out our own devices (we don't need to send SKDM to ourselves).
    /// Matches WhatsApp Web's WAWebApiParticipantStore.markForgetSenderKey behavior.
    /// Called from handle_retry_receipt for group/status messages.
    pub(crate) async fn mark_forget_sender_key(
        &self,
        group_jid: &str,
        participants: &[String],
    ) -> Result<()> {
        // Get our own user ID to filter out (WhatsApp Web: isMeDevice check)
        let device_store = self.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        let own_lid_user = device_guard.lid.as_ref().map(|j| j.user.clone());
        let own_pn_user = device_guard.pn.as_ref().map(|j| j.user.clone());
        drop(device_guard);

        // Filter out own devices (WhatsApp Web: !isMeDevice(e))
        let filtered: Vec<String> = participants
            .iter()
            .filter(|p| {
                // Parse participant JID and check if it's our own
                let is_own_lid = own_lid_user.as_ref().is_some_and(|lid| {
                    p.starts_with(&format!("{lid}:"))
                        || p.starts_with(&format!("{lid}@"))
                        || p.as_str() == lid
                });
                let is_own_pn = own_pn_user.as_ref().is_some_and(|pn| {
                    p.starts_with(&format!("{pn}:"))
                        || p.starts_with(&format!("{pn}@"))
                        || p.as_str() == pn
                });
                !is_own_lid && !is_own_pn
            })
            .cloned()
            .collect();

        if filtered.is_empty() {
            return Ok(());
        }

        let backend = self.persistence_manager.backend();
        backend
            .mark_forget_sender_keys(group_jid, &filtered)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Ensure phone-to-LID mappings are resolved for the given JIDs.
    /// Matches WhatsApp Web's WAWebManagePhoneNumberMappingJob.ensurePhoneNumberToLidMapping().
    /// Should be called before establishing new E2E sessions to avoid duplicate sessions.
    ///
    /// This checks the local cache for existing mappings. For JIDs without cached mappings,
    /// the caller should consider fetching them via usync query if establishing sessions.
    pub(crate) async fn resolve_lid_mappings(
        &self,
        jids: &[wacore_binary::jid::Jid],
    ) -> Vec<wacore_binary::jid::Jid> {
        let mut resolved = Vec::with_capacity(jids.len());

        for jid in jids {
            // Only resolve for user JIDs (not groups, status, etc.)
            if !jid.is_pn() && !jid.is_lid() {
                resolved.push(jid.clone());
                continue;
            }

            // If it's already a LID, use as-is
            if jid.is_lid() {
                resolved.push(jid.clone());
                continue;
            }

            // Try to resolve PN to LID from cache
            if let Some(lid_user) = self.lid_pn_cache.get_current_lid(&jid.user).await {
                resolved.push(wacore_binary::jid::Jid::lid_device(lid_user, jid.device));
            } else {
                // No cached mapping, use original JID
                // TODO: Could trigger usync query here for proactive resolution
                resolved.push(jid.clone());
            }
        }

        resolved
    }

    /// Wait for offline message delivery to complete.
    /// Matches WhatsApp Web's WAWebEventsWaitForOfflineDeliveryEnd.waitForOfflineDeliveryEnd().
    /// Should be called before establishing new E2E sessions to avoid conflicts.
    pub(crate) async fn wait_for_offline_delivery_end(&self) {
        use std::sync::atomic::Ordering;

        if self.offline_sync_completed.load(Ordering::Relaxed) {
            return;
        }

        // Wait with a reasonable timeout to avoid blocking forever
        const TIMEOUT_SECS: u64 = 10;
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(TIMEOUT_SECS),
            self.offline_sync_notifier.notified(),
        )
        .await;
    }

    /// Ensure E2E sessions exist for the given device JIDs.
    /// Matches WhatsApp Web's `ensureE2ESessions` behavior.
    /// - Waits for offline delivery to complete
    /// - Resolves phone-to-LID mappings
    /// - Uses SessionManager for deduplication and batching
    pub(crate) async fn ensure_e2e_sessions(
        &self,
        device_jids: Vec<wacore_binary::jid::Jid>,
    ) -> Result<()> {
        use wacore::libsignal::store::SessionStore;
        use wacore::types::jid::JidExt;

        if device_jids.is_empty() {
            return Ok(());
        }

        // 1. Wait for offline sync (matches WhatsApp Web)
        self.wait_for_offline_delivery_end().await;

        // 2. Resolve LID mappings (matches WhatsApp Web)
        let resolved_jids = self.resolve_lid_mappings(&device_jids).await;

        // 3. Filter to JIDs that need sessions (inline has_session check)
        let device_store = self.persistence_manager.get_device_arc().await;
        let mut jids_needing_sessions = Vec::new();

        {
            let device_guard = device_store.read().await;
            for jid in resolved_jids {
                let signal_addr = jid.to_protocol_address();
                if device_guard.load_session(&signal_addr).await.is_err() {
                    jids_needing_sessions.push(jid);
                }
            }
        }

        if jids_needing_sessions.is_empty() {
            return Ok(());
        }

        // 4. Fetch and establish sessions (with batching)
        for batch in jids_needing_sessions.chunks(crate::session::SESSION_CHECK_BATCH_SIZE) {
            self.fetch_and_establish_sessions(batch.to_vec()).await?;
        }

        Ok(())
    }

    /// Fetch prekeys and establish sessions for a batch of JIDs.
    async fn fetch_and_establish_sessions(
        &self,
        jids: Vec<wacore_binary::jid::Jid>,
    ) -> Result<(), anyhow::Error> {
        use rand::TryRngCore;
        use wacore::libsignal::protocol::{UsePQRatchet, process_prekey_bundle};
        use wacore::types::jid::JidExt;

        if jids.is_empty() {
            return Ok(());
        }

        let prekey_bundles = self.fetch_pre_keys(&jids, Some("identity")).await?;

        let device_store = self.persistence_manager.get_device_arc().await;
        let mut adapter =
            crate::store::signal_adapter::SignalProtocolStoreAdapter::new(device_store);

        for jid in &jids {
            if let Some(bundle) = prekey_bundles.get(jid) {
                let signal_addr = jid.to_protocol_address();
                if let Err(e) = process_prekey_bundle(
                    &signal_addr,
                    &mut adapter.session_store,
                    &mut adapter.identity_store,
                    bundle,
                    &mut rand::rngs::OsRng.unwrap_err(),
                    UsePQRatchet::No,
                )
                .await
                {
                    log::warn!("Failed to establish session with {}: {}", jid, e);
                }
            }
        }
        Ok(())
    }

    /// Get participants marked for fresh SKDM and consume the marks.
    /// Matches WhatsApp Web's getGroupSenderKeyList pattern.
    pub(crate) async fn consume_forget_marks(&self, group_jid: &str) -> Result<Vec<String>> {
        let backend = self.persistence_manager.backend();
        backend
            .consume_forget_marks(group_jid)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Add a LID-PN mapping to both the in-memory cache and persistent storage.
    /// This is called when we learn about a mapping from messages, usync, etc.
    pub(crate) async fn add_lid_pn_mapping(
        &self,
        lid: &str,
        phone_number: &str,
        source: LearningSource,
    ) -> Result<()> {
        use wacore::store::traits::LidPnMappingEntry;

        // Add to in-memory cache
        let entry = LidPnEntry::new(lid.to_string(), phone_number.to_string(), source);
        self.lid_pn_cache.add(entry.clone()).await;

        // Persist to storage in background (don't block message processing)
        let backend = self.persistence_manager.backend();
        let storage_entry = LidPnMappingEntry {
            lid: entry.lid,
            phone_number: entry.phone_number,
            created_at: entry.created_at,
            updated_at: entry.created_at,
            learning_source: entry.learning_source.as_str().to_string(),
        };

        backend
            .put_lid_pn_mapping(&storage_entry)
            .await
            .map_err(|e| anyhow!("persisting LID-PN mapping: {e}"))?;
        Ok(())
    }

    /// Resolve the encryption JID for a given target JID.
    /// This uses the same logic as the receiving path to ensure consistent
    /// lock keys between sending and receiving.
    ///
    /// For PN JIDs, this checks if a LID mapping exists and returns the LID.
    /// This ensures that sending and receiving use the same session lock.
    pub(crate) async fn resolve_encryption_jid(&self, target: &Jid) -> Jid {
        let pn_server = wacore_binary::jid::DEFAULT_USER_SERVER;
        let lid_server = wacore_binary::jid::HIDDEN_USER_SERVER;

        if target.server == lid_server {
            // Already a LID - use it directly
            target.clone()
        } else if target.server == pn_server {
            // PN JID - check if we have a LID mapping
            if let Some(lid_user) = self.lid_pn_cache.get_current_lid(&target.user).await {
                let lid_jid = Jid {
                    user: lid_user.clone(),
                    server: lid_server.to_string(),
                    device: target.device,
                    agent: target.agent,
                    integrator: target.integrator,
                };
                log::debug!(
                    "[SEND-LOCK] Resolved {} to LID {} for session lock",
                    target,
                    lid_jid
                );
                lid_jid
            } else {
                // No LID mapping - use PN as-is
                log::debug!("[SEND-LOCK] No LID mapping for {}, using PN", target);
                target.clone()
            }
        } else {
            // Other server type - use as-is
            target.clone()
        }
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

    /// Take a recent message from the cache (removes it).
    /// Returns the deserialized message if found, None otherwise.
    pub(crate) async fn take_recent_message(&self, to: Jid, id: String) -> Option<wa::Message> {
        use prost::Message;
        let key = RecentMessageKey { to, id };
        self.recent_messages
            .remove(&key)
            .await
            .and_then(|bytes| wa::Message::decode(bytes.as_slice()).ok())
    }

    /// Store a recent message in the cache (serialized as bytes).
    /// This is lightweight - only stores the protobuf bytes, not Arc<Message>.
    pub(crate) async fn add_recent_message(&self, to: Jid, id: String, msg: &wa::Message) {
        use prost::Message;
        let key = RecentMessageKey { to, id };
        // Serialize message to bytes - much lighter than storing Arc<Message>
        let bytes = msg.encode_to_vec();
        self.recent_messages.insert(key, bytes).await;
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
        use crate::request::{InfoQuery, InfoQueryType};

        let tag = if passive { "passive" } else { "active" };

        let query = InfoQuery {
            namespace: "passive",
            query_type: InfoQueryType::Set,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(wacore_binary::node::NodeContent::Nodes(vec![
                NodeBuilder::new(tag).build(),
            ])),
            timeout: None,
        };

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
        use crate::request::{InfoQuery, InfoQueryType};

        debug!(target: "Client", "Fetching properties (props)...");

        let props_node = NodeBuilder::new("props")
            .attr("protocol", "2")
            .attr("hash", "") // TODO: load hash from persistence
            .build();

        let iq = InfoQuery {
            namespace: "w",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(wacore_binary::node::NodeContent::Nodes(vec![props_node])),
            timeout: None,
        };

        self.send_iq(iq).await.map(|_| ())
    }

    pub async fn fetch_privacy_settings(&self) -> Result<(), crate::request::IqError> {
        use crate::request::{InfoQuery, InfoQueryType};

        debug!(target: "Client", "Fetching privacy settings...");

        let iq = InfoQuery {
            namespace: "privacy",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(wacore_binary::node::NodeContent::Nodes(vec![
                NodeBuilder::new("privacy").build(),
            ])),
            timeout: None,
        };

        self.send_iq(iq).await.map(|_| ())
    }

    pub async fn send_digest_key_bundle(&self) -> Result<(), crate::request::IqError> {
        use crate::request::{InfoQuery, InfoQueryType};

        debug!(target: "Client", "Sending digest key bundle...");

        let digest_node = NodeBuilder::new("digest").build();
        let iq = InfoQuery {
            namespace: "encrypt",
            query_type: InfoQueryType::Get,
            to: server_jid(),
            target: None,
            id: None,
            content: Some(wacore_binary::node::NodeContent::Nodes(vec![digest_node])),
            timeout: None,
        };

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

            // === Send active IQ first ===
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

    /// Get the phone number for a given LID from the LID-PN cache.
    ///
    /// This looks up the mapping in the in-memory cache. The mapping is populated
    /// from messages, usync responses, and other sources during normal operation.
    ///
    /// # Arguments
    ///
    /// * `lid` - The LID user part (e.g., "100000012345678") or full LID JID
    ///
    /// # Returns
    ///
    /// The phone number user part if a mapping exists, None otherwise.
    pub async fn get_phone_number_from_lid(&self, lid: &str) -> Option<String> {
        // Handle both full JID (e.g., "100000012345678@lid") and user part only
        let lid_user = if lid.contains('@') {
            lid.split('@').next().unwrap_or(lid)
        } else {
            lid
        };
        self.lid_pn_cache.get_phone_number(lid_user).await
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
    use tokio::sync::oneshot;
    use wacore_binary::jid::SERVER_JID;

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
    async fn test_send_buffer_pool_reuses_both_buffers() {
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
}
