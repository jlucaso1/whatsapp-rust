use moka::future::Cache;
use std::time::Duration;

/// Configuration for a single cache instance.
///
/// Controls the expiry timeout and maximum capacity of a moka cache.
/// The `timeout` field is used as either TTL (`build_with_ttl`) or TTI
/// (`build_with_tti`) depending on which builder method is called.
/// Set `timeout` to `None` to disable time-based expiry (entries stay until
/// evicted by capacity).
#[derive(Debug, Clone)]
pub struct CacheEntryConfig {
    /// Expiry timeout duration. `None` means no time-based expiry.
    /// Interpreted as TTL or TTI depending on the builder method used.
    pub timeout: Option<Duration>,
    /// Maximum number of entries.
    pub capacity: u64,
}

impl CacheEntryConfig {
    pub fn new(timeout: Option<Duration>, capacity: u64) -> Self {
        Self { timeout, capacity }
    }

    /// Build a moka Cache using time_to_live semantics.
    pub(crate) fn build_with_ttl<K, V>(&self) -> Cache<K, V>
    where
        K: std::hash::Hash + Eq + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let mut builder = Cache::builder().max_capacity(self.capacity);
        if let Some(timeout) = self.timeout {
            builder = builder.time_to_live(timeout);
        }
        builder.build()
    }

    /// Build a moka Cache using time_to_idle semantics.
    pub(crate) fn build_with_tti<K, V>(&self) -> Cache<K, V>
    where
        K: std::hash::Hash + Eq + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        let mut builder = Cache::builder().max_capacity(self.capacity);
        if let Some(timeout) = self.timeout {
            builder = builder.time_to_idle(timeout);
        }
        builder.build()
    }
}

/// Configuration for all client caches and resource pools.
///
/// All fields default to WhatsApp Web behavior. Use `..Default::default()` to
/// override only specific settings.
///
/// # Example
///
/// ```rust,ignore
/// use whatsapp_rust::{CacheConfig, CacheEntryConfig};
/// use std::time::Duration;
///
/// let config = CacheConfig {
///     group_cache: CacheEntryConfig::new(None, 1_000), // no TTL
///     ..Default::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Group metadata cache (time_to_live). Default: 1h TTL, 250 entries.
    pub group_cache: CacheEntryConfig,
    /// Device list cache (time_to_live). Default: 1h TTL, 5000 entries.
    pub device_cache: CacheEntryConfig,
    /// Device registry cache (time_to_live). Default: 1h TTL, 5000 entries.
    pub device_registry_cache: CacheEntryConfig,
    /// LID-to-phone cache (time_to_idle). Default: 1h timeout, 10000 entries.
    pub lid_pn_cache: CacheEntryConfig,
    /// Retried group messages tracker (time_to_live). Default: 5m TTL, 2000 entries.
    pub retried_group_messages: CacheEntryConfig,
    /// Optional L1 in-memory cache for sent messages (retry support).
    /// Default: capacity 0 (disabled — DB-only, matching WA Web).
    /// Set capacity > 0 to enable a fast in-memory cache in front of the DB.
    pub recent_messages: CacheEntryConfig,
    /// Message retry counts (time_to_live). Default: 5m TTL, 1000 entries.
    pub message_retry_counts: CacheEntryConfig,
    /// PDO pending requests (time_to_live). Default: 30s TTL, 500 entries.
    pub pdo_pending_requests: CacheEntryConfig,

    // --- Coordination caches (capacity-only, no TTL) ---
    /// Per-device Signal session lock capacity. Default: 2000.
    pub session_locks_capacity: u64,
    /// Per-chat message processing queue capacity. Default: 2000.
    pub message_queues_capacity: u64,
    /// Per-chat message enqueue lock capacity. Default: 2000.
    pub message_enqueue_locks_capacity: u64,

    // --- Buffer pool ---
    /// Max number of reusable plaintext marshal buffers. Default: 8.
    pub max_pooled_buffers: usize,
    /// Max byte capacity per pooled buffer. Default: 256 KiB.
    pub max_pooled_buffer_capacity: usize,

    // --- Sent message DB cleanup ---
    /// TTL in seconds for sent messages in DB before periodic cleanup.
    /// 0 = no automatic cleanup. Default: 300 (5 minutes).
    pub sent_message_ttl_secs: u64,
}

impl Default for CacheConfig {
    fn default() -> Self {
        let one_hour = Some(Duration::from_secs(3600));
        let five_min = Some(Duration::from_secs(300));

        Self {
            group_cache: CacheEntryConfig::new(one_hour, 250),
            device_cache: CacheEntryConfig::new(one_hour, 5_000),
            device_registry_cache: CacheEntryConfig::new(one_hour, 5_000),
            lid_pn_cache: CacheEntryConfig::new(one_hour, 10_000),
            retried_group_messages: CacheEntryConfig::new(five_min, 2_000),
            recent_messages: CacheEntryConfig::new(five_min, 0),
            message_retry_counts: CacheEntryConfig::new(five_min, 1_000),
            pdo_pending_requests: CacheEntryConfig::new(Some(Duration::from_secs(30)), 500),
            session_locks_capacity: 2_000,
            message_queues_capacity: 2_000,
            message_enqueue_locks_capacity: 2_000,
            max_pooled_buffers: 8,
            max_pooled_buffer_capacity: 256 * 1024,
            sent_message_ttl_secs: 300,
        }
    }
}
