//! Portable in-process cache with TTL/TTI support.
//!
//! This module provides [`PortableCache`], a platform-agnostic cache that can
//! replace moka when the `moka-cache` feature is disabled. It uses
//! [`wacore::time::now_millis`] for time checks (no `std::time::Instant`),
//! making it suitable for WASM and other non-standard runtimes.
//!
//! The API surface mirrors moka's [`Cache`](moka::future::Cache) so that
//! call-sites can switch between moka and this implementation via a type alias.
//!
//! # Single-flight `get_with`
//!
//! Like moka, [`PortableCache::get_with`] guarantees that concurrent calls for
//! the same missing key will only run the initializer **once**. Other callers
//! wait for the first initialization to complete and receive the same value.
//! This is critical for caches that store coordination primitives (mutexes,
//! channels) where each key must map to exactly one instance.

use async_lock::{Mutex as AsyncMutex, RwLock};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

/// A single cache entry with metadata for TTL/TTI bookkeeping.
struct CacheEntry<V> {
    value: V,
    /// Timestamp (ms since epoch) when the entry was inserted.
    inserted_at: i64,
    /// Timestamp (ms since epoch) when the entry was last accessed (for TTI).
    last_accessed_at: i64,
}

/// A portable, runtime-agnostic in-process cache.
///
/// Supports:
/// - Maximum capacity with oldest-inserted eviction
/// - Time-to-live (TTL) -- entries expire a fixed duration after insertion
/// - Time-to-idle (TTI) -- entries expire after a fixed duration of no access
/// - Single-flight `get_with` / `get_with_by_ref` (concurrent inits coalesce)
///
/// All time checks use [`wacore::time::now_millis`].
pub struct PortableCache<K, V> {
    inner: Arc<RwLock<CacheInner<K, V>>>,
    /// Per-key init locks for single-flight `get_with`. Stored separately from
    /// `CacheInner` so we can hold an init lock without blocking cache reads.
    init_locks: Arc<AsyncMutex<HashMap<K, Arc<AsyncMutex<()>>>>>,
    max_capacity: Option<u64>,
    ttl_ms: Option<i64>,
    tti_ms: Option<i64>,
}

struct CacheInner<K, V> {
    map: HashMap<K, CacheEntry<V>>,
    /// Insertion-order tracking for eviction. Stores keys in insertion order.
    insertion_order: Vec<K>,
}

impl<K, V> CacheInner<K, V>
where
    K: Hash + Eq + Clone,
{
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            insertion_order: Vec::new(),
        }
    }

    /// Find and remove a key from the map, returning the entry.
    /// Also removes it from the insertion_order vec.
    fn remove_key(&mut self, key: &K) -> Option<CacheEntry<V>> {
        let entry = self.map.remove(key)?;
        self.insertion_order.retain(|ik| ik != key);
        Some(entry)
    }
}

// -- Builder ------------------------------------------------------------------

/// Builder for [`PortableCache`].
pub struct PortableCacheBuilder<K, V> {
    max_capacity: Option<u64>,
    ttl: Option<Duration>,
    tti: Option<Duration>,
    _marker: std::marker::PhantomData<fn(K, V)>,
}

impl<K, V> PortableCacheBuilder<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn new() -> Self {
        Self {
            max_capacity: None,
            ttl: None,
            tti: None,
            _marker: std::marker::PhantomData,
        }
    }

    /// Set the maximum number of entries.
    pub fn max_capacity(mut self, cap: u64) -> Self {
        self.max_capacity = Some(cap);
        self
    }

    /// Set the time-to-live for entries.
    pub fn time_to_live(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Set the time-to-idle for entries.
    pub fn time_to_idle(mut self, tti: Duration) -> Self {
        self.tti = Some(tti);
        self
    }

    /// Build the cache.
    pub fn build(self) -> PortableCache<K, V> {
        PortableCache {
            inner: Arc::new(RwLock::new(CacheInner::new())),
            init_locks: Arc::new(AsyncMutex::new(HashMap::new())),
            max_capacity: self.max_capacity,
            ttl_ms: self.ttl.map(|d| d.as_millis() as i64),
            tti_ms: self.tti.map(|d| d.as_millis() as i64),
        }
    }
}

// -- PortableCache impl -------------------------------------------------------

impl<K, V> PortableCache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Returns a new builder.
    pub fn builder() -> PortableCacheBuilder<K, V> {
        PortableCacheBuilder::new()
    }

    /// Check if an entry is expired based on TTL/TTI.
    fn is_expired(&self, entry: &CacheEntry<V>, now_ms: i64) -> bool {
        if let Some(ttl_ms) = self.ttl_ms {
            if now_ms - entry.inserted_at >= ttl_ms {
                return true;
            }
        }
        if let Some(tti_ms) = self.tti_ms {
            if now_ms - entry.last_accessed_at >= tti_ms {
                return true;
            }
        }
        false
    }

    /// Lookup a key in the inner map, returning the owned `K` if found.
    /// This avoids lifetime issues with generic `Q` keys.
    fn find_key<Q>(inner: &CacheInner<K, V>, key: &Q) -> Option<K>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        // HashMap::get_key_value lets us get the actual K stored.
        inner.map.get_key_value(key).map(|(k, _)| k.clone())
    }

    /// Get a value by key. Returns `None` if missing or expired.
    pub async fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let now_ms = wacore::time::now_millis();

        // Try read lock first.
        {
            let guard = self.inner.read().await;
            let entry = guard.map.get(key)?;
            if self.is_expired(entry, now_ms) {
                let owned_key = Self::find_key(&guard, key)?;
                drop(guard);
                // Take write lock to remove expired entry.
                let mut wguard = self.inner.write().await;
                if let Some(e) = wguard.map.get(key) {
                    if self.is_expired(e, now_ms) {
                        wguard.remove_key(&owned_key);
                    }
                }
                return None;
            }
            let value = entry.value.clone();
            // Update last_accessed_at for TTI if needed.
            if self.tti_ms.is_some() {
                drop(guard);
                let mut wguard = self.inner.write().await;
                if let Some(e) = wguard.map.get_mut(key) {
                    e.last_accessed_at = now_ms;
                }
            }
            return Some(value);
        }
    }

    /// Insert a key-value pair. Evicts the oldest entry if at capacity.
    pub async fn insert(&self, key: K, value: V) {
        let now_ms = wacore::time::now_millis();
        let mut guard = self.inner.write().await;

        // If the key already exists, update it in-place.
        if let Some(entry) = guard.map.get_mut(&key) {
            entry.value = value;
            entry.inserted_at = now_ms;
            entry.last_accessed_at = now_ms;
            return;
        }

        // Zero capacity means caching is disabled.
        if self.max_capacity == Some(0) {
            return;
        }

        // Evict oldest entries if at capacity.
        if let Some(cap) = self.max_capacity {
            while guard.map.len() as u64 >= cap {
                if let Some(oldest_key) = guard.insertion_order.first().cloned() {
                    guard.map.remove(&oldest_key);
                    guard.insertion_order.remove(0);
                } else {
                    break;
                }
            }
        }

        guard.insertion_order.push(key.clone());
        guard.map.insert(
            key,
            CacheEntry {
                value,
                inserted_at: now_ms,
                last_accessed_at: now_ms,
            },
        );
    }

    /// Remove a key and return its value (if present and not expired).
    pub async fn remove<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let now_ms = wacore::time::now_millis();
        let mut guard = self.inner.write().await;
        let owned_key = Self::find_key(&guard, key)?;
        let entry = guard.remove_key(&owned_key)?;
        if self.is_expired(&entry, now_ms) {
            None
        } else {
            Some(entry.value)
        }
    }

    /// Remove a key (moka-compatible name).
    pub async fn invalidate<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut guard = self.inner.write().await;
        if let Some(owned_key) = Self::find_key(&guard, key) {
            guard.remove_key(&owned_key);
        }
    }

    /// Remove all entries (sync, best-effort under contention).
    ///
    /// This matches moka's synchronous `invalidate_all()` signature. If a
    /// concurrent reader/writer holds the lock, the clear is retried with a
    /// spin loop to avoid silently dropping the operation.
    pub fn invalidate_all(&self) {
        // Spin briefly to avoid silently skipping the clear under contention.
        // The critical sections holding the RwLock are very short (in-memory
        // HashMap ops), so contention resolves within a few iterations.
        for _ in 0..64 {
            if let Some(mut guard) = self.inner.try_write() {
                guard.map.clear();
                guard.insertion_order.clear();
                return;
            }
            std::hint::spin_loop();
        }
        // If we still can't acquire after 64 spins, log and skip.
        // This is extremely unlikely given the short critical sections.
        log::warn!("PortableCache::invalidate_all: could not acquire write lock after retries");
    }

    /// Approximate entry count (sync). May include expired entries.
    pub fn entry_count(&self) -> u64 {
        self.inner
            .try_read()
            .map(|g| g.map.len() as u64)
            .unwrap_or(0)
    }

    /// Get or insert with single-flight guarantee: if the key is present (and
    /// not expired), return its value. Otherwise, evaluate the future and
    /// insert its result. Concurrent calls for the same missing key will only
    /// run the initializer **once**; other callers wait and receive the same
    /// value.
    pub async fn get_with<F>(&self, key: K, init: F) -> V
    where
        F: std::future::Future<Output = V>,
    {
        // Fast path: cache hit (no lock contention).
        if let Some(v) = self.get(&key).await {
            return v;
        }

        // Get or create a per-key init mutex to serialize concurrent inits.
        // Keep the critical section short — only HashMap access, no I/O.
        let init_mutex = {
            let mut locks = self.init_locks.lock().await;
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };

        // Serialize per key — only one task runs the initializer.
        let _init_guard = init_mutex.lock().await;

        // Double-check: another task that held this lock may have already
        // initialized the value while we waited.
        if let Some(v) = self.get(&key).await {
            return v;
        }

        // We won the race — run the initializer and insert.
        let value = init.await;
        self.insert(key, value.clone()).await;
        value
    }

    /// Same as [`get_with`](Self::get_with) but takes the key by reference.
    pub async fn get_with_by_ref<F>(&self, key: &K, init: F) -> V
    where
        F: std::future::Future<Output = V>,
    {
        if let Some(v) = self.get(key).await {
            return v;
        }

        let init_mutex = {
            let mut locks = self.init_locks.lock().await;
            locks
                .entry(key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };

        let _init_guard = init_mutex.lock().await;

        if let Some(v) = self.get(key).await {
            return v;
        }

        let value = init.await;
        self.insert(key.clone(), value.clone()).await;
        value
    }

    /// Trigger an eviction sweep, removing all expired entries and cleaning up
    /// init locks for keys no longer in the cache.
    pub async fn run_pending_tasks(&self) {
        let now_ms = wacore::time::now_millis();
        let mut guard = self.inner.write().await;
        let expired_keys: Vec<K> = guard
            .map
            .iter()
            .filter(|(_, entry)| self.is_expired(entry, now_ms))
            .map(|(k, _)| k.clone())
            .collect();
        for k in &expired_keys {
            guard.map.remove(k);
        }
        guard.insertion_order.retain(|k| !expired_keys.contains(k));
        // Release `inner` before acquiring `init_locks` to maintain a
        // consistent lock ordering (init_locks → inner) across all methods.
        drop(guard);

        // Clean up init locks for keys no longer being initialized.
        // Keep locks that are currently held (strong_count > 1 means someone
        // has a clone and may be actively initializing).
        let mut locks = self.init_locks.lock().await;
        locks.retain(|_, v| Arc::strong_count(v) > 1);
    }
}

impl<K, V> Clone for PortableCache<K, V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            init_locks: Arc::clone(&self.init_locks),
            max_capacity: self.max_capacity,
            ttl_ms: self.ttl_ms,
            tti_ms: self.tti_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn build_cache<K, V>() -> PortableCache<K, V>
    where
        K: Hash + Eq + Clone + Send + Sync + 'static,
        V: Clone + Send + Sync + 'static,
    {
        PortableCache::builder().max_capacity(100).build()
    }

    #[tokio::test]
    async fn test_basic_insert_and_get() {
        let cache = build_cache::<String, String>();

        assert!(cache.get("key1").await.is_none());

        cache.insert("key1".to_string(), "value1".to_string()).await;
        assert_eq!(cache.get("key1").await, Some("value1".to_string()));
    }

    #[tokio::test]
    async fn test_update_existing_key() {
        let cache = build_cache::<String, String>();

        cache.insert("key1".to_string(), "v1".to_string()).await;
        cache.insert("key1".to_string(), "v2".to_string()).await;
        assert_eq!(cache.get("key1").await, Some("v2".to_string()));
        assert_eq!(cache.entry_count(), 1);
    }

    #[tokio::test]
    async fn test_capacity_eviction() {
        let cache: PortableCache<String, u32> = PortableCache::builder().max_capacity(3).build();

        cache.insert("a".into(), 1).await;
        cache.insert("b".into(), 2).await;
        cache.insert("c".into(), 3).await;
        assert_eq!(cache.entry_count(), 3);

        // Inserting a 4th should evict the oldest ("a").
        cache.insert("d".into(), 4).await;
        assert_eq!(cache.entry_count(), 3);
        assert!(cache.get("a").await.is_none());
        assert_eq!(cache.get("b").await, Some(2));
        assert_eq!(cache.get("d").await, Some(4));
    }

    #[tokio::test]
    async fn test_zero_capacity_disables_caching() {
        let cache: PortableCache<String, u32> = PortableCache::builder().max_capacity(0).build();

        cache.insert("a".into(), 1).await;
        assert!(cache.get("a").await.is_none());
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn test_ttl_expiry() {
        let cache: PortableCache<String, String> = PortableCache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_millis(50))
            .build();

        cache.insert("key1".to_string(), "value1".to_string()).await;
        assert_eq!(cache.get("key1").await, Some("value1".to_string()));

        // Wait for TTL to expire.
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert!(cache.get("key1").await.is_none());
    }

    #[tokio::test]
    async fn test_invalidate() {
        let cache = build_cache::<String, String>();

        cache.insert("key1".to_string(), "value1".to_string()).await;
        cache.invalidate("key1").await;
        assert!(cache.get("key1").await.is_none());
    }

    #[tokio::test]
    async fn test_invalidate_all() {
        let cache = build_cache::<String, u32>();

        cache.insert("a".into(), 1).await;
        cache.insert("b".into(), 2).await;
        cache.invalidate_all();
        assert_eq!(cache.entry_count(), 0);
        assert!(cache.get("a").await.is_none());
    }

    #[tokio::test]
    async fn test_remove() {
        let cache = build_cache::<String, String>();

        cache.insert("key1".to_string(), "v1".to_string()).await;
        let removed = cache.remove("key1").await;
        assert_eq!(removed, Some("v1".to_string()));
        assert!(cache.get("key1").await.is_none());
    }

    #[tokio::test]
    async fn test_get_with_basic() {
        let cache = build_cache::<String, u32>();

        let v = cache.get_with("key1".to_string(), async { 42 }).await;
        assert_eq!(v, 42);

        // Second call should return cached value without running init.
        let v = cache.get_with("key1".to_string(), async { 99 }).await;
        assert_eq!(v, 42);
    }

    #[tokio::test]
    async fn test_get_with_by_ref_basic() {
        let cache = build_cache::<String, u32>();
        let key = "key1".to_string();

        let v = cache.get_with_by_ref(&key, async { 42 }).await;
        assert_eq!(v, 42);

        let v = cache.get_with_by_ref(&key, async { 99 }).await;
        assert_eq!(v, 42);
    }

    /// Verifies single-flight: concurrent `get_with` calls for the same key
    /// only run the initializer once.
    #[tokio::test]
    async fn test_get_with_single_flight() {
        let cache: PortableCache<String, Arc<AtomicUsize>> =
            PortableCache::builder().max_capacity(100).build();

        let init_count = Arc::new(AtomicUsize::new(0));
        let num_tasks = 20;
        let barrier = Arc::new(tokio::sync::Barrier::new(num_tasks));

        let mut handles = Vec::new();
        for _ in 0..num_tasks {
            let cache = cache.clone();
            let init_count = init_count.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                // Synchronize all tasks to start at the same time.
                barrier.wait().await;
                cache
                    .get_with("shared_key".to_string(), async {
                        init_count.fetch_add(1, Ordering::SeqCst);
                        // Small yield to widen the race window.
                        tokio::task::yield_now().await;
                        Arc::new(AtomicUsize::new(0))
                    })
                    .await
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap());
        }

        // The initializer should have been called exactly once.
        assert_eq!(
            init_count.load(Ordering::SeqCst),
            1,
            "init should run exactly once (single-flight)"
        );

        // All tasks should receive the same Arc instance.
        let first = &results[0];
        for r in &results[1..] {
            assert!(
                Arc::ptr_eq(first, r),
                "all tasks must receive the same Arc instance"
            );
        }
    }

    /// Verifies single-flight for `get_with_by_ref`.
    #[tokio::test]
    async fn test_get_with_by_ref_single_flight() {
        let cache: PortableCache<String, Arc<AtomicUsize>> =
            PortableCache::builder().max_capacity(100).build();

        let init_count = Arc::new(AtomicUsize::new(0));
        let num_tasks = 20;
        let barrier = Arc::new(tokio::sync::Barrier::new(num_tasks));

        let mut handles = Vec::new();
        for _ in 0..num_tasks {
            let cache = cache.clone();
            let init_count = init_count.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let key = "shared_key".to_string();
                cache
                    .get_with_by_ref(&key, async {
                        init_count.fetch_add(1, Ordering::SeqCst);
                        tokio::task::yield_now().await;
                        Arc::new(AtomicUsize::new(0))
                    })
                    .await
            }));
        }

        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap());
        }

        assert_eq!(init_count.load(Ordering::SeqCst), 1);
        let first = &results[0];
        for r in &results[1..] {
            assert!(Arc::ptr_eq(first, r));
        }
    }

    /// Concurrent get_with on DIFFERENT keys should run initializers in parallel.
    #[tokio::test]
    async fn test_get_with_different_keys_parallel() {
        let cache = build_cache::<String, u32>();

        let init_count = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for i in 0..10 {
            let cache = cache.clone();
            let init_count = init_count.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .get_with(format!("key_{i}"), async {
                        init_count.fetch_add(1, Ordering::SeqCst);
                        i as u32
                    })
                    .await
            }));
        }

        for (i, h) in handles.into_iter().enumerate() {
            assert_eq!(h.await.unwrap(), i as u32);
        }
        // Each key should have its own init call.
        assert_eq!(init_count.load(Ordering::SeqCst), 10);
    }

    /// Verifies that session-lock-style usage works: concurrent `get_with` for
    /// the same key returns the same `Arc<Mutex>`, so locking actually serializes.
    #[tokio::test]
    async fn test_session_lock_pattern() {
        let cache: PortableCache<String, Arc<async_lock::Mutex<()>>> =
            PortableCache::builder().max_capacity(100).build();

        let counter = Arc::new(AtomicUsize::new(0));
        let num_tasks = 50;
        let barrier = Arc::new(tokio::sync::Barrier::new(num_tasks));

        let mut handles = Vec::new();
        for _ in 0..num_tasks {
            let cache = cache.clone();
            let counter = counter.clone();
            let barrier = barrier.clone();
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                let mutex = cache
                    .get_with("sender_123".to_string(), async {
                        Arc::new(async_lock::Mutex::new(()))
                    })
                    .await;
                let _guard = mutex.lock().await;
                // Critical section: read-modify-write that must be serialized.
                let val = counter.load(Ordering::SeqCst);
                tokio::task::yield_now().await;
                counter.store(val + 1, Ordering::SeqCst);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // If serialization works, final count should be exactly num_tasks.
        assert_eq!(counter.load(Ordering::SeqCst), num_tasks);
    }

    #[tokio::test]
    async fn test_run_pending_tasks_cleans_expired() {
        let cache: PortableCache<String, u32> = PortableCache::builder()
            .max_capacity(100)
            .time_to_live(Duration::from_millis(50))
            .build();

        cache.insert("a".into(), 1).await;
        cache.insert("b".into(), 2).await;
        assert_eq!(cache.entry_count(), 2);

        tokio::time::sleep(Duration::from_millis(60)).await;
        cache.run_pending_tasks().await;
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn test_run_pending_tasks_cleans_init_locks() {
        let cache: PortableCache<String, u32> = PortableCache::builder().max_capacity(100).build();

        // Trigger init lock creation.
        let _ = cache.get_with("key1".to_string(), async { 1 }).await;

        // Init lock should exist.
        {
            let locks = cache.init_locks.lock().await;
            assert!(locks.contains_key("key1"));
        }

        // run_pending_tasks should clean up init locks that aren't actively held.
        cache.run_pending_tasks().await;
        {
            let locks = cache.init_locks.lock().await;
            assert!(
                !locks.contains_key("key1"),
                "init lock should be cleaned up after run_pending_tasks"
            );
        }
    }
}
