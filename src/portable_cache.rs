//! Portable in-process cache (moka replacement for WASM).
//!
//! Uses [`wacore::time::now_millis`] for time checks — no `std::time::Instant`.
//! API mirrors moka's [`Cache`](moka::future::Cache).
//!
//! `get_with` / `get_with_by_ref` are single-flight: concurrent inits for the
//! same missing key run the initializer once.

use async_lock::{Mutex as AsyncMutex, RwLock};
use std::borrow::Borrow;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

struct CacheEntry<V> {
    value: V,
    inserted_at: i64,
    last_accessed_at: i64,
}

/// Portable, runtime-agnostic in-process cache.
///
/// - Max capacity with FIFO eviction
/// - TTL (time-to-live) and TTI (time-to-idle)
/// - Single-flight `get_with` / `get_with_by_ref`
pub struct PortableCache<K, V> {
    inner: Arc<RwLock<CacheInner<K, V>>>,
    /// Per-key init locks for single-flight `get_with`.
    init_locks: Arc<AsyncMutex<HashMap<K, Arc<AsyncMutex<()>>>>>,
    max_capacity: Option<u64>,
    ttl_ms: Option<i64>,
    tti_ms: Option<i64>,
}

struct CacheInner<K, V> {
    map: HashMap<K, CacheEntry<V>>,
    /// FIFO eviction order. VecDeque for O(1) pop_front.
    insertion_order: VecDeque<K>,
}

impl<K, V> CacheInner<K, V>
where
    K: Hash + Eq + Clone,
{
    fn new() -> Self {
        Self {
            map: HashMap::new(),
            insertion_order: VecDeque::new(),
        }
    }

    fn remove_key(&mut self, key: &K) -> Option<CacheEntry<V>> {
        // Lazy deletion: remove from map but leave stale key in insertion_order.
        // Stale keys are skipped during FIFO eviction (map.remove returns None).
        // run_pending_tasks() periodically compacts insertion_order.
        self.map.remove(key)
    }
}

// -- Builder --

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

    pub fn max_capacity(mut self, cap: u64) -> Self {
        self.max_capacity = Some(cap);
        self
    }

    pub fn time_to_live(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    pub fn time_to_idle(mut self, tti: Duration) -> Self {
        self.tti = Some(tti);
        self
    }

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

// -- PortableCache impl --

impl<K, V> PortableCache<K, V>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn builder() -> PortableCacheBuilder<K, V> {
        PortableCacheBuilder::new()
    }

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

    fn find_key<Q>(inner: &CacheInner<K, V>, key: &Q) -> Option<K>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        inner.map.get_key_value(key).map(|(k, _)| k.clone())
    }

    pub async fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let now_ms = wacore::time::now_millis();

        // Fast path (no TTI): read lock only, no write needed.
        if self.tti_ms.is_none() {
            let guard = self.inner.read().await;
            let entry = guard.map.get(key)?;
            if self.is_expired(entry, now_ms) {
                let owned_key = Self::find_key(&guard, key)?;
                drop(guard);
                let mut wguard = self.inner.write().await;
                if let Some(e) = wguard.map.get(key) {
                    if self.is_expired(e, now_ms) {
                        wguard.remove_key(&owned_key);
                    }
                }
                return None;
            }
            return Some(entry.value.clone());
        }

        // TTI path: write lock to update last_accessed_at.
        let mut guard = self.inner.write().await;
        let entry = guard.map.get_mut(key)?;
        if self.is_expired(entry, now_ms) {
            let owned_key = Self::find_key(&guard, key)?;
            guard.remove_key(&owned_key);
            return None;
        }
        entry.last_accessed_at = now_ms;
        Some(entry.value.clone())
    }

    pub async fn insert(&self, key: K, value: V) {
        let now_ms = wacore::time::now_millis();
        let mut guard = self.inner.write().await;

        if let Some(entry) = guard.map.get_mut(&key) {
            entry.value = value;
            entry.inserted_at = now_ms;
            entry.last_accessed_at = now_ms;
            return;
        }

        if self.max_capacity == Some(0) {
            return;
        }

        if let Some(cap) = self.max_capacity {
            while guard.map.len() as u64 >= cap {
                if let Some(oldest_key) = guard.insertion_order.pop_front() {
                    guard.map.remove(&oldest_key);
                } else {
                    break;
                }
            }
        }

        guard.insertion_order.push_back(key.clone());
        guard.map.insert(
            key,
            CacheEntry {
                value,
                inserted_at: now_ms,
                last_accessed_at: now_ms,
            },
        );
    }

    /// Insert and return a clone of the value in one write lock.
    async fn insert_and_return(&self, key: K, value: V) -> V {
        let now_ms = wacore::time::now_millis();
        let mut guard = self.inner.write().await;

        if let Some(entry) = guard.map.get_mut(&key) {
            let ret = value.clone();
            entry.value = value;
            entry.inserted_at = now_ms;
            entry.last_accessed_at = now_ms;
            return ret;
        }

        if self.max_capacity == Some(0) {
            return value;
        }

        if let Some(cap) = self.max_capacity {
            while guard.map.len() as u64 >= cap {
                if let Some(oldest_key) = guard.insertion_order.pop_front() {
                    guard.map.remove(&oldest_key);
                } else {
                    break;
                }
            }
        }

        guard.insertion_order.push_back(key.clone());
        let ret = value.clone();
        guard.map.insert(
            key,
            CacheEntry {
                value,
                inserted_at: now_ms,
                last_accessed_at: now_ms,
            },
        );
        ret
    }

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

    /// Sync invalidate (moka-compatible). Spins briefly if lock is held.
    pub fn invalidate_all(&self) {
        for _ in 0..64 {
            if let Some(mut guard) = self.inner.try_write() {
                guard.map.clear();
                guard.insertion_order.clear();
                return;
            }
            std::hint::spin_loop();
        }
        log::warn!("PortableCache::invalidate_all: could not acquire write lock after retries");
    }

    pub fn entry_count(&self) -> u64 {
        self.inner
            .try_read()
            .map(|g| g.map.len() as u64)
            .unwrap_or(0)
    }

    /// Get or insert (single-flight). Takes key by value.
    pub async fn get_with<F>(&self, key: K, init: F) -> V
    where
        F: std::future::Future<Output = V>,
    {
        if let Some(v) = self.get(&key).await {
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

        // Double-check after acquiring per-key lock.
        if let Some(v) = self.get(&key).await {
            return v;
        }

        self.insert_and_return(key, init.await).await
    }

    /// Get or insert (single-flight). Takes key by reference — only allocates
    /// the owned key on cache miss.
    pub async fn get_with_by_ref<Q, F>(&self, key: &Q, init: F) -> V
    where
        K: Borrow<Q>,
        Q: ToOwned<Owned = K> + Hash + Eq + ?Sized,
        F: std::future::Future<Output = V>,
    {
        if let Some(v) = self.get(key).await {
            return v;
        }

        let owned_key = key.to_owned();
        let init_mutex = {
            let mut locks = self.init_locks.lock().await;
            locks
                .entry(owned_key.clone())
                .or_insert_with(|| Arc::new(AsyncMutex::new(())))
                .clone()
        };

        let _init_guard = init_mutex.lock().await;

        if let Some(v) = self.get(key).await {
            return v;
        }

        self.insert_and_return(owned_key, init.await).await
    }

    /// Evict expired entries and clean up unused init locks.
    pub async fn run_pending_tasks(&self) {
        let now_ms = wacore::time::now_millis();
        let mut guard = self.inner.write().await;

        guard.map.retain(|_, entry| !self.is_expired(entry, now_ms));

        // Rebuild insertion_order to only contain live keys.
        // Borrow fields separately to satisfy the borrow checker.
        let CacheInner {
            map,
            insertion_order,
        } = &mut *guard;
        insertion_order.retain(|k| map.contains_key(k));

        drop(guard);

        // Clean up init locks not actively held.
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
                barrier.wait().await;
                cache
                    .get_with("shared_key".to_string(), async {
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
        assert_eq!(init_count.load(Ordering::SeqCst), 10);
    }

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
                let val = counter.load(Ordering::SeqCst);
                tokio::task::yield_now().await;
                counter.store(val + 1, Ordering::SeqCst);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

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

        let _ = cache.get_with("key1".to_string(), async { 1 }).await;

        {
            let locks = cache.init_locks.lock().await;
            assert!(locks.contains_key("key1"));
        }

        cache.run_pending_tasks().await;
        {
            let locks = cache.init_locks.lock().await;
            assert!(!locks.contains_key("key1"));
        }
    }
}
