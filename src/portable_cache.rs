//! Portable in-process cache with TTL/TTI support.
//!
//! This module provides [`PortableCache`], a platform-agnostic cache that can
//! replace moka when the `moka-cache` feature is disabled. It uses
//! [`wacore::time::now_millis`] for time checks (no `std::time::Instant`),
//! making it suitable for WASM and other non-standard runtimes.
//!
//! The API surface mirrors moka's [`Cache`](moka::future::Cache) so that
//! call-sites can switch between moka and this implementation via a type alias.

use async_lock::RwLock;
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
///
/// All time checks use [`wacore::time::now_millis`].
pub struct PortableCache<K, V> {
    inner: Arc<RwLock<CacheInner<K, V>>>,
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

        // Evict oldest entries if at capacity.
        if let Some(cap) = self.max_capacity {
            while guard.map.len() as u64 >= cap && cap > 0 {
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

    /// Remove all entries (sync, best-effort).
    pub fn invalidate_all(&self) {
        if let Some(mut guard) = self.inner.try_write() {
            guard.map.clear();
            guard.insertion_order.clear();
        }
    }

    /// Approximate entry count (sync). May include expired entries.
    pub fn entry_count(&self) -> u64 {
        self.inner
            .try_read()
            .map(|g| g.map.len() as u64)
            .unwrap_or(0)
    }

    /// Get or insert: if key is present (and not expired), return its value.
    /// Otherwise, evaluate the future and insert its result.
    pub async fn get_with<F>(&self, key: K, init: F) -> V
    where
        F: std::future::Future<Output = V>,
    {
        if let Some(v) = self.get(&key).await {
            return v;
        }
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
        let value = init.await;
        self.insert(key.clone(), value.clone()).await;
        value
    }

    /// Trigger an eviction sweep, removing all expired entries.
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
    }
}

impl<K, V> Clone for PortableCache<K, V> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            max_capacity: self.max_capacity,
            ttl_ms: self.ttl_ms,
            tti_ms: self.tti_ms,
        }
    }
}
