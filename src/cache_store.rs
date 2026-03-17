//! Typed cache wrapper that dispatches to either moka (in-process) or a custom
//! [`CacheStore`] backend (e.g., Redis).
//!
//! [`TypedCache`] presents the same interface regardless of the backing store.
//! Keys are serialised via [`Display`]; values are serialised with `serde_json`
//! only on the custom-store path — the moka path has zero extra overhead.

use std::borrow::Borrow;
use std::fmt::Display;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;
use serde::{Serialize, de::DeserializeOwned};

pub use wacore::store::cache::CacheStore;

// ── Internal storage variant ──────────────────────────────────────────────────

enum Inner<K, V> {
    Moka(Cache<K, V>),
    Custom {
        store: Arc<dyn CacheStore>,
        namespace: &'static str,
        ttl: Option<Duration>,
        _marker: PhantomData<fn(K, V)>,
    },
}

// ── TypedCache ─────────────────────────────────────────────────────────────────

/// A cache over `K → V` backed by either moka or any [`CacheStore`].
///
/// The moka path has **zero extra overhead** — values are stored in-process
/// without any serialisation.  The custom-store path serialises values with
/// `serde_json` and keys via [`Display`].
///
/// Methods mirror moka's API so call sites need no changes.
pub struct TypedCache<K, V> {
    inner: Inner<K, V>,
}

impl<K, V> TypedCache<K, V>
where
    K: std::hash::Hash + Eq + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    /// Wrap an existing moka cache (zero overhead vs. using moka directly).
    pub fn from_moka(cache: Cache<K, V>) -> Self {
        Self {
            inner: Inner::Moka(cache),
        }
    }
}

impl<K, V> TypedCache<K, V>
where
    K: std::hash::Hash + Eq + Display + Send + Sync + 'static,
    V: Clone + Serialize + DeserializeOwned + Send + Sync + 'static,
{
    /// Create a cache backed by a custom store.
    ///
    /// - `namespace` — unique string for this cache (e.g., `"group"`)
    /// - `ttl` — forwarded to [`CacheStore::set`]; `None` means no expiry
    pub fn from_store(
        store: Arc<dyn CacheStore>,
        namespace: &'static str,
        ttl: Option<Duration>,
    ) -> Self {
        Self {
            inner: Inner::Custom {
                store,
                namespace,
                ttl,
                _marker: PhantomData,
            },
        }
    }

    /// Look up a value.
    ///
    /// Accepts borrowed keys (`&str` for `String`, `&Jid` for `Jid`, etc.)
    /// following the same pattern as [`std::collections::HashMap::get`].
    ///
    /// Cache misses and deserialisation failures both return `None`; the
    /// caller re-fetches from the authoritative source.
    pub async fn get<Q>(&self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: std::hash::Hash + Eq + Display + ?Sized,
    {
        match &self.inner {
            Inner::Moka(cache) => cache.get(key).await,
            Inner::Custom {
                store, namespace, ..
            } => {
                let key_str = key.to_string();
                match store.get(namespace, &key_str).await {
                    Ok(Some(bytes)) => serde_json::from_slice(&bytes)
                        .inspect_err(|e| {
                            log::warn!(
                                "TypedCache[{namespace}]: deserialise failed for {key_str}: {e}"
                            );
                        })
                        .ok(),
                    Ok(None) => None,
                    Err(e) => {
                        log::warn!("TypedCache[{namespace}]: get({key_str}) error: {e}");
                        None
                    }
                }
            }
        }
    }

    /// Insert or update a value (takes ownership of key and value).
    pub async fn insert(&self, key: K, value: V) {
        match &self.inner {
            Inner::Moka(cache) => cache.insert(key, value).await,
            Inner::Custom {
                store,
                namespace,
                ttl,
                ..
            } => {
                let key_str = key.to_string();
                match serde_json::to_vec(&value) {
                    Ok(bytes) => {
                        if let Err(e) = store.set(namespace, &key_str, &bytes, *ttl).await {
                            log::warn!("TypedCache[{namespace}]: set({key_str}) error: {e}");
                        }
                    }
                    Err(e) => {
                        log::warn!("TypedCache[{namespace}]: serialise failed for {key_str}: {e}");
                    }
                }
            }
        }
    }

    /// Remove a single key.
    ///
    /// Accepts borrowed keys following the same pattern as `get`.
    pub async fn invalidate<Q>(&self, key: &Q)
    where
        K: Borrow<Q>,
        Q: std::hash::Hash + Eq + Display + ?Sized,
    {
        match &self.inner {
            Inner::Moka(cache) => cache.invalidate(key).await,
            Inner::Custom {
                store, namespace, ..
            } => {
                let key_str = key.to_string();
                if let Err(e) = store.delete(namespace, &key_str).await {
                    log::warn!("TypedCache[{namespace}]: delete({key_str}) error: {e}");
                }
            }
        }
    }

    /// Remove all entries.
    ///
    /// For the moka backend this is synchronous (matching moka's API).
    /// For the custom backend this spawns a fire-and-forget task via
    /// [`tokio::runtime::Handle::try_current`] to avoid panicking if
    /// called outside a Tokio runtime.
    pub fn invalidate_all(&self) {
        match &self.inner {
            Inner::Moka(cache) => cache.invalidate_all(),
            Inner::Custom {
                store, namespace, ..
            } => {
                let store = store.clone();
                let ns = *namespace;
                match tokio::runtime::Handle::try_current() {
                    Ok(handle) => {
                        handle.spawn(async move {
                            if let Err(e) = store.clear(ns).await {
                                log::warn!("TypedCache[{ns}]: clear() error: {e}");
                            }
                        });
                    }
                    Err(_) => {
                        log::warn!("TypedCache[{ns}]: clear() skipped: no Tokio runtime");
                    }
                }
            }
        }
    }

    /// Remove all entries, awaiting completion for custom backends.
    pub async fn clear(&self) {
        match &self.inner {
            Inner::Moka(cache) => cache.invalidate_all(),
            Inner::Custom {
                store, namespace, ..
            } => {
                if let Err(e) = store.clear(namespace).await {
                    log::warn!("TypedCache[{namespace}]: clear() error: {e}");
                }
            }
        }
    }

    /// Run any pending internal housekeeping tasks (moka only).
    ///
    /// For the moka backend this ensures all writes have been applied before
    /// calling [`entry_count`](Self::entry_count), which can otherwise lag.
    /// For custom backends this is a no-op.
    pub async fn run_pending_tasks(&self) {
        if let Inner::Moka(cache) = &self.inner {
            cache.run_pending_tasks().await;
        }
    }

    /// Approximate entry count (sync). Returns `0` for custom backends.
    ///
    /// For diagnostics that need custom backend counts, use
    /// [`entry_count_async`](Self::entry_count_async) instead.
    pub fn entry_count(&self) -> u64 {
        match &self.inner {
            Inner::Moka(cache) => cache.entry_count(),
            Inner::Custom { .. } => 0,
        }
    }

    /// Approximate entry count, delegating to the custom backend if available.
    pub async fn entry_count_async(&self) -> u64 {
        match &self.inner {
            Inner::Moka(cache) => cache.entry_count(),
            Inner::Custom {
                store, namespace, ..
            } => store.entry_count(namespace).await.unwrap_or(0),
        }
    }
}
