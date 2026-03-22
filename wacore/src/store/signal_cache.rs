use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;
use async_lock::Mutex;

use crate::store::traits::SignalStore;

/// In-memory cache for Signal protocol state, matching WhatsApp Web's SignalStoreCache.
///
/// All crypto operations read/write this cache. DB writes are deferred to `flush()`.
/// Each store type has its own mutex for independent locking.
///
/// Values are stored as `Arc<[u8]>` so cache reads are O(1) clones (reference count bump)
/// instead of O(n) byte copies.
///
/// Keys use `Arc<str>` so that cloning a key (needed for both cache and dirty/deleted sets)
/// is an O(1) refcount bump instead of an O(n) heap allocation.
pub struct SignalStoreCache {
    sessions: Mutex<StoreState>,
    identities: Mutex<StoreState>,
    sender_keys: Mutex<StoreState>,
}

struct StoreState {
    /// Cached entries. `None` value = known-absent (negative cache).
    cache: HashMap<Arc<str>, Option<Arc<[u8]>>>,
    /// Keys that have been modified and need flushing to the backend.
    dirty: HashSet<Arc<str>>,
    /// Keys that have been deleted and need flushing to the backend.
    deleted: HashSet<Arc<str>>,
}

impl StoreState {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            dirty: HashSet::new(),
            deleted: HashSet::new(),
        }
    }

    /// Insert data, skipping if bytes are identical (avoids redundant dirty marks).
    fn put(&mut self, address: &str, data: &[u8]) {
        if let Some(Some(existing)) = self.cache.get(address)
            && existing.as_ref() == data
        {
            return;
        }
        let addr: Arc<str> = Arc::from(address);
        self.cache.insert(addr.clone(), Some(Arc::from(data)));
        self.dirty.insert(addr.clone());
        self.deleted.remove(&addr);
    }

    /// Mark an entry as deleted (negative-cached).
    fn delete(&mut self, address: &str) {
        let addr: Arc<str> = Arc::from(address);
        self.cache.insert(addr.clone(), None);
        self.deleted.insert(addr.clone());
        self.dirty.remove(&addr);
    }

    /// Clear all cached state, retaining allocated capacity for reuse.
    fn clear(&mut self) {
        self.cache.clear();
        self.dirty.clear();
        self.deleted.clear();
    }
}

impl Default for SignalStoreCache {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalStoreCache {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(StoreState::new()),
            identities: Mutex::new(StoreState::new()),
            sender_keys: Mutex::new(StoreState::new()),
        }
    }

    // === Sessions ===

    pub async fn get_session(
        &self,
        address: &str,
        backend: &dyn SignalStore,
    ) -> Result<Option<Arc<[u8]>>> {
        let mut state = self.sessions.lock().await;
        if let Some(cached) = state.cache.get(address) {
            return Ok(cached.clone());
        }
        let data = backend.get_session(address).await?;
        let arc_data = data.map(Arc::from);
        state.cache.insert(Arc::from(address), arc_data.clone());
        Ok(arc_data)
    }

    pub async fn put_session(&self, address: &str, data: &[u8]) {
        self.sessions.lock().await.put(address, data);
    }

    pub async fn delete_session(&self, address: &str) {
        self.sessions.lock().await.delete(address);
    }

    pub async fn has_session(&self, address: &str, backend: &dyn SignalStore) -> Result<bool> {
        Ok(self.get_session(address, backend).await?.is_some())
    }

    // === Identities ===

    pub async fn get_identity(
        &self,
        address: &str,
        backend: &dyn SignalStore,
    ) -> Result<Option<Arc<[u8]>>> {
        let mut state = self.identities.lock().await;
        if let Some(cached) = state.cache.get(address) {
            return Ok(cached.clone());
        }
        let data = backend.load_identity(address).await?;
        let arc_data = data.map(Arc::from);
        state.cache.insert(Arc::from(address), arc_data.clone());
        Ok(arc_data)
    }

    pub async fn put_identity(&self, address: &str, data: &[u8]) {
        self.identities.lock().await.put(address, data);
    }

    pub async fn delete_identity(&self, address: &str) {
        self.identities.lock().await.delete(address);
    }

    // === Sender Keys ===

    pub async fn get_sender_key(
        &self,
        address: &str,
        backend: &dyn SignalStore,
    ) -> Result<Option<Arc<[u8]>>> {
        let mut state = self.sender_keys.lock().await;
        if let Some(cached) = state.cache.get(address) {
            return Ok(cached.clone());
        }
        let data = backend.get_sender_key(address).await?;
        let arc_data = data.map(Arc::from);
        state.cache.insert(Arc::from(address), arc_data.clone());
        Ok(arc_data)
    }

    pub async fn put_sender_key(&self, address: &str, data: &[u8]) {
        self.sender_keys.lock().await.put(address, data);
    }

    // === Flush ===

    /// Flush all dirty state to the backend in a single batch.
    /// Acquires all 3 mutexes to ensure consistency (matches WhatsApp Web's pattern).
    ///
    /// Dirty sets are only cleared after ALL writes succeed. If any write fails,
    /// dirty tracking is preserved so the next flush retries everything.
    /// This matches WA Web's `clearDirty()` which runs only after successful persist.
    pub async fn flush(&self, backend: &dyn SignalStore) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        let mut identities = self.identities.lock().await;
        let mut sender_keys = self.sender_keys.lock().await;

        // Snapshot dirty/deleted sets WITHOUT draining — preserve on failure
        let session_dirty: Vec<_> = sessions.dirty.iter().cloned().collect();
        let session_deleted: Vec<_> = sessions.deleted.iter().cloned().collect();
        let identity_dirty: Vec<_> = identities.dirty.iter().cloned().collect();
        let identity_deleted: Vec<_> = identities.deleted.iter().cloned().collect();
        let sender_key_dirty: Vec<_> = sender_keys.dirty.iter().cloned().collect();

        // Persist all dirty state
        for address in &session_dirty {
            if let Some(Some(data)) = sessions.cache.get(address.as_ref()) {
                backend.put_session(address, data).await?;
            }
        }
        for address in &session_deleted {
            backend.delete_session(address).await?;
        }

        for address in &identity_dirty {
            if let Some(Some(data)) = identities.cache.get(address.as_ref()) {
                let key: [u8; 32] = data.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "Corrupted identity key for {address}: expected 32 bytes, got {}",
                        data.len()
                    )
                })?;
                backend.put_identity(address, key).await?;
            }
        }
        for address in &identity_deleted {
            backend.delete_identity(address).await?;
        }

        for name in &sender_key_dirty {
            if let Some(Some(data)) = sender_keys.cache.get(name.as_ref()) {
                backend.put_sender_key(name, data).await?;
            }
        }

        // All writes succeeded — clear dirty sets (matches WA Web's clearDirty())
        sessions.dirty.clear();
        sessions.deleted.clear();
        identities.dirty.clear();
        identities.deleted.clear();
        sender_keys.dirty.clear();

        Ok(())
    }

    /// Returns the number of entries in each store (sessions, identities, sender_keys).
    #[cfg(feature = "debug-diagnostics")]
    pub async fn entry_counts(&self) -> (usize, usize, usize) {
        let s = self.sessions.lock().await;
        let i = self.identities.lock().await;
        let sk = self.sender_keys.lock().await;
        (s.cache.len(), i.cache.len(), sk.cache.len())
    }

    /// Clear all cached state (used on disconnect/reconnect).
    /// Retains allocated capacity for reuse on reconnect.
    pub async fn clear(&self) {
        self.sessions.lock().await.clear();
        self.identities.lock().await.clear();
        self.sender_keys.lock().await.clear();
    }
}
