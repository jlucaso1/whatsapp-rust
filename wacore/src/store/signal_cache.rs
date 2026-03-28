use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use anyhow::Result;
use async_lock::Mutex;

use crate::libsignal::protocol::{ProtocolAddress, SenderKeyRecord, SessionRecord};
use crate::libsignal::store::sender_key_name::SenderKeyName;
use crate::store::traits::SignalStore;

/// In-memory cache for Signal protocol state, matching WhatsApp Web's SignalStoreCache.
///
/// Sessions are cached as `SessionRecord` objects (not bytes), matching WA Web's pattern
/// where the JS object IS the cache. Serialization only happens during `flush()`.
///
/// Identity and sender key stores use `Arc<[u8]>` byte caches with dedup checks.
///
/// Keys use `Arc<str>` so that cloning a key (needed for both cache and dirty/deleted sets)
/// is an O(1) refcount bump instead of an O(n) heap allocation.
pub struct SignalStoreCache {
    sessions: Mutex<SessionStoreState>,
    identities: Mutex<ByteStoreState>,
    sender_keys: Mutex<SenderKeyStoreState>,
}

// === Session object cache (no per-message serialize/deserialize) ===

struct SessionStoreState {
    /// Cached entries. `None` value = known-absent (negative cache).
    cache: HashMap<Arc<str>, Option<SessionRecord>>,
    dirty: HashSet<Arc<str>>,
    deleted: HashSet<Arc<str>>,
}

impl SessionStoreState {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            dirty: HashSet::new(),
            deleted: HashSet::new(),
        }
    }

    /// Reuse the existing Arc<str> key if the address is already in the cache,
    /// avoiding a heap allocation on every call (hot path: key always exists).
    fn key_for(&self, address: &str) -> Arc<str> {
        match self.cache.get_key_value(address) {
            Some((existing, _)) => existing.clone(),
            None => Arc::from(address),
        }
    }

    fn put(&mut self, address: &str, record: SessionRecord) {
        let addr = self.key_for(address);
        self.cache.insert(addr.clone(), Some(record));
        self.dirty.insert(addr.clone());
        self.deleted.remove(&addr);
    }

    fn delete(&mut self, address: &str) {
        let addr = self.key_for(address);
        self.cache.insert(addr.clone(), None);
        self.deleted.insert(addr.clone());
        self.dirty.remove(&addr);
    }

    fn clear(&mut self) {
        self.cache.clear();
        self.dirty.clear();
        self.deleted.clear();
    }
}

// === Sender key object cache (same pattern as sessions) ===

struct SenderKeyStoreState {
    cache: HashMap<Arc<str>, Option<SenderKeyRecord>>,
    dirty: HashSet<Arc<str>>,
}

impl SenderKeyStoreState {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            dirty: HashSet::new(),
        }
    }

    fn key_for(&self, address: &str) -> Arc<str> {
        match self.cache.get_key_value(address) {
            Some((existing, _)) => existing.clone(),
            None => Arc::from(address),
        }
    }

    fn put(&mut self, address: &str, record: SenderKeyRecord) {
        let addr = self.key_for(address);
        self.cache.insert(addr.clone(), Some(record));
        self.dirty.insert(addr.clone());
    }

    fn delete(&mut self, address: &str) {
        let addr = self.key_for(address);
        self.cache.insert(addr.clone(), None);
        self.dirty.insert(addr);
    }

    fn clear(&mut self) {
        self.cache.clear();
        self.dirty.clear();
    }
}

// === Byte cache for identities ===

struct ByteStoreState {
    /// Cached entries. `None` value = known-absent (negative cache).
    cache: HashMap<Arc<str>, Option<Arc<[u8]>>>,
    dirty: HashSet<Arc<str>>,
    deleted: HashSet<Arc<str>>,
}

impl ByteStoreState {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            dirty: HashSet::new(),
            deleted: HashSet::new(),
        }
    }

    /// Reuse the existing Arc<str> key if the address is already in the cache.
    fn key_for(&self, address: &str) -> Arc<str> {
        match self.cache.get_key_value(address) {
            Some((existing, _)) => existing.clone(),
            None => Arc::from(address),
        }
    }

    /// Insert data, skipping if bytes are identical (avoids redundant dirty marks).
    /// Use for stores where data rarely changes (identities).
    fn put_dedup(&mut self, address: &str, data: &[u8]) {
        if let Some(Some(existing)) = self.cache.get(address)
            && existing.as_ref() == data
        {
            return;
        }
        self.put(address, data);
    }

    /// Insert data unconditionally. Use for stores where data changes every
    /// message (sender keys) — the byte comparison would always fail.
    fn put(&mut self, address: &str, data: &[u8]) {
        let addr = self.key_for(address);
        self.cache.insert(addr.clone(), Some(Arc::from(data)));
        self.dirty.insert(addr.clone());
        self.deleted.remove(&addr);
    }

    /// Mark an entry as deleted (negative-cached).
    fn delete(&mut self, address: &str) {
        let addr = self.key_for(address);
        self.cache.insert(addr.clone(), None);
        self.deleted.insert(addr.clone());
        self.dirty.remove(&addr);
    }

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
            sessions: Mutex::new(SessionStoreState::new()),
            identities: Mutex::new(ByteStoreState::new()),
            sender_keys: Mutex::new(SenderKeyStoreState::new()),
        }
    }

    // === Sessions (object cache — serialize only during flush) ===

    pub async fn get_session(
        &self,
        address: &ProtocolAddress,
        backend: &dyn SignalStore,
    ) -> Result<Option<SessionRecord>> {
        let key = address.as_str();
        let mut state = self.sessions.lock().await;
        if let Some(cached) = state.cache.get(key) {
            return Ok(cached.clone());
        }
        let record = match backend.get_session(key).await? {
            Some(bytes) => Some(SessionRecord::deserialize(&bytes)?),
            None => None,
        };
        state.cache.insert(Arc::from(key), record.clone());
        Ok(record)
    }

    pub async fn put_session(&self, address: &ProtocolAddress, record: SessionRecord) {
        self.sessions.lock().await.put(address.as_str(), record);
    }

    pub async fn delete_session(&self, address: &ProtocolAddress) {
        self.sessions.lock().await.delete(address.as_str());
    }

    pub async fn has_session(
        &self,
        address: &ProtocolAddress,
        backend: &dyn SignalStore,
    ) -> Result<bool> {
        let key = address.as_str();
        let mut state = self.sessions.lock().await;
        if let Some(cached) = state.cache.get(key) {
            return Ok(cached.is_some());
        }
        let record = match backend.get_session(key).await? {
            Some(bytes) => Some(SessionRecord::deserialize(&bytes)?),
            None => None,
        };
        let exists = record.is_some();
        state.cache.insert(Arc::from(key), record);
        Ok(exists)
    }

    // === Identities ===

    pub async fn get_identity(
        &self,
        address: &ProtocolAddress,
        backend: &dyn SignalStore,
    ) -> Result<Option<Arc<[u8]>>> {
        let key = address.as_str();
        let mut state = self.identities.lock().await;
        if let Some(cached) = state.cache.get(key) {
            return Ok(cached.clone());
        }
        let data = backend.load_identity(key).await?;
        let arc_data = data.map(Arc::from);
        state.cache.insert(Arc::from(key), arc_data.clone());
        Ok(arc_data)
    }

    pub async fn put_identity(&self, address: &ProtocolAddress, data: &[u8]) {
        self.identities
            .lock()
            .await
            .put_dedup(address.as_str(), data);
    }

    pub async fn delete_identity(&self, address: &ProtocolAddress) {
        self.identities.lock().await.delete(address.as_str());
    }

    // === Sender Keys ===

    pub async fn get_sender_key(
        &self,
        name: &SenderKeyName,
        backend: &dyn SignalStore,
    ) -> Result<Option<SenderKeyRecord>> {
        let key = name.cache_key();
        let mut state = self.sender_keys.lock().await;
        if let Some(cached) = state.cache.get(key) {
            return Ok(cached.clone());
        }
        let record = match backend.get_sender_key(key).await? {
            Some(bytes) => Some(SenderKeyRecord::deserialize(&bytes)?),
            None => None,
        };
        state.cache.insert(Arc::from(key), record.clone());
        Ok(record)
    }

    pub async fn put_sender_key(&self, name: &SenderKeyName, record: SenderKeyRecord) {
        self.sender_keys.lock().await.put(name.cache_key(), record);
    }

    /// Delete a sender key from cache and mark for backend deletion on flush.
    pub async fn delete_sender_key(&self, cache_key: &str) {
        self.sender_keys.lock().await.delete(cache_key);
    }

    // === Flush ===

    /// Flush all dirty state to the backend in a single batch.
    ///
    /// Uses a snapshot-then-release pattern: serialize dirty data under the lock,
    /// release locks, then write to the backend. This avoids blocking all
    /// encrypt/decrypt operations for the duration of I/O.
    ///
    /// Dirty sets are only cleared after ALL writes succeed, preserving retry
    /// semantics on partial failure.
    pub async fn flush(&self, backend: &dyn SignalStore) -> Result<()> {
        // Phase 1: snapshot + serialize under lock, then release.
        let (session_writes, session_delete_keys, session_dirty_keys) = {
            let state = self.sessions.lock().await;
            let dirty_keys: Vec<_> = state.dirty.iter().cloned().collect();
            let deleted_keys: Vec<_> = state.deleted.iter().cloned().collect();
            let mut writes = Vec::with_capacity(dirty_keys.len());
            for address in &dirty_keys {
                if let Some(Some(record)) = state.cache.get(address.as_ref()) {
                    let bytes = record
                        .serialize()
                        .map_err(|e| anyhow::anyhow!("session serialize for {address}: {e}"))?;
                    writes.push((address.clone(), bytes));
                }
            }
            (writes, deleted_keys, dirty_keys)
        };

        let (identity_writes, identity_delete_keys, identity_dirty_keys) = {
            let state = self.identities.lock().await;
            let dirty_keys: Vec<_> = state.dirty.iter().cloned().collect();
            let deleted_keys: Vec<_> = state.deleted.iter().cloned().collect();
            let mut writes = Vec::with_capacity(dirty_keys.len());
            for address in &dirty_keys {
                if let Some(Some(data)) = state.cache.get(address.as_ref()) {
                    let key: [u8; 32] = data.as_ref().try_into().map_err(|_| {
                        anyhow::anyhow!(
                            "Corrupted identity key for {address}: expected 32 bytes, got {}",
                            data.len()
                        )
                    })?;
                    writes.push((address.clone(), key));
                }
            }
            (writes, deleted_keys, dirty_keys)
        };

        let (sender_key_ops, sender_key_dirty_keys) = {
            let state = self.sender_keys.lock().await;
            let dirty_keys: Vec<_> = state.dirty.iter().cloned().collect();
            let mut ops: Vec<(Arc<str>, Option<Vec<u8>>)> = Vec::with_capacity(dirty_keys.len());
            for name in &dirty_keys {
                match state.cache.get(name.as_ref()) {
                    Some(Some(record)) => {
                        let bytes = record
                            .serialize()
                            .map_err(|e| anyhow::anyhow!("sender key serialize for {name}: {e}"))?;
                        ops.push((name.clone(), Some(bytes)));
                    }
                    Some(None) => {
                        ops.push((name.clone(), None));
                    }
                    None => {}
                }
            }
            (ops, dirty_keys)
        };

        // Phase 2: write to backend without holding any locks.
        for (address, bytes) in &session_writes {
            backend.put_session(address, bytes).await?;
        }
        for address in &session_delete_keys {
            backend.delete_session(address).await?;
        }

        for (address, key) in &identity_writes {
            backend.put_identity(address, *key).await?;
        }
        for address in &identity_delete_keys {
            backend.delete_identity(address).await?;
        }

        for (name, bytes_opt) in &sender_key_ops {
            match bytes_opt {
                Some(bytes) => backend.put_sender_key(name, bytes).await?,
                None => backend.delete_sender_key(name).await?,
            }
        }

        // Phase 3: all writes succeeded — remove only the flushed keys from dirty sets.
        // New mutations that occurred during Phase 2 remain in the dirty sets.
        {
            let mut state = self.sessions.lock().await;
            for key in &session_dirty_keys {
                state.dirty.remove(key);
            }
            for key in &session_delete_keys {
                state.deleted.remove(key);
            }
        }
        {
            let mut state = self.identities.lock().await;
            for key in &identity_dirty_keys {
                state.dirty.remove(key);
            }
            for key in &identity_delete_keys {
                state.deleted.remove(key);
            }
        }
        {
            let mut state = self.sender_keys.lock().await;
            for key in &sender_key_dirty_keys {
                state.dirty.remove(key);
            }
        }

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
