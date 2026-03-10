use std::collections::{HashMap, HashSet};

use anyhow::Result;
use tokio::sync::Mutex;

use wacore::store::traits::SignalStore;

/// In-memory cache for Signal protocol state, matching WhatsApp Web's SignalStoreCache.
///
/// All crypto operations read/write this cache. DB writes are deferred to `flush()`.
/// Each store type has its own mutex for independent locking.
pub struct SignalStoreCache {
    sessions: Mutex<StoreState>,
    identities: Mutex<StoreState>,
    sender_keys: Mutex<StoreState>,
}

struct StoreState {
    /// Cached entries. `None` value = known-absent (negative cache).
    cache: HashMap<String, Option<Vec<u8>>>,
    /// Keys that have been modified and need flushing to the backend.
    dirty: HashSet<String>,
    /// Keys that have been deleted and need flushing to the backend.
    deleted: HashSet<String>,
}

impl StoreState {
    fn new() -> Self {
        Self {
            cache: HashMap::new(),
            dirty: HashSet::new(),
            deleted: HashSet::new(),
        }
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
    ) -> Result<Option<Vec<u8>>> {
        let mut state = self.sessions.lock().await;
        if let Some(cached) = state.cache.get(address) {
            return Ok(cached.clone());
        }
        let data = backend.get_session(address).await?;
        state.cache.insert(address.to_string(), data.clone());
        Ok(data)
    }

    pub async fn put_session(&self, address: &str, data: &[u8]) {
        let mut state = self.sessions.lock().await;
        state.cache.insert(address.to_string(), Some(data.to_vec()));
        state.dirty.insert(address.to_string());
        state.deleted.remove(address);
    }

    pub async fn delete_session(&self, address: &str) {
        let mut state = self.sessions.lock().await;
        state.cache.insert(address.to_string(), None);
        state.deleted.insert(address.to_string());
        state.dirty.remove(address);
    }

    pub async fn has_session(&self, address: &str, backend: &dyn SignalStore) -> Result<bool> {
        Ok(self.get_session(address, backend).await?.is_some())
    }

    // === Identities ===

    pub async fn get_identity(
        &self,
        address: &str,
        backend: &dyn SignalStore,
    ) -> Result<Option<Vec<u8>>> {
        let mut state = self.identities.lock().await;
        if let Some(cached) = state.cache.get(address) {
            return Ok(cached.clone());
        }
        let data = backend.load_identity(address).await?;
        state.cache.insert(address.to_string(), data.clone());
        Ok(data)
    }

    pub async fn put_identity(&self, address: &str, data: &[u8]) {
        let mut state = self.identities.lock().await;
        state.cache.insert(address.to_string(), Some(data.to_vec()));
        state.dirty.insert(address.to_string());
        state.deleted.remove(address);
    }

    pub async fn delete_identity(&self, address: &str) {
        let mut state = self.identities.lock().await;
        state.cache.insert(address.to_string(), None);
        state.deleted.insert(address.to_string());
        state.dirty.remove(address);
    }

    // === Sender Keys ===

    pub async fn get_sender_key(
        &self,
        address: &str,
        backend: &dyn SignalStore,
    ) -> Result<Option<Vec<u8>>> {
        let mut state = self.sender_keys.lock().await;
        if let Some(cached) = state.cache.get(address) {
            return Ok(cached.clone());
        }
        let data = backend.get_sender_key(address).await?;
        state.cache.insert(address.to_string(), data.clone());
        Ok(data)
    }

    pub async fn put_sender_key(&self, address: &str, data: &[u8]) {
        let mut state = self.sender_keys.lock().await;
        state.cache.insert(address.to_string(), Some(data.to_vec()));
        state.dirty.insert(address.to_string());
        state.deleted.remove(address);
    }

    // === Flush ===

    /// Flush all dirty state to the backend in a single batch.
    /// Acquires all 3 mutexes to ensure consistency (matches WhatsApp Web's pattern).
    pub async fn flush(&self, backend: &dyn SignalStore) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        let mut identities = self.identities.lock().await;
        let mut sender_keys = self.sender_keys.lock().await;

        // Flush sessions
        let dirty: Vec<_> = sessions.dirty.drain().collect();
        for address in dirty {
            if let Some(Some(data)) = sessions.cache.get(&address) {
                backend.put_session(&address, data).await?;
            }
        }
        let deleted: Vec<_> = sessions.deleted.drain().collect();
        for address in deleted {
            backend.delete_session(&address).await?;
        }

        // Flush identities
        let dirty: Vec<_> = identities.dirty.drain().collect();
        for address in dirty {
            if let Some(Some(data)) = identities.cache.get(&address)
                && let Ok(key) = <&[u8; 32]>::try_from(data.as_slice())
            {
                backend.put_identity(&address, *key).await?;
            }
        }
        let deleted: Vec<_> = identities.deleted.drain().collect();
        for address in deleted {
            backend.delete_identity(&address).await?;
        }

        // Flush sender keys
        let dirty: Vec<_> = sender_keys.dirty.drain().collect();
        for name in dirty {
            if let Some(Some(data)) = sender_keys.cache.get(&name) {
                backend.put_sender_key(&name, data).await?;
            }
        }

        Ok(())
    }

    /// Clear all cached state (used on disconnect/reconnect).
    pub async fn clear(&self) {
        self.sessions.lock().await.clear();
        self.identities.lock().await.clear();
        self.sender_keys.lock().await.clear();
    }
}
