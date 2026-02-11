use crate::store::Device;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use wacore::libsignal::protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, PreKeyId,
    PreKeyRecord, PreKeyStore, ProtocolAddress, SessionRecord, SessionStore, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};
use wacore::libsignal::protocol::{SenderKeyRecord, SenderKeyStore};

use wacore::libsignal::store::record_helpers as wacore_record;
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::libsignal::store::{
    PreKeyStore as WacorePreKeyStore, SignedPreKeyStore as WacoreSignedPreKeyStore,
};

#[derive(Clone)]
struct SharedDevice {
    device: Arc<RwLock<Device>>,
}

#[derive(Clone)]
pub struct SessionAdapter(SharedDevice);
#[derive(Clone)]
pub struct IdentityAdapter(SharedDevice);
#[derive(Clone)]
pub struct PreKeyAdapter(SharedDevice);
#[derive(Clone)]
pub struct SignedPreKeyAdapter(SharedDevice);

#[derive(Clone)]
pub struct SenderKeyAdapter(SharedDevice);

#[derive(Clone)]
pub struct SignalProtocolStoreAdapter {
    pub session_store: SessionAdapter,
    pub identity_store: IdentityAdapter,
    pub pre_key_store: PreKeyAdapter,
    pub signed_pre_key_store: SignedPreKeyAdapter,
    pub sender_key_store: SenderKeyAdapter,
}

impl SignalProtocolStoreAdapter {
    pub fn new(device: Arc<RwLock<Device>>) -> Self {
        let shared = SharedDevice { device };
        Self {
            session_store: SessionAdapter(shared.clone()),
            identity_store: IdentityAdapter(shared.clone()),
            pre_key_store: PreKeyAdapter(shared.clone()),
            signed_pre_key_store: SignedPreKeyAdapter(shared.clone()),
            sender_key_store: SenderKeyAdapter(shared),
        }
    }
}

#[derive(Default)]
struct BatchWriteCache {
    sessions: HashMap<ProtocolAddress, Option<SessionRecord>>,
    dirty_sessions: HashSet<ProtocolAddress>,
    identities: HashMap<ProtocolAddress, Option<IdentityKey>>,
    dirty_identities: HashSet<ProtocolAddress>,
    sender_keys: HashMap<SenderKeyName, Option<SenderKeyRecord>>,
    dirty_sender_keys: HashSet<SenderKeyName>,
}

#[derive(Clone)]
pub struct CachedSessionAdapter {
    inner: SessionAdapter,
    cache: Arc<Mutex<BatchWriteCache>>,
}

impl CachedSessionAdapter {
    fn new(inner: SessionAdapter, cache: Arc<Mutex<BatchWriteCache>>) -> Self {
        Self { inner, cache }
    }

    async fn flush(&mut self) -> Result<(), SignalProtocolError> {
        let pending_writes = {
            let mut cache = self.cache.lock().await;
            let dirty = std::mem::take(&mut cache.dirty_sessions);
            let mut writes = Vec::with_capacity(dirty.len());
            for address in dirty {
                if let Some(Some(record)) = cache.sessions.get(&address) {
                    writes.push((address, record.clone()));
                }
            }
            writes
        };

        for (address, record) in pending_writes {
            SessionStore::store_session(&mut self.inner, &address, &record).await?;
        }

        Ok(())
    }

    async fn invalidate(&mut self, address: &ProtocolAddress) {
        let mut cache = self.cache.lock().await;
        cache.sessions.remove(address);
        cache.dirty_sessions.remove(address);
    }
}

#[derive(Clone)]
pub struct CachedIdentityAdapter {
    inner: IdentityAdapter,
    cache: Arc<Mutex<BatchWriteCache>>,
}

impl CachedIdentityAdapter {
    fn new(inner: IdentityAdapter, cache: Arc<Mutex<BatchWriteCache>>) -> Self {
        Self { inner, cache }
    }

    async fn flush(&mut self) -> Result<(), SignalProtocolError> {
        let pending_writes = {
            let mut cache = self.cache.lock().await;
            let dirty = std::mem::take(&mut cache.dirty_identities);
            let mut writes = Vec::with_capacity(dirty.len());
            for address in dirty {
                if let Some(Some(identity)) = cache.identities.get(&address) {
                    writes.push((address, *identity));
                }
            }
            writes
        };

        for (address, identity) in pending_writes {
            IdentityKeyStore::save_identity(&mut self.inner, &address, &identity).await?;
        }

        Ok(())
    }

    async fn invalidate(&mut self, address: &ProtocolAddress) {
        let mut cache = self.cache.lock().await;
        cache.identities.remove(address);
        cache.dirty_identities.remove(address);
    }
}

#[derive(Clone)]
pub struct CachedSenderKeyAdapter {
    inner: SenderKeyAdapter,
    cache: Arc<Mutex<BatchWriteCache>>,
}

impl CachedSenderKeyAdapter {
    fn new(inner: SenderKeyAdapter, cache: Arc<Mutex<BatchWriteCache>>) -> Self {
        Self { inner, cache }
    }

    async fn flush(&mut self) -> Result<(), SignalProtocolError> {
        let pending_writes = {
            let mut cache = self.cache.lock().await;
            let dirty = std::mem::take(&mut cache.dirty_sender_keys);
            let mut writes = Vec::with_capacity(dirty.len());
            for sender_key_name in dirty {
                if let Some(Some(record)) = cache.sender_keys.get(&sender_key_name) {
                    writes.push((sender_key_name, record.clone()));
                }
            }
            writes
        };

        for (sender_key_name, record) in pending_writes {
            SenderKeyStore::store_sender_key(&mut self.inner, &sender_key_name, &record).await?;
        }

        Ok(())
    }

    async fn invalidate(&mut self, sender_key_name: &SenderKeyName) {
        let mut cache = self.cache.lock().await;
        cache.sender_keys.remove(sender_key_name);
        cache.dirty_sender_keys.remove(sender_key_name);
    }
}

pub struct BatchedSignalProtocolStoreAdapter {
    pub session_store: CachedSessionAdapter,
    pub identity_store: CachedIdentityAdapter,
    pub pre_key_store: PreKeyAdapter,
    pub signed_pre_key_store: SignedPreKeyAdapter,
    pub sender_key_store: CachedSenderKeyAdapter,
}

impl BatchedSignalProtocolStoreAdapter {
    pub fn new(device: Arc<RwLock<Device>>) -> Self {
        let base = SignalProtocolStoreAdapter::new(device);
        let cache = Arc::new(Mutex::new(BatchWriteCache::default()));
        Self {
            session_store: CachedSessionAdapter::new(base.session_store, Arc::clone(&cache)),
            identity_store: CachedIdentityAdapter::new(base.identity_store, Arc::clone(&cache)),
            pre_key_store: base.pre_key_store,
            signed_pre_key_store: base.signed_pre_key_store,
            sender_key_store: CachedSenderKeyAdapter::new(base.sender_key_store, cache),
        }
    }

    pub async fn flush(&mut self) -> Result<(), SignalProtocolError> {
        // Preserve original operation order: identity first, then session.
        self.identity_store.flush().await?;
        self.session_store.flush().await?;
        self.sender_key_store.flush().await?;
        Ok(())
    }

    pub async fn invalidate_identity(&mut self, address: &ProtocolAddress) {
        self.identity_store.invalidate(address).await;
    }

    pub async fn invalidate_session(&mut self, address: &ProtocolAddress) {
        self.session_store.invalidate(address).await;
    }

    pub async fn invalidate_sender_key(&mut self, sender_key_name: &SenderKeyName) {
        self.sender_key_store.invalidate(sender_key_name).await;
    }
}

#[async_trait]
impl SessionStore for SessionAdapter {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let addr_str = address.to_string();

        let device = self.0.device.read().await;
        match device
            .backend
            .get_session(&addr_str)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?
        {
            Some(data) => Ok(Some(SessionRecord::deserialize(&data)?)),
            None => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let addr_str = address.to_string();

        let device = self.0.device.read().await;
        let record_bytes = record.serialize()?;
        device
            .backend
            .put_session(&addr_str, &record_bytes)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl IdentityKeyStore for IdentityAdapter {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let device = self.0.device.read().await;
        IdentityKeyStore::get_identity_key_pair(&*device)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("get_identity_key_pair", e.to_string()))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let device = self.0.device.read().await;
        IdentityKeyStore::get_local_registration_id(&*device)
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidState("get_local_registration_id", e.to_string())
            })
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let mut device = self.0.device.write().await;
        IdentityKeyStore::save_identity(&mut *device, address, identity)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("save_identity", e.to_string()))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let device = self.0.device.read().await;
        IdentityKeyStore::is_trusted_identity(&*device, address, identity, direction)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("is_trusted_identity", e.to_string()))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let device = self.0.device.read().await;
        IdentityKeyStore::get_identity(&*device, address)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("get_identity", e.to_string()))
    }
}

#[async_trait]
impl SessionStore for CachedSessionAdapter {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        {
            let cache = self.cache.lock().await;
            if let Some(cached) = cache.sessions.get(address) {
                return Ok(cached.clone());
            }
        }

        let loaded = SessionStore::load_session(&self.inner, address).await?;
        let mut cache = self.cache.lock().await;
        let cached = cache
            .sessions
            .entry(address.clone())
            .or_insert_with(|| loaded.clone());
        Ok(cached.clone())
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let mut cache = self.cache.lock().await;
        cache.sessions.insert(address.clone(), Some(record.clone()));
        cache.dirty_sessions.insert(address.clone());
        Ok(())
    }
}

#[async_trait]
impl IdentityKeyStore for CachedIdentityAdapter {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        IdentityKeyStore::get_identity_key_pair(&self.inner).await
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        IdentityKeyStore::get_local_registration_id(&self.inner).await
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let existing = self.get_identity(address).await?;
        let mut cache = self.cache.lock().await;
        cache.identities.insert(address.clone(), Some(*identity));
        cache.dirty_identities.insert(address.clone());
        Ok(IdentityChange::from_changed(
            existing.is_some_and(|current| current != *identity),
        ))
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        let existing = self.get_identity(address).await?;
        Ok(match existing {
            None => true,
            Some(stored) => stored == *identity,
        })
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        {
            let cache = self.cache.lock().await;
            if let Some(cached) = cache.identities.get(address) {
                return Ok(*cached);
            }
        }

        let loaded = IdentityKeyStore::get_identity(&self.inner, address).await?;
        let mut cache = self.cache.lock().await;
        let cached = cache
            .identities
            .entry(address.clone())
            .or_insert_with(|| loaded);
        Ok(*cached)
    }
}

#[async_trait]
impl PreKeyStore for PreKeyAdapter {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let device = self.0.device.read().await;
        WacorePreKeyStore::load_prekey(&*device, prekey_id.into())
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?
            .ok_or(SignalProtocolError::InvalidPreKeyId)
            .and_then(wacore_record::prekey_structure_to_record)
    }
    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let device = self.0.device.read().await;
        let structure = wacore_record::prekey_record_to_structure(record)?;
        WacorePreKeyStore::store_prekey(&*device, prekey_id.into(), structure, false)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))
    }
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let device = self.0.device.read().await;
        WacorePreKeyStore::remove_prekey(&*device, prekey_id.into())
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))
    }
}

#[async_trait]
impl SignedPreKeyStore for SignedPreKeyAdapter {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let device = self.0.device.read().await;
        WacoreSignedPreKeyStore::load_signed_prekey(&*device, signed_prekey_id.into())
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)
            .and_then(wacore_record::signed_prekey_structure_to_record)
    }
    async fn save_signed_pre_key(
        &mut self,
        _id: SignedPreKeyId,
        _record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        Ok(())
    }
}

#[async_trait]
impl wacore::libsignal::protocol::SenderKeyStore for SenderKeyAdapter {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &wacore::libsignal::protocol::SenderKeyRecord,
    ) -> wacore::libsignal::protocol::error::Result<()> {
        let mut device = self.0.device.write().await;
        wacore::libsignal::protocol::SenderKeyStore::store_sender_key(
            &mut *device,
            sender_key_name,
            record,
        )
        .await
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> wacore::libsignal::protocol::error::Result<
        Option<wacore::libsignal::protocol::SenderKeyRecord>,
    > {
        let mut device = self.0.device.write().await;
        wacore::libsignal::protocol::SenderKeyStore::load_sender_key(&mut *device, sender_key_name)
            .await
    }
}

#[async_trait]
impl SenderKeyStore for CachedSenderKeyAdapter {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> wacore::libsignal::protocol::error::Result<()> {
        let mut cache = self.cache.lock().await;
        cache
            .sender_keys
            .insert(sender_key_name.clone(), Some(record.clone()));
        cache.dirty_sender_keys.insert(sender_key_name.clone());
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> wacore::libsignal::protocol::error::Result<Option<SenderKeyRecord>> {
        {
            let cache = self.cache.lock().await;
            if let Some(cached) = cache.sender_keys.get(sender_key_name) {
                return Ok(cached.clone());
            }
        }

        let loaded = SenderKeyStore::load_sender_key(&mut self.inner, sender_key_name).await?;
        let mut cache = self.cache.lock().await;
        let cached = cache
            .sender_keys
            .entry(sender_key_name.clone())
            .or_insert_with(|| loaded.clone());
        Ok(cached.clone())
    }
}
