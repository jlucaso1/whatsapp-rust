use crate::store::Device;
use async_trait::async_trait;
use moka::future::Cache;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use wacore::libsignal::protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, PreKeyId,
    PreKeyRecord, PreKeyStore, ProtocolAddress, SessionRecord, SessionStore, SignalProtocolError,
    SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
};

use wacore::libsignal::store::record_helpers as wacore_record;
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::libsignal::store::{
    PreKeyStore as WacorePreKeyStore, SignedPreKeyStore as WacoreSignedPreKeyStore,
};

/// Default cache capacity for sessions (covers typical large group scenarios)
const SESSION_CACHE_CAPACITY: u64 = 5_000;
/// Time-to-live for cached sessions (1 hour)
const SESSION_CACHE_TTL_SECS: u64 = 3600;

#[derive(Clone)]
struct SharedDevice {
    device: Arc<RwLock<Device>>,
    /// In-memory cache for session records to reduce database I/O.
    /// Key: Protocol address string, Value: Serialized session bytes
    session_cache: Cache<String, Vec<u8>>,
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
        // Build a session cache with LRU eviction and TTL
        let session_cache: Cache<String, Vec<u8>> = Cache::builder()
            .max_capacity(SESSION_CACHE_CAPACITY)
            .time_to_live(Duration::from_secs(SESSION_CACHE_TTL_SECS))
            .build();

        let shared = SharedDevice {
            device,
            session_cache,
        };
        Self {
            session_store: SessionAdapter(shared.clone()),
            identity_store: IdentityAdapter(shared.clone()),
            pre_key_store: PreKeyAdapter(shared.clone()),
            signed_pre_key_store: SignedPreKeyAdapter(shared.clone()),
            sender_key_store: SenderKeyAdapter(shared),
        }
    }

    /// Creates a new adapter with a custom session cache capacity.
    /// Useful for scenarios with very large groups or many concurrent chats.
    pub fn with_cache_capacity(device: Arc<RwLock<Device>>, capacity: u64) -> Self {
        let session_cache: Cache<String, Vec<u8>> = Cache::builder()
            .max_capacity(capacity)
            .time_to_live(Duration::from_secs(SESSION_CACHE_TTL_SECS))
            .build();

        let shared = SharedDevice {
            device,
            session_cache,
        };
        Self {
            session_store: SessionAdapter(shared.clone()),
            identity_store: IdentityAdapter(shared.clone()),
            pre_key_store: PreKeyAdapter(shared.clone()),
            signed_pre_key_store: SignedPreKeyAdapter(shared.clone()),
            sender_key_store: SenderKeyAdapter(shared),
        }
    }

    /// Invalidates a specific session from the cache.
    /// Call this when you know a session has been modified externally.
    pub async fn invalidate_session(&self, address: &ProtocolAddress) {
        self.session_store
            .0
            .session_cache
            .invalidate(&address.to_string())
            .await;
    }

    /// Clears the entire session cache.
    /// Useful when reconnecting or when session state may be stale.
    pub async fn clear_session_cache(&self) {
        self.session_store.0.session_cache.invalidate_all();
    }
}

#[async_trait]
impl SessionStore for SessionAdapter {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let addr_str = address.to_string();

        // 1. Check cache first (fast path)
        if let Some(cached_bytes) = self.0.session_cache.get(&addr_str).await {
            return Ok(Some(SessionRecord::deserialize(&cached_bytes)?));
        }

        // 2. Cache miss - load from database
        let device = self.0.device.read().await;
        match device
            .backend
            .get_session(&addr_str)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?
        {
            Some(data) => {
                // 3. Populate cache with the loaded data
                self.0.session_cache.insert(addr_str, data.clone()).await;
                Ok(Some(SessionRecord::deserialize(&data)?))
            }
            None => Ok(None),
        }
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let addr_str = address.to_string();
        let record_bytes = record.serialize()?;

        // 1. Update the database
        let device = self.0.device.read().await;
        device
            .backend
            .put_session(&addr_str, &record_bytes)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("backend", e.to_string()))?;

        // 2. Update the cache with the new session data
        self.0.session_cache.insert(addr_str, record_bytes).await;

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
        let existing_identity = self.get_identity(address).await?;

        let mut device = self.0.device.write().await;
        IdentityKeyStore::save_identity(&mut *device, address, identity)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("save_identity", e.to_string()))?;

        match existing_identity {
            None => Ok(IdentityChange::NewOrUnchanged),
            Some(existing) if &existing == identity => Ok(IdentityChange::NewOrUnchanged),
            Some(_) => Ok(IdentityChange::ReplacedExisting),
        }
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
