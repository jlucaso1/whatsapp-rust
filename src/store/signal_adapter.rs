use crate::store::Device;
use crate::store::signal_cache::SignalStoreCache;
use async_trait::async_trait;
use std::sync::Arc;
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

#[derive(Clone)]
struct SharedDevice {
    device: Arc<RwLock<Device>>,
    cache: Arc<SignalStoreCache>,
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
    pub fn new(device: Arc<RwLock<Device>>, cache: Arc<SignalStoreCache>) -> Self {
        let shared = SharedDevice { device, cache };
        Self {
            session_store: SessionAdapter(shared.clone()),
            identity_store: IdentityAdapter(shared.clone()),
            pre_key_store: PreKeyAdapter(shared.clone()),
            signed_pre_key_store: SignedPreKeyAdapter(shared.clone()),
            sender_key_store: SenderKeyAdapter(shared),
        }
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
        match self
            .0
            .cache
            .get_session(&addr_str, &*device.backend)
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
        let record_bytes = record.serialize()?;

        // Check for base key changes using cache (not DB) for logging
        let device = self.0.device.read().await;
        let existing_data = self
            .0
            .cache
            .get_session(&addr_str, &*device.backend)
            .await
            .ok()
            .flatten();
        drop(device);

        let existing_session = existing_data.and_then(|d| SessionRecord::deserialize(&d).ok());

        if let (Some(existing), Some(new_state)) = (&existing_session, record.session_state()) {
            if let Some(existing_state) = existing.session_state() {
                let old_base_key = existing_state.alice_base_key();
                let new_base_key = new_state.alice_base_key();

                if old_base_key != new_base_key {
                    let backtrace = std::backtrace::Backtrace::force_capture();
                    log::warn!(
                        target: "signal_session_store",
                        "⚠️ SESSION BASE KEY CHANGED for {}!\n\
                         Old base_key: {}\n\
                         New base_key: {}\n\
                         Old version: {:?}, New version: {:?}\n\
                         Old prev_sessions: {}, New prev_sessions: {}\n\
                         This will cause MAC verification failures on future messages!\n\
                         Backtrace:\n{}",
                        addr_str,
                        hex::encode(old_base_key),
                        hex::encode(new_base_key),
                        existing_state.session_version(),
                        new_state.session_version(),
                        existing.previous_session_count(),
                        record.previous_session_count(),
                        backtrace
                    );
                }
            }
        } else if let (None, Some(state)) = (&existing_session, record.session_state()) {
            log::debug!(
                target: "signal_session_store",
                "Creating new session for {}: base_key={}",
                addr_str,
                hex::encode(&state.alice_base_key()[..8.min(state.alice_base_key().len())])
            );
        }

        // Write to cache only (deferred flush to DB)
        self.0.cache.put_session(&addr_str, &record_bytes).await;

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

        // Update the Device's in-memory identity store first (for is_trusted_identity checks).
        // Cache is only marked dirty after Device accepts the identity.
        let mut device = self.0.device.write().await;
        IdentityKeyStore::save_identity(&mut *device, address, identity)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("save_identity", e.to_string()))?;
        drop(device);

        // Device accepted — now write to cache (deferred flush to DB)
        let addr_str = address.to_string();
        self.0
            .cache
            .put_identity(&addr_str, identity.serialize().as_ref())
            .await;

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
        let addr_str = address.to_string();
        let device = self.0.device.read().await;
        match self
            .0
            .cache
            .get_identity(&addr_str, &*device.backend)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("get_identity", e.to_string()))?
        {
            Some(data) => Ok(Some(IdentityKey::decode(&data)?)),
            None => Ok(None),
        }
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
        let key = format!(
            "{}:{}",
            sender_key_name.group_id(),
            sender_key_name.sender_id()
        );
        let data = record.serialize()?;
        self.0.cache.put_sender_key(&key, &data).await;
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> wacore::libsignal::protocol::error::Result<
        Option<wacore::libsignal::protocol::SenderKeyRecord>,
    > {
        let key = format!(
            "{}:{}",
            sender_key_name.group_id(),
            sender_key_name.sender_id()
        );
        let device = self.0.device.read().await;
        match self
            .0
            .cache
            .get_sender_key(&key, &*device.backend)
            .await
            .map_err(|e| {
                wacore::libsignal::protocol::SignalProtocolError::InvalidState(
                    "backend",
                    e.to_string(),
                )
            })? {
            Some(data) => Ok(Some(
                wacore::libsignal::protocol::SenderKeyRecord::deserialize(&data)?,
            )),
            None => Ok(None),
        }
    }
}
