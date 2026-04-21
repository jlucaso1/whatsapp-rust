use crate::store::Device;
use crate::store::signal_cache::SignalStoreCache;
use async_lock::RwLock;
use async_trait::async_trait;
use std::sync::Arc;
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

fn signal_err<E: std::fmt::Display>(
    context: &'static str,
) -> impl FnOnce(E) -> SignalProtocolError {
    move |e| SignalProtocolError::InvalidState(context, e.to_string())
}

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

    pub fn as_signal_stores(
        &mut self,
    ) -> wacore::send::SignalStores<
        '_,
        SessionAdapter,
        IdentityAdapter,
        PreKeyAdapter,
        SignedPreKeyAdapter,
    > {
        wacore::send::SignalStores {
            session_store: &mut self.session_store,
            identity_store: &mut self.identity_store,
            prekey_store: &mut self.pre_key_store,
            signed_prekey_store: &self.signed_pre_key_store,
            sender_key_store: &mut self.sender_key_store,
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SessionStore for SessionAdapter {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let device = self.0.device.read().await;
        self.0
            .cache
            .get_session(address, &*device.backend)
            .await
            .map_err(signal_err("backend"))
    }

    async fn has_session(&self, address: &ProtocolAddress) -> Result<bool, SignalProtocolError> {
        let device = self.0.device.read().await;
        self.0
            .cache
            .has_session(address, &*device.backend)
            .await
            .map_err(signal_err("backend"))
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        self.0.cache.put_session(address, record).await;
        Ok(())
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl IdentityKeyStore for IdentityAdapter {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let device = self.0.device.read().await;
        IdentityKeyStore::get_identity_key_pair(&*device)
            .await
            .map_err(signal_err("get_identity_key_pair"))
    }

    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let device = self.0.device.read().await;
        IdentityKeyStore::get_local_registration_id(&*device)
            .await
            .map_err(signal_err("get_local_registration_id"))
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        let existing_identity = self.get_identity(address).await?;

        // Cache-first: write to cache only. The cache flushes to the backend
        // during flush_signal_cache(). This avoids a synchronous backend write
        // on every encrypt/decrypt. is_trusted_identity always returns true
        // (matching WA Web), so the Device-level save is redundant.
        self.0
            .cache
            .put_identity(address, identity.public_key().public_key_bytes())
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
            .map_err(signal_err("is_trusted_identity"))
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let device = self.0.device.read().await;
        match self
            .0
            .cache
            .get_identity(address, &*device.backend)
            .await
            .map_err(signal_err("get_identity"))?
        {
            Some(data) if !data.is_empty() => {
                // Cache and backend store raw 32-byte DJB public key bytes
                let public_key =
                    wacore::libsignal::protocol::PublicKey::from_djb_public_key_bytes(&data)?;
                Ok(Some(IdentityKey::new(public_key)))
            }
            _ => Ok(None),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl PreKeyStore for PreKeyAdapter {
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let device = self.0.device.read().await;
        WacorePreKeyStore::load_prekey(&*device, prekey_id.into())
            .await
            .map_err(signal_err("backend"))?
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
            .map_err(signal_err("backend"))
    }
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let device = self.0.device.read().await;
        WacorePreKeyStore::remove_prekey(&*device, prekey_id.into())
            .await
            .map_err(signal_err("backend"))
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SignedPreKeyStore for SignedPreKeyAdapter {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let device = self.0.device.read().await;
        WacoreSignedPreKeyStore::load_signed_prekey(&*device, signed_prekey_id.into())
            .await
            .map_err(signal_err("backend"))?
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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl wacore::libsignal::protocol::SenderKeyStore for SenderKeyAdapter {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: wacore::libsignal::protocol::SenderKeyRecord,
    ) -> wacore::libsignal::protocol::error::Result<()> {
        self.0.cache.put_sender_key(sender_key_name, record).await;
        Ok(())
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> wacore::libsignal::protocol::error::Result<
        Option<wacore::libsignal::protocol::SenderKeyRecord>,
    > {
        let device = self.0.device.read().await;
        self.0
            .cache
            .get_sender_key(sender_key_name, &*device.backend)
            .await
            .map_err(signal_err("backend"))
    }
}
