use crate::store::Device;
use async_trait::async_trait;
use libsignal_protocol::ProtocolAddress;
use libsignal_protocol::SenderKeyRecord;
use libsignal_protocol::SenderKeyStore;
use libsignal_protocol::SessionRecord;
use libsignal_protocol::SignalProtocolError;
use libsignal_protocol::error::Result as SignalResult;
use std::sync::Arc;
use tokio::sync::Mutex;
use wacore::signal::ecc::keys::EcPublicKey;
use wacore::signal::identity::{IdentityKey, IdentityKeyPair};
use wacore::signal::store::*;
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

type StoreError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait]
impl IdentityKeyStore for Device {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, StoreError> {
        let private_key = self.identity_key.private_key;
        let public_key = self.identity_key.public_key;

        use wacore::signal::ecc::key_pair::EcKeyPair;
        use wacore::signal::ecc::keys::{DjbEcPrivateKey, DjbEcPublicKey};
        use wacore::signal::identity::{IdentityKey, IdentityKeyPair};

        let djb_public_key = DjbEcPublicKey::new(public_key);
        let djb_private_key = DjbEcPrivateKey::new(private_key);
        let identity_key = IdentityKey::new(djb_public_key.clone());
        let key_pair = EcKeyPair::new(djb_public_key, djb_private_key);

        Ok(IdentityKeyPair::new(identity_key, key_pair))
    }

    async fn get_local_registration_id(&self) -> Result<u32, StoreError> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), StoreError> {
        let address_str = address.to_string();
        let key_bytes = identity_key.public_key().public_key();

        self.backend
            .put_identity(&address_str, key_bytes)
            .await
            .map_err(|e| Box::new(e) as StoreError)?;
        Ok(())
    }

    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity_key: &IdentityKey,
    ) -> Result<bool, StoreError> {
        Ok(true)
    }
}

#[async_trait]
impl PreKeyStore for Device {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, StoreError> {
        self.backend.load_prekey(prekey_id).await
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        self.backend.store_prekey(prekey_id, record).await
    }

    async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError> {
        self.backend.contains_prekey(prekey_id).await
    }

    async fn remove_prekey(&self, prekey_id: u32) -> Result<(), StoreError> {
        self.backend.remove_prekey(prekey_id).await
    }
}

#[async_trait]
impl SignedPreKeyStore for Device {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
        if signed_prekey_id == self.signed_pre_key.key_id {
            use wacore::signal::ecc::key_pair::EcKeyPair;
            use wacore::signal::ecc::keys::{DjbEcPrivateKey, DjbEcPublicKey};

            let key_pair = EcKeyPair::new(
                DjbEcPublicKey::new(self.signed_pre_key.key_pair.public_key),
                DjbEcPrivateKey::new(self.signed_pre_key.key_pair.private_key),
            );
            let record = wacore::signal::state::record::new_signed_pre_key_record(
                self.signed_pre_key.key_id,
                key_pair,
                self.signed_pre_key
                    .signature
                    .ok_or("Signature missing from device's signed pre-key")?,
                chrono::Utc::now(),
            );
            return Ok(Some(record));
        }
        Ok(None)
    }

    async fn load_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError> {
        log::warn!(
            "Device: load_signed_prekeys() - returning empty list. Only the device's own signed pre-key should be accessed via load_signed_prekey()."
        );
        Ok(Vec::new())
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        _record: SignedPreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        log::warn!(
            "Device: store_signed_prekey({}) - no-op. Signed pre-keys should only be set once during device creation/pairing and managed via PersistenceManager.",
            signed_prekey_id
        );
        Ok(())
    }

    async fn contains_signed_prekey(&self, signed_prekey_id: u32) -> Result<bool, StoreError> {
        Ok(signed_prekey_id == self.signed_pre_key.key_id)
    }

    async fn remove_signed_prekey(&self, signed_prekey_id: u32) -> Result<(), StoreError> {
        log::warn!(
            "Device: remove_signed_prekey({}) - no-op. Signed pre-keys are managed via PersistenceManager and should not be removed individually.",
            signed_prekey_id
        );
        Ok(())
    }
}

#[async_trait]
impl SessionStore for Device {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<SessionRecord, StoreError> {
        let address_str = address.to_string();
        match self.backend.get_session(&address_str).await {
            Ok(Some(session_data)) => {
                SessionRecord::deserialize(&session_data).map_err(|e| Box::new(e) as StoreError)
            }
            Ok(None) => Ok(SessionRecord::new_fresh()),
            Err(e) => Err(Box::new(e) as StoreError),
        }
    }

    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError> {
        let _ = name;
        Ok(Vec::new())
    }

    async fn store_session(
        &self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), StoreError> {
        let address_str = address.to_string();
        let session_data = record.serialize().map_err(|e| Box::new(e) as StoreError)?;

        self.backend
            .put_session(&address_str, &session_data)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }

    async fn contains_session(&self, address: &ProtocolAddress) -> Result<bool, StoreError> {
        let address_str = address.to_string();
        self.backend
            .has_session(&address_str)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }

    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), StoreError> {
        let address_str = address.to_string();
        self.backend
            .delete_session(&address_str)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }

    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError> {
        let _ = name;
        Ok(())
    }
}

pub struct DeviceArcWrapper(pub Arc<Device>);

impl DeviceArcWrapper {
    pub fn new(device: Arc<Device>) -> Self {
        Self(device)
    }
}

impl Clone for DeviceArcWrapper {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

use tokio::sync::RwLock;

pub struct DeviceRwLockWrapper(pub Arc<RwLock<Device>>);

impl DeviceRwLockWrapper {
    pub fn new(device: Arc<RwLock<Device>>) -> Self {
        Self(device)
    }
}

impl Clone for DeviceRwLockWrapper {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[async_trait]
impl IdentityKeyStore for DeviceRwLockWrapper {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, StoreError> {
        self.0.read().await.get_identity_key_pair().await
    }

    async fn get_local_registration_id(&self) -> Result<u32, StoreError> {
        self.0.read().await.get_local_registration_id().await
    }

    async fn save_identity(
        &self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), StoreError> {
        self.0
            .read()
            .await
            .save_identity(address, identity_key)
            .await
    }

    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity_key: &IdentityKey,
    ) -> Result<bool, StoreError> {
        Ok(true)
    }
}

#[async_trait]
impl PreKeyStore for DeviceRwLockWrapper {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, StoreError> {
        self.0.read().await.load_prekey(prekey_id).await
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        self.0.read().await.store_prekey(prekey_id, record).await
    }

    async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError> {
        self.0.read().await.contains_prekey(prekey_id).await
    }

    async fn remove_prekey(&self, prekey_id: u32) -> Result<(), StoreError> {
        self.0.read().await.remove_prekey(prekey_id).await
    }
}

#[async_trait]
impl SignedPreKeyStore for DeviceRwLockWrapper {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
        self.0
            .read()
            .await
            .load_signed_prekey(signed_prekey_id)
            .await
    }

    async fn load_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError> {
        self.0.read().await.load_signed_prekeys().await
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        self.0
            .read()
            .await
            .store_signed_prekey(signed_prekey_id, record)
            .await
    }

    async fn contains_signed_prekey(&self, signed_prekey_id: u32) -> Result<bool, StoreError> {
        self.0
            .read()
            .await
            .contains_signed_prekey(signed_prekey_id)
            .await
    }

    async fn remove_signed_prekey(&self, signed_prekey_id: u32) -> Result<(), StoreError> {
        self.0
            .read()
            .await
            .remove_signed_prekey(signed_prekey_id)
            .await
    }
}

#[async_trait]
impl SessionStore for DeviceRwLockWrapper {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<SessionRecord, StoreError> {
        self.0.read().await.load_session(address).await
    }

    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError> {
        self.0.read().await.get_sub_device_sessions(name).await
    }

    async fn store_session(
        &self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), StoreError> {
        self.0.read().await.store_session(address, record).await
    }

    async fn contains_session(&self, address: &ProtocolAddress) -> Result<bool, StoreError> {
        self.0.read().await.contains_session(address).await
    }

    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), StoreError> {
        self.0.read().await.delete_session(address).await
    }

    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError> {
        self.0.read().await.delete_all_sessions(name).await
    }
}

pub struct DeviceStore(pub Arc<Mutex<Device>>);

impl DeviceStore {
    pub fn new(device: Arc<Mutex<Device>>) -> Self {
        Self(device)
    }
}

impl Clone for DeviceStore {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

#[async_trait]
impl IdentityKeyStore for DeviceStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, StoreError> {
        self.0.lock().await.get_identity_key_pair().await
    }

    async fn get_local_registration_id(&self) -> Result<u32, StoreError> {
        self.0.lock().await.get_local_registration_id().await
    }

    async fn save_identity(
        &self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), StoreError> {
        self.0
            .lock()
            .await
            .save_identity(address, identity_key)
            .await
    }

    async fn is_trusted_identity(
        &self,
        _address: &ProtocolAddress,
        _identity_key: &IdentityKey,
    ) -> Result<bool, StoreError> {
        Ok(true)
    }
}

#[async_trait]
impl PreKeyStore for DeviceStore {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, StoreError> {
        self.0.lock().await.load_prekey(prekey_id).await
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        self.0.lock().await.store_prekey(prekey_id, record).await
    }

    async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError> {
        self.0.lock().await.contains_prekey(prekey_id).await
    }

    async fn remove_prekey(&self, prekey_id: u32) -> Result<(), StoreError> {
        self.0.lock().await.remove_prekey(prekey_id).await
    }
}

#[async_trait]
impl SignedPreKeyStore for DeviceStore {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
        self.0
            .lock()
            .await
            .load_signed_prekey(signed_prekey_id)
            .await
    }

    async fn load_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError> {
        self.0.lock().await.load_signed_prekeys().await
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        self.0
            .lock()
            .await
            .store_signed_prekey(signed_prekey_id, record)
            .await
    }

    async fn contains_signed_prekey(&self, signed_prekey_id: u32) -> Result<bool, StoreError> {
        self.0
            .lock()
            .await
            .contains_signed_prekey(signed_prekey_id)
            .await
    }

    async fn remove_signed_prekey(&self, signed_prekey_id: u32) -> Result<(), StoreError> {
        self.0
            .lock()
            .await
            .remove_signed_prekey(signed_prekey_id)
            .await
    }
}

#[async_trait]
impl SessionStore for DeviceStore {
    async fn load_session(&self, address: &ProtocolAddress) -> Result<SessionRecord, StoreError> {
        self.0.lock().await.load_session(address).await
    }

    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError> {
        self.0.lock().await.get_sub_device_sessions(name).await
    }

    async fn store_session(
        &self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), StoreError> {
        self.0.lock().await.store_session(address, record).await
    }

    async fn contains_session(&self, address: &ProtocolAddress) -> Result<bool, StoreError> {
        self.0.lock().await.contains_session(address).await
    }

    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), StoreError> {
        self.0.lock().await.delete_session(address).await
    }

    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError> {
        self.0.lock().await.delete_all_sessions(name).await
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for Device {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        record: &SenderKeyRecord,
    ) -> SignalResult<()> {
        // NOTE: The return type now matches the trait
        let unique_key = sender.name().to_string();
        let serialized_record = record.serialize()?;
        self.backend
            .put_sender_key(&unique_key, &serialized_record)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("store_sender_key", e.to_string()))
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
    ) -> SignalResult<Option<SenderKeyRecord>> {
        // NOTE: The return type now matches the trait
        let unique_key = sender.name().to_string();
        match self
            .backend
            .get_sender_key(&unique_key)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("load_sender_key", e.to_string()))?
        {
            Some(data) => {
                // FIX: Use the public `serialize()` method to check for emptiness.
                // An empty/fresh record serializes to an empty Vec.
                let record = SenderKeyRecord::deserialize(&data)?;
                if record.serialize()?.is_empty() {
                    Ok(None)
                } else {
                    Ok(Some(record))
                }
            }
            None => Ok(None),
        }
    }
}
