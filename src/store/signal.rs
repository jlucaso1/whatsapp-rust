use crate::store::Device;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::Mutex;
use wacore::libsignal::protocol::error::Result as SignalResult;
use wacore::libsignal::protocol::{
    Direction, IdentityChange, IdentityKey, IdentityKeyPair, IdentityKeyStore, PrivateKey,
    ProtocolAddress, PublicKey, SenderKeyRecord, SenderKeyStore, SessionRecord,
    SignalProtocolError,
};
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::libsignal::store::*;
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

type StoreError = Box<dyn std::error::Error + Send + Sync>;

macro_rules! impl_store_wrapper {
    ($wrapper_ty:ty, $read_lock:ident, $write_lock:ident) => {
        #[async_trait]
        impl IdentityKeyStore for $wrapper_ty {
            async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
                self.0.$read_lock().await.get_identity_key_pair().await
            }

            async fn get_local_registration_id(&self) -> SignalResult<u32> {
                self.0.$read_lock().await.get_local_registration_id().await
            }

            async fn save_identity(
                &mut self,
                address: &ProtocolAddress,
                identity_key: &IdentityKey,
            ) -> SignalResult<IdentityChange> {
                self.0
                    .$write_lock()
                    .await
                    .save_identity(address, identity_key)
                    .await
            }

            async fn is_trusted_identity(
                &self,
                address: &ProtocolAddress,
                identity_key: &IdentityKey,
                direction: Direction,
            ) -> SignalResult<bool> {
                self.0
                    .$read_lock()
                    .await
                    .is_trusted_identity(address, identity_key, direction)
                    .await
            }

            async fn get_identity(
                &self,
                address: &ProtocolAddress,
            ) -> SignalResult<Option<IdentityKey>> {
                self.0.$read_lock().await.get_identity(address).await
            }
        }

        #[async_trait]
        impl PreKeyStore for $wrapper_ty {
            async fn load_prekey(
                &self,
                prekey_id: u32,
            ) -> Result<Option<PreKeyRecordStructure>, StoreError> {
                self.0.$read_lock().await.load_prekey(prekey_id).await
            }

            async fn store_prekey(
                &self,
                prekey_id: u32,
                record: PreKeyRecordStructure,
                uploaded: bool,
            ) -> Result<(), StoreError> {
                self.0
                    .$write_lock()
                    .await
                    .store_prekey(prekey_id, record, uploaded)
                    .await
            }

            async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError> {
                self.0.$read_lock().await.contains_prekey(prekey_id).await
            }

            async fn remove_prekey(&self, prekey_id: u32) -> Result<(), StoreError> {
                self.0.$write_lock().await.remove_prekey(prekey_id).await
            }
        }

        #[async_trait]
        impl SignedPreKeyStore for $wrapper_ty {
            async fn load_signed_prekey(
                &self,
                signed_prekey_id: u32,
            ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
                self.0
                    .$read_lock()
                    .await
                    .load_signed_prekey(signed_prekey_id)
                    .await
            }

            async fn load_signed_prekeys(
                &self,
            ) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError> {
                self.0.$read_lock().await.load_signed_prekeys().await
            }

            async fn store_signed_prekey(
                &self,
                signed_prekey_id: u32,
                record: SignedPreKeyRecordStructure,
            ) -> Result<(), StoreError> {
                self.0
                    .$write_lock()
                    .await
                    .store_signed_prekey(signed_prekey_id, record)
                    .await
            }

            async fn contains_signed_prekey(
                &self,
                signed_prekey_id: u32,
            ) -> Result<bool, StoreError> {
                self.0
                    .$read_lock()
                    .await
                    .contains_signed_prekey(signed_prekey_id)
                    .await
            }

            async fn remove_signed_prekey(&self, signed_prekey_id: u32) -> Result<(), StoreError> {
                self.0
                    .$write_lock()
                    .await
                    .remove_signed_prekey(signed_prekey_id)
                    .await
            }
        }

        #[async_trait]
        impl SessionStore for $wrapper_ty {
            async fn load_session(
                &self,
                address: &ProtocolAddress,
            ) -> Result<SessionRecord, StoreError> {
                self.0.$read_lock().await.load_session(address).await
            }

            async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError> {
                self.0
                    .$read_lock()
                    .await
                    .get_sub_device_sessions(name)
                    .await
            }

            async fn store_session(
                &self,
                address: &ProtocolAddress,
                record: &SessionRecord,
            ) -> Result<(), StoreError> {
                self.0
                    .$write_lock()
                    .await
                    .store_session(address, record)
                    .await
            }

            async fn contains_session(
                &self,
                address: &ProtocolAddress,
            ) -> Result<bool, StoreError> {
                self.0.$read_lock().await.contains_session(address).await
            }

            async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), StoreError> {
                self.0.$write_lock().await.delete_session(address).await
            }

            async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError> {
                self.0.$write_lock().await.delete_all_sessions(name).await
            }
        }
    };
}

#[async_trait]
impl IdentityKeyStore for Device {
    async fn get_identity_key_pair(&self) -> SignalResult<IdentityKeyPair> {
        Ok(self.identity_key.clone().into())
    }

    async fn get_local_registration_id(&self) -> SignalResult<u32> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
    ) -> SignalResult<IdentityChange> {
        let address_str = address.to_string();
        let key_bytes = identity_key.public_key().public_key_bytes();
        let existing_identity_opt = self.get_identity(address).await?;

        self.backend
            .put_identity(
                &address_str,
                key_bytes.try_into().map_err(|_| {
                    SignalProtocolError::InvalidArgument("Invalid key length".into())
                })?,
            )
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidState("backend put_identity", e.to_string())
            })?;

        match existing_identity_opt {
            None => Ok(IdentityChange::NewOrUnchanged),
            Some(existing) if &existing == identity_key => Ok(IdentityChange::NewOrUnchanged),
            Some(_) => Ok(IdentityChange::ReplacedExisting),
        }
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
        _direction: Direction,
    ) -> SignalResult<bool> {
        // Trust on first use: if we don't have an identity stored, trust this one
        // If we have one stored, it must match
        match self.get_identity(address).await? {
            None => Ok(true), // Trust on first use
            Some(stored_identity) => Ok(&stored_identity == identity_key),
        }
    }

    async fn get_identity(&self, address: &ProtocolAddress) -> SignalResult<Option<IdentityKey>> {
        let identity_bytes = self
            .backend
            .load_identity(&address.to_string())
            .await
            .map_err(|e| {
                SignalProtocolError::InvalidState("backend get_identity", e.to_string())
            })?;

        match identity_bytes {
            Some(bytes) if !bytes.is_empty() => {
                let public_key = PublicKey::from_djb_public_key_bytes(&bytes)?;
                Ok(Some(IdentityKey::new(public_key)))
            }
            _ => Ok(None),
        }
    }
}

#[async_trait]
impl PreKeyStore for Device {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, StoreError> {
        use prost::Message;
        use wacore::libsignal::protocol::KeyPair;
        use wacore::libsignal::store::record_helpers::new_pre_key_record;

        match self.backend.load_prekey(prekey_id).await {
            Ok(Some(bytes)) => {
                // Try new format first (protobuf-encoded PreKeyRecordStructure)
                if let Ok(record) = PreKeyRecordStructure::decode(bytes.as_slice()) {
                    return Ok(Some(record));
                }

                // Fallback: old format stored just the private key bytes (32 bytes)
                // Reconstruct the full record by deriving the public key
                if let Ok(private_key) = PrivateKey::deserialize(&bytes)
                    && let Ok(public_key) = private_key.public_key()
                {
                    let key_pair = KeyPair::new(public_key, private_key);
                    let record = new_pre_key_record(prekey_id, &key_pair);
                    return Ok(Some(record));
                }

                // Could not decode in either format
                Ok(None)
            }
            Ok(None) => Ok(None),
            Err(e) => Err(Box::new(e) as StoreError),
        }
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
        uploaded: bool,
    ) -> Result<(), StoreError> {
        use prost::Message;
        let bytes = record.encode_to_vec();
        self.backend
            .store_prekey(prekey_id, &bytes, uploaded)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }

    async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError> {
        match self.backend.load_prekey(prekey_id).await {
            Ok(opt) => Ok(opt.is_some()),
            Err(e) => Err(Box::new(e) as StoreError),
        }
    }

    async fn remove_prekey(&self, prekey_id: u32) -> Result<(), StoreError> {
        self.backend
            .remove_prekey(prekey_id)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }
}

#[async_trait]
impl SignedPreKeyStore for Device {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
        if signed_prekey_id == self.signed_pre_key_id {
            let record = wacore::libsignal::store::record_helpers::new_signed_pre_key_record(
                self.signed_pre_key_id,
                &self.signed_pre_key,
                self.signed_pre_key_signature,
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
        Ok(signed_prekey_id == self.signed_pre_key_id)
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

impl_store_wrapper!(DeviceRwLockWrapper, read, write);

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

impl_store_wrapper!(DeviceStore, lock, lock);

#[async_trait]
impl SenderKeyStore for Device {
    async fn store_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> SignalResult<()> {
        let unique_key = format!(
            "{}:{}",
            sender_key_name.group_id(),
            sender_key_name.sender_id()
        );
        let serialized_record = record.serialize()?;
        self.backend
            .put_sender_key(&unique_key, &serialized_record)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("store_sender_key", e.to_string()))
    }

    async fn load_sender_key(
        &mut self,
        sender_key_name: &SenderKeyName,
    ) -> SignalResult<Option<SenderKeyRecord>> {
        let unique_key = format!(
            "{}:{}",
            sender_key_name.group_id(),
            sender_key_name.sender_id()
        );
        match self
            .backend
            .get_sender_key(&unique_key)
            .await
            .map_err(|e| SignalProtocolError::InvalidState("load_sender_key", e.to_string()))?
        {
            Some(data) => {
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
