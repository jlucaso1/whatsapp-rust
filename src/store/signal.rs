// Temporary stub implementations for Device signal store traits
// TODO: Implement proper signal store methods matching whatsapp-core trait signatures

use crate::store::Device;
use async_trait::async_trait;
use std::sync::Arc;
use whatsapp_core::signal::address::SignalAddress;
use whatsapp_core::signal::identity::{IdentityKey, IdentityKeyPair};
use whatsapp_core::signal::sender_key_name::SenderKeyName;
use whatsapp_core::signal::state::sender_key_record::SenderKeyRecord;
use whatsapp_core::signal::state::session_record::SessionRecord;
use whatsapp_core::signal::store::*;
use whatsapp_proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

// Use the StoreError from whatsapp-core signal module
type StoreError = Box<dyn std::error::Error + Send + Sync>;

// --- IdentityKeyStore ---
#[async_trait]
impl IdentityKeyStore for Device {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, StoreError> {
        // Convert from our KeyPair to signal protocol IdentityKeyPair
        let private_key = self.identity_key.private_key;
        let public_key = self.identity_key.public_key;

        use whatsapp_core::signal::ecc::key_pair::EcKeyPair;
        use whatsapp_core::signal::ecc::keys::{DjbEcPrivateKey, DjbEcPublicKey};
        use whatsapp_core::signal::identity::{IdentityKey, IdentityKeyPair};

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
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), StoreError> {
        let address_str = address.to_string();
        let key_bytes = identity_key.serialize();

        // Ensure we have exactly 32 bytes for the key
        if key_bytes.len() != 32 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid key length: expected 32, got {}", key_bytes.len()),
            )) as StoreError);
        }

        let key_array: [u8; 32] = key_bytes.try_into().unwrap();
        self.backend
            .put_identity(&address_str, key_array)
            .await
            .map_err(|e| Box::new(e) as StoreError)?;
        Ok(())
    }

    async fn is_trusted_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<bool, StoreError> {
        let address_str = address.to_string();
        let key_bytes = identity_key.serialize();

        // Ensure we have exactly 32 bytes for the key
        if key_bytes.len() != 32 {
            return Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid key length: expected 32, got {}", key_bytes.len()),
            )) as StoreError);
        }

        let key_array: [u8; 32] = key_bytes.try_into().unwrap();
        self.backend
            .is_trusted_identity(&address_str, &key_array)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }
}

// --- PreKeyStore ---
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

// --- SignedPreKeyStore ---
#[async_trait]
impl SignedPreKeyStore for Device {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
        self.backend.load_signed_prekey(signed_prekey_id).await
    }

    async fn load_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError> {
        self.backend.load_signed_prekeys().await
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        self.backend
            .store_signed_prekey(signed_prekey_id, record)
            .await
    }

    async fn contains_signed_prekey(&self, signed_prekey_id: u32) -> Result<bool, StoreError> {
        self.backend.contains_signed_prekey(signed_prekey_id).await
    }

    async fn remove_signed_prekey(&self, signed_prekey_id: u32) -> Result<(), StoreError> {
        self.backend.remove_signed_prekey(signed_prekey_id).await
    }
}

// --- SessionStore ---
#[async_trait]
impl SessionStore for Device {
    async fn load_session(&self, address: &SignalAddress) -> Result<SessionRecord, StoreError> {
        let address_str = address.to_string();
        match self.backend.get_session(&address_str).await {
            Ok(Some(session_data)) => {
                // Deserialize the session data into a SessionRecord using bincode
                bincode::serde::decode_from_slice(&session_data, bincode::config::standard())
                    .map(|(record, _)| record)
                    .map_err(|e| Box::new(e) as StoreError)
            }
            Ok(None) => Ok(SessionRecord::new()),
            Err(e) => Err(Box::new(e) as StoreError),
        }
    }

    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError> {
        // TODO: Implement proper sub device session listing by querying backend
        // For now, this requires extending the Backend trait to support this query
        let _ = name;
        Ok(Vec::new())
    }

    async fn store_session(
        &self,
        address: &SignalAddress,
        record: &SessionRecord,
    ) -> Result<(), StoreError> {
        let address_str = address.to_string();
        // Serialize the session record using bincode
        let session_data = bincode::serde::encode_to_vec(record, bincode::config::standard())
            .map_err(|e| Box::new(e) as StoreError)?;

        self.backend
            .put_session(&address_str, &session_data)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }

    async fn contains_session(&self, address: &SignalAddress) -> Result<bool, StoreError> {
        let address_str = address.to_string();
        self.backend
            .has_session(&address_str)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }

    async fn delete_session(&self, address: &SignalAddress) -> Result<(), StoreError> {
        let address_str = address.to_string();
        self.backend
            .delete_session(&address_str)
            .await
            .map_err(|e| Box::new(e) as StoreError)
    }

    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError> {
        // TODO: Implement proper all sessions deletion by extending Backend trait
        // For now, this is a simplified implementation
        let _ = name;
        Ok(())
    }
}

// --- SenderKeyStore ---
#[async_trait]
impl SenderKeyStore for Device {
    async fn store_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
        record: SenderKeyRecord,
    ) -> Result<(), StoreError> {
        self.backend.store_sender_key(sender_key_name, record).await
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, StoreError> {
        self.backend.load_sender_key(sender_key_name).await
    }

    async fn delete_sender_key(&self, sender_key_name: &SenderKeyName) -> Result<(), StoreError> {
        self.backend.delete_sender_key(sender_key_name).await
    }
}

// Implement signal store traits on Arc<Mutex<Device>> for easier use in the main crate
use tokio::sync::Mutex;

// Wrapper type to work around orphan rules
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
        address: &SignalAddress,
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
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<bool, StoreError> {
        self.0
            .lock()
            .await
            .is_trusted_identity(address, identity_key)
            .await
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
    async fn load_session(&self, address: &SignalAddress) -> Result<SessionRecord, StoreError> {
        self.0.lock().await.load_session(address).await
    }

    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError> {
        self.0.lock().await.get_sub_device_sessions(name).await
    }

    async fn store_session(
        &self,
        address: &SignalAddress,
        record: &SessionRecord,
    ) -> Result<(), StoreError> {
        self.0.lock().await.store_session(address, record).await
    }

    async fn contains_session(&self, address: &SignalAddress) -> Result<bool, StoreError> {
        self.0.lock().await.contains_session(address).await
    }

    async fn delete_session(&self, address: &SignalAddress) -> Result<(), StoreError> {
        self.0.lock().await.delete_session(address).await
    }

    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError> {
        self.0.lock().await.delete_all_sessions(name).await
    }
}

#[async_trait]
impl SenderKeyStore for DeviceStore {
    async fn store_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
        record: SenderKeyRecord,
    ) -> Result<(), StoreError> {
        self.0
            .lock()
            .await
            .store_sender_key(sender_key_name, record)
            .await
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, StoreError> {
        self.0.lock().await.load_sender_key(sender_key_name).await
    }

    async fn delete_sender_key(&self, sender_key_name: &SenderKeyName) -> Result<(), StoreError> {
        self.0.lock().await.delete_sender_key(sender_key_name).await
    }
}
