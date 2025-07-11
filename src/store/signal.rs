// Temporary stub implementations for Device signal store traits
// TODO: Implement proper signal store methods matching whatsapp-core trait signatures

use whatsapp_core::signal::address::SignalAddress;
use whatsapp_core::signal::identity::{IdentityKey, IdentityKeyPair};
use whatsapp_core::signal::sender_key_name::SenderKeyName;
use whatsapp_core::signal::state::sender_key_record::SenderKeyRecord;
use whatsapp_core::signal::state::session_record::SessionRecord;
use whatsapp_core::signal::store::*;
use crate::store::Device;
use async_trait::async_trait;
use whatsapp_proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

// Use the StoreError from whatsapp-core signal module
type StoreError = Box<dyn std::error::Error + Send + Sync>;

// --- IdentityKeyStore ---
#[async_trait]
impl IdentityKeyStore for Device {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, StoreError> {
        // TODO: Convert from KeyPair to IdentityKeyPair properly
        // For now, create a new one from the private key
        Ok(IdentityKeyPair::generate())
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
        let key_bytes: [u8; 32] = identity_key.serialize().try_into().map_err(|_| {
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key length")) as StoreError
        })?;

        self.backend.put_identity(&address_str, key_bytes).await
            .map_err(|e| Box::new(e) as StoreError)?;
        Ok(())
    }

    async fn is_trusted_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<bool, StoreError> {
        let address_str = address.to_string();
        let key_bytes: [u8; 32] = identity_key.serialize().try_into().map_err(|_| {
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key length")) as StoreError
        })?;

        self.backend.is_trusted_identity(&address_str, &key_bytes).await
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
        // TODO: Implement proper prekey loading
        let _ = prekey_id;
        Ok(None)
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        // TODO: Implement proper prekey storage
        let _ = (prekey_id, record);
        Ok(())
    }

    async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError> {
        // TODO: Implement proper prekey existence check
        let _ = prekey_id;
        Ok(false)
    }

    async fn remove_prekey(&self, prekey_id: u32) -> Result<(), StoreError> {
        // TODO: Implement proper prekey removal
        let _ = prekey_id;
        Ok(())
    }
}

// --- SignedPreKeyStore ---
#[async_trait]
impl SignedPreKeyStore for Device {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
        // TODO: Implement proper signed prekey loading
        let _ = signed_prekey_id;
        Ok(None)
    }

    async fn load_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError> {
        // TODO: Implement proper signed prekey loading
        Ok(Vec::new())
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), StoreError> {
        // TODO: Implement proper signed prekey storage
        let _ = (signed_prekey_id, record);
        Ok(())
    }
}

// --- SessionStore ---
#[async_trait]
impl SessionStore for Device {
    async fn load_session(&self, address: &SignalAddress) -> Result<SessionRecord, StoreError> {
        // TODO: Implement proper session loading - for now return a new session
        let _ = address;
        Ok(SessionRecord::new())
    }

    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, StoreError> {
        // TODO: Implement proper sub device session listing
        let _ = name;
        Ok(Vec::new())
    }

    async fn store_session(
        &self,
        address: &SignalAddress,
        record: SessionRecord,
    ) -> Result<(), StoreError> {
        // TODO: Implement proper session storage
        let _ = (address, record);
        Ok(())
    }

    async fn contains_session(&self, address: &SignalAddress) -> Result<bool, StoreError> {
        // TODO: Implement proper session existence check
        let _ = address;
        Ok(false)
    }

    async fn delete_session(&self, address: &SignalAddress) -> Result<(), StoreError> {
        // TODO: Implement proper session deletion
        let _ = address;
        Ok(())
    }

    async fn delete_all_sessions(&self, name: &str) -> Result<(), StoreError> {
        // TODO: Implement proper all sessions deletion
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
        // TODO: Implement proper sender key storage
        let _ = (sender_key_name, record);
        Ok(())
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, StoreError> {
        // TODO: Implement proper sender key loading - for now return a new record
        let _ = sender_key_name;
        Ok(SenderKeyRecord::new())
    }
}