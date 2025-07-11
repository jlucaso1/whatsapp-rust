use whatsapp_core::signal::address::SignalAddress;
use whatsapp_core::signal::ecc;
use whatsapp_core::signal::identity::{IdentityKey, IdentityKeyPair};
use whatsapp_core::signal::sender_key_name::SenderKeyName;

use whatsapp_core::signal::state::sender_key_record::SenderKeyRecord;
use whatsapp_core::signal::state::session_record::SessionRecord;
use whatsapp_core::signal::store::*;
use crate::store::Device;
use async_trait::async_trait;
use whatsapp_proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

// --- IdentityKeyStore ---
#[async_trait]
impl IdentityKeyStore for Device {
    async fn get_identity_key_pair(
        &self,
    ) -> Result<IdentityKeyPair, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.identity_key.clone().into())
    }

    async fn get_local_registration_id(
        &self,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.registration_id)
    }

    async fn save_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let address_str = address.to_string();
        let key_bytes: [u8; 32] = identity_key.serialize().try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key length")
        })?;

        self.backend.put_identity(&address_str, key_bytes).await?;
        Ok(())
    }

    async fn is_trusted_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let _ = direction; // Unused in this implementation
        let address_str = address.to_string();
        let key_bytes: [u8; 32] = identity_key.serialize().try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key length")
        })?;

        self.backend.is_trusted_identity(&address_str, &key_bytes).await.map_err(Into::into)
    }

    async fn get_identity(
        &self,
        address: &SignalAddress,
    ) -> Result<Option<IdentityKey>, Box<dyn std::error::Error + Send + Sync>> {
        let address_str = address.to_string();
        if self.backend.is_trusted_identity(&address_str, &[0u8; 32]).await? {
            // This is a simplified implementation - in practice you'd store and retrieve the actual key
            // For now, return None to indicate no stored key
            Ok(None)
        } else {
            Ok(None)
        }
    }
}

// --- PreKeyStore ---
#[async_trait]
impl PreKeyStore for Device {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
    ) -> Result<PreKeyRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.get_pre_key(prekey_id).await.map_err(Into::into)
    }

    async fn save_pre_key(
        &self,
        prekey_id: u32,
        record: &PreKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.put_pre_key(prekey_id, record).await.map_err(Into::into)
    }

    async fn remove_pre_key(
        &self,
        prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.remove_pre_key(prekey_id).await.map_err(Into::into)
    }
}

// --- SignedPreKeyStore ---
#[async_trait]
impl SignedPreKeyStore for Device {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: u32,
    ) -> Result<SignedPreKeyRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.get_signed_pre_key(signed_prekey_id).await.map_err(Into::into)
    }

    async fn save_signed_pre_key(
        &self,
        signed_prekey_id: u32,
        record: &SignedPreKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.put_signed_pre_key(signed_prekey_id, record).await.map_err(Into::into)
    }

    async fn get_signed_pre_keys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.get_signed_pre_keys().await.map_err(Into::into)
    }
}

// --- SessionStore ---
#[async_trait]
impl SessionStore for Device {
    async fn load_session(
        &self,
        address: &SignalAddress,
    ) -> Result<Option<SessionRecord>, Box<dyn std::error::Error + Send + Sync>> {
        let address_str = address.to_string();
        if let Some(session_data) = self.backend.get_session(&address_str).await? {
            let record = SessionRecord::deserialize(&session_data)?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }

    async fn store_session(
        &self,
        address: &SignalAddress,
        record: &SessionRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let address_str = address.to_string();
        let session_data = record.serialize()?;
        self.backend.put_session(&address_str, &session_data).await?;
        Ok(())
    }

    async fn contains_session(
        &self,
        address: &SignalAddress,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let address_str = address.to_string();
        self.backend.has_session(&address_str).await.map_err(Into::into)
    }

    async fn delete_session(
        &self,
        address: &SignalAddress,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let address_str = address.to_string();
        self.backend.delete_session(&address_str).await.map_err(Into::into)
    }

    async fn delete_all_sessions(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let _ = name; // Simplified implementation
        // In a real implementation, you'd iterate through all sessions for this name
        Ok(())
    }
}

// --- SenderKeyStore ---
#[async_trait]
impl SenderKeyStore for Device {
    async fn store_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
        record: &SenderKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let key = sender_key_name.to_string();
        let data = record.serialize()?;
        self.backend.store_sender_key(&key, &data).await.map_err(Into::into)
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<Option<SenderKeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
        let key = sender_key_name.to_string();
        if let Some(data) = self.backend.load_sender_key(&key).await? {
            let record = SenderKeyRecord::deserialize(&data)?;
            Ok(Some(record))
        } else {
            Ok(None)
        }
    }
}