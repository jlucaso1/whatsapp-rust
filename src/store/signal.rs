use crate::signal::address::SignalAddress;
use crate::signal::ecc;
use crate::signal::identity::{IdentityKey, IdentityKeyPair};
use crate::signal::sender_key_name::SenderKeyName;
use crate::signal::state::record::SignedPreKeyRecordStructureExt;
use crate::signal::state::sender_key_record::SenderKeyRecord;
use crate::signal::state::session_record::SessionRecord;
use crate::signal::store::*;
use crate::store::Device;
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::RwLock;
use whatsapp_proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

// --- IdentityKeyStore ---
#[async_trait]
impl IdentityKeyStore for Device {
    async fn get_identity_key_pair(
        &self,
    ) -> Result<IdentityKeyPair, Box<dyn std::error::Error + Send + Sync>> {
        let public = IdentityKey::new(ecc::keys::DjbEcPublicKey::new(self.identity_key.public_key));
        let private = ecc::key_pair::EcKeyPair::new(
            ecc::keys::DjbEcPublicKey::new(self.identity_key.public_key),
            ecc::keys::DjbEcPrivateKey::new(self.identity_key.private_key),
        );
        Ok(IdentityKeyPair::new(public, private))
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
        self.backend
            .put_identity(&address.to_string(), identity_key.public_key().public_key)
            .await
            .map_err(|e| e.into())
    }

    async fn is_trusted_identity(
        &self,
        _address: &SignalAddress,
        _identity_key: &IdentityKey,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // For now, we trust all identities. A real implementation would compare against a stored key.
        Ok(true)
    }
}

// --- PreKeyStore ---
#[async_trait]
impl PreKeyStore for Device {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.load_prekey(prekey_id).await
    }
    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.store_prekey(prekey_id, record).await
    }
    async fn contains_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.contains_prekey(prekey_id).await
    }
    async fn remove_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.remove_prekey(prekey_id).await
    }
}

// --- SignedPreKeyStore ---
#[async_trait]
impl SignedPreKeyStore for Device {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        // First, check if the requested ID matches the one we hold directly.
        if signed_prekey_id == self.signed_pre_key.key_id {
            let key_pair = crate::signal::ecc::key_pair::EcKeyPair::new(
                crate::signal::ecc::keys::DjbEcPublicKey::new(
                    self.signed_pre_key.key_pair.public_key,
                ),
                crate::signal::ecc::keys::DjbEcPrivateKey::new(
                    self.signed_pre_key.key_pair.private_key,
                ),
            );
            let record = SignedPreKeyRecordStructure::new(
                self.signed_pre_key.key_id,
                key_pair,
                self.signed_pre_key
                    .signature
                    .ok_or("Signature missing from device's signed pre-key")?,
                chrono::Utc::now(),
            );
            return Ok(Some(record));
        }
        // Otherwise, delegate to the underlying store.
        self.backend.load_signed_prekey(signed_prekey_id).await
    }
    async fn load_signed_prekeys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.load_signed_prekeys().await
    }
    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend
            .store_signed_prekey(signed_prekey_id, record)
            .await
    }
    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.contains_signed_prekey(signed_prekey_id).await
    }
    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.remove_signed_prekey(signed_prekey_id).await
    }
}

// --- SessionStore ---
#[async_trait]
impl SessionStore for Device {
    async fn load_session(
        &self,
        address: &SignalAddress,
    ) -> Result<SessionRecord, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(data) = self.backend.get_session(&address.to_string()).await? {
            if !data.is_empty() {
                let record: SessionRecord =
                    bincode::serde::decode_from_slice(&data, bincode::config::standard())?.0;
                return Ok(record);
            }
            Ok(SessionRecord::new())
        } else {
            Ok(SessionRecord::new())
        }
    }

    async fn store_session(
        &self,
        address: &SignalAddress,
        record: &SessionRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let data = bincode::serde::encode_to_vec(record, bincode::config::standard())?;
        self.backend
            .put_session(&address.to_string(), &data)
            .await
            .map_err(|e| e.into())
    }

    async fn get_sub_device_sessions(
        &self,
        _name: &str,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(vec![])
    }
    async fn contains_session(
        &self,
        address: &SignalAddress,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.backend
            .has_session(&address.to_string())
            .await
            .map_err(|e| e.into())
    }
    async fn delete_session(
        &self,
        address: &SignalAddress,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend
            .delete_session(&address.to_string())
            .await
            .map_err(|e| e.into())
    }
    async fn delete_all_sessions(
        &self,
        _name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.backend.store_sender_key(sender_key_name, record).await
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.backend.load_sender_key(sender_key_name).await
    }
}

// --- Arc<RwLock<T>> wrappers for SignalProtocolStore traits ---

#[async_trait]
impl<T: IdentityKeyStore + Send + Sync> IdentityKeyStore for Arc<RwLock<T>> {
    async fn get_identity_key_pair(
        &self,
    ) -> Result<IdentityKeyPair, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.get_identity_key_pair().await
    }
    async fn get_local_registration_id(
        &self,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.get_local_registration_id().await
    }
    async fn save_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.save_identity(address, identity_key).await
    }
    async fn is_trusted_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.read()
            .await
            .is_trusted_identity(address, identity_key)
            .await
    }
}

#[async_trait]
impl<T: PreKeyStore + Send + Sync> PreKeyStore for Arc<RwLock<T>> {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.load_prekey(prekey_id).await
    }
    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.store_prekey(prekey_id, record).await
    }
    async fn contains_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.contains_prekey(prekey_id).await
    }
    async fn remove_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.remove_prekey(prekey_id).await
    }
}

#[async_trait]
impl<T: SignedPreKeyStore + Send + Sync> SignedPreKeyStore for Arc<RwLock<T>> {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.load_signed_prekey(signed_prekey_id).await
    }
    async fn load_signed_prekeys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.load_signed_prekeys().await
    }
    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read()
            .await
            .store_signed_prekey(signed_prekey_id, record)
            .await
    }
    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.read()
            .await
            .contains_signed_prekey(signed_prekey_id)
            .await
    }
    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read()
            .await
            .remove_signed_prekey(signed_prekey_id)
            .await
    }
}

#[async_trait]
impl<T: SessionStore + Send + Sync> SessionStore for Arc<RwLock<T>> {
    async fn load_session(
        &self,
        address: &SignalAddress,
    ) -> Result<SessionRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.load_session(address).await
    }
    async fn get_sub_device_sessions(
        &self,
        name: &str,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.get_sub_device_sessions(name).await
    }
    async fn store_session(
        &self,
        address: &SignalAddress,
        record: &SessionRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.store_session(address, record).await
    }
    async fn contains_session(
        &self,
        address: &SignalAddress,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.contains_session(address).await
    }
    async fn delete_session(
        &self,
        address: &SignalAddress,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.delete_session(address).await
    }
    async fn delete_all_sessions(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.delete_all_sessions(name).await
    }
}

#[async_trait]
impl<T: SenderKeyStore + Send + Sync> SenderKeyStore for Arc<RwLock<T>> {
    async fn store_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
        record: SenderKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.read()
            .await
            .store_sender_key(sender_key_name, record)
            .await
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.read().await.load_sender_key(sender_key_name).await
    }
}

//
// --- Arc<T> wrappers for SignalProtocolStore traits ---
//

#[async_trait]
impl<T: IdentityKeyStore + Send + Sync> IdentityKeyStore for Arc<T> {
    async fn get_identity_key_pair(
        &self,
    ) -> Result<IdentityKeyPair, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().get_identity_key_pair().await
    }
    async fn get_local_registration_id(
        &self,
    ) -> Result<u32, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().get_local_registration_id().await
    }
    async fn save_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().save_identity(address, identity_key).await
    }
    async fn is_trusted_identity(
        &self,
        address: &SignalAddress,
        identity_key: &IdentityKey,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref()
            .is_trusted_identity(address, identity_key)
            .await
    }
}

#[async_trait]
impl<T: PreKeyStore + Send + Sync> PreKeyStore for Arc<T> {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<Option<PreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().load_prekey(prekey_id).await
    }
    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().store_prekey(prekey_id, record).await
    }
    async fn contains_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().contains_prekey(prekey_id).await
    }
    async fn remove_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().remove_prekey(prekey_id).await
    }
}

#[async_trait]
impl<T: SignedPreKeyStore + Send + Sync> SignedPreKeyStore for Arc<T> {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().load_signed_prekey(signed_prekey_id).await
    }
    async fn load_signed_prekeys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().load_signed_prekeys().await
    }
    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref()
            .store_signed_prekey(signed_prekey_id, record)
            .await
    }
    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().contains_signed_prekey(signed_prekey_id).await
    }
    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().remove_signed_prekey(signed_prekey_id).await
    }
}

#[async_trait]
impl<T: SessionStore + Send + Sync> SessionStore for Arc<T> {
    async fn load_session(
        &self,
        address: &SignalAddress,
    ) -> Result<SessionRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().load_session(address).await
    }
    async fn get_sub_device_sessions(
        &self,
        name: &str,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().get_sub_device_sessions(name).await
    }
    async fn store_session(
        &self,
        address: &SignalAddress,
        record: &SessionRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().store_session(address, record).await
    }
    async fn contains_session(
        &self,
        address: &SignalAddress,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().contains_session(address).await
    }
    async fn delete_session(
        &self,
        address: &SignalAddress,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().delete_session(address).await
    }
    async fn delete_all_sessions(
        &self,
        name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().delete_all_sessions(name).await
    }
}

#[async_trait]
impl<T: SenderKeyStore + Send + Sync> SenderKeyStore for Arc<T> {
    async fn store_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
        record: SenderKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref()
            .store_sender_key(sender_key_name, record)
            .await
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> Result<SenderKeyRecord, Box<dyn std::error::Error + Send + Sync>> {
        self.as_ref().load_sender_key(sender_key_name).await
    }
}
