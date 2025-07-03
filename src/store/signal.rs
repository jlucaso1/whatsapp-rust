// src/store/signal.rs
use crate::signal::address::SignalAddress;
use crate::signal::ecc;
use crate::signal::identity::{IdentityKey, IdentityKeyPair};
use crate::signal::state::prekey_record::PreKeyRecord;
use crate::signal::state::session_record::SessionRecord;
use crate::signal::state::signed_prekey_record::SignedPreKeyRecord;
use crate::signal::store::*;
use crate::store::Device;
use async_trait::async_trait;
use thiserror::Error;

#[derive(Debug, Error)]
#[error("In-memory store error: {0}")]
pub struct StoreError(String);

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
        self.identities
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
    ) -> Result<Option<PreKeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
        self.pre_keys.load_prekey(prekey_id).await
    }
    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.pre_keys.store_prekey(prekey_id, record).await
    }
    async fn contains_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.pre_keys.contains_prekey(prekey_id).await
    }
    async fn remove_prekey(
        &self,
        prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.pre_keys.remove_prekey(prekey_id).await
    }
}

// --- SignedPreKeyStore ---
#[async_trait]
impl SignedPreKeyStore for Device {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
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
            let record = crate::signal::state::signed_prekey_record::SignedPreKeyRecord::new(
                self.signed_pre_key.key_id,
                key_pair,
                self.signed_pre_key
                    .signature
                    .clone()
                    .ok_or("Signature missing from device's signed pre-key")?,
                chrono::Utc::now(),
            );
            return Ok(Some(record));
        }
        // Otherwise, delegate to the underlying store.
        self.signed_pre_keys
            .load_signed_prekey(signed_prekey_id)
            .await
    }
    async fn load_signed_prekeys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
        self.signed_pre_keys.load_signed_prekeys().await
    }
    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.signed_pre_keys
            .store_signed_prekey(signed_prekey_id, record)
            .await
    }
    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        self.signed_pre_keys
            .contains_signed_prekey(signed_prekey_id)
            .await
    }
    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.signed_pre_keys
            .remove_signed_prekey(signed_prekey_id)
            .await
    }
}

// --- SessionStore ---
#[async_trait]
impl SessionStore for Device {
    async fn load_session(
        &self,
        address: &SignalAddress,
    ) -> Result<SessionRecord, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(data) = self.sessions.get_session(&address.to_string()).await? {
            if !data.is_empty() {
                let record: SessionRecord = serde_json::from_slice(&data)?;
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
        let data = serde_json::to_vec(record)?;
        self.sessions
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
        self.sessions
            .has_session(&address.to_string())
            .await
            .map_err(|e| e.into())
    }
    async fn delete_session(
        &self,
        address: &SignalAddress,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.sessions
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
