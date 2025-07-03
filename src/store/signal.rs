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
use std::sync::Arc;
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
        let public = IdentityKey::new(Arc::new(ecc::keys::DjbEcPublicKey::new(
            self.identity_key.public_key,
        )));
        let private = ecc::key_pair::EcKeyPair::new(
            Arc::new(ecc::keys::DjbEcPublicKey::new(self.identity_key.public_key)),
            Arc::new(ecc::keys::DjbEcPrivateKey::new(
                self.identity_key.private_key,
            )),
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
            .put_identity(&address.to_string(), identity_key.public_key().public_key())
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
        _prekey_id: u32,
    ) -> Result<Option<PreKeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
        // TODO: This requires adding PreKey storage to your `store::traits` and `MemoryStore`.
        // For now, we return None.
        Ok(None)
    }
    async fn store_prekey(
        &self,
        _prekey_id: u32,
        _record: PreKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn contains_prekey(
        &self,
        _prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false)
    }
    async fn remove_prekey(
        &self,
        _prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

// --- SignedPreKeyStore ---
#[async_trait]
impl SignedPreKeyStore for Device {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> Result<Option<SignedPreKeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
        if self.signed_pre_key.key_id == signed_prekey_id {
            let key_pair = ecc::key_pair::EcKeyPair::new(
                Arc::new(ecc::keys::DjbEcPublicKey::new(
                    self.signed_pre_key.key_pair.public_key,
                )),
                Arc::new(ecc::keys::DjbEcPrivateKey::new(
                    self.signed_pre_key.key_pair.private_key,
                )),
            );
            let record = SignedPreKeyRecord::new(
                signed_prekey_id,
                key_pair,
                self.signed_pre_key.signature.unwrap(),
                chrono::Utc::now(),
            );
            return Ok(Some(record));
        }
        Ok(None)
    }
    async fn load_signed_prekeys(
        &self,
    ) -> Result<Vec<SignedPreKeyRecord>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(vec![])
    }
    async fn store_signed_prekey(
        &self,
        _signed_prekey_id: u32,
        _record: SignedPreKeyRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn contains_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(false)
    }
    async fn remove_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

// --- SessionStore ---
#[async_trait]
impl SessionStore for Device {
    async fn load_session(
        &self,
        _address: &SignalAddress,
    ) -> Result<SessionRecord, Box<dyn std::error::Error + Send + Sync>> {
        // This is where you'd deserialize from your main session store.
        // For now, we return a new, empty record.
        Ok(SessionRecord::new())
    }

    async fn store_session(
        &self,
        _address: &SignalAddress,
        _record: &SessionRecord,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // This is where you'd serialize the record and save it.
        Ok(())
    }

    async fn get_sub_device_sessions(
        &self,
        _name: &str,
    ) -> Result<Vec<u32>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(vec![])
    }
    async fn contains_session(
        &self,
        _address: &SignalAddress,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(true)
    } // Assume true for now
    async fn delete_session(
        &self,
        _address: &SignalAddress,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
    async fn delete_all_sessions(
        &self,
        _name: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}
