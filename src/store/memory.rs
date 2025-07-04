use crate::proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};
use crate::signal::state::sender_key_record::SenderKeyRecord;
use crate::store::error::Result;
use crate::store::traits::*;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct MemoryStore {
    identities: Mutex<HashMap<String, [u8; 32]>>,
    sessions: Mutex<HashMap<String, Vec<u8>>>,
    app_state_versions: Mutex<HashMap<String, crate::appstate::hash::HashState>>,
    app_state_keys: Mutex<HashMap<Vec<u8>, AppStateSyncKey>>,
    // --- Signal Protocol fields ---
    pre_keys: Mutex<HashMap<u32, PreKeyRecordStructure>>,
    signed_pre_keys: Mutex<HashMap<u32, SignedPreKeyRecordStructure>>,
    sender_keys: Mutex<
        std::collections::HashMap<crate::signal::sender_key_name::SenderKeyName, SenderKeyRecord>,
    >,
}

impl MemoryStore {
    pub fn new() -> Self {
        Default::default()
    }
}

#[async_trait]
impl IdentityStore for MemoryStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        let mut identities = self.identities.lock().await;
        identities.insert(address.to_string(), key);
        Ok(())
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        let mut identities = self.identities.lock().await;
        identities.remove(address);
        Ok(())
    }

    async fn is_trusted_identity(&self, address: &str, key: &[u8; 32]) -> Result<bool> {
        let identities = self.identities.lock().await;

        if let Some(stored_key) = identities.get(address) {
            Ok(stored_key == key)
        } else {
            Ok(false)
        }
    }
}

// --- SenderKeyStore implementation for MemoryStore ---
#[async_trait]
impl crate::signal::store::SenderKeyStore for MemoryStore {
    async fn store_sender_key(
        &self,
        sender_key_name: &crate::signal::sender_key_name::SenderKeyName,
        record: SenderKeyRecord,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut sender_keys = self.sender_keys.lock().await;
        sender_keys.insert(sender_key_name.clone(), record);
        Ok(())
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &crate::signal::sender_key_name::SenderKeyName,
    ) -> std::result::Result<SenderKeyRecord, Box<dyn std::error::Error + Send + Sync>> {
        let sender_keys = self.sender_keys.lock().await;
        Ok(sender_keys
            .get(sender_key_name)
            .cloned()
            .unwrap_or_default())
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let sessions = self.sessions.lock().await;
        Ok(sessions.get(address).cloned())
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(address.to_string(), session.to_vec());
        Ok(())
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(address);
        Ok(())
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        let sessions = self.sessions.lock().await;
        Ok(sessions.contains_key(address))
    }
}

#[async_trait]
impl AppStateStore for MemoryStore {
    async fn get_app_state_version(&self, name: &str) -> Result<crate::appstate::hash::HashState> {
        let versions = self.app_state_versions.lock().await;
        Ok(versions
            .get(name)
            .cloned()
            .unwrap_or(crate::appstate::hash::HashState {
                version: 0,
                hash: [0; 128],
            }))
    }

    // --- Existing Trait Implementations (IdentityStore, AppStateStore, etc.) ---

    async fn set_app_state_version(
        &self,
        name: &str,
        state: crate::appstate::hash::HashState,
    ) -> Result<()> {
        let mut versions = self.app_state_versions.lock().await;
        versions.insert(name.to_string(), state);
        Ok(())
    }
}

// --- Signal Protocol Store Implementations ---

#[async_trait]
impl crate::signal::store::PreKeyStore for MemoryStore {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<Option<PreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>>
    {
        let keys = self.pre_keys.lock().await;
        Ok(keys.get(&prekey_id).cloned())
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut keys = self.pre_keys.lock().await;
        keys.insert(prekey_id, record);
        Ok(())
    }

    async fn contains_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let keys = self.pre_keys.lock().await;
        Ok(keys.contains_key(&prekey_id))
    }

    async fn remove_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut keys = self.pre_keys.lock().await;
        keys.remove(&prekey_id);
        Ok(())
    }
}

#[async_trait]
impl crate::signal::store::SignedPreKeyStore for MemoryStore {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<
        Option<SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let keys = self.signed_pre_keys.lock().await;
        Ok(keys.get(&signed_prekey_id).cloned())
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<
        Vec<SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        let keys = self.signed_pre_keys.lock().await;
        Ok(keys.values().cloned().collect())
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut keys = self.signed_pre_keys.lock().await;
        keys.insert(signed_prekey_id, record);
        Ok(())
    }

    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let keys = self.signed_pre_keys.lock().await;
        Ok(keys.contains_key(&signed_prekey_id))
    }

    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut keys = self.signed_pre_keys.lock().await;
        keys.remove(&signed_prekey_id);
        Ok(())
    }
}

#[async_trait]
impl AppStateKeyStore for MemoryStore {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        let keys = self.app_state_keys.lock().await;
        Ok(keys.get(key_id).cloned())
    }
    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        let mut keys = self.app_state_keys.lock().await;
        keys.insert(key_id.to_vec(), key);
        Ok(())
    }
}
