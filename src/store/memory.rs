use crate::proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};
use crate::signal::state::sender_key_record::SenderKeyRecord;
use crate::store::error::Result;
use crate::store::generic::GenericMemoryStore;
use crate::store::traits::*;
use async_trait::async_trait;

type IdentityMap = GenericMemoryStore<String, [u8; 32]>;
type SessionMap = GenericMemoryStore<String, Vec<u8>>;
type AppStateVersionMap = GenericMemoryStore<String, crate::appstate::hash::HashState>;
type AppStateKeyMap = GenericMemoryStore<Vec<u8>, AppStateSyncKey>;
type PreKeyMap = GenericMemoryStore<u32, PreKeyRecordStructure>;
type SignedPreKeyMap = GenericMemoryStore<u32, SignedPreKeyRecordStructure>;
type SenderKeyMap =
    GenericMemoryStore<crate::signal::sender_key_name::SenderKeyName, SenderKeyRecord>;

#[derive(Default)]
pub struct MemoryStore {
    identities: IdentityMap,
    sessions: SessionMap,
    app_state_versions: AppStateVersionMap,
    app_state_keys: AppStateKeyMap,
    // --- Signal Protocol fields ---
    pre_keys: PreKeyMap,
    signed_pre_keys: SignedPreKeyMap,
    sender_keys: SenderKeyMap,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            identities: IdentityMap::new(),
            sessions: SessionMap::new(),
            app_state_versions: AppStateVersionMap::new(),
            app_state_keys: AppStateKeyMap::new(),
            pre_keys: PreKeyMap::new(),
            signed_pre_keys: SignedPreKeyMap::new(),
            sender_keys: SenderKeyMap::new(),
        }
    }
}

#[async_trait]
impl IdentityStore for MemoryStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        self.identities.put(address.to_string(), key).await;
        Ok(())
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        self.identities.remove(&address.to_string()).await;
        Ok(())
    }

    async fn is_trusted_identity(&self, address: &str, key: &[u8; 32]) -> Result<bool> {
        if let Some(stored_key) = self.identities.get(&address.to_string()).await {
            Ok(stored_key == *key)
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
        self.sender_keys.put(sender_key_name.clone(), record).await;
        Ok(())
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &crate::signal::sender_key_name::SenderKeyName,
    ) -> std::result::Result<SenderKeyRecord, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self
            .sender_keys
            .get(sender_key_name)
            .await
            .unwrap_or_default())
    }
}

#[async_trait]
impl SessionStore for MemoryStore {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.sessions.get(&address.to_string()).await)
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        self.sessions
            .put(address.to_string(), session.to_vec())
            .await;
        Ok(())
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        self.sessions.remove(&address.to_string()).await;
        Ok(())
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        Ok(self.sessions.contains(&address.to_string()).await)
    }
}

#[async_trait]
impl AppStateStore for MemoryStore {
    async fn get_app_state_version(&self, name: &str) -> Result<crate::appstate::hash::HashState> {
        Ok(self
            .app_state_versions
            .get(&name.to_string())
            .await
            .unwrap_or(crate::appstate::hash::HashState {
                version: 0,
                hash: [0; 128],
            }))
    }

    async fn set_app_state_version(
        &self,
        name: &str,
        state: crate::appstate::hash::HashState,
    ) -> Result<()> {
        self.app_state_versions.put(name.to_string(), state).await;
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
        Ok(self.pre_keys.get(&prekey_id).await)
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.pre_keys.put(prekey_id, record).await;
        Ok(())
    }

    async fn contains_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.pre_keys.contains(&prekey_id).await)
    }

    async fn remove_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.pre_keys.remove(&prekey_id).await;
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
        Ok(self.signed_pre_keys.get(&signed_prekey_id).await)
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<
        Vec<SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        Ok(self.signed_pre_keys.values().await)
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.signed_pre_keys.put(signed_prekey_id, record).await;
        Ok(())
    }

    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        Ok(self.signed_pre_keys.contains(&signed_prekey_id).await)
    }

    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.signed_pre_keys.remove(&signed_prekey_id).await;
        Ok(())
    }
}

#[async_trait]
impl AppStateKeyStore for MemoryStore {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        Ok(self.app_state_keys.get(&key_id.to_vec()).await)
    }
    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        self.app_state_keys.put(key_id.to_vec(), key).await;
        Ok(())
    }
}
