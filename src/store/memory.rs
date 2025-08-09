use crate::store::generic::GenericMemoryStore;
use crate::store::traits::*;
use async_trait::async_trait;
use wacore::appstate::hash::HashState;
use wacore::signal::store::{PreKeyStore, SignedPreKeyStore};
use wacore::store::error::Result;

type SignalStoreError = Box<dyn std::error::Error + Send + Sync>;
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

type IdentityMap = GenericMemoryStore<String, [u8; 32]>;
type SessionMap = GenericMemoryStore<String, Vec<u8>>;
type AppStateVersionMap = GenericMemoryStore<String, HashState>;
type PreKeyMap = GenericMemoryStore<u32, PreKeyRecordStructure>;
type SignedPreKeyMap = GenericMemoryStore<u32, SignedPreKeyRecordStructure>;
type SenderKeyMap = GenericMemoryStore<String, Vec<u8>>;
type AppStateSyncKeyMap = GenericMemoryStore<Vec<u8>, AppStateSyncKey>;

#[derive(Default)]
pub struct MemoryStore {
    identities: IdentityMap,
    sessions: SessionMap,
    app_state_versions: AppStateVersionMap,
    prekeys: PreKeyMap,
    signed_prekeys: SignedPreKeyMap,
    sender_keys: SenderKeyMap,
    app_state_sync_keys: AppStateSyncKeyMap,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl IdentityStore for MemoryStore {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        self.identities.put(address.to_string(), key).await;
        Ok(())
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        self.identities.delete(&address.to_string()).await;
        Ok(())
    }

    async fn is_trusted_identity(&self, address: &str, key: &[u8; 32]) -> Result<bool> {
        if let Some(stored_key) = self.identities.get(&address.to_string()).await {
            Ok(stored_key == *key)
        } else {
            Ok(true)
        }
    }

    async fn load_identity(&self, _address: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
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
        self.sessions.delete(&address.to_string()).await;
        Ok(())
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        Ok(self.sessions.get(&address.to_string()).await.is_some())
    }
}

#[async_trait]
impl AppStateStore for MemoryStore {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState> {
        Ok(self
            .app_state_versions
            .get(&name.to_string())
            .await
            .unwrap_or_default())
    }

    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()> {
        self.app_state_versions.put(name.to_string(), state).await;
        Ok(())
    }
}

#[async_trait]
impl AppStateKeyStore for MemoryStore {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        Ok(self.app_state_sync_keys.get(&key_id.to_vec()).await)
    }

    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        self.app_state_sync_keys.put(key_id.to_vec(), key).await;
        Ok(())
    }
}

#[async_trait]
impl PreKeyStore for MemoryStore {
    async fn load_prekey(
        &self,
        prekey_id: u32,
    ) -> std::result::Result<Option<PreKeyRecordStructure>, SignalStoreError> {
        Ok(self.prekeys.get(&prekey_id).await)
    }

    async fn store_prekey(
        &self,
        prekey_id: u32,
        record: PreKeyRecordStructure,
    ) -> std::result::Result<(), SignalStoreError> {
        self.prekeys.put(prekey_id, record).await;
        Ok(())
    }

    async fn contains_prekey(&self, prekey_id: u32) -> std::result::Result<bool, SignalStoreError> {
        Ok(self.prekeys.get(&prekey_id).await.is_some())
    }

    async fn remove_prekey(&self, prekey_id: u32) -> std::result::Result<(), SignalStoreError> {
        self.prekeys.delete(&prekey_id).await;
        Ok(())
    }
}

#[async_trait]
impl SignedPreKeyStore for MemoryStore {
    async fn load_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<Option<SignedPreKeyRecordStructure>, SignalStoreError> {
        Ok(self.signed_prekeys.get(&signed_prekey_id).await)
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<Vec<SignedPreKeyRecordStructure>, SignalStoreError> {
        Ok(self.signed_prekeys.values().await)
    }

    async fn store_signed_prekey(
        &self,
        signed_prekey_id: u32,
        record: SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), SignalStoreError> {
        self.signed_prekeys.put(signed_prekey_id, record).await;
        Ok(())
    }

    async fn contains_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<bool, SignalStoreError> {
        Ok(self.signed_prekeys.get(&signed_prekey_id).await.is_some())
    }

    async fn remove_signed_prekey(
        &self,
        signed_prekey_id: u32,
    ) -> std::result::Result<(), SignalStoreError> {
        self.signed_prekeys.delete(&signed_prekey_id).await;
        Ok(())
    }
}

#[async_trait]
impl SenderKeyStoreHelper for MemoryStore {
    async fn put_sender_key(&self, _address: &str, _record: &[u8]) -> Result<()> {
        Ok(())
    }

    async fn get_sender_key(&self, _address: &str) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        self.sender_keys.delete(&address.to_string()).await;
        Ok(())
    }
}
