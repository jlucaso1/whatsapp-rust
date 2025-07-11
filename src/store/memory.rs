// Temporarily simplified memory store to get build working
// TODO: Re-implement full trait compatibility

use crate::store::generic::GenericMemoryStore;
use crate::store::traits::*;
use async_trait::async_trait;
use whatsapp_core::signal::sender_key_name::SenderKeyName;
use whatsapp_core::signal::state::sender_key_record::SenderKeyRecord;
use whatsapp_core::signal::store::{PreKeyStore, SignedPreKeyStore, SenderKeyStore};
use whatsapp_core::store::error::Result;

// For signal store traits, we need to use the signal module's StoreError
type SignalStoreError = Box<dyn std::error::Error + Send + Sync>;
use whatsapp_proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

type IdentityMap = GenericMemoryStore<String, [u8; 32]>;
type SessionMap = GenericMemoryStore<String, Vec<u8>>;
type AppStateVersionMap = GenericMemoryStore<String, crate::appstate::hash::HashState>;
type PreKeyMap = GenericMemoryStore<u32, PreKeyRecordStructure>;
type SignedPreKeyMap = GenericMemoryStore<u32, SignedPreKeyRecordStructure>;
type SenderKeyMap = GenericMemoryStore<String, SenderKeyRecord>;
type AppStateSyncKeyMap = GenericMemoryStore<Vec<u8>, AppStateSyncKey>;
type BufferedEventMap = GenericMemoryStore<[u8; 32], BufferedEvent>;

#[derive(Default)]
pub struct MemoryStore {
    identities: IdentityMap,
    sessions: SessionMap,
    app_state_versions: AppStateVersionMap,
    prekeys: PreKeyMap,
    signed_prekeys: SignedPreKeyMap,
    sender_keys: SenderKeyMap,
    app_state_sync_keys: AppStateSyncKeyMap,
    buffered_events: BufferedEventMap,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }
}

// Basic implementations for local traits only
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
            Ok(true) // Trust new identities
        }
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
    async fn get_app_state_version(&self, name: &str) -> Result<crate::appstate::hash::HashState> {
        Ok(self
            .app_state_versions
            .get(&name.to_string())
            .await
            .unwrap_or_default())
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

// Missing trait implementations for MemoryStore to work as Backend

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
impl EventBufferStore for MemoryStore {
    async fn get_buffered_event(&self, ciphertext_hash: &[u8; 32])
    -> Result<Option<BufferedEvent>> {
        Ok(self.buffered_events.get(ciphertext_hash).await)
    }

    async fn put_buffered_event(
        &self,
        ciphertext_hash: &[u8; 32],
        plaintext: Option<Vec<u8>>,
        server_timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<()> {
        let event = BufferedEvent {
            plaintext,
            insert_time: server_timestamp,
        };
        self.buffered_events.put(*ciphertext_hash, event).await;
        Ok(())
    }

    async fn delete_old_buffered_events(
        &self,
        _older_than: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize> {
        // For now, don't delete anything in memory store
        Ok(0)
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

    async fn load_signed_prekeys(&self) -> std::result::Result<Vec<SignedPreKeyRecordStructure>, SignalStoreError> {
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

    async fn contains_signed_prekey(&self, signed_prekey_id: u32) -> std::result::Result<bool, SignalStoreError> {
        Ok(self.signed_prekeys.get(&signed_prekey_id).await.is_some())
    }

    async fn remove_signed_prekey(&self, signed_prekey_id: u32) -> std::result::Result<(), SignalStoreError> {
        self.signed_prekeys.delete(&signed_prekey_id).await;
        Ok(())
    }
}

#[async_trait]
impl SenderKeyStore for MemoryStore {
    async fn store_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
        record: SenderKeyRecord,
    ) -> std::result::Result<(), SignalStoreError> {
        let key = format!("{}:{}", sender_key_name.group_id(), sender_key_name.sender_id());
        self.sender_keys.put(key, record).await;
        Ok(())
    }

    async fn load_sender_key(
        &self,
        sender_key_name: &SenderKeyName,
    ) -> std::result::Result<SenderKeyRecord, SignalStoreError> {
        let key = format!("{}:{}", sender_key_name.group_id(), sender_key_name.sender_id());
        Ok(self.sender_keys.get(&key).await.unwrap_or_default())
    }

    async fn delete_sender_key(&self, sender_key_name: &SenderKeyName) -> std::result::Result<(), SignalStoreError> {
        let key = format!("{}:{}", sender_key_name.group_id(), sender_key_name.sender_id());
        self.sender_keys.delete(&key).await;
        Ok(())
    }
}
