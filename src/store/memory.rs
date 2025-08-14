use crate::store::generic::GenericMemoryStore;
use crate::store::traits::*;
use async_trait::async_trait;
use libsignal_protocol::{Direction, KeyPair, PrivateKey};
use wacore::appstate::hash::HashState;
use wacore::signal::store::{PreKeyStore, SignedPreKeyStore};
use wacore::store::error::Result;
use std::sync::atomic::{AtomicU32, Ordering};

type SignalStoreError = Box<dyn std::error::Error + Send + Sync>;
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

type IdentityMap = GenericMemoryStore<String, [u8; 32]>;
type SessionMap = GenericMemoryStore<String, Vec<u8>>;
type AppStateVersionMap = GenericMemoryStore<String, HashState>;
type PreKeyMap = GenericMemoryStore<u32, PreKeyRecordStructure>;
type AppPreKeyMap = GenericMemoryStore<u32, (Vec<u8>, bool)>; // (private_key_bytes, uploaded)
type SignedPreKeyMap = GenericMemoryStore<u32, SignedPreKeyRecordStructure>;
type SenderKeyMap = GenericMemoryStore<String, Vec<u8>>;
type AppStateSyncKeyMap = GenericMemoryStore<Vec<u8>, AppStateSyncKey>;

pub struct MemoryStore {
    identities: IdentityMap,
    sessions: SessionMap,
    app_state_versions: AppStateVersionMap,
    prekeys: PreKeyMap,
    app_prekeys: AppPreKeyMap, // For application-specific pre-key management
    signed_prekeys: SignedPreKeyMap,
    sender_keys: SenderKeyMap,
    app_state_sync_keys: AppStateSyncKeyMap,
    next_prekey_id: AtomicU32,
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryStore {
    pub fn new() -> Self {
        Self {
            identities: IdentityMap::new(),
            sessions: SessionMap::new(),
            app_state_versions: AppStateVersionMap::new(),
            prekeys: PreKeyMap::new(),
            app_prekeys: AppPreKeyMap::new(),
            signed_prekeys: SignedPreKeyMap::new(),
            sender_keys: SenderKeyMap::new(),
            app_state_sync_keys: AppStateSyncKeyMap::new(),
            next_prekey_id: AtomicU32::new(1),
        }
    }

    // Expose for testing
    #[cfg(test)]
    pub fn get_next_prekey_id_atomic(&self) -> &AtomicU32 {
        &self.next_prekey_id
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

    async fn is_trusted_identity(
        &self,
        _address: &str,
        _key: &[u8; 32],
        _direction: Direction,
    ) -> Result<bool> {
        Ok(true)
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

#[async_trait(?Send)]
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

#[async_trait(?Send)]
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
    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        self.sender_keys
            .put(address.to_string(), record.to_vec())
            .await;
        Ok(())
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.sender_keys.get(&address.to_string()).await)
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        self.sender_keys.delete(&address.to_string()).await;
        Ok(())
    }
}

#[async_trait]
impl AppPreKeyStore for MemoryStore {
    async fn get_next_prekey_id(&self) -> Result<u32> {
        let next_id = self.next_prekey_id.fetch_add(1, Ordering::SeqCst);
        // Ensure we stay within the valid range (1 to 0xFFFFFF)
        if next_id >= 16777215 {
            self.next_prekey_id.store(1, Ordering::SeqCst);
            Ok(1)
        } else {
            Ok(next_id)
        }
    }

    async fn store_app_prekey(&self, id: u32, key_pair: &KeyPair, uploaded: bool) -> Result<()> {
        let private_key_bytes = key_pair.private_key.serialize().to_vec();
        self.app_prekeys.put(id, (private_key_bytes, uploaded)).await;
        Ok(())
    }

    async fn get_unuploaded_pre_keys(&self, count: u32) -> Result<Vec<(u32, KeyPair)>> {
        let all_keys = self.app_prekeys.all().await;
        let mut unuploaded_keys = Vec::new();
        
        for (id, (private_key_bytes, uploaded)) in all_keys {
            if !uploaded && unuploaded_keys.len() < count as usize {
                if let Ok(private_key) = PrivateKey::deserialize(&private_key_bytes) {
                    if let Ok(public_key) = private_key.public_key() {
                        let key_pair = KeyPair::new(public_key, private_key);
                        unuploaded_keys.push((id, key_pair));
                    }
                }
            }
        }
        
        Ok(unuploaded_keys)
    }

    async fn mark_pre_keys_as_uploaded(&self, up_to_id: u32) -> Result<()> {
        let all_keys = self.app_prekeys.all().await;
        
        for (id, (private_key_bytes, _uploaded)) in all_keys {
            if id <= up_to_id {
                self.app_prekeys.put(id, (private_key_bytes, true)).await;
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_protocol::KeyPair;
    use rand_core::OsRng;
    use rand::TryRngCore;

    #[tokio::test]
    async fn test_app_prekey_store_workflow() {
        let store = MemoryStore::new();
        
        // Test get_next_prekey_id - should start at 1
        let id1 = store.get_next_prekey_id().await.unwrap();
        assert_eq!(id1, 1);
        
        let id2 = store.get_next_prekey_id().await.unwrap();
        assert_eq!(id2, 2);
        
        // Test store_app_prekey
        let key_pair1 = KeyPair::generate(&mut OsRng.unwrap_err());
        let key_pair2 = KeyPair::generate(&mut OsRng.unwrap_err());
        
        store.store_app_prekey(id1, &key_pair1, false).await.unwrap();
        store.store_app_prekey(id2, &key_pair2, true).await.unwrap();
        
        // Test get_unuploaded_pre_keys - should only return the first one
        let unuploaded = store.get_unuploaded_pre_keys(10).await.unwrap();
        assert_eq!(unuploaded.len(), 1);
        assert_eq!(unuploaded[0].0, id1);
        
        // Test mark_pre_keys_as_uploaded
        store.mark_pre_keys_as_uploaded(id1).await.unwrap();
        
        // Now there should be no unuploaded keys
        let unuploaded = store.get_unuploaded_pre_keys(10).await.unwrap();
        assert_eq!(unuploaded.len(), 0);
    }

    #[tokio::test]
    async fn test_app_prekey_sequential_ids() {
        let store = MemoryStore::new();
        
        // Test that IDs are generated sequentially
        let mut last_id = 0;
        for _ in 0..10 {
            let id = store.get_next_prekey_id().await.unwrap();
            assert!(id > last_id);
            last_id = id;
        }
        
        // Test wraparound at maximum
        store.next_prekey_id.store(16777215, std::sync::atomic::Ordering::SeqCst);
        let id = store.get_next_prekey_id().await.unwrap();
        assert_eq!(id, 1); // Should wrap around to 1
    }
}
