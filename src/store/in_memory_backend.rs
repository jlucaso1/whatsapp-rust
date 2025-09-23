use crate::store::traits::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use wacore::appstate::hash::HashState;
use wacore::libsignal::protocol::Direction;
use wacore::store::error::Result;
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

/// A simple in-memory backend implementation for testing purposes
#[derive(Clone)]
pub struct InMemoryBackend {
    identities: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    sessions: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    sender_keys: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    app_state_keys: Arc<RwLock<HashMap<Vec<u8>, AppStateSyncKey>>>,
    app_state_versions: Arc<RwLock<HashMap<String, HashState>>>,
    #[allow(clippy::type_complexity)]
    app_state_mutation_macs: Arc<RwLock<HashMap<String, HashMap<Vec<u8>, Vec<u8>>>>>,
    device_data: Arc<RwLock<Option<wacore::store::Device>>>,
    device_data_by_id: Arc<RwLock<HashMap<i32, wacore::store::Device>>>,
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            identities: Arc::new(RwLock::new(HashMap::new())),
            sessions: Arc::new(RwLock::new(HashMap::new())),
            sender_keys: Arc::new(RwLock::new(HashMap::new())),
            app_state_keys: Arc::new(RwLock::new(HashMap::new())),
            app_state_versions: Arc::new(RwLock::new(HashMap::new())),
            app_state_mutation_macs: Arc::new(RwLock::new(HashMap::new())),
            device_data: Arc::new(RwLock::new(None)),
            device_data_by_id: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl IdentityStore for InMemoryBackend {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        let mut identities = self.identities.write().await;
        identities.insert(address.to_string(), key.to_vec());
        Ok(())
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        let mut identities = self.identities.write().await;
        identities.remove(address);
        Ok(())
    }

    async fn is_trusted_identity(
        &self,
        _address: &str,
        _key: &[u8; 32],
        _direction: Direction,
    ) -> Result<bool> {
        // Always trust for testing
        Ok(true)
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let identities = self.identities.read().await;
        Ok(identities.get(address).cloned())
    }
}

#[async_trait]
impl SessionStore for InMemoryBackend {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let sessions = self.sessions.read().await;
        Ok(sessions.get(address).cloned())
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.insert(address.to_string(), session.to_vec());
        Ok(())
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        sessions.remove(address);
        Ok(())
    }

    async fn has_session(&self, address: &str) -> Result<bool> {
        let sessions = self.sessions.read().await;
        Ok(sessions.contains_key(address))
    }
}

#[async_trait]
impl SenderKeyStoreHelper for InMemoryBackend {
    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        let mut sender_keys = self.sender_keys.write().await;
        sender_keys.insert(address.to_string(), record.to_vec());
        Ok(())
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        let sender_keys = self.sender_keys.read().await;
        Ok(sender_keys.get(address).cloned())
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        let mut sender_keys = self.sender_keys.write().await;
        sender_keys.remove(address);
        Ok(())
    }
}

#[async_trait]
impl AppStateKeyStore for InMemoryBackend {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        let app_state_keys = self.app_state_keys.read().await;
        Ok(app_state_keys.get(key_id).cloned())
    }

    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        let mut app_state_keys = self.app_state_keys.write().await;
        app_state_keys.insert(key_id.to_vec(), key);
        Ok(())
    }
}

#[async_trait]
impl AppStateStore for InMemoryBackend {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState> {
        let app_state_versions = self.app_state_versions.read().await;
        Ok(app_state_versions.get(name).cloned().unwrap_or_default())
    }

    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()> {
        let mut app_state_versions = self.app_state_versions.write().await;
        app_state_versions.insert(name.to_string(), state);
        Ok(())
    }

    async fn put_app_state_mutation_macs(
        &self,
        name: &str,
        _version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        let mut app_state_mutation_macs = self.app_state_mutation_macs.write().await;
        let map = app_state_mutation_macs
            .entry(name.to_string())
            .or_insert_with(HashMap::new);

        for mutation in mutations {
            map.insert(mutation.index_mac.clone(), mutation.value_mac.clone());
        }

        Ok(())
    }

    async fn delete_app_state_mutation_macs(
        &self,
        name: &str,
        index_macs: &[Vec<u8>],
    ) -> Result<()> {
        let mut app_state_mutation_macs = self.app_state_mutation_macs.write().await;
        if let Some(map) = app_state_mutation_macs.get_mut(name) {
            for index_mac in index_macs {
                map.remove(index_mac);
            }
        }
        Ok(())
    }

    async fn get_app_state_mutation_mac(
        &self,
        name: &str,
        index_mac: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let app_state_mutation_macs = self.app_state_mutation_macs.read().await;
        if let Some(map) = app_state_mutation_macs.get(name) {
            Ok(map.get(index_mac).cloned())
        } else {
            Ok(None)
        }
    }
}

// Implement libsignal store traits
#[async_trait]
impl wacore::libsignal::store::PreKeyStore for InMemoryBackend {
    async fn load_prekey(
        &self,
        _prekey_id: u32,
    ) -> std::result::Result<Option<PreKeyRecordStructure>, Box<dyn std::error::Error + Send + Sync>>
    {
        // For simplicity, always return None for testing
        Ok(None)
    }

    async fn store_prekey(
        &self,
        _prekey_id: u32,
        _record: PreKeyRecordStructure,
        _uploaded: bool,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // No-op for testing
        Ok(())
    }

    async fn contains_prekey(
        &self,
        _prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // For simplicity, always return false for testing
        Ok(false)
    }

    async fn remove_prekey(
        &self,
        _prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // No-op for testing
        Ok(())
    }
}

#[async_trait]
impl wacore::libsignal::store::SignedPreKeyStore for InMemoryBackend {
    async fn load_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<
        Option<SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        // For simplicity, always return None for testing
        Ok(None)
    }

    async fn load_signed_prekeys(
        &self,
    ) -> std::result::Result<
        Vec<SignedPreKeyRecordStructure>,
        Box<dyn std::error::Error + Send + Sync>,
    > {
        // For simplicity, always return empty vec for testing
        Ok(Vec::new())
    }

    async fn store_signed_prekey(
        &self,
        _signed_prekey_id: u32,
        _record: SignedPreKeyRecordStructure,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // No-op for testing
        Ok(())
    }

    async fn contains_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        // For simplicity, always return false for testing
        Ok(false)
    }

    async fn remove_signed_prekey(
        &self,
        _signed_prekey_id: u32,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // No-op for testing
        Ok(())
    }
}

#[async_trait]
impl wacore::store::traits::DevicePersistence for InMemoryBackend {
    async fn save_device_data(
        &self,
        device_data: &wacore::store::Device,
    ) -> wacore::store::error::Result<()> {
        let mut device_data_store = self.device_data.write().await;
        *device_data_store = Some(device_data.clone());
        Ok(())
    }

    async fn save_device_data_for_device(
        &self,
        device_id: i32,
        device_data: &wacore::store::Device,
    ) -> wacore::store::error::Result<()> {
        let mut device_data_by_id = self.device_data_by_id.write().await;
        device_data_by_id.insert(device_id, device_data.clone());
        Ok(())
    }

    async fn load_device_data(
        &self,
    ) -> wacore::store::error::Result<Option<wacore::store::Device>> {
        let device_data_store = self.device_data.read().await;
        Ok(device_data_store.clone())
    }

    async fn load_device_data_for_device(
        &self,
        device_id: i32,
    ) -> wacore::store::error::Result<Option<wacore::store::Device>> {
        let device_data_by_id = self.device_data_by_id.read().await;
        Ok(device_data_by_id.get(&device_id).cloned())
    }

    async fn device_exists(&self, device_id: i32) -> wacore::store::error::Result<bool> {
        let device_data_by_id = self.device_data_by_id.read().await;
        Ok(device_data_by_id.contains_key(&device_id) || self.device_data.read().await.is_some())
    }

    async fn create_new_device(&self) -> wacore::store::error::Result<i32> {
        let dev = wacore::store::Device::new();
        // For single-device tests, store under id=1
        let mut device_data_by_id = self.device_data_by_id.write().await;
        device_data_by_id.insert(1, dev.clone());
        let mut device_data_store = self.device_data.write().await;
        *device_data_store = Some(dev);
        Ok(1)
    }
}
