// src/store/memory.rs
use crate::store::error::Result;
use crate::store::traits::*;
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;

#[derive(Debug, Default)]
pub struct MemoryStore {
    identities: Mutex<HashMap<String, [u8; 32]>>,
    sessions: Mutex<HashMap<String, Vec<u8>>>,
    // Add other HashMaps for additional stores as needed
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

// This allows us to use a single MemoryStore instance for all traits.
impl AllStores for MemoryStore {}
