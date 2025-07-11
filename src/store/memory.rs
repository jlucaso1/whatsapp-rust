// Temporarily simplified memory store to get build working
// TODO: Re-implement full trait compatibility

use crate::store::generic::GenericMemoryStore;
use crate::store::traits::*;
use async_trait::async_trait;
use whatsapp_core::store::error::Result;

type IdentityMap = GenericMemoryStore<String, [u8; 32]>;
type SessionMap = GenericMemoryStore<String, Vec<u8>>;
type AppStateVersionMap = GenericMemoryStore<String, crate::appstate::hash::HashState>;

#[derive(Default)]
pub struct MemoryStore {
    identities: IdentityMap,
    sessions: SessionMap,
    app_state_versions: AppStateVersionMap,
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
