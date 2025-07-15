// Local traits for whatsapp-rust that depend on platform-specific types
use async_trait::async_trait;
use std::sync::Arc;
use wacore::{appstate::hash::HashState, store::error::Result};

#[async_trait]
pub trait AppStateStore: Send + Sync {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState>;
    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()>;
}

// Re-export the core traits
pub use wacore::store::traits::*;

// Extended Backend that includes our platform-specific traits
pub trait ExtendedBackend: Backend + AppStateStore {}

// Blanket implementation for any type that implements both traits
impl<T> ExtendedBackend for T where T: Backend + AppStateStore {}

// Helper wrapper that provides AppStateStore interface for Backend
pub struct AppStateWrapper {
    backend: Arc<dyn Backend>,
}

impl AppStateWrapper {
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl AppStateStore for AppStateWrapper {
    async fn get_app_state_version(&self, _name: &str) -> Result<HashState> {
        // We need to cast to concrete type to access AppStateStore methods
        // For now, return default - this is a temporary workaround
        Ok(Default::default())
    }

    async fn set_app_state_version(&self, _name: &str, _state: HashState) -> Result<()> {
        // Temporary implementation
        Ok(())
    }
}

#[async_trait]
impl AppStateKeyStore for AppStateWrapper {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        self.backend.get_app_state_sync_key(key_id).await
    }

    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        self.backend.set_app_state_sync_key(key_id, key).await
    }
}
