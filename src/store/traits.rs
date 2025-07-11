// Local traits for whatsapp-rust that depend on platform-specific types
use async_trait::async_trait;
use whatsapp_core::store::error::Result;

#[async_trait]
pub trait AppStateStore: Send + Sync {
    async fn get_app_state_version(&self, name: &str) -> Result<crate::appstate::hash::HashState>;
    async fn set_app_state_version(
        &self,
        name: &str,
        state: crate::appstate::hash::HashState,
    ) -> Result<()>;
}

// Re-export the core traits
pub use whatsapp_core::store::traits::*;

// Extended Backend that includes our platform-specific traits
pub trait ExtendedBackend: Backend + AppStateStore {}

// Blanket implementation for any type that implements both traits
impl<T> ExtendedBackend for T where T: Backend + AppStateStore {}