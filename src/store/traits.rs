use crate::store::error::Result;
use async_trait::async_trait;

#[derive(Debug, Clone, Default)]
pub struct AppStateSyncKey {
    pub key_data: Vec<u8>,
    pub fingerprint: Vec<u8>,
    pub timestamp: i64,
}

#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()>;
    async fn delete_identity(&self, address: &str) -> Result<()>;
    async fn is_trusted_identity(&self, address: &str, key: &[u8; 32]) -> Result<bool>;
    // TODO: Add other methods like delete_all_identities
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>>;
    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()>;
    async fn delete_session(&self, address: &str) -> Result<()>;
    async fn has_session(&self, address: &str) -> Result<bool>;
    // TODO: Add other methods like delete_all_sessions, migrate_pn_to_lid
}

#[async_trait]
pub trait AppStateStore: Send + Sync {
    async fn get_app_state_version(&self, name: &str) -> Result<crate::appstate::hash::HashState>;
    async fn set_app_state_version(
        &self,
        name: &str,
        state: crate::appstate::hash::HashState,
    ) -> Result<()>;
}

#[async_trait]
pub trait AppStateKeyStore: Send + Sync {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>>;
    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()>;
}

// TODO: Define PreKeyStore, SenderKeyStore, ContactStore, etc.

pub trait AllStores:
    IdentityStore + SessionStore + AppStateStore + AppStateKeyStore + Send + Sync
{
}

impl<T: IdentityStore + SessionStore + AppStateStore + AppStateKeyStore + Send + Sync> AllStores
    for T
{
}
