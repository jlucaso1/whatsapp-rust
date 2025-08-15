use crate::store::error::Result;
use crate::{appstate::hash::HashState, signal};
use async_trait::async_trait;

use crate::libsignal::protocol::Direction;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppStateSyncKey {
    pub key_data: Vec<u8>,
    pub fingerprint: Vec<u8>,
    pub timestamp: i64,
}

#[async_trait]
pub trait IdentityStore: Send + Sync {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()>;
    async fn delete_identity(&self, address: &str) -> Result<()>;
    async fn is_trusted_identity(
        &self,
        address: &str,
        key: &[u8; 32],
        direction: Direction,
    ) -> Result<bool>;
    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>>;
}

#[async_trait]
pub trait SenderKeyStoreHelper: Send + Sync {
    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()>;
    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>>;
    async fn delete_sender_key(&self, address: &str) -> Result<()>;
}

#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>>;
    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()>;
    async fn delete_session(&self, address: &str) -> Result<()>;
    async fn has_session(&self, address: &str) -> Result<bool>;
}

#[async_trait]
pub trait AppStateKeyStore: Send + Sync {
    async fn get_app_state_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>>;
    async fn set_app_state_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()>;
}

#[async_trait]
pub trait AppStateStore: Send + Sync {
    async fn get_app_state_version(&self, name: &str) -> Result<HashState>;
    async fn set_app_state_version(&self, name: &str, state: HashState) -> Result<()>;
}

pub trait Backend:
    IdentityStore
    + SessionStore
    + AppStateKeyStore
    + AppStateStore
    + signal::store::PreKeyStore
    + signal::store::SignedPreKeyStore
    + SenderKeyStoreHelper
    + Send
    + Sync
{
}

impl<T> Backend for T where
    T: IdentityStore
        + SessionStore
        + AppStateKeyStore
        + AppStateStore
        + signal::store::PreKeyStore
        + signal::store::SignedPreKeyStore
        + SenderKeyStoreHelper
        + Send
        + Sync
{
}
