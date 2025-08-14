use crate::store::error::Result;
use crate::{appstate::hash::HashState, signal};
use async_trait::async_trait;

use libsignal_protocol::{Direction, KeyPair};
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

/// Application-specific pre-key management trait.
/// This provides intelligent pre-key management separate from the generic libsignal traits.
#[async_trait]
pub trait AppPreKeyStore: Send + Sync {
    /// Get the next available pre-key ID for sequential generation.
    async fn get_next_prekey_id(&self) -> Result<u32>;
    
    /// Store an application pre-key with upload status tracking.
    async fn store_app_prekey(&self, id: u32, key_pair: &KeyPair, uploaded: bool) -> Result<()>;
    
    /// Get a list of unuploaded pre-keys up to the specified count.
    async fn get_unuploaded_pre_keys(&self, count: u32) -> Result<Vec<(u32, KeyPair)>>;
    
    /// Mark pre-keys as uploaded up to the specified ID (inclusive).
    async fn mark_pre_keys_as_uploaded(&self, up_to_id: u32) -> Result<()>;
}

pub trait Backend:
    IdentityStore
    + SessionStore
    + AppStateKeyStore
    + AppStateStore
    + signal::store::PreKeyStore
    + signal::store::SignedPreKeyStore
    + SenderKeyStoreHelper
    + AppPreKeyStore
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
        + AppPreKeyStore
        + Send
        + Sync
{
}
