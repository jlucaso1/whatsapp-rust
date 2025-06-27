// src/store/traits.rs
use crate::store::error::Result;
use async_trait::async_trait;

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

// TODO: Define PreKeyStore, SenderKeyStore, ContactStore, etc.

pub trait AllStores:
    IdentityStore + SessionStore /* + PreKeyStore + SenderKeyStore + ... */ + Send + Sync
{
}
