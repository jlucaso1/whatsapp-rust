use crate::appstate::hash::HashState;
use crate::store::error::Result;
use async_trait::async_trait;
use wacore_appstate::processor::AppStateMutationMAC;

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
    async fn put_app_state_mutation_macs(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()>;
    async fn delete_app_state_mutation_macs(
        &self,
        name: &str,
        index_macs: &[Vec<u8>],
    ) -> Result<()>;
    async fn get_app_state_mutation_mac(
        &self,
        name: &str,
        index_mac: &[u8],
    ) -> Result<Option<Vec<u8>>>;
}

/// Trait for tracking which devices have received Sender Key Distribution Messages (SKDM)
/// for each group. This prevents sending SKDM to devices that already have the sender key.
#[async_trait]
pub trait SenderKeyDistributionStore: Send + Sync {
    /// Get the list of device JIDs that have already received SKDM for a group
    async fn get_skdm_recipients(&self, group_jid: &str) -> Result<Vec<String>>;

    /// Mark devices as having received SKDM for a group
    async fn add_skdm_recipients(&self, group_jid: &str, device_jids: &[String]) -> Result<()>;

    /// Clear all SKDM recipients for a group (used when sender key is rotated)
    async fn clear_skdm_recipients(&self, group_jid: &str) -> Result<()>;
}

/// Entry representing a LID to Phone Number mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LidPnMappingEntry {
    /// The LID user part (e.g., "100000012345678")
    pub lid: String,
    /// The phone number user part (e.g., "559980000001")
    pub phone_number: String,
    /// Unix timestamp when the mapping was first learned
    pub created_at: i64,
    /// Unix timestamp when the mapping was last updated (drives "most recent" by phone)
    pub updated_at: i64,
    /// The source from which this mapping was learned (e.g., "usync", "peer_pn_message")
    pub learning_source: String,
}

/// Trait for LID to Phone Number mapping persistence
#[async_trait]
pub trait LidPnMappingStore: Send + Sync {
    /// Get a mapping by LID
    async fn get_lid_pn_mapping_by_lid(&self, lid: &str) -> Result<Option<LidPnMappingEntry>>;

    /// Get a mapping by phone number (returns the most recent LID for that phone)
    async fn get_lid_pn_mapping_by_phone(&self, phone: &str) -> Result<Option<LidPnMappingEntry>>;

    /// Store or update a LID-PN mapping
    async fn put_lid_pn_mapping(&self, entry: &LidPnMappingEntry) -> Result<()>;

    /// Get all LID-PN mappings (for cache warm-up)
    async fn get_all_lid_pn_mappings(&self) -> Result<Vec<LidPnMappingEntry>>;

    /// Delete a mapping by LID
    async fn delete_lid_pn_mapping(&self, lid: &str) -> Result<()>;
}

/// Trait for device data persistence operations
#[async_trait]
pub trait DevicePersistence: Send + Sync {
    /// Save device data (single device mode)
    async fn save_device_data(&self, device_data: &crate::store::Device) -> Result<()>;

    /// Save device data for a specific device ID (multi-account mode)
    async fn save_device_data_for_device(
        &self,
        device_id: i32,
        device_data: &crate::store::Device,
    ) -> Result<()>;

    /// Load device data (single device mode)
    async fn load_device_data(&self) -> Result<Option<crate::store::Device>>;

    /// Load device data for a specific device ID (multi-account mode)
    async fn load_device_data_for_device(
        &self,
        device_id: i32,
    ) -> Result<Option<crate::store::Device>>;

    /// Check if a device row exists for the given `device_id`.
    async fn device_exists(&self, device_id: i32) -> Result<bool>;

    /// Create a new device row and return its generated `device_id`.
    async fn create_new_device(&self) -> Result<i32>;
}

pub trait Backend:
    IdentityStore
    + SessionStore
    + AppStateKeyStore
    + AppStateStore
    + crate::libsignal::store::PreKeyStore
    + crate::libsignal::store::SignedPreKeyStore
    + SenderKeyStoreHelper
    + SenderKeyDistributionStore
    + LidPnMappingStore
    + DevicePersistence
    + Send
    + Sync
{
}

impl<T> Backend for T where
    T: IdentityStore
        + SessionStore
        + AppStateKeyStore
        + AppStateStore
        + crate::libsignal::store::PreKeyStore
        + crate::libsignal::store::SignedPreKeyStore
        + SenderKeyStoreHelper
        + SenderKeyDistributionStore
        + LidPnMappingStore
        + DevicePersistence
        + Send
        + Sync
{
}
