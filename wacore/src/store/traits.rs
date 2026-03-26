//! Storage traits for the WhatsApp client.
//!
//! This module defines 4 domain-grouped traits that together form the `Backend` trait:
//!
//! - [`SignalStore`]: Signal protocol cryptographic operations (identity, sessions, keys)
//! - [`AppSyncStore`]: WhatsApp app state synchronization
//! - [`ProtocolStore`]: WhatsApp Web protocol alignment (SKDM, LID mapping, device registry)
//! - [`DeviceStore`]: Device persistence operations

use crate::appstate::hash::HashState;
use crate::store::error::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use wacore_appstate::processor::AppStateMutationMAC;

/// App state synchronization key for WhatsApp's app state protocol.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AppStateSyncKey {
    pub key_data: Vec<u8>,
    pub fingerprint: Vec<u8>,
    pub timestamp: i64,
}

/// Entry representing a LID to Phone Number mapping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LidPnMappingEntry {
    /// The LID user part (e.g., "100000012345678")
    pub lid: String,
    /// The phone number user part (e.g., "559980000001")
    pub phone_number: String,
    /// Unix timestamp when the mapping was first learned
    pub created_at: i64,
    /// Unix timestamp when the mapping was last updated
    pub updated_at: i64,
    /// The source from which this mapping was learned (e.g., "usync", "peer_pn_message")
    pub learning_source: String,
}

/// Trusted contact privacy token entry.
///
/// Matches WhatsApp Web's Chat.tcToken / tcTokenTimestamp / tcTokenSenderTimestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcTokenEntry {
    /// Raw token bytes received from the server.
    pub token: Vec<u8>,
    /// Unix timestamp (seconds) when the token was received.
    pub token_timestamp: i64,
    /// Unix timestamp (seconds) when we last issued our token to this contact.
    pub sender_timestamp: Option<i64>,
}

/// Device information for registry tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// The device ID (0 = primary device, 1+ = companion devices)
    pub device_id: u32,
    /// The key index, if known
    pub key_index: Option<u32>,
}

/// Device list record matching WhatsApp Web's DeviceListRecord structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceListRecord {
    /// The user part of the JID (phone number or LID)
    pub user: String,
    /// List of known devices for this user
    pub devices: Vec<DeviceInfo>,
    /// Timestamp when this record was last updated
    pub timestamp: i64,
    /// Participant hash from usync, if available
    pub phash: Option<String>,
}

/// Signal protocol cryptographic storage operations.
///
/// Handles identity keys, sessions, pre-keys, signed pre-keys, and sender keys
/// for end-to-end encryption.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait SignalStore: Send + Sync {
    // --- Identity Operations ---

    /// Store an identity key for a remote address.
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()>;

    /// Load an identity key for a remote address.
    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>>;

    /// Delete an identity key.
    async fn delete_identity(&self, address: &str) -> Result<()>;

    // --- Session Operations ---

    /// Get an encrypted session for an address.
    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>>;

    /// Store an encrypted session.
    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()>;

    /// Delete a session.
    async fn delete_session(&self, address: &str) -> Result<()>;

    /// Check if a session exists. Default implementation uses `get_session`.
    async fn has_session(&self, address: &str) -> Result<bool> {
        Ok(self.get_session(address).await?.is_some())
    }

    // --- PreKey Operations ---

    /// Store a pre-key.
    async fn store_prekey(&self, id: u32, record: &[u8], uploaded: bool) -> Result<()>;

    /// Store multiple pre-keys in a single batch operation.
    /// Default implementation falls back to individual `store_prekey` calls.
    async fn store_prekeys_batch(&self, keys: &[(u32, Vec<u8>)], uploaded: bool) -> Result<()> {
        for (id, record) in keys {
            self.store_prekey(*id, record, uploaded).await?;
        }
        Ok(())
    }

    /// Load a pre-key by ID.
    async fn load_prekey(&self, id: u32) -> Result<Option<Vec<u8>>>;

    /// Remove a pre-key.
    async fn remove_prekey(&self, id: u32) -> Result<()>;

    /// Get the maximum pre-key ID currently stored, or 0 if none exist.
    /// Used for migration when `next_pre_key_id` counter is not yet initialized.
    async fn get_max_prekey_id(&self) -> Result<u32>;

    // --- Signed PreKey Operations ---

    /// Store a signed pre-key.
    async fn store_signed_prekey(&self, id: u32, record: &[u8]) -> Result<()>;

    /// Load a signed pre-key by ID.
    async fn load_signed_prekey(&self, id: u32) -> Result<Option<Vec<u8>>>;

    /// Load all signed pre-keys. Returns (id, record) pairs.
    async fn load_all_signed_prekeys(&self) -> Result<Vec<(u32, Vec<u8>)>>;

    /// Remove a signed pre-key.
    async fn remove_signed_prekey(&self, id: u32) -> Result<()>;

    // --- Sender Key Operations ---

    /// Store a sender key for group messaging.
    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()>;

    /// Get a sender key.
    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>>;

    /// Delete a sender key.
    async fn delete_sender_key(&self, address: &str) -> Result<()>;
}

/// WhatsApp app state synchronization storage.
///
/// Handles sync keys, version tracking, and mutation MACs for the app state protocol.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait AppSyncStore: Send + Sync {
    /// Get an app state sync key by ID.
    async fn get_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>>;

    /// Set an app state sync key.
    async fn set_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()>;

    /// Get the app state version for a collection.
    async fn get_version(&self, name: &str) -> Result<HashState>;

    /// Set the app state version for a collection.
    async fn set_version(&self, name: &str, state: HashState) -> Result<()>;

    /// Store mutation MACs for a version.
    async fn put_mutation_macs(
        &self,
        name: &str,
        version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()>;

    /// Get a mutation MAC by index.
    async fn get_mutation_mac(&self, name: &str, index_mac: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Delete mutation MACs by their index MACs.
    async fn delete_mutation_macs(&self, name: &str, index_macs: &[Vec<u8>]) -> Result<()>;

    /// Get the most recently stored app state sync key ID.
    async fn get_latest_sync_key_id(&self) -> Result<Option<Vec<u8>>>;
}

/// WhatsApp Web protocol alignment storage.
///
/// Handles SKDM tracking, LID-PN mapping, base key collision detection,
/// device registry, and sender key status.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait ProtocolStore: Send + Sync {
    // --- Per-Device Sender Key Tracking (matches WA Web's participant.senderKey Map) ---

    /// Get the sender key distribution status for all known devices in a group.
    /// Returns `(device_jid_string, has_key)` pairs where `has_key` indicates
    /// whether the device has a valid sender key (`true`) or needs fresh SKDM (`false`).
    async fn get_sender_key_devices(&self, group_jid: &str) -> Result<Vec<(String, bool)>>;

    /// Set sender key status for devices. Called with `has_key=true` after successful
    /// SKDM distribution (WA Web: `markHasSenderKey`), or `has_key=false` to mark
    /// devices as needing fresh SKDM (WA Web: `markForgetSenderKey`).
    async fn set_sender_key_status(&self, group_jid: &str, entries: &[(&str, bool)]) -> Result<()>;

    /// Clear all sender key device tracking for a group (on sender key rotation).
    async fn clear_sender_key_devices(&self, group_jid: &str) -> Result<()>;

    // --- LID-PN Mapping ---

    /// Get a mapping by LID.
    async fn get_lid_mapping(&self, lid: &str) -> Result<Option<LidPnMappingEntry>>;

    /// Get a mapping by phone number (returns the most recent LID for that phone).
    async fn get_pn_mapping(&self, phone: &str) -> Result<Option<LidPnMappingEntry>>;

    /// Store or update a LID-PN mapping.
    async fn put_lid_mapping(&self, entry: &LidPnMappingEntry) -> Result<()>;

    /// Get all LID-PN mappings (for cache warm-up).
    async fn get_all_lid_mappings(&self) -> Result<Vec<LidPnMappingEntry>>;

    // --- Base Key Collision Detection ---

    /// Save the base key for a session address during retry collision detection.
    async fn save_base_key(&self, address: &str, message_id: &str, base_key: &[u8]) -> Result<()>;

    /// Check if the current session has the same base key as the saved one.
    async fn has_same_base_key(
        &self,
        address: &str,
        message_id: &str,
        current_base_key: &[u8],
    ) -> Result<bool>;

    /// Delete a base key entry.
    async fn delete_base_key(&self, address: &str, message_id: &str) -> Result<()>;

    // --- Device Registry ---

    /// Update the device list for a user (called after usync responses).
    async fn update_device_list(&self, record: DeviceListRecord) -> Result<()>;

    /// Get all known devices for a user.
    async fn get_devices(&self, user: &str) -> Result<Option<DeviceListRecord>>;

    // --- TcToken Storage ---

    /// Get a trusted contact token for a JID (stored under LID).
    async fn get_tc_token(&self, jid: &str) -> Result<Option<TcTokenEntry>>;

    /// Store or update a trusted contact token for a JID.
    async fn put_tc_token(&self, jid: &str, entry: &TcTokenEntry) -> Result<()>;

    /// Delete a trusted contact token for a JID.
    async fn delete_tc_token(&self, jid: &str) -> Result<()>;

    /// Get all JIDs that have stored tc tokens.
    async fn get_all_tc_token_jids(&self) -> Result<Vec<String>>;

    /// Delete tc tokens with token_timestamp older than cutoff. Returns count deleted.
    async fn delete_expired_tc_tokens(&self, cutoff_timestamp: i64) -> Result<u32>;

    // --- Sent Message Store (retry support, matches WA Web's getMessageTable) ---

    /// Store a sent message's serialized payload for retry handling.
    /// Called after each send_message(); the payload is the protobuf-encoded Message.
    async fn store_sent_message(
        &self,
        chat_jid: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<()>;

    /// Retrieve and delete a sent message (atomic take). Returns serialized payload.
    /// Called when a retry receipt arrives; consuming prevents double-retry.
    async fn take_sent_message(&self, chat_jid: &str, message_id: &str) -> Result<Option<Vec<u8>>>;

    /// Delete sent messages older than cutoff (unix timestamp seconds). Returns count deleted.
    async fn delete_expired_sent_messages(&self, cutoff_timestamp: i64) -> Result<u32>;
}

/// Device data persistence operations.
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DeviceStore: Send + Sync {
    /// Save device data.
    async fn save(&self, device: &crate::store::Device) -> Result<()>;

    /// Load device data.
    async fn load(&self) -> Result<Option<crate::store::Device>>;

    /// Check if a device exists.
    async fn exists(&self) -> Result<bool>;

    /// Create a new device row and return its generated device_id.
    async fn create(&self) -> Result<i32>;

    /// Create a snapshot of the database state.
    /// The argument `name` can be used to label the snapshot file.
    /// `extra_content` can be used to save a related binary blob (e.g. the message that caused the failure).
    async fn snapshot_db(&self, _name: &str, _extra_content: Option<&[u8]>) -> Result<()> {
        Ok(())
    }
}

/// Combined storage backend trait.
///
/// Any type implementing all four domain traits automatically implements `Backend`.
pub trait Backend: SignalStore + AppSyncStore + ProtocolStore + DeviceStore + Send + Sync {}

impl<T> Backend for T where T: SignalStore + AppSyncStore + ProtocolStore + DeviceStore + Send + Sync
{}
