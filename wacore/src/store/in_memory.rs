//! In-memory implementation of the [`Backend`] trait.
//!
//! Intended for testing and as a reference implementation for FFI bridges.
//! All data lives in RAM behind a single [`async_lock::Mutex`] and is lost
//! when the struct is dropped.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI32, Ordering};

use crate::appstate::hash::HashState;
use crate::store::Device;
use crate::store::error::Result;
use crate::store::traits::*;
use async_lock::Mutex;
use async_trait::async_trait;
use wacore_appstate::processor::AppStateMutationMAC;

/// Key for the sent-message store: `(chat_jid, message_id)`.
type SentMessageKey = (String, String);

/// Value stored alongside a sent message (includes timestamp for expiration).
struct SentMessageEntry {
    payload: Vec<u8>,
    timestamp: i64,
}

/// Key for pre-keys: `id`.
struct PreKeyEntry {
    record: Vec<u8>,
}

/// Key for base-key collision detection: `(address, message_id)`.
type BaseKeyKey = (String, String);

/// Inner state protected by the mutex.
#[derive(Default)]
struct InMemoryState {
    // --- Signal ---
    identities: HashMap<String, [u8; 32]>,
    sessions: HashMap<String, Vec<u8>>,
    prekeys: HashMap<u32, PreKeyEntry>,
    signed_prekeys: HashMap<u32, Vec<u8>>,
    sender_keys: HashMap<String, Vec<u8>>,

    // --- AppSync ---
    sync_keys: HashMap<Vec<u8>, AppStateSyncKey>,
    latest_sync_key_id: Option<Vec<u8>>,
    versions: HashMap<String, HashState>,
    /// `(collection_name, hex(index_mac))` -> `value_mac`
    mutation_macs: HashMap<(String, Vec<u8>), Vec<u8>>,

    // --- Protocol ---
    /// Unified per-device sender key tracking: group_jid -> (device_jid -> has_key)
    sender_key_devices: HashMap<String, HashMap<String, bool>>,
    lid_mappings: HashMap<String, LidPnMappingEntry>,
    /// Reverse index: phone_number -> lid
    pn_to_lid: HashMap<String, String>,
    base_keys: HashMap<BaseKeyKey, Vec<u8>>,
    device_lists: HashMap<String, DeviceListRecord>,
    tc_tokens: HashMap<String, TcTokenEntry>,
    sent_messages: HashMap<SentMessageKey, SentMessageEntry>,

    // --- Device ---
    device: Option<Device>,
}

/// In-memory implementation of the full [`Backend`] trait.
///
/// Thread-safe and runtime-agnostic (uses [`async_lock::Mutex`]).
/// All data is ephemeral — it lives only as long as this struct.
pub struct InMemoryBackend {
    state: Mutex<InMemoryState>,
    next_device_id: AtomicI32,
}

impl InMemoryBackend {
    /// Create a new, empty in-memory store.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(InMemoryState::default()),
            next_device_id: AtomicI32::new(1),
        }
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SignalStore
// ---------------------------------------------------------------------------

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SignalStore for InMemoryBackend {
    async fn put_identity(&self, address: &str, key: [u8; 32]) -> Result<()> {
        self.state
            .lock()
            .await
            .identities
            .insert(address.to_string(), key);
        Ok(())
    }

    async fn load_identity(&self, address: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .state
            .lock()
            .await
            .identities
            .get(address)
            .map(|k| k.to_vec()))
    }

    async fn delete_identity(&self, address: &str) -> Result<()> {
        self.state.lock().await.identities.remove(address);
        Ok(())
    }

    async fn get_session(&self, address: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.state.lock().await.sessions.get(address).cloned())
    }

    async fn put_session(&self, address: &str, session: &[u8]) -> Result<()> {
        self.state
            .lock()
            .await
            .sessions
            .insert(address.to_string(), session.to_vec());
        Ok(())
    }

    async fn delete_session(&self, address: &str) -> Result<()> {
        self.state.lock().await.sessions.remove(address);
        Ok(())
    }

    async fn store_prekey(&self, id: u32, record: &[u8], _uploaded: bool) -> Result<()> {
        self.state.lock().await.prekeys.insert(
            id,
            PreKeyEntry {
                record: record.to_vec(),
            },
        );
        Ok(())
    }

    async fn load_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        Ok(self
            .state
            .lock()
            .await
            .prekeys
            .get(&id)
            .map(|e| e.record.clone()))
    }

    async fn remove_prekey(&self, id: u32) -> Result<()> {
        self.state.lock().await.prekeys.remove(&id);
        Ok(())
    }

    async fn get_max_prekey_id(&self) -> Result<u32> {
        Ok(self
            .state
            .lock()
            .await
            .prekeys
            .keys()
            .copied()
            .max()
            .unwrap_or(0))
    }

    async fn store_signed_prekey(&self, id: u32, record: &[u8]) -> Result<()> {
        self.state
            .lock()
            .await
            .signed_prekeys
            .insert(id, record.to_vec());
        Ok(())
    }

    async fn load_signed_prekey(&self, id: u32) -> Result<Option<Vec<u8>>> {
        Ok(self.state.lock().await.signed_prekeys.get(&id).cloned())
    }

    async fn load_all_signed_prekeys(&self) -> Result<Vec<(u32, Vec<u8>)>> {
        Ok(self
            .state
            .lock()
            .await
            .signed_prekeys
            .iter()
            .map(|(id, rec)| (*id, rec.clone()))
            .collect())
    }

    async fn remove_signed_prekey(&self, id: u32) -> Result<()> {
        self.state.lock().await.signed_prekeys.remove(&id);
        Ok(())
    }

    async fn put_sender_key(&self, address: &str, record: &[u8]) -> Result<()> {
        self.state
            .lock()
            .await
            .sender_keys
            .insert(address.to_string(), record.to_vec());
        Ok(())
    }

    async fn get_sender_key(&self, address: &str) -> Result<Option<Vec<u8>>> {
        Ok(self.state.lock().await.sender_keys.get(address).cloned())
    }

    async fn delete_sender_key(&self, address: &str) -> Result<()> {
        self.state.lock().await.sender_keys.remove(address);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// AppSyncStore
// ---------------------------------------------------------------------------

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl AppSyncStore for InMemoryBackend {
    async fn get_sync_key(&self, key_id: &[u8]) -> Result<Option<AppStateSyncKey>> {
        Ok(self.state.lock().await.sync_keys.get(key_id).cloned())
    }

    async fn set_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> Result<()> {
        let mut s = self.state.lock().await;
        s.sync_keys.insert(key_id.to_vec(), key);
        s.latest_sync_key_id = Some(key_id.to_vec());
        Ok(())
    }

    async fn get_version(&self, name: &str) -> Result<HashState> {
        Ok(self
            .state
            .lock()
            .await
            .versions
            .get(name)
            .cloned()
            .unwrap_or_default())
    }

    async fn set_version(&self, name: &str, state: HashState) -> Result<()> {
        self.state
            .lock()
            .await
            .versions
            .insert(name.to_string(), state);
        Ok(())
    }

    async fn put_mutation_macs(
        &self,
        name: &str,
        _version: u64,
        mutations: &[AppStateMutationMAC],
    ) -> Result<()> {
        let mut s = self.state.lock().await;
        for m in mutations {
            s.mutation_macs
                .insert((name.to_string(), m.index_mac.clone()), m.value_mac.clone());
        }
        Ok(())
    }

    async fn get_mutation_mac(&self, name: &str, index_mac: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .state
            .lock()
            .await
            .mutation_macs
            .get(&(name.to_string(), index_mac.to_vec()))
            .cloned())
    }

    async fn delete_mutation_macs(&self, name: &str, index_macs: &[Vec<u8>]) -> Result<()> {
        let mut s = self.state.lock().await;
        for im in index_macs {
            s.mutation_macs.remove(&(name.to_string(), im.clone()));
        }
        Ok(())
    }

    async fn get_latest_sync_key_id(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.state.lock().await.latest_sync_key_id.clone())
    }
}

// ---------------------------------------------------------------------------
// ProtocolStore
// ---------------------------------------------------------------------------

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl ProtocolStore for InMemoryBackend {
    // --- Per-Device Sender Key Tracking ---

    async fn get_sender_key_devices(&self, group_jid: &str) -> Result<Vec<(String, bool)>> {
        Ok(self
            .state
            .lock()
            .await
            .sender_key_devices
            .get(group_jid)
            .map(|map| map.iter().map(|(k, v)| (k.clone(), *v)).collect())
            .unwrap_or_default())
    }

    async fn set_sender_key_status(&self, group_jid: &str, entries: &[(&str, bool)]) -> Result<()> {
        let mut s = self.state.lock().await;
        let map = s
            .sender_key_devices
            .entry(group_jid.to_string())
            .or_default();
        for (device_jid, has_key) in entries {
            map.insert(device_jid.to_string(), *has_key);
        }
        Ok(())
    }

    async fn clear_sender_key_devices(&self, group_jid: &str) -> Result<()> {
        self.state.lock().await.sender_key_devices.remove(group_jid);
        Ok(())
    }

    // --- LID-PN Mapping ---

    async fn get_lid_mapping(&self, lid: &str) -> Result<Option<LidPnMappingEntry>> {
        Ok(self.state.lock().await.lid_mappings.get(lid).cloned())
    }

    async fn get_pn_mapping(&self, phone: &str) -> Result<Option<LidPnMappingEntry>> {
        let s = self.state.lock().await;
        let entry = s
            .pn_to_lid
            .get(phone)
            .and_then(|lid| s.lid_mappings.get(lid))
            .cloned();
        Ok(entry)
    }

    async fn put_lid_mapping(&self, entry: &LidPnMappingEntry) -> Result<()> {
        let mut s = self.state.lock().await;
        // Remove stale reverse entry if the LID was previously mapped to a different phone number
        if let Some(old_phone) = s
            .lid_mappings
            .get(&entry.lid)
            .filter(|old| old.phone_number != entry.phone_number)
            .map(|old| old.phone_number.clone())
        {
            s.pn_to_lid.remove(&old_phone);
        }
        s.pn_to_lid
            .insert(entry.phone_number.clone(), entry.lid.clone());
        s.lid_mappings.insert(entry.lid.clone(), entry.clone());
        Ok(())
    }

    async fn get_all_lid_mappings(&self) -> Result<Vec<LidPnMappingEntry>> {
        Ok(self
            .state
            .lock()
            .await
            .lid_mappings
            .values()
            .cloned()
            .collect())
    }

    // --- Base Key Collision Detection ---

    async fn save_base_key(&self, address: &str, message_id: &str, base_key: &[u8]) -> Result<()> {
        self.state.lock().await.base_keys.insert(
            (address.to_string(), message_id.to_string()),
            base_key.to_vec(),
        );
        Ok(())
    }

    async fn has_same_base_key(
        &self,
        address: &str,
        message_id: &str,
        current_base_key: &[u8],
    ) -> Result<bool> {
        let s = self.state.lock().await;
        let same = s
            .base_keys
            .get(&(address.to_string(), message_id.to_string()))
            .is_some_and(|stored| stored == current_base_key);
        Ok(same)
    }

    async fn delete_base_key(&self, address: &str, message_id: &str) -> Result<()> {
        self.state
            .lock()
            .await
            .base_keys
            .remove(&(address.to_string(), message_id.to_string()));
        Ok(())
    }

    // --- Device Registry ---

    async fn update_device_list(&self, record: DeviceListRecord) -> Result<()> {
        self.state
            .lock()
            .await
            .device_lists
            .insert(record.user.clone(), record);
        Ok(())
    }

    async fn get_devices(&self, user: &str) -> Result<Option<DeviceListRecord>> {
        Ok(self.state.lock().await.device_lists.get(user).cloned())
    }

    // --- TcToken Storage ---

    async fn get_tc_token(&self, jid: &str) -> Result<Option<TcTokenEntry>> {
        Ok(self.state.lock().await.tc_tokens.get(jid).cloned())
    }

    async fn put_tc_token(&self, jid: &str, entry: &TcTokenEntry) -> Result<()> {
        self.state
            .lock()
            .await
            .tc_tokens
            .insert(jid.to_string(), entry.clone());
        Ok(())
    }

    async fn delete_tc_token(&self, jid: &str) -> Result<()> {
        self.state.lock().await.tc_tokens.remove(jid);
        Ok(())
    }

    async fn get_all_tc_token_jids(&self) -> Result<Vec<String>> {
        Ok(self.state.lock().await.tc_tokens.keys().cloned().collect())
    }

    async fn delete_expired_tc_tokens(&self, cutoff_timestamp: i64) -> Result<u32> {
        let mut s = self.state.lock().await;
        let before = s.tc_tokens.len();
        s.tc_tokens
            .retain(|_, entry| entry.token_timestamp >= cutoff_timestamp);
        Ok((before - s.tc_tokens.len()) as u32)
    }

    // --- Sent Message Store ---

    async fn store_sent_message(
        &self,
        chat_jid: &str,
        message_id: &str,
        payload: &[u8],
    ) -> Result<()> {
        let now = crate::time::now_secs();
        self.state.lock().await.sent_messages.insert(
            (chat_jid.to_string(), message_id.to_string()),
            SentMessageEntry {
                payload: payload.to_vec(),
                timestamp: now,
            },
        );
        Ok(())
    }

    async fn take_sent_message(&self, chat_jid: &str, message_id: &str) -> Result<Option<Vec<u8>>> {
        Ok(self
            .state
            .lock()
            .await
            .sent_messages
            .remove(&(chat_jid.to_string(), message_id.to_string()))
            .map(|e| e.payload))
    }

    async fn delete_expired_sent_messages(&self, cutoff_timestamp: i64) -> Result<u32> {
        let mut s = self.state.lock().await;
        let before = s.sent_messages.len();
        s.sent_messages
            .retain(|_, entry| entry.timestamp >= cutoff_timestamp);
        Ok((before - s.sent_messages.len()) as u32)
    }
}

// ---------------------------------------------------------------------------
// DeviceStore
// ---------------------------------------------------------------------------

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DeviceStore for InMemoryBackend {
    async fn save(&self, device: &Device) -> Result<()> {
        self.state.lock().await.device = Some(device.clone());
        Ok(())
    }

    async fn load(&self) -> Result<Option<Device>> {
        Ok(self.state.lock().await.device.clone())
    }

    async fn exists(&self) -> Result<bool> {
        Ok(self.state.lock().await.device.is_some())
    }

    async fn create(&self) -> Result<i32> {
        let id = self.next_device_id.fetch_add(1, Ordering::Relaxed);
        // Materialize a default Device so that `exists()` returns true after `create()`.
        let mut state = self.state.lock().await;
        if state.device.is_none() {
            state.device = Some(Device::new());
        }
        Ok(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn is_backend<T: crate::store::traits::Backend>() {}

    #[test]
    fn in_memory_backend_implements_backend() {
        is_backend::<InMemoryBackend>();
    }
}
