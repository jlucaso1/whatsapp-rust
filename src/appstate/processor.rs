use super::errors::{AppStateError, Result};
use super::hash::HashState;
use super::keys;
use crate::crypto::cbc;
use hex; // Added for hex::encode
use crate::crypto::hmac_sha512;
use crate::store::traits::{AppStateKeyStore, AppStateStore};
use prost::Message;
use std::sync::Arc;
use whatsapp_proto::whatsapp as wa;

pub struct Processor {
    #[allow(dead_code)] // TODO: This will be used when hash calculation is implemented
    store: Arc<dyn AppStateStore>,
    key_store: Arc<dyn AppStateKeyStore>,
}

#[derive(Debug, Clone)]
pub struct Mutation {
    pub operation: wa::syncd_mutation::SyncdOperation,
    pub action: wa::SyncActionValue,
    pub index: Vec<String>,
    pub index_mac: Vec<u8>,
    pub value_mac: Vec<u8>,
}

pub struct PatchList {
    pub name: String,
    pub has_more_patches: bool,
    pub patches: Vec<wa::SyncdPatch>,
    pub snapshot: Option<wa::SyncdSnapshot>,
}

impl Processor {
    pub fn new(store: Arc<dyn AppStateStore>, key_store: Arc<dyn AppStateKeyStore>) -> Self {
        Self { store, key_store }
    }

    pub async fn decode_patches(
        &self,
        list: &PatchList,
        initial_state: HashState,
    ) -> Result<(Vec<Mutation>, HashState)> {
        let mut current_state = initial_state;
        let mut new_mutations: Vec<Mutation> = Vec::new();
        let mut missing_keys: Vec<Vec<u8>> = Vec::new(); // Modified to be mutable

        if let Some(snapshot) = &list.snapshot {
            log::info!(target: "AppState", "Processing snapshot for collection '{}', version: {}", list.name, snapshot.version.as_ref().map_or(0, |v| v.version()));

            current_state.version = snapshot.version.as_ref().map_or(current_state.version, |v| v.version());

            if let Some(key_id_proto) = &snapshot.key_id {
                if let Some(key_id_bytes) = &key_id_proto.id {
                    match self.key_store.get_app_state_sync_key(key_id_bytes).await {
                        Ok(Some(key_struct)) => {
                            let expanded_keys = keys::expand_app_state_keys(&key_struct.key_data);
                            log::info!(target: "AppState", "Processing {} records from snapshot for '{}'", snapshot.records.len(), list.name);
                            for record_from_snapshot in &snapshot.records {
                                let virtual_mutation = wa::SyncdMutation {
                                    operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
                                    record: Some(record_from_snapshot.clone()),
                                };
                                match self.decode_mutation(&expanded_keys, &virtual_mutation, &mut new_mutations).await {
                                    Ok(_) => {}
                                    Err(e) => {
                                        log::warn!(target: "AppState", "Failed to decode a mutation from snapshot for '{}': {:?}. Skipping record.", list.name, e);
                                        if let AppStateError::KeysNotFound(mut v) = e {
                                            missing_keys.append(&mut v);
                                        }
                                    }
                                }
                            }
                        }
                        Ok(None) => {
                            log::warn!(target: "AppState", "Snapshot for '{}' references key_id {:?} which was not found. Skipping snapshot processing.", list.name, hex::encode(key_id_bytes));
                            missing_keys.push(key_id_bytes.to_vec());
                        }
                        Err(e) => {
                            log::error!(target: "AppState", "Failed to fetch app state sync key for snapshot of '{}': {:?}. Skipping snapshot processing.", list.name, e);
                        }
                    }
                } else {
                    log::warn!(target: "AppState", "Snapshot for '{}' has KeyId message but missing 'id' bytes. Skipping snapshot processing.", list.name);
                }
            } else {
                log::warn!(target: "AppState", "Snapshot for '{}' is missing key_id. Skipping snapshot processing.", list.name);
            }
            // TODO: Verify snapshot.mac (using the expanded_keys.snapshot_mac)
            // TODO: Recalculate LT-Hash (current_state.hash) based on all records in new_mutations from snapshot
        }

        // Process patches (runs whether snapshot was present or not)
        for patch in &list.patches {
            let version = patch.version.as_ref().map_or(0, |v| v.version());
            current_state.version = version;

            // TODO: Verify patch.snapshot_mac and patch.patch_mac
            // For now, we will proceed directly to mutation decoding.

            let key_id_bytes_from_patch = patch
                .key_id
                .as_ref()
                .and_then(|k| k.id.as_ref())
                .map_or(&[][..], |v| &v[..]);

            // Fetch the real key from the key store
            let key_struct = match self.key_store.get_app_state_sync_key(key_id_bytes_from_patch).await {
                Ok(Some(k)) => k,
                Ok(None) => {
                    log::warn!(target: "AppState", "No app state sync key found for patch key_id: {:?} in collection '{}'. Skipping patch.", hex::encode(key_id_bytes_from_patch), list.name);
                    missing_keys.push(key_id_bytes_from_patch.to_vec()); // Add to missing keys
                    continue;
                }
                Err(e) => {
                    log::warn!(target: "AppState", "Failed to fetch app state sync key for patch in '{}': {e:?}. Skipping patch.", list.name);
                    continue;
                }
            };
            let expanded_keys_for_patch = keys::expand_app_state_keys(&key_struct.key_data);

            for mutation_from_patch in &patch.mutations {
                if let Err(e) = self
                    .decode_mutation(&expanded_keys_for_patch, mutation_from_patch, &mut new_mutations)
                    .await
                {
                    log::warn!(target: "AppState", "Failed to decode a mutation from patch for '{}': {:?}. Skipping mutation.", list.name, e);
                    if let AppStateError::KeysNotFound(mut v) = e {
                        missing_keys.append(&mut v);
                    }
                }
            }
        }

        if !missing_keys.is_empty() {
            return Err(AppStateError::KeysNotFound(missing_keys));
        }

        Ok((new_mutations, current_state))
    }

    pub async fn decode_mutation(
        &self,
        keys: &keys::ExpandedAppStateKeys,
        mutation: &wa::SyncdMutation,
        out: &mut Vec<Mutation>,
    ) -> Result<()> {
        let record = mutation
            .record
            .as_ref()
            .ok_or(AppStateError::KeysNotFound(vec![]))?;
        let key_id_bytes = record
            .key_id
            .as_ref()
            .and_then(|k| k.id.as_deref())
            .ok_or(AppStateError::KeysNotFound(vec![]))?;

        let value_blob = record
            .value
            .as_ref()
            .and_then(|v| v.blob.as_deref())
            .ok_or(AppStateError::KeysNotFound(vec![]))?;
        if value_blob.len() < 32 {
            return Err(AppStateError::KeysNotFound(vec![]));
        }
        let (content, value_mac) = value_blob.split_at(value_blob.len() - 32);

        // Verify the content MAC before attempting decryption.
        let expected_value_mac = hmac_sha512::generate_content_mac(
            mutation.operation(),
            content,
            key_id_bytes,
            &keys.value_mac,
        );

        if expected_value_mac != value_mac {
            return Err(AppStateError::MismatchingContentMAC);
        }

        if content.len() < 16 {
            return Err(AppStateError::KeysNotFound(vec![]));
        }
        let (iv, ciphertext) = content.split_at(16);

        let plaintext = cbc::decrypt(&keys.value_encryption, iv, ciphertext)?;

        let mut sync_action =
            wa::SyncActionData::decode(plaintext.as_slice()).map_err(AppStateError::Unmarshal)?;

        let index_mac = record
            .index
            .as_ref()
            .and_then(|i| i.blob.as_deref())
            .ok_or(AppStateError::KeysNotFound(vec![]))?;
        // TODO: Verify index_mac with `hash::concat_and_hmac`

        let index_json = sync_action
            .index
            .as_deref()
            .ok_or(AppStateError::KeysNotFound(vec![]))?;
        let index: Vec<String> = serde_json::from_slice(index_json)?;

        let new_mutation = Mutation {
            operation: mutation.operation(),
            action: sync_action.value.take().unwrap(),
            index,
            index_mac: index_mac.to_vec(),
            value_mac: value_mac.to_vec(),
        };

        out.push(new_mutation);
        Ok(())
    }
}
