use super::errors::{AppStateError, Result};
use super::hash::HashState;
use super::keys;
use super::lthash::WA_PATCH_INTEGRITY;
use crate::crypto::cbc;
use crate::crypto::hmac_sha512;
use base64::Engine as _;
use base64::prelude::*;
use prost::Message;
use waproto::whatsapp as wa;

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

pub struct ProcessorUtils;

impl ProcessorUtils {
    /// Decode patches into mutations using provided keys
    /// Platform-independent core logic
    pub fn decode_patches_core(
        list: &PatchList,
        initial_state: HashState,
        key_lookup: impl Fn(&[u8]) -> Option<Vec<u8>>,
    ) -> Result<(Vec<Mutation>, HashState)> {
        let mut current_state = initial_state;
        let mut new_mutations: Vec<Mutation> = Vec::new();
        let mut missing_keys: Vec<Vec<u8>> = Vec::new();

        if let Some(snapshot) = &list.snapshot {
            // TODO: Implement snapshot decoding. This involves:
            // 1. Verifying snapshot.mac
            // 2. Updating the hash state
            // 3. Decoding all mutations within the snapshot
            // For now, we'll just log and move to patches.
            current_state.version = snapshot.version.as_ref().map_or(0, |v| v.version());
        }

        for patch in &list.patches {
            let version = patch.version.as_ref().map_or(0, |v| v.version());
            current_state.version = version;

            let key_id = patch
                .key_id
                .as_ref()
                .and_then(|k| k.id.as_ref())
                .map_or(&[][..], |v| &v[..]);

            // Fetch the real key using the provided lookup function
            let key_data = match key_lookup(key_id) {
                Some(k) => k,
                None => {
                    missing_keys.push(key_id.to_vec());
                    continue;
                }
            };
            let keys = keys::expand_app_state_keys(&key_data);

            // Decode mutations to get their index_mac and value_mac before validating patch
            let mut patch_mutations: Vec<Mutation> = Vec::new();
            for mutation in &patch.mutations {
                if let Err(_e) = Self::decode_mutation(&keys, mutation, &mut patch_mutations) {
                    //log::warn!(target: "AppState", "Failed to decode one mutation, skipping: {e:?}");
                }
            }

            // Validate patch MAC if present
            if let Some(patch_mac) = &patch.patch_mac {
                // Calculate expected patch MAC from the mutations
                let mut subtract_macs_data: Vec<Vec<u8>> = Vec::new();
                let mut add_macs_data: Vec<Vec<u8>> = Vec::new();

                for mutation in &patch_mutations {
                    let index_mac_b64 = BASE64_STANDARD.encode(&mutation.index_mac);

                    match mutation.operation {
                        wa::syncd_mutation::SyncdOperation::Remove => {
                            // For REMOVE operations, we need the old value MAC from index_value_map
                            if let Some(old_value_mac) =
                                current_state.index_value_map.get(&index_mac_b64)
                            {
                                subtract_macs_data.push(old_value_mac.clone());
                            } else {
                                return Err(AppStateError::MissingPreviousSetValue(index_mac_b64));
                            }
                        }
                        wa::syncd_mutation::SyncdOperation::Set => {
                            // For SET operations, we use the new value MAC
                            add_macs_data.push(mutation.value_mac.clone());
                        }
                    }
                }

                // Convert to slice references
                let subtract_macs: Vec<&[u8]> =
                    subtract_macs_data.iter().map(|v| v.as_slice()).collect();
                let add_macs: Vec<&[u8]> = add_macs_data.iter().map(|v| v.as_slice()).collect();

                // Calculate expected patch MAC using LT-Hash
                let mut expected_hash = current_state.hash;
                WA_PATCH_INTEGRITY.subtract_then_add_in_place(
                    &mut expected_hash,
                    &subtract_macs,
                    &add_macs,
                );

                // The patch MAC should match the final hash
                if patch_mac.as_slice() != &expected_hash[..patch_mac.len()] {
                    return Err(AppStateError::MismatchingPatchMAC);
                }
            }

            // If patch MAC validation passed, update the hash state and index_value_map
            let mut subtract_macs_data: Vec<Vec<u8>> = Vec::new();
            let mut add_macs_data: Vec<Vec<u8>> = Vec::new();

            for mutation in &patch_mutations {
                let index_mac_b64 = BASE64_STANDARD.encode(&mutation.index_mac);

                match mutation.operation {
                    wa::syncd_mutation::SyncdOperation::Remove => {
                        // Remove from index_value_map and collect for hash subtraction
                        if let Some(old_value_mac) =
                            current_state.index_value_map.remove(&index_mac_b64)
                        {
                            subtract_macs_data.push(old_value_mac);
                        }
                    }
                    wa::syncd_mutation::SyncdOperation::Set => {
                        // Add to index_value_map and collect for hash addition
                        add_macs_data.push(mutation.value_mac.clone());
                        current_state
                            .index_value_map
                            .insert(index_mac_b64, mutation.value_mac.clone());
                    }
                }
            }

            // Convert to slice references for hash update
            let subtract_macs: Vec<&[u8]> =
                subtract_macs_data.iter().map(|v| v.as_slice()).collect();
            let add_macs: Vec<&[u8]> = add_macs_data.iter().map(|v| v.as_slice()).collect();

            // Update the hash state
            WA_PATCH_INTEGRITY.subtract_then_add_in_place(
                &mut current_state.hash,
                &subtract_macs,
                &add_macs,
            );

            // Add mutations to the result
            new_mutations.extend(patch_mutations);
        }

        if !missing_keys.is_empty() {
            return Err(AppStateError::KeysNotFound(missing_keys));
        }

        Ok((new_mutations, current_state))
    }

    /// Decode a single mutation
    /// Platform-independent core logic
    pub fn decode_mutation(
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
