use super::errors::{AppStateError, Result};
use super::hash::HashState;
use super::keys;
use super::lthash::WA_PATCH_INTEGRITY;
use crate::crypto::cbc;
use crate::crypto::hmac_sha512;
use crate::store::traits::AppStateKeyStore;
use base64::Engine as _;
use base64::prelude::*;
use hmac::{Hmac, Mac};
use log;
use prost::Message;
use sha2::Sha256;
use std::sync::Arc;
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

pub struct Processor {
    key_store: Arc<dyn AppStateKeyStore>,
}

fn generate_patch_mac(patch: &wa::SyncdPatch, name: &str, key: &[u8], version: u64) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC can take key of any size");

    if let Some(snapshot_mac) = &patch.snapshot_mac {
        mac.update(snapshot_mac);
    }

    for mutation in &patch.mutations {
        if let Some(record) = &mutation.record
            && let Some(value) = &record.value
            && let Some(blob) = &value.blob
            && blob.len() >= 32
        {
            let value_mac = &blob[blob.len() - 32..];
            mac.update(value_mac);
        }
    }

    mac.update(&version.to_be_bytes());
    mac.update(name.as_bytes());

    mac.finalize().into_bytes().to_vec()
}

impl Processor {
    pub fn new(key_store: Arc<dyn AppStateKeyStore>) -> Self {
        Self { key_store }
    }

    pub async fn decode_patches(
        &self,
        list: &PatchList,
        mut current_state: HashState,
    ) -> Result<(Vec<Mutation>, HashState)> {
        let mut new_mutations: Vec<Mutation> = Vec::new();
        let mut missing_keys: Vec<Vec<u8>> = Vec::new();

        if let Some(snapshot) = &list.snapshot {
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

            let key_data = match self.key_store.get_app_state_sync_key(key_id).await {
                Ok(Some(key)) => key.key_data,
                _ => {
                    missing_keys.push(key_id.to_vec());
                    continue;
                }
            };
            let keys = keys::expand_app_state_keys(&key_data);

            let mut patch_mutations: Vec<Mutation> = Vec::new();
            for mutation in &patch.mutations {
                if let Err(_e) =
                    ProcessorUtils::decode_mutation(&keys, mutation, &mut patch_mutations)
                {
                }
            }

            if let Some(patch_mac_from_server) = &patch.patch_mac {
                let expected_patch_mac =
                    generate_patch_mac(patch, &list.name, &keys.patch_mac, version);
                if patch_mac_from_server.as_slice() != expected_patch_mac {
                    return Err(AppStateError::MismatchingPatchMAC);
                }
            }

            let mut subtract_macs_for_lthash: Vec<Vec<u8>> = Vec::new();
            let mut add_macs_for_lthash: Vec<Vec<u8>> = Vec::new();

            for (i, mutation) in patch_mutations.iter().enumerate() {
                if mutation.operation == wa::syncd_mutation::SyncdOperation::Set {
                    add_macs_for_lthash.push(mutation.value_mac.clone());
                } else if mutation.operation == wa::syncd_mutation::SyncdOperation::Remove {
                    let index_mac_b64 = BASE64_STANDARD.encode(&mutation.index_mac);

                    let mut found_in_patch = false;
                    for j in (0..i).rev() {
                        let prev_mutation = &patch_mutations[j];
                        if prev_mutation.operation == wa::syncd_mutation::SyncdOperation::Set
                            && prev_mutation.index_mac == mutation.index_mac
                        {
                            subtract_macs_for_lthash.push(prev_mutation.value_mac.clone());
                            found_in_patch = true;
                            break;
                        }
                    }

                    if !found_in_patch {
                        if let Some(old_value_mac) =
                            current_state.index_value_map.get(&index_mac_b64)
                        {
                            subtract_macs_for_lthash.push(old_value_mac.clone());
                        } else {
                            log::warn!(
                                "Could not find previous value for REMOVE operation with index MAC {}. This may be a non-fatal inconsistency.",
                                index_mac_b64
                            );
                        }
                    }
                }
            }

            let subtract_macs_refs: Vec<&[u8]> = subtract_macs_for_lthash
                .iter()
                .map(|v| v.as_slice())
                .collect();
            let add_macs_refs: Vec<&[u8]> =
                add_macs_for_lthash.iter().map(|v| v.as_slice()).collect();
            WA_PATCH_INTEGRITY.subtract_then_add_in_place(
                &mut current_state.hash,
                &subtract_macs_refs,
                &add_macs_refs,
            );

            for mutation in &patch_mutations {
                let index_mac_b64 = BASE64_STANDARD.encode(&mutation.index_mac);
                match mutation.operation {
                    wa::syncd_mutation::SyncdOperation::Remove => {
                        current_state.index_value_map.remove(&index_mac_b64);
                    }
                    wa::syncd_mutation::SyncdOperation::Set => {
                        current_state
                            .index_value_map
                            .insert(index_mac_b64, mutation.value_mac.clone());
                    }
                }
            }

            new_mutations.extend(patch_mutations);
        }

        if !missing_keys.is_empty() {
            return Err(AppStateError::KeysNotFound(missing_keys));
        }

        Ok((new_mutations, current_state))
    }
}

pub struct ProcessorUtils;

impl ProcessorUtils {
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
