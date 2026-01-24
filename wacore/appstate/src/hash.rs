use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::collections::HashMap;
use wacore_libsignal::crypto::CryptographicMac;
use waproto::whatsapp as wa;

use crate::{AppStateError, WAPATCH_INTEGRITY};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashState {
    pub version: u64,
    #[serde(with = "BigArray")]
    pub hash: [u8; 128],
    pub index_value_map: HashMap<String, Vec<u8>>,
}

impl Default for HashState {
    fn default() -> Self {
        Self {
            version: 0,
            hash: [0; 128],
            index_value_map: HashMap::new(),
        }
    }
}

/// Result of updating the hash state with mutations.
#[derive(Debug, Clone, Default)]
pub struct HashUpdateResult {
    /// Whether a REMOVE mutation was missing its previous value.
    /// This happens when the server has an entry we don't have locally.
    /// WhatsApp Web tracks this as `hasMissingRemove` and uses it to
    /// determine if MAC validation failures should be fatal.
    pub has_missing_remove: bool,
}

impl HashState {
    pub fn update_hash<F>(
        &mut self,
        mutations: &[wa::SyncdMutation],
        mut get_prev_set_value_mac: F,
    ) -> (HashUpdateResult, anyhow::Result<()>)
    where
        F: FnMut(&[u8], usize) -> anyhow::Result<Option<Vec<u8>>>,
    {
        let mut added: Vec<Vec<u8>> = Vec::new();
        let mut removed: Vec<Vec<u8>> = Vec::new();
        let mut result = HashUpdateResult::default();

        for (i, mutation) in mutations.iter().enumerate() {
            let op = mutation.operation.unwrap_or_default();
            if op == wa::syncd_mutation::SyncdOperation::Set as i32
                && let Some(record) = &mutation.record
                && let Some(value) = &record.value
                && let Some(blob) = &value.blob
                && blob.len() >= 32
            {
                added.push(blob[blob.len() - 32..].to_vec());
            }
            let index_mac_opt = mutation
                .record
                .as_ref()
                .and_then(|r| r.index.as_ref())
                .and_then(|idx| idx.blob.as_ref());
            if let Some(index_mac) = index_mac_opt {
                match get_prev_set_value_mac(index_mac, i) {
                    Ok(Some(prev)) => removed.push(prev),
                    Ok(None) => {
                        if op == wa::syncd_mutation::SyncdOperation::Remove as i32 {
                            result.has_missing_remove = true;
                            log::trace!(
                                target: "AppState",
                                "REMOVE mutation missing previous value (hasMissingRemove=true)"
                            );
                        }
                    }
                    Err(e) => return (result, Err(anyhow::anyhow!(e))),
                }
            }
        }

        WAPATCH_INTEGRITY.subtract_then_add_in_place(&mut self.hash, &removed, &added);
        (result, Ok(()))
    }

    /// Update hash state from snapshot records directly (avoids cloning into SyncdMutation).
    ///
    /// This is an optimized version for snapshots where all operations are SET
    /// and there are no previous values to look up.
    pub fn update_hash_from_records(&mut self, records: &[wa::SyncdRecord]) {
        let added: Vec<Vec<u8>> = records
            .iter()
            .filter_map(|record| {
                record
                    .value
                    .as_ref()
                    .and_then(|v| v.blob.as_ref())
                    .filter(|blob| blob.len() >= 32)
                    .map(|blob| blob[blob.len() - 32..].to_vec())
            })
            .collect();

        WAPATCH_INTEGRITY.subtract_then_add_in_place(&mut self.hash, &[], &added);
    }

    pub fn generate_snapshot_mac(&self, name: &str, key: &[u8]) -> Vec<u8> {
        let version_be = u64_to_be(self.version);
        let mut mac =
            CryptographicMac::new("HmacSha256", key).expect("HmacSha256 is a valid algorithm");
        mac.update(&self.hash);
        mac.update(&version_be);
        mac.update(name.as_bytes());
        mac.finalize()
    }
}

pub fn generate_patch_mac(patch: &wa::SyncdPatch, name: &str, key: &[u8], version: u64) -> Vec<u8> {
    let mut parts: Vec<Vec<u8>> = Vec::new();
    if let Some(sm) = &patch.snapshot_mac {
        parts.push(sm.clone());
    }
    for m in &patch.mutations {
        if let Some(record) = &m.record
            && let Some(val) = &record.value
            && let Some(blob) = &val.blob
            && blob.len() >= 32
        {
            parts.push(blob[blob.len() - 32..].to_vec());
        }
    }
    parts.push(u64_to_be(version).to_vec());
    parts.push(name.as_bytes().to_vec());
    let mut mac =
        CryptographicMac::new("HmacSha256", key).expect("HmacSha256 is a valid algorithm");
    for p in parts.iter() {
        mac.update(p);
    }
    mac.finalize()
}

pub fn generate_content_mac(
    operation: wa::syncd_mutation::SyncdOperation,
    data: &[u8],
    key_id: &[u8],
    key: &[u8],
) -> Vec<u8> {
    let op_byte = [operation as u8 + 1];
    let key_data_length = u64_to_be((key_id.len() + 1) as u64);
    let mac_full = {
        let mut mac =
            CryptographicMac::new("HmacSha512", key).expect("HmacSha512 is a valid algorithm");
        mac.update(&op_byte);
        mac.update(key_id);
        mac.update(data);
        mac.update(&key_data_length);
        mac.finalize()
    };
    mac_full[..32].to_vec()
}

fn u64_to_be(val: u64) -> [u8; 8] {
    val.to_be_bytes()
}

pub fn validate_index_mac(
    index_json_bytes: &[u8],
    expected_mac: &[u8],
    key: &[u8; 32],
) -> Result<(), AppStateError> {
    let computed = {
        let mut mac =
            CryptographicMac::new("HmacSha256", key).expect("HmacSha256 is a valid algorithm");
        mac.update(index_json_bytes);
        mac.finalize()
    };
    if computed.as_slice() != expected_mac {
        Err(AppStateError::MismatchingIndexMAC)
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_mutation(
        operation: wa::syncd_mutation::SyncdOperation,
        index_mac: Vec<u8>,
        value_mac: Option<Vec<u8>>,
    ) -> wa::SyncdMutation {
        let value_blob = value_mac.map(|mac| {
            let mut blob = vec![0u8; 16];
            blob.extend_from_slice(&mac);
            blob
        });

        wa::SyncdMutation {
            operation: Some(operation as i32),
            record: Some(wa::SyncdRecord {
                index: Some(wa::SyncdIndex {
                    blob: Some(index_mac),
                }),
                value: value_blob.map(|b| wa::SyncdValue { blob: Some(b) }),
                key_id: Some(wa::KeyId {
                    id: Some(b"test_key_id".to_vec()),
                }),
            }),
        }
    }

    #[test]
    fn test_update_hash_with_set_overwrite_and_remove() {
        const INDEX_MAC_1: &[u8] = &[1; 32];
        const VALUE_MAC_1: &[u8] = &[10; 32];

        const INDEX_MAC_2: &[u8] = &[2; 32];
        const VALUE_MAC_2: &[u8] = &[20; 32];

        const VALUE_MAC_3_OVERWRITE: &[u8] = &[30; 32];

        let mut prev_macs = HashMap::<Vec<u8>, Vec<u8>>::new();

        let mut state = HashState::default();
        let initial_mutations = vec![
            create_mutation(
                wa::syncd_mutation::SyncdOperation::Set,
                INDEX_MAC_1.to_vec(),
                Some(VALUE_MAC_1.to_vec()),
            ),
            create_mutation(
                wa::syncd_mutation::SyncdOperation::Set,
                INDEX_MAC_2.to_vec(),
                Some(VALUE_MAC_2.to_vec()),
            ),
        ];

        let get_prev_mac_closure = |_: &[u8], _: usize| Ok(None);
        let (hash_result, result) = state.update_hash(&initial_mutations, get_prev_mac_closure);
        assert!(result.is_ok());
        assert!(!hash_result.has_missing_remove);

        let expected_hash_after_add = WAPATCH_INTEGRITY.subtract_then_add(
            &[0; 128],
            &[],
            &[VALUE_MAC_1.to_vec(), VALUE_MAC_2.to_vec()],
        );
        assert_eq!(state.hash.as_slice(), expected_hash_after_add.as_slice());

        prev_macs.insert(INDEX_MAC_1.to_vec(), VALUE_MAC_1.to_vec());
        prev_macs.insert(INDEX_MAC_2.to_vec(), VALUE_MAC_2.to_vec());

        let update_and_remove_mutations = vec![
            create_mutation(
                wa::syncd_mutation::SyncdOperation::Set,
                INDEX_MAC_1.to_vec(),
                Some(VALUE_MAC_3_OVERWRITE.to_vec()),
            ),
            create_mutation(
                wa::syncd_mutation::SyncdOperation::Remove,
                INDEX_MAC_2.to_vec(),
                None,
            ),
        ];

        let get_prev_mac_closure_phase2 =
            |index_mac: &[u8], _: usize| Ok(prev_macs.get(index_mac).cloned());
        let (hash_result, result) =
            state.update_hash(&update_and_remove_mutations, get_prev_mac_closure_phase2);
        assert!(result.is_ok());
        assert!(!hash_result.has_missing_remove);

        let expected_final_hash = WAPATCH_INTEGRITY.subtract_then_add(
            &expected_hash_after_add,
            &[VALUE_MAC_1.to_vec(), VALUE_MAC_2.to_vec()],
            &[VALUE_MAC_3_OVERWRITE.to_vec()],
        );

        assert_eq!(
            state.hash.as_slice(),
            expected_final_hash.as_slice(),
            "The final hash state after overwrite and remove is incorrect."
        );
    }
}
