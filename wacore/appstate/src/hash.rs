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
        let mut added: Vec<Vec<u8>> = Vec::with_capacity(mutations.len());
        let mut removed: Vec<Vec<u8>> = Vec::with_capacity(mutations.len());
        let mut result = HashUpdateResult::default();

        for (i, mutation) in mutations.iter().enumerate() {
            let op = mutation.operation.unwrap_or_default();
            if op == wa::syncd_mutation::SyncdOperation::SET
                && mutation.record.is_set()
                && let Some(blob) = &mutation.record.value.blob
                && blob.len() >= 32
            {
                added.push(blob[blob.len() - 32..].to_vec());
            }
            let index_mac_opt = mutation.record.index.blob.as_ref();
            if let Some(index_mac) = index_mac_opt {
                match get_prev_set_value_mac(index_mac, i) {
                    Ok(Some(prev)) => removed.push(prev),
                    Ok(None) => {
                        if op == wa::syncd_mutation::SyncdOperation::REMOVE {
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
        // Collect slices directly — no Vec<u8> allocation per MAC.
        let added: Vec<&[u8]> = records
            .iter()
            .filter_map(|record| {
                record
                    .value
                    .blob
                    .as_ref()
                    .filter(|blob| blob.len() >= 32)
                    .map(|blob| &blob[blob.len() - 32..])
            })
            .collect();

        WAPATCH_INTEGRITY.subtract_then_add_in_place(&mut self.hash, &[] as &[&[u8]], &added);
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
    let mut mac =
        CryptographicMac::new("HmacSha256", key).expect("HmacSha256 is a valid algorithm");

    // Feed directly to HMAC without collecting into Vec<Vec<u8>>
    if let Some(sm) = &patch.snapshot_mac {
        mac.update(sm);
    }
    for m in &patch.mutations {
        if m.record.is_set()
            && let Some(blob) = &m.record.value.blob
            && blob.len() >= 32
        {
            mac.update(&blob[blob.len() - 32..]);
        }
    }
    mac.update(&u64_to_be(version));
    mac.update(name.as_bytes());

    mac.finalize()
}

pub fn generate_content_mac(
    operation: wa::syncd_mutation::SyncdOperation,
    data: &[u8],
    key_id: &[u8],
    key: &[u8],
) -> [u8; 32] {
    let op_byte = [operation as u8 + 1];
    let key_data_length = u64_to_be((key_id.len() + 1) as u64);
    let mut mac =
        CryptographicMac::new("HmacSha512", key).expect("HmacSha512 is a valid algorithm");
    mac.update(&op_byte);
    mac.update(key_id);
    mac.update(data);
    mac.update(&key_data_length);
    let mut out = [0u8; 64];
    mac.finalize_into(&mut out)
        .expect("64 bytes is enough for HmacSha512");
    let mut result = [0u8; 32];
    result.copy_from_slice(&out[..32]);
    result
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

        let value = if let Some(b) = value_blob {
            buffa::MessageField::some(wa::SyncdValue {
                blob: Some(b),
                ..Default::default()
            })
        } else {
            buffa::MessageField::none()
        };

        wa::SyncdMutation {
            operation: Some(operation),
            record: buffa::MessageField::some(wa::SyncdRecord {
                index: buffa::MessageField::some(wa::SyncdIndex {
                    blob: Some(index_mac),
                    ..Default::default()
                }),
                value,
                key_id: buffa::MessageField::some(wa::KeyId {
                    id: Some(b"test_key_id".to_vec()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
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
                wa::syncd_mutation::SyncdOperation::SET,
                INDEX_MAC_1.to_vec(),
                Some(VALUE_MAC_1.to_vec()),
            ),
            create_mutation(
                wa::syncd_mutation::SyncdOperation::SET,
                INDEX_MAC_2.to_vec(),
                Some(VALUE_MAC_2.to_vec()),
            ),
        ];

        let get_prev_mac_closure = |_: &[u8], _: usize| Ok(None);
        let (hash_result, result) = state.update_hash(&initial_mutations, get_prev_mac_closure);
        assert!(result.is_ok());
        assert!(!hash_result.has_missing_remove);

        const EMPTY: &[Vec<u8>] = &[];
        let expected_hash_after_add = WAPATCH_INTEGRITY.subtract_then_add(
            &[0; 128],
            EMPTY,
            &[VALUE_MAC_1.to_vec(), VALUE_MAC_2.to_vec()],
        );
        assert_eq!(state.hash.as_slice(), expected_hash_after_add.as_slice());

        prev_macs.insert(INDEX_MAC_1.to_vec(), VALUE_MAC_1.to_vec());
        prev_macs.insert(INDEX_MAC_2.to_vec(), VALUE_MAC_2.to_vec());

        let update_and_remove_mutations = vec![
            create_mutation(
                wa::syncd_mutation::SyncdOperation::SET,
                INDEX_MAC_1.to_vec(),
                Some(VALUE_MAC_3_OVERWRITE.to_vec()),
            ),
            create_mutation(
                wa::syncd_mutation::SyncdOperation::REMOVE,
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

    /// Known-answer test for generate_patch_mac to guard byte ordering and input
    /// concatenation.  The expected MAC was computed by feeding:
    ///   snapshot_mac ‖ mutation1_tail(32) ‖ mutation2_tail(32)
    ///   ‖ u64_to_be(42) ‖ b"regular_high"
    /// into HMAC-SHA256 with key = [0xAA; 32].
    #[test]
    fn test_generate_patch_mac_known_answer() {
        let key = [0xAAu8; 32];
        let name = "regular_high";
        let version: u64 = 42;

        // Build a patch with snapshot_mac and two mutations with >=32 byte blobs.
        let snapshot_mac = vec![0x11u8; 32];
        let mut blob1 = vec![0u8; 16]; // 16 prefix bytes
        blob1.extend_from_slice(&[0x22u8; 32]); // 32-byte tail taken by generate_patch_mac
        let mut blob2 = vec![0u8; 16];
        blob2.extend_from_slice(&[0x33u8; 32]);

        let patch = wa::SyncdPatch {
            version: buffa::MessageField::some(wa::SyncdVersion {
                version: Some(version),
                ..Default::default()
            }),
            snapshot_mac: Some(snapshot_mac.clone()),
            mutations: vec![
                wa::SyncdMutation {
                    operation: Some(wa::syncd_mutation::SyncdOperation::SET),
                    record: buffa::MessageField::some(wa::SyncdRecord {
                        value: buffa::MessageField::some(wa::SyncdValue {
                            blob: Some(blob1),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                wa::SyncdMutation {
                    operation: Some(wa::syncd_mutation::SyncdOperation::SET),
                    record: buffa::MessageField::some(wa::SyncdRecord {
                        value: buffa::MessageField::some(wa::SyncdValue {
                            blob: Some(blob2),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };

        // Compute expected MAC manually using the same HMAC-SHA256 inputs.
        let mut expected_mac =
            CryptographicMac::new("HmacSha256", &key).expect("HmacSha256 is a valid algorithm");
        expected_mac.update(&snapshot_mac); // snapshot_mac
        expected_mac.update(&[0x22u8; 32]); // mutation 1 tail
        expected_mac.update(&[0x33u8; 32]); // mutation 2 tail
        expected_mac.update(&42u64.to_be_bytes()); // version
        expected_mac.update(b"regular_high"); // name
        let expected = expected_mac.finalize();

        let actual = generate_patch_mac(&patch, name, &key, version);
        assert_eq!(
            actual, expected,
            "generate_patch_mac output must match manual HMAC-SHA256 computation"
        );
    }
}
