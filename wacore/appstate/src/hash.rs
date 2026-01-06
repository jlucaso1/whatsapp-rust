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
    /// Flag indicating the collection is in MAC mismatch state.
    /// When true, MAC validation is skipped for this collection.
    /// This matches WhatsApp Web's `isCollectionInMacMismatchFatal` behavior.
    #[serde(default)]
    pub mac_mismatch_fatal: bool,
}

impl Default for HashState {
    fn default() -> Self {
        Self {
            version: 0,
            hash: [0; 128],
            index_value_map: HashMap::new(),
            mac_mismatch_fatal: false,
        }
    }
}

impl HashState {
    pub fn update_hash<F>(
        &mut self,
        mutations: &[wa::SyncdMutation],
        mut get_prev_set_value_mac: F,
    ) -> (Vec<anyhow::Error>, anyhow::Result<()>)
    where
        F: FnMut(&[u8], usize) -> anyhow::Result<Option<Vec<u8>>>,
    {
        let mut added: Vec<Vec<u8>> = Vec::new();
        let mut removed: Vec<Vec<u8>> = Vec::new();
        let mut warnings: Vec<anyhow::Error> = Vec::new();

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
                            warnings.push(anyhow::anyhow!(
                                AppStateError::MissingPreviousSetValueOperation
                            ));
                        }
                    }
                    Err(e) => return (warnings, Err(anyhow::anyhow!(e))),
                }
            }
        }

        log::debug!(
            target: "Client/AppState",
            "update_hash: mutations={} added={} removed={} version={}",
            mutations.len(),
            added.len(),
            removed.len(),
            self.version
        );
        WAPATCH_INTEGRITY.subtract_then_add_in_place(&mut self.hash, &removed, &added);
        (warnings, Ok(()))
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
        let (warnings, result) = state.update_hash(&initial_mutations, get_prev_mac_closure);
        assert!(result.is_ok());
        assert!(warnings.is_empty());

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
        let (warnings, result) =
            state.update_hash(&update_and_remove_mutations, get_prev_mac_closure_phase2);
        assert!(result.is_ok());
        assert!(warnings.is_empty());

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

    /// Test content MAC generation against known good values from whatsmeow.
    /// These values were verified by running identical Go code.
    #[test]
    fn test_content_mac_matches_whatsmeow() {
        use crate::keys::expand_app_state_keys;

        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id";

        // Test data: 48 bytes (simulated IV + ciphertext)
        let test_data: Vec<u8> = (0..48).collect();

        // Test SET operation
        let content_mac = generate_content_mac(
            wa::syncd_mutation::SyncdOperation::Set,
            &test_data,
            key_id,
            &keys.value_mac,
        );

        // Expected value verified against whatsmeow Go implementation
        assert_eq!(
            hex::encode(&content_mac),
            "e5560be868de386d31bd936717b9b92eb1866256173d07ac0f718a5615bce43b",
            "Content MAC for SET operation mismatch"
        );

        // Test REMOVE operation
        let content_mac_remove = generate_content_mac(
            wa::syncd_mutation::SyncdOperation::Remove,
            &test_data,
            key_id,
            &keys.value_mac,
        );

        // REMOVE should produce different MAC (operation byte is different)
        assert_ne!(
            hex::encode(&content_mac),
            hex::encode(&content_mac_remove),
            "SET and REMOVE should produce different MACs"
        );
    }

    /// Test snapshot MAC generation against known good values from whatsmeow.
    #[test]
    fn test_snapshot_mac_matches_whatsmeow() {
        use crate::keys::expand_app_state_keys;

        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);

        // Create a hash state with known values
        let mut state = HashState::default();
        for i in 0..128 {
            state.hash[i] = (i % 256) as u8;
        }
        state.version = 28;

        let snapshot_mac = state.generate_snapshot_mac("regular_low", &keys.snapshot_mac);

        // Expected value verified against whatsmeow Go implementation
        assert_eq!(
            hex::encode(&snapshot_mac),
            "ab7a404c7e0a07d1d196c5a9c3750c7e69f918e2cd3005206e6e8032a6fe57ba",
            "Snapshot MAC mismatch"
        );
    }

    /// Test patch MAC generation against known good values from whatsmeow.
    #[test]
    fn test_patch_mac_matches_whatsmeow() {
        use crate::keys::expand_app_state_keys;

        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);

        // Use the same snapshot MAC as in the previous test
        let snapshot_mac =
            hex::decode("ab7a404c7e0a07d1d196c5a9c3750c7e69f918e2cd3005206e6e8032a6fe57ba")
                .unwrap();

        // Use the content MAC from the content MAC test
        let value_mac =
            hex::decode("e5560be868de386d31bd936717b9b92eb1866256173d07ac0f718a5615bce43b")
                .unwrap();

        let patch_mac = generate_patch_mac_for_push(
            &snapshot_mac,
            &[value_mac],
            29,
            "regular_low",
            &keys.patch_mac,
        );

        // Expected value verified against whatsmeow Go implementation
        assert_eq!(
            hex::encode(&patch_mac),
            "d5330dc191d518a89eb7394a004464878e852023859f4c13d74b1863774cb9f6",
            "Patch MAC mismatch"
        );
    }

    /// Generate patch MAC for push operations (helper for testing).
    /// This matches whatsmeow's generatePatchMAC function.
    fn generate_patch_mac_for_push(
        snapshot_mac: &[u8],
        value_macs: &[Vec<u8>],
        version: u64,
        name: &str,
        key: &[u8],
    ) -> Vec<u8> {
        let mut mac =
            CryptographicMac::new("HmacSha256", key).expect("HmacSha256 is a valid algorithm");
        mac.update(snapshot_mac);
        for vm in value_macs {
            mac.update(vm);
        }
        mac.update(&u64_to_be(version));
        mac.update(name.as_bytes());
        mac.finalize()
    }
}
