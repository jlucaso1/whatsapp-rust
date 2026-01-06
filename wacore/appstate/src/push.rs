//! Patch building for app state sync action pushing.
//!
//! This module provides functionality to build SyncdPatch protos for
//! pushing mutations to WhatsApp servers.

use crate::encode::EncryptedMutation;
use crate::hash::HashState;
use crate::keys::ExpandedAppStateKeys;
use crate::lthash::WAPATCH_INTEGRITY;
use wacore_libsignal::crypto::CryptographicMac;
use waproto::whatsapp as wa;

/// Build a SyncdPatch for pushing mutations.
///
/// This function takes encrypted mutations and builds a complete patch proto
/// with proper version, MACs, and snapshot MAC.
///
/// # Arguments
/// * `mutations` - The encrypted mutations to include
/// * `key_id` - The key ID bytes
/// * `keys` - The expanded app state keys
/// * `current_state` - The current hash state (version + LT hash)
/// * `collection_name` - The collection name (e.g., "regular")
///
/// # Returns
/// A tuple of (SyncdPatch, new_hash_state) where new_hash_state is the updated
/// hash state after applying the mutations.
pub fn build_patch(
    mutations: &[EncryptedMutation],
    key_id: &[u8],
    keys: &ExpandedAppStateKeys,
    current_state: &HashState,
    collection_name: &str,
) -> (wa::SyncdPatch, HashState) {
    let new_version = current_state.version + 1;

    // Collect value MACs to add
    let value_macs: Vec<Vec<u8>> = mutations.iter().map(|m| m.value_mac.clone()).collect();

    // Look up previous value MACs to remove (for index replacements)
    let mut removed_macs: Vec<Vec<u8>> = Vec::new();
    for mutation in mutations {
        // Convert index_mac to hex string for lookup
        let index_mac_hex = hex::encode(&mutation.index_mac);
        if let Some(prev_mac) = current_state.index_value_map.get(&index_mac_hex) {
            removed_macs.push(prev_mac.clone());
        }
    }

    // Update LTHash: subtract old MACs, add new MACs
    let mut new_hash = current_state.hash;
    WAPATCH_INTEGRITY.subtract_then_add_in_place(&mut new_hash, &removed_macs, &value_macs);

    // Build SyncdMutation protos
    let syncd_mutations: Vec<wa::SyncdMutation> = mutations
        .iter()
        .map(|m| wa::SyncdMutation {
            operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
            record: Some(wa::SyncdRecord {
                index: Some(wa::SyncdIndex {
                    blob: Some(m.index_mac.clone()),
                }),
                value: Some(wa::SyncdValue {
                    blob: Some(m.value_blob.clone()),
                }),
                key_id: Some(wa::KeyId {
                    id: Some(key_id.to_vec()),
                }),
            }),
        })
        .collect();

    // Create new state with updated index_value_map
    let mut new_index_value_map = current_state.index_value_map.clone();
    for mutation in mutations {
        let index_mac_hex = hex::encode(&mutation.index_mac);
        new_index_value_map.insert(index_mac_hex, mutation.value_mac.clone());
    }

    let new_state = HashState {
        version: new_version,
        hash: new_hash,
        index_value_map: new_index_value_map,
        mac_mismatch_fatal: false, // Fresh state from push
    };

    // Generate snapshot MAC (hash of current state + version + collection name)
    let snapshot_mac = new_state.generate_snapshot_mac(collection_name, &keys.snapshot_mac);

    // Generate patch MAC
    let patch_mac = generate_push_patch_mac(
        &snapshot_mac,
        &value_macs,
        new_version,
        collection_name,
        &keys.patch_mac,
    );

    // Note: whatsmeow does NOT include the version field in the patch proto
    // The version is only used for MAC computation, not sent in the patch itself
    let patch = wa::SyncdPatch {
        version: None,
        mutations: syncd_mutations,
        external_mutations: None,
        snapshot_mac: Some(snapshot_mac),
        patch_mac: Some(patch_mac),
        key_id: Some(wa::KeyId {
            id: Some(key_id.to_vec()),
        }),
        exit_code: None,
        device_index: None,
        client_debug_data: None,
    };

    (patch, new_state)
}

/// Generate the patch MAC for a push operation.
fn generate_push_patch_mac(
    snapshot_mac: &[u8],
    value_macs: &[Vec<u8>],
    version: u64,
    collection_name: &str,
    key: &[u8],
) -> Vec<u8> {
    let mut mac =
        CryptographicMac::new("HmacSha256", key).expect("HmacSha256 is a valid algorithm");

    // Include snapshot MAC
    mac.update(snapshot_mac);

    // Include all value MACs
    for value_mac in value_macs {
        mac.update(value_mac);
    }

    // Include version and collection name
    mac.update(&version.to_be_bytes());
    mac.update(collection_name.as_bytes());

    mac.finalize()
}

/// Build a SyncdPatch with REMOVE operations for the given mutations.
///
/// This is used when removing entries (e.g., un-starring a message).
pub fn build_remove_patch(
    mutations: &[EncryptedMutation],
    old_value_macs: &[Vec<u8>],
    key_id: &[u8],
    keys: &ExpandedAppStateKeys,
    current_state: &HashState,
    collection_name: &str,
) -> (wa::SyncdPatch, HashState) {
    let new_version = current_state.version + 1;

    // For REMOVE operations, we need to:
    // 1. Subtract the old value MACs from LTHash
    // 2. Add the new value MACs (for the REMOVE mutation itself)
    let mut new_hash = current_state.hash;
    let new_value_macs: Vec<Vec<u8>> = mutations.iter().map(|m| m.value_mac.clone()).collect();
    WAPATCH_INTEGRITY.subtract_then_add_in_place(&mut new_hash, old_value_macs, &new_value_macs);

    // Build SyncdMutation protos with REMOVE operation
    let syncd_mutations: Vec<wa::SyncdMutation> = mutations
        .iter()
        .map(|m| wa::SyncdMutation {
            operation: Some(wa::syncd_mutation::SyncdOperation::Remove as i32),
            record: Some(wa::SyncdRecord {
                index: Some(wa::SyncdIndex {
                    blob: Some(m.index_mac.clone()),
                }),
                value: Some(wa::SyncdValue {
                    blob: Some(m.value_blob.clone()),
                }),
                key_id: Some(wa::KeyId {
                    id: Some(key_id.to_vec()),
                }),
            }),
        })
        .collect();

    // Create new state with removed entries pruned from index_value_map
    let mut new_index_value_map = current_state.index_value_map.clone();
    for mutation in mutations {
        let index_mac_hex = hex::encode(&mutation.index_mac);
        new_index_value_map.remove(&index_mac_hex);
    }

    let new_state = HashState {
        version: new_version,
        hash: new_hash,
        index_value_map: new_index_value_map,
        mac_mismatch_fatal: current_state.mac_mismatch_fatal, // Preserve state from current
    };

    let snapshot_mac = new_state.generate_snapshot_mac(collection_name, &keys.snapshot_mac);

    let patch_mac = generate_push_patch_mac(
        &snapshot_mac,
        &new_value_macs,
        new_version,
        collection_name,
        &keys.patch_mac,
    );

    // Note: whatsmeow does NOT include the version field in the patch proto
    // The version is only used for MAC computation, not sent in the patch itself
    let patch = wa::SyncdPatch {
        version: None,
        mutations: syncd_mutations,
        external_mutations: None,
        snapshot_mac: Some(snapshot_mac),
        patch_mac: Some(patch_mac),
        key_id: Some(wa::KeyId {
            id: Some(key_id.to_vec()),
        }),
        exit_code: None,
        device_index: None,
        client_debug_data: None,
    };

    (patch, new_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::encrypt_mutation;
    use crate::keys::expand_app_state_keys;

    #[test]
    fn test_build_patch_single_mutation() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();

        let index = vec!["star".to_string(), "chat@s.whatsapp.net".to_string()];
        let value = wa::SyncActionValue {
            timestamp: Some(1234567890),
            star_action: Some(wa::sync_action_value::StarAction {
                starred: Some(true),
            }),
            ..Default::default()
        };

        let encrypted = encrypt_mutation(
            &index,
            &value,
            &keys,
            &key_id,
            wa::syncd_mutation::SyncdOperation::Set,
            2, // star action uses version 2
        )
        .expect("encryption should succeed");

        let current_state = HashState::default();
        let (patch, new_state) =
            build_patch(&[encrypted], &key_id, &keys, &current_state, "regular");

        // Verify patch structure
        // Note: version is NOT included in the patch proto (only used for MAC computation)
        assert!(patch.version.is_none());
        assert_eq!(patch.mutations.len(), 1);
        assert!(patch.snapshot_mac.is_some());
        assert!(patch.patch_mac.is_some());
        assert!(patch.key_id.is_some());

        // Verify state was updated
        assert_eq!(new_state.version, 1);
        assert_ne!(new_state.hash, current_state.hash);
    }

    #[test]
    fn test_build_patch_multiple_mutations() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();

        let mutations: Vec<EncryptedMutation> = (0..3)
            .map(|i| {
                let index = vec!["star".to_string(), format!("chat{}@s.whatsapp.net", i)];
                let value = wa::SyncActionValue {
                    timestamp: Some(1234567890 + i),
                    star_action: Some(wa::sync_action_value::StarAction {
                        starred: Some(true),
                    }),
                    ..Default::default()
                };
                encrypt_mutation(
                    &index,
                    &value,
                    &keys,
                    &key_id,
                    wa::syncd_mutation::SyncdOperation::Set,
                    2, // star action uses version 2
                )
                .expect("encryption should succeed")
            })
            .collect();

        let current_state = HashState::default();
        let (patch, new_state) = build_patch(&mutations, &key_id, &keys, &current_state, "regular");

        assert_eq!(patch.mutations.len(), 3);
        assert_eq!(new_state.version, 1);
    }

    /// Test that a built patch has valid MACs that would pass verification.
    /// This ensures our patch building produces correct snapshot and patch MACs.
    #[test]
    fn test_build_patch_mac_validity() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();

        let index = vec!["pin_v1".to_string(), "test@s.whatsapp.net".to_string()];
        let value = wa::SyncActionValue {
            timestamp: Some(1234567890),
            pin_action: Some(wa::sync_action_value::PinAction { pinned: Some(true) }),
            ..Default::default()
        };

        let encrypted = encrypt_mutation(
            &index,
            &value,
            &keys,
            &key_id,
            wa::syncd_mutation::SyncdOperation::Set,
            5, // pin action version
        )
        .expect("encryption should succeed");

        let current_state = HashState::default();
        let (patch, new_state) = build_patch(
            std::slice::from_ref(&encrypted),
            &key_id,
            &keys,
            &current_state,
            "regular",
        );

        // Verify snapshot MAC is correct
        let computed_snapshot_mac = new_state.generate_snapshot_mac("regular", &keys.snapshot_mac);
        assert_eq!(
            patch.snapshot_mac.as_ref().unwrap(),
            &computed_snapshot_mac,
            "Built patch should have correct snapshot MAC"
        );

        // Verify patch MAC is correct using the same computation as generate_push_patch_mac
        let value_macs = vec![encrypted.value_mac.clone()];
        let mut mac =
            wacore_libsignal::crypto::CryptographicMac::new("HmacSha256", &keys.patch_mac)
                .expect("valid algorithm");
        mac.update(&computed_snapshot_mac);
        for vm in &value_macs {
            mac.update(vm);
        }
        mac.update(&new_state.version.to_be_bytes());
        mac.update("regular".as_bytes());
        let computed_patch_mac = mac.finalize();

        assert_eq!(
            patch.patch_mac.as_ref().unwrap(),
            &computed_patch_mac,
            "Built patch should have correct patch MAC"
        );
    }

    /// Test that hash state is correctly updated after building a patch
    /// with an existing entry (overwrite scenario).
    #[test]
    fn test_build_patch_overwrite_hash_update() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();

        // Create initial mutation
        let index = vec!["star".to_string(), "test@s.whatsapp.net".to_string()];
        let initial_value = wa::SyncActionValue {
            timestamp: Some(1000),
            star_action: Some(wa::sync_action_value::StarAction {
                starred: Some(true),
            }),
            ..Default::default()
        };

        let initial_encrypted = encrypt_mutation(
            &index,
            &initial_value,
            &keys,
            &key_id,
            wa::syncd_mutation::SyncdOperation::Set,
            2,
        )
        .expect("encryption should succeed");

        // Build initial patch
        let initial_state = HashState::default();
        let (_patch1, state_after_first) = build_patch(
            std::slice::from_ref(&initial_encrypted),
            &key_id,
            &keys,
            &initial_state,
            "regular",
        );

        // Verify index_value_map was populated
        let index_mac_hex = hex::encode(&initial_encrypted.index_mac);
        assert!(
            state_after_first
                .index_value_map
                .contains_key(&index_mac_hex),
            "index_value_map should contain the new entry"
        );

        // Now create an overwrite mutation (same index, new value)
        let new_value = wa::SyncActionValue {
            timestamp: Some(2000),
            star_action: Some(wa::sync_action_value::StarAction {
                starred: Some(false),
            }),
            ..Default::default()
        };

        let new_encrypted = encrypt_mutation(
            &index,
            &new_value,
            &keys,
            &key_id,
            wa::syncd_mutation::SyncdOperation::Set,
            2,
        )
        .expect("encryption should succeed");

        // Build second patch (overwrite)
        let (_patch2, state_after_second) = build_patch(
            std::slice::from_ref(&new_encrypted),
            &key_id,
            &keys,
            &state_after_first,
            "regular",
        );

        // Verify version incremented
        assert_eq!(state_after_second.version, 2);

        // Verify hash was correctly updated (old value subtracted, new value added)
        let expected_hash = WAPATCH_INTEGRITY.subtract_then_add(
            &state_after_first.hash,
            std::slice::from_ref(&initial_encrypted.value_mac),
            std::slice::from_ref(&new_encrypted.value_mac),
        );

        assert_eq!(
            state_after_second.hash.as_slice(),
            expected_hash.as_slice(),
            "Hash should be updated correctly for overwrite"
        );

        // Verify index_value_map was updated
        assert_eq!(
            state_after_second.index_value_map.get(&index_mac_hex),
            Some(&new_encrypted.value_mac),
            "index_value_map should be updated with new value MAC"
        );
    }

    /// Test build_remove_patch creates correct REMOVE operations.
    #[test]
    fn test_build_remove_patch() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();

        // First create and "apply" a SET mutation
        let index = vec!["star".to_string(), "test@s.whatsapp.net".to_string()];
        let value = wa::SyncActionValue {
            timestamp: Some(1000),
            star_action: Some(wa::sync_action_value::StarAction {
                starred: Some(true),
            }),
            ..Default::default()
        };

        let initial_encrypted = encrypt_mutation(
            &index,
            &value,
            &keys,
            &key_id,
            wa::syncd_mutation::SyncdOperation::Set,
            2,
        )
        .expect("encryption should succeed");

        let initial_state = HashState::default();
        let (_patch1, state_after_set) = build_patch(
            std::slice::from_ref(&initial_encrypted),
            &key_id,
            &keys,
            &initial_state,
            "regular",
        );

        // Now create a REMOVE mutation for the same entry
        let remove_encrypted = encrypt_mutation(
            &index,
            &wa::SyncActionValue {
                timestamp: Some(2000),
                star_action: Some(wa::sync_action_value::StarAction {
                    starred: Some(false),
                }),
                ..Default::default()
            },
            &keys,
            &key_id,
            wa::syncd_mutation::SyncdOperation::Remove,
            2,
        )
        .expect("encryption should succeed");

        // Build REMOVE patch
        let (remove_patch, state_after_remove) = build_remove_patch(
            std::slice::from_ref(&remove_encrypted),
            std::slice::from_ref(&initial_encrypted.value_mac),
            &key_id,
            &keys,
            &state_after_set,
            "regular",
        );

        // Verify patch structure
        assert_eq!(remove_patch.mutations.len(), 1);
        assert_eq!(
            remove_patch.mutations[0].operation,
            Some(wa::syncd_mutation::SyncdOperation::Remove as i32)
        );

        // Verify version incremented
        assert_eq!(state_after_remove.version, 2);

        // Verify hash was correctly updated (old value subtracted, new remove value added)
        let expected_hash = WAPATCH_INTEGRITY.subtract_then_add(
            &state_after_set.hash,
            &[initial_encrypted.value_mac],
            &[remove_encrypted.value_mac],
        );

        assert_eq!(
            state_after_remove.hash.as_slice(),
            expected_hash.as_slice(),
            "Hash should be updated correctly for REMOVE"
        );

        // Verify index_value_map had entry removed
        let index_mac_hex = hex::encode(&remove_encrypted.index_mac);
        assert!(
            !state_after_remove
                .index_value_map
                .contains_key(&index_mac_hex),
            "index_value_map should have entry removed"
        );
    }
}
