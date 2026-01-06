//! Pure, synchronous patch and snapshot processing logic for app state.
//!
//! This module provides runtime-agnostic processing of app state patches and snapshots.
//! All functions are synchronous and take callbacks for key lookup, making them
//! suitable for use in both async and sync contexts.

use crate::AppStateError;
use crate::decode::{Mutation, decode_record};
use crate::hash::{HashState, generate_patch_mac};
use crate::keys::ExpandedAppStateKeys;
use serde::{Deserialize, Serialize};
use waproto::whatsapp as wa;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppStateMutationMAC {
    pub index_mac: Vec<u8>,
    pub value_mac: Vec<u8>,
}

/// Result of processing a snapshot.
#[derive(Debug, Clone)]
pub struct ProcessedSnapshot {
    /// The updated hash state after processing.
    pub state: HashState,
    /// The decoded mutations from the snapshot.
    pub mutations: Vec<Mutation>,
    /// The mutation MACs to store (for later patch processing).
    pub mutation_macs: Vec<AppStateMutationMAC>,
}

/// Result of processing a single patch.
#[derive(Debug, Clone)]
pub struct PatchProcessingResult {
    /// The updated hash state after processing.
    pub state: HashState,
    /// The decoded mutations from the patch.
    pub mutations: Vec<Mutation>,
    /// The mutation MACs that were added.
    pub added_macs: Vec<AppStateMutationMAC>,
    /// The index MACs that were removed.
    pub removed_index_macs: Vec<Vec<u8>>,
}

/// Process a snapshot and decode all its records.
///
/// This is a pure, synchronous function that processes a snapshot without
/// any async operations. Key lookup is done via a callback.
///
/// # Arguments
/// * `snapshot` - The snapshot to process
/// * `initial_state` - The initial hash state (will be mutated in place)
/// * `get_keys` - Callback to get expanded keys for a key ID
/// * `validate_macs` - Whether to validate MACs during processing
/// * `collection_name` - The collection name (for MAC validation)
///
/// # Returns
/// A `ProcessedSnapshot` containing the new state and decoded mutations.
pub fn process_snapshot<F>(
    snapshot: &wa::SyncdSnapshot,
    initial_state: &mut HashState,
    mut get_keys: F,
    validate_macs: bool,
    collection_name: &str,
) -> Result<ProcessedSnapshot, AppStateError>
where
    F: FnMut(&[u8]) -> Result<ExpandedAppStateKeys, AppStateError>,
{
    let version = snapshot
        .version
        .as_ref()
        .and_then(|v| v.version)
        .unwrap_or(0);
    initial_state.version = version;
    // Reset mac_mismatch_fatal since snapshot is a fresh state
    initial_state.mac_mismatch_fatal = false;

    // Update hash state directly from records (no cloning needed)
    initial_state.update_hash_from_records(&snapshot.records);

    // Validate snapshot MAC if requested
    if validate_macs
        && let (Some(mac_expected), Some(key_id)) = (
            snapshot.mac.as_ref(),
            snapshot.key_id.as_ref().and_then(|k| k.id.as_ref()),
        )
    {
        let keys = get_keys(key_id)?;
        let computed = initial_state.generate_snapshot_mac(collection_name, &keys.snapshot_mac);
        if computed != *mac_expected {
            return Err(AppStateError::SnapshotMACMismatch);
        }
    }

    // Decode all records and collect MACs in a single pass
    let mut mutations = Vec::with_capacity(snapshot.records.len());
    let mut mutation_macs = Vec::with_capacity(snapshot.records.len());

    for rec in &snapshot.records {
        let key_id = rec
            .key_id
            .as_ref()
            .and_then(|k| k.id.as_ref())
            .ok_or(AppStateError::MissingKeyId)?;
        let keys = get_keys(key_id)?;

        let mutation = decode_record(
            wa::syncd_mutation::SyncdOperation::Set,
            rec,
            &keys,
            key_id,
            validate_macs,
        )?;

        mutation_macs.push(AppStateMutationMAC {
            index_mac: mutation.index_mac.clone(),
            value_mac: mutation.value_mac.clone(),
        });

        mutations.push(mutation);
    }

    Ok(ProcessedSnapshot {
        state: initial_state.clone(),
        mutations,
        mutation_macs,
    })
}

/// Process a single patch and decode its mutations.
///
/// This is a pure, synchronous function that processes a patch without
/// any async operations. Key and previous value lookup are done via callbacks.
///
/// # Arguments
/// * `patch` - The patch to process
/// * `state` - The current hash state (will be mutated in place)
/// * `get_keys` - Callback to get expanded keys for a key ID
/// * `get_prev_value_mac` - Callback to get previous value MAC for an index MAC
/// * `validate_macs` - Whether to validate MACs during processing
/// * `collection_name` - The collection name (for MAC validation)
///
/// # Returns
/// A `PatchProcessingResult` containing the new state and decoded mutations.
pub fn process_patch<F, G>(
    patch: &wa::SyncdPatch,
    state: &mut HashState,
    mut get_keys: F,
    mut get_prev_value_mac: G,
    validate_macs: bool,
    collection_name: &str,
) -> Result<PatchProcessingResult, AppStateError>
where
    F: FnMut(&[u8]) -> Result<ExpandedAppStateKeys, AppStateError>,
    G: FnMut(&[u8]) -> Result<Option<Vec<u8>>, AppStateError>,
{
    // Check for server exit code - indicates a terminal error from the server
    // WhatsApp Web throws a fatal error when exit_code is present
    if let Some(exit_code) = &patch.exit_code {
        let code = exit_code.code.unwrap_or(0);
        let text = exit_code.text.clone().unwrap_or_default();
        log::error!(
            target: "Client/AppState",
            "Server returned exit code {} for {} v{}: {}",
            code,
            collection_name,
            patch.version.as_ref().and_then(|v| v.version).unwrap_or(0),
            text
        );
        return Err(AppStateError::ServerExitCode { code, text });
    }

    // Capture original state before modification - needed for MAC validation logic
    // If original state was empty (version=0, hash all zeros), we cannot validate
    // snapshotMac because we don't have the baseline state the patch was built against.
    // This matches WhatsApp Web behavior which throws a retryable error in this case.
    let original_version = state.version;
    let original_hash_is_empty = state.hash == [0u8; 128];
    let had_no_prior_state = original_version == 0 && original_hash_is_empty;

    state.version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);

    // Update hash state - the closure handles finding previous values
    let (warnings, result) = state.update_hash(&patch.mutations, |index_mac, idx| {
        // First check previous mutations in this patch (for overwrites within same patch)
        for prev in patch.mutations[..idx].iter().rev() {
            if let Some(rec) = &prev.record
                && let Some(ind) = &rec.index
                && let Some(b) = &ind.blob
                && b == index_mac
            {
                // Found a previous mutation for the same index
                let prev_op =
                    wa::syncd_mutation::SyncdOperation::try_from(prev.operation.unwrap_or(0))
                        .unwrap_or(wa::syncd_mutation::SyncdOperation::Set);

                if prev_op == wa::syncd_mutation::SyncdOperation::Remove {
                    // Previous operation was REMOVE - entry was deleted, so there's no
                    // previous value to subtract for the current operation. This prevents
                    // double-subtraction when a patch contains [REMOVE A, SET A].
                    return Ok(None);
                }

                // Previous operation was SET - return its value MAC if valid
                if let Some(val) = &rec.value
                    && let Some(vb) = &val.blob
                    && vb.len() >= 32
                {
                    return Ok(Some(vb[vb.len() - 32..].to_vec()));
                }
            }
        }
        // Then check database via callback
        get_prev_value_mac(index_mac).map_err(|e| anyhow::anyhow!(e))
    });
    if !warnings.is_empty() {
        log::warn!(
            target: "Client/AppState",
            "process_patch: {} warnings while updating hash for {} v{}: {:?}",
            warnings.len(),
            collection_name,
            state.version,
            warnings
        );
    }
    result.map_err(|_| AppStateError::MismatchingLTHash)?;

    // Validate MACs if requested
    // Skip validation if collection is already in mac mismatch state (like WhatsApp Web)
    if validate_macs
        && !state.mac_mismatch_fatal
        && let Some(key_id) = patch.key_id.as_ref().and_then(|k| k.id.as_ref())
    {
        let keys = get_keys(key_id)?;
        if let Err(e) =
            validate_patch_macs(patch, state, &keys, collection_name, had_no_prior_state)
        {
            // On MAC mismatch, set the flag and continue processing (like WhatsApp Web)
            // This allows mutations to still be applied for usability, while the hash
            // state is corrected on the next proper sync with a snapshot.
            log::warn!(
                target: "Client/AppState",
                "MAC validation failed for {} v{}: {:?}, entering mac_mismatch_fatal mode",
                collection_name,
                state.version,
                e
            );
            state.mac_mismatch_fatal = true;
        }
    } else if state.mac_mismatch_fatal {
        log::debug!(
            target: "Client/AppState",
            "Skipping MAC validation for {} v{} (mac_mismatch_fatal=true)",
            collection_name,
            state.version
        );
    }

    // Decode all mutations and collect MACs in a single pass
    let mut mutations = Vec::with_capacity(patch.mutations.len());
    let mut added_macs = Vec::new();
    let mut removed_index_macs = Vec::new();

    for m in &patch.mutations {
        if let Some(rec) = &m.record {
            let op = wa::syncd_mutation::SyncdOperation::try_from(m.operation.unwrap_or(0))
                .unwrap_or(wa::syncd_mutation::SyncdOperation::Set);

            let key_id = rec
                .key_id
                .as_ref()
                .and_then(|k| k.id.as_ref())
                .ok_or(AppStateError::MissingKeyId)?;
            let keys = get_keys(key_id)?;

            let mutation = decode_record(op, rec, &keys, key_id, validate_macs)?;

            match op {
                wa::syncd_mutation::SyncdOperation::Set => {
                    added_macs.push(AppStateMutationMAC {
                        index_mac: mutation.index_mac.clone(),
                        value_mac: mutation.value_mac.clone(),
                    });
                }
                wa::syncd_mutation::SyncdOperation::Remove => {
                    removed_index_macs.push(mutation.index_mac.clone());
                }
            }

            mutations.push(mutation);
        }
    }

    Ok(PatchProcessingResult {
        state: state.clone(),
        mutations,
        added_macs,
        removed_index_macs,
    })
}

/// Validate the snapshot and patch MACs for a patch.
///
/// This is a pure function that validates the MACs without any I/O.
///
/// # Arguments
/// * `patch` - The patch to validate
/// * `state` - The hash state AFTER applying the patch mutations
/// * `keys` - The expanded app state keys for MAC computation
/// * `collection_name` - The collection name
/// * `had_no_prior_state` - If true, skip ALL MAC validation. This should be true
///   when processing patches without a prior local state (e.g., first sync without snapshot).
///   WhatsApp Web handles this case by throwing a retryable error ("empty lthash"), but we
///   can safely skip validation and process the mutations for usability. The state will be
///   corrected on the next proper sync with a snapshot.
pub fn validate_patch_macs(
    patch: &wa::SyncdPatch,
    state: &HashState,
    keys: &ExpandedAppStateKeys,
    collection_name: &str,
    had_no_prior_state: bool,
) -> Result<(), AppStateError> {
    // Skip ALL MAC validation if we had no prior state.
    // When we receive patches without a snapshot for a never-synced collection,
    // WhatsApp Web throws a retryable "empty lthash" error. We can't properly validate
    // either the snapshotMac (computed from wrong baseline) or the patchMac (which
    // includes the snapshotMac). Instead, we process the mutations and rely on
    // future syncs with snapshots to correct the state.
    if had_no_prior_state {
        return Ok(());
    }

    if let Some(snap_mac) = patch.snapshot_mac.as_ref() {
        let computed_snap = state.generate_snapshot_mac(collection_name, &keys.snapshot_mac);
        if computed_snap != *snap_mac {
            log::debug!(
                target: "Client/AppState",
                "Patch snapshot MAC mismatch for {} v{}: expected {:02x?}... computed {:02x?}... hash[:16]={:02x?}",
                collection_name,
                state.version,
                &snap_mac[..std::cmp::min(16, snap_mac.len())],
                &computed_snap[..std::cmp::min(16, computed_snap.len())],
                &state.hash[..16]
            );
            return Err(AppStateError::PatchSnapshotMACMismatch);
        }
    }

    if let Some(patch_mac) = patch.patch_mac.as_ref() {
        let version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);
        let computed_patch = generate_patch_mac(patch, collection_name, &keys.patch_mac, version);
        if computed_patch != *patch_mac {
            return Err(AppStateError::PatchMACMismatch);
        }
    }

    Ok(())
}

/// Validate a snapshot MAC.
///
/// This is a pure function that validates the snapshot MAC without any I/O.
pub fn validate_snapshot_mac(
    snapshot: &wa::SyncdSnapshot,
    state: &HashState,
    keys: &ExpandedAppStateKeys,
    collection_name: &str,
) -> Result<(), AppStateError> {
    if let Some(mac_expected) = snapshot.mac.as_ref() {
        let computed = state.generate_snapshot_mac(collection_name, &keys.snapshot_mac);
        if computed != *mac_expected {
            return Err(AppStateError::SnapshotMACMismatch);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::generate_content_mac;
    use crate::keys::expand_app_state_keys;
    use crate::lthash::WAPATCH_INTEGRITY;
    use prost::Message;
    use wacore_libsignal::crypto::aes_256_cbc_encrypt_into;

    fn create_encrypted_record(
        op: wa::syncd_mutation::SyncdOperation,
        index_mac: &[u8],
        keys: &ExpandedAppStateKeys,
        key_id: &[u8],
        timestamp: i64,
    ) -> wa::SyncdRecord {
        let action_data = wa::SyncActionData {
            value: Some(wa::SyncActionValue {
                timestamp: Some(timestamp),
                ..Default::default()
            }),
            ..Default::default()
        };
        let plaintext = action_data.encode_to_vec();

        let iv = vec![0u8; 16];
        let mut ciphertext = Vec::new();
        aes_256_cbc_encrypt_into(&plaintext, &keys.value_encryption, &iv, &mut ciphertext)
            .expect("test data should be valid");

        let mut value_with_iv = iv;
        value_with_iv.extend_from_slice(&ciphertext);
        let value_mac = generate_content_mac(op, &value_with_iv, key_id, &keys.value_mac);
        let mut value_blob = value_with_iv;
        value_blob.extend_from_slice(&value_mac);

        wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(index_mac.to_vec()),
            }),
            value: Some(wa::SyncdValue {
                blob: Some(value_blob),
            }),
            key_id: Some(wa::KeyId {
                id: Some(key_id.to_vec()),
            }),
        }
    }

    #[test]
    fn test_process_snapshot_basic() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();
        let index_mac = vec![1; 32];

        let record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            1234567890,
        );

        let snapshot = wa::SyncdSnapshot {
            version: Some(wa::SyncdVersion { version: Some(1) }),
            records: vec![record],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());

        let mut state = HashState::default();
        let result = process_snapshot(&snapshot, &mut state, get_keys, false, "regular")
            .expect("test data should be valid");

        assert_eq!(result.state.version, 1);
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.mutation_macs.len(), 1);
        assert_eq!(
            result.mutations[0]
                .action_value
                .as_ref()
                .and_then(|v| v.timestamp),
            Some(1234567890)
        );
    }

    #[test]
    fn test_process_patch_basic() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();
        let index_mac = vec![1; 32];

        let record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            1234567890,
        );

        let patch = wa::SyncdPatch {
            version: Some(wa::SyncdVersion { version: Some(2) }),
            mutations: vec![wa::SyncdMutation {
                operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
                record: Some(record),
            }],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        let get_prev = |_: &[u8]| Ok(None);

        let mut state = HashState::default();
        let result = process_patch(&patch, &mut state, get_keys, get_prev, false, "regular")
            .expect("test data should be valid");

        assert_eq!(result.state.version, 2);
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(result.added_macs.len(), 1);
        assert!(result.removed_index_macs.is_empty());
    }

    #[test]
    fn test_process_patch_with_overwrite() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();
        let index_mac = vec![1; 32];

        // Create initial record
        let initial_record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            1000,
        );
        let initial_value_blob = initial_record
            .value
            .as_ref()
            .expect("test data should be valid")
            .blob
            .as_ref()
            .expect("test data should be valid");
        let initial_value_mac = initial_value_blob[initial_value_blob.len() - 32..].to_vec();

        // Process initial snapshot to get starting state
        let snapshot = wa::SyncdSnapshot {
            version: Some(wa::SyncdVersion { version: Some(1) }),
            records: vec![initial_record],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        let mut snapshot_state = HashState::default();
        let snapshot_result =
            process_snapshot(&snapshot, &mut snapshot_state, get_keys, false, "regular")
                .expect("test data should be valid");

        // Create overwrite record
        let overwrite_record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            2000,
        );

        let patch = wa::SyncdPatch {
            version: Some(wa::SyncdVersion { version: Some(2) }),
            mutations: vec![wa::SyncdMutation {
                operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
                record: Some(overwrite_record.clone()),
            }],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        // Return the previous value MAC when asked
        let get_prev = |idx: &[u8]| {
            if idx == index_mac.as_slice() {
                Ok(Some(initial_value_mac.clone()))
            } else {
                Ok(None)
            }
        };

        let mut patch_state = snapshot_result.state.clone();
        let result = process_patch(
            &patch,
            &mut patch_state,
            get_keys,
            get_prev,
            false,
            "regular",
        )
        .expect("test data should be valid");

        assert_eq!(result.state.version, 2);
        assert_eq!(result.mutations.len(), 1);
        assert_eq!(
            result.mutations[0]
                .action_value
                .as_ref()
                .and_then(|v| v.timestamp),
            Some(2000)
        );

        // Verify the hash was updated correctly (old value removed, new added)
        let new_value_blob = overwrite_record
            .value
            .expect("test data should be valid")
            .blob
            .expect("test data should be valid");
        let new_value_mac = new_value_blob[new_value_blob.len() - 32..].to_vec();

        let expected_hash = WAPATCH_INTEGRITY.subtract_then_add(
            &snapshot_result.state.hash,
            &[initial_value_mac],
            &[new_value_mac],
        );

        assert_eq!(result.state.hash.as_slice(), expected_hash.as_slice());
    }

    /// Test that REMOVE followed by SET for the same index in the same patch
    /// does NOT cause double-subtraction of the old value.
    ///
    /// Scenario: Entry A exists with old_value. Patch contains:
    /// 1. REMOVE A (should subtract old_value)
    /// 2. SET A=new_value (should NOT subtract old_value again)
    ///
    /// Expected hash: old_hash - old_value + new_value
    /// Bug hash (without fix): old_hash - old_value - old_value + new_value
    #[test]
    fn test_process_patch_remove_then_set_same_index_no_double_subtraction() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();
        let index_mac = vec![1; 32];

        // Create initial record for snapshot
        let initial_record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            1000,
        );
        let initial_value_blob = initial_record
            .value
            .as_ref()
            .expect("test data should be valid")
            .blob
            .as_ref()
            .expect("test data should be valid");
        let initial_value_mac = initial_value_blob[initial_value_blob.len() - 32..].to_vec();

        // Process initial snapshot to get starting state
        let snapshot = wa::SyncdSnapshot {
            version: Some(wa::SyncdVersion { version: Some(1) }),
            records: vec![initial_record],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        let mut snapshot_state = HashState::default();
        let snapshot_result =
            process_snapshot(&snapshot, &mut snapshot_state, get_keys, false, "regular")
                .expect("test data should be valid");

        // Create REMOVE mutation (still needs a valid encrypted record for decoding)
        let remove_record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Remove,
            &index_mac,
            &keys,
            &key_id,
            1500, // Different timestamp to distinguish from initial
        );
        let remove_mutation = wa::SyncdMutation {
            operation: Some(wa::syncd_mutation::SyncdOperation::Remove as i32),
            record: Some(remove_record),
        };

        // Create SET mutation for the same index with new value
        let new_record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            2000,
        );
        let new_value_blob = new_record
            .value
            .as_ref()
            .expect("test data should be valid")
            .blob
            .as_ref()
            .expect("test data should be valid");
        let new_value_mac = new_value_blob[new_value_blob.len() - 32..].to_vec();

        let set_mutation = wa::SyncdMutation {
            operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
            record: Some(new_record),
        };

        // Create patch with [REMOVE A, SET A] - order matters!
        let patch = wa::SyncdPatch {
            version: Some(wa::SyncdVersion { version: Some(2) }),
            mutations: vec![remove_mutation, set_mutation],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        // Database returns the old value MAC when looking up the index
        let get_prev = |idx: &[u8]| {
            if idx == index_mac.as_slice() {
                Ok(Some(initial_value_mac.clone()))
            } else {
                Ok(None)
            }
        };

        let mut patch_state = snapshot_result.state.clone();
        let result = process_patch(
            &patch,
            &mut patch_state,
            get_keys,
            get_prev,
            false,
            "regular",
        )
        .expect("test data should be valid");

        assert_eq!(result.state.version, 2);
        assert_eq!(result.mutations.len(), 2);
        assert_eq!(result.added_macs.len(), 1); // Only the SET adds a MAC
        assert_eq!(result.removed_index_macs.len(), 1); // REMOVE removes the index

        // CRITICAL: Verify the hash was computed correctly with SINGLE subtraction
        // Expected: old_hash - old_value + new_value
        let expected_hash = WAPATCH_INTEGRITY.subtract_then_add(
            &snapshot_result.state.hash,
            std::slice::from_ref(&initial_value_mac), // Single subtraction of old value
            std::slice::from_ref(&new_value_mac),     // Add new value
        );

        assert_eq!(
            result.state.hash.as_slice(),
            expected_hash.as_slice(),
            "Hash should match single-subtraction result. \
            If hash is wrong, double-subtraction bug may have regressed."
        );

        // Also verify it's NOT the double-subtraction result
        let buggy_hash = WAPATCH_INTEGRITY.subtract_then_add(
            &snapshot_result.state.hash,
            &[initial_value_mac.clone(), initial_value_mac], // Double subtraction (bug)
            std::slice::from_ref(&new_value_mac),
        );
        assert_ne!(
            result.state.hash.as_slice(),
            buggy_hash.as_slice(),
            "Hash incorrectly matches double-subtraction result - bug detected!"
        );
    }

    /// Test that mac_mismatch_fatal flag is set on MAC validation failure
    /// and subsequent validations are skipped.
    #[test]
    fn test_mac_mismatch_fatal_flag_behavior() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();
        let index_mac = vec![1; 32];

        let record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            1234567890,
        );

        // Create patch with WRONG snapshot MAC to trigger mismatch
        let patch = wa::SyncdPatch {
            version: Some(wa::SyncdVersion { version: Some(2) }),
            mutations: vec![wa::SyncdMutation {
                operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
                record: Some(record),
            }],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            snapshot_mac: Some(vec![0xBA; 32]), // Wrong MAC - will trigger mismatch
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        let get_prev = |_: &[u8]| Ok(None);

        // Start with valid state (not empty)
        let mut state = HashState {
            version: 1,
            hash: [1u8; 128], // Non-empty hash to trigger validation
            index_value_map: std::collections::HashMap::new(),
            mac_mismatch_fatal: false,
        };

        // Process with MAC validation enabled
        let result = process_patch(
            &patch, &mut state, get_keys, get_prev, true, // Enable MAC validation
            "regular",
        );

        // Should succeed (continue processing despite mismatch)
        assert!(result.is_ok(), "Should succeed despite MAC mismatch");

        // Flag should be set
        assert!(
            state.mac_mismatch_fatal,
            "mac_mismatch_fatal should be set after MAC mismatch"
        );
    }

    /// Test that snapshot processing resets mac_mismatch_fatal flag.
    #[test]
    fn test_snapshot_resets_mac_mismatch_fatal_flag() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();
        let index_mac = vec![1; 32];

        let record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            1234567890,
        );

        let snapshot = wa::SyncdSnapshot {
            version: Some(wa::SyncdVersion { version: Some(5) }),
            records: vec![record],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());

        // Start with mac_mismatch_fatal = true
        let mut state = HashState {
            version: 3,
            hash: [1u8; 128],
            index_value_map: std::collections::HashMap::new(),
            mac_mismatch_fatal: true, // Flag is set
        };

        let result = process_snapshot(&snapshot, &mut state, get_keys, false, "regular");

        assert!(result.is_ok());
        assert!(
            !state.mac_mismatch_fatal,
            "mac_mismatch_fatal should be reset after snapshot"
        );
        assert_eq!(state.version, 5);
    }

    /// Test that server exit_code in patch returns an error.
    #[test]
    fn test_server_exit_code_returns_error() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();

        // Create patch with exit_code
        let patch = wa::SyncdPatch {
            version: Some(wa::SyncdVersion { version: Some(2) }),
            mutations: vec![],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            exit_code: Some(wa::ExitCode {
                code: Some(100),
                text: Some("Test error".to_string()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        let get_prev = |_: &[u8]| Ok(None);
        let mut state = HashState::default();

        let result = process_patch(&patch, &mut state, get_keys, get_prev, false, "regular");

        assert!(result.is_err());
        match result {
            Err(AppStateError::ServerExitCode { code, text }) => {
                assert_eq!(code, 100);
                assert_eq!(text, "Test error");
            }
            _ => panic!("Expected ServerExitCode error"),
        }
    }

    /// Test REMOVE-only operation.
    #[test]
    fn test_process_patch_remove_only() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();
        let index_mac = vec![1; 32];

        // Create initial record for snapshot
        let initial_record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &keys,
            &key_id,
            1000,
        );
        let initial_value_blob = initial_record
            .value
            .as_ref()
            .unwrap()
            .blob
            .as_ref()
            .unwrap();
        let initial_value_mac = initial_value_blob[initial_value_blob.len() - 32..].to_vec();

        // Process initial snapshot
        let snapshot = wa::SyncdSnapshot {
            version: Some(wa::SyncdVersion { version: Some(1) }),
            records: vec![initial_record],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        let mut snapshot_state = HashState::default();
        let snapshot_result =
            process_snapshot(&snapshot, &mut snapshot_state, get_keys, false, "regular").unwrap();

        // Create REMOVE mutation
        let remove_record = create_encrypted_record(
            wa::syncd_mutation::SyncdOperation::Remove,
            &index_mac,
            &keys,
            &key_id,
            2000,
        );

        let patch = wa::SyncdPatch {
            version: Some(wa::SyncdVersion { version: Some(2) }),
            mutations: vec![wa::SyncdMutation {
                operation: Some(wa::syncd_mutation::SyncdOperation::Remove as i32),
                record: Some(remove_record),
            }],
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            ..Default::default()
        };

        let get_keys = |_: &[u8]| Ok(keys.clone());
        let get_prev = |idx: &[u8]| {
            if idx == index_mac.as_slice() {
                Ok(Some(initial_value_mac.clone()))
            } else {
                Ok(None)
            }
        };

        let mut patch_state = snapshot_result.state.clone();
        let result = process_patch(
            &patch,
            &mut patch_state,
            get_keys,
            get_prev,
            false,
            "regular",
        )
        .unwrap();

        assert_eq!(result.state.version, 2);
        assert_eq!(result.mutations.len(), 1);
        assert!(result.added_macs.is_empty()); // REMOVE doesn't add MACs
        assert_eq!(result.removed_index_macs.len(), 1);
        assert_eq!(result.removed_index_macs[0], index_mac);

        // Hash should have the value MAC subtracted
        let expected_hash = WAPATCH_INTEGRITY.subtract_then_add(
            &snapshot_result.state.hash,
            &[initial_value_mac],
            &[],
        );

        assert_eq!(result.state.hash.as_slice(), expected_hash.as_slice());
    }

    /// Test multiple sequential patches maintain correct hash state.
    #[test]
    fn test_multiple_sequential_patches() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();

        // Start with empty state
        let mut state = HashState::default();
        let mut all_value_macs: Vec<Vec<u8>> = Vec::new();

        // Apply 3 sequential patches, each adding a new entry
        for i in 0..3 {
            let index_mac = vec![i as u8 + 1; 32];
            let record = create_encrypted_record(
                wa::syncd_mutation::SyncdOperation::Set,
                &index_mac,
                &keys,
                &key_id,
                1000 + i as i64,
            );
            let value_blob = record.value.as_ref().unwrap().blob.as_ref().unwrap();
            let value_mac = value_blob[value_blob.len() - 32..].to_vec();
            all_value_macs.push(value_mac);

            let patch = wa::SyncdPatch {
                version: Some(wa::SyncdVersion {
                    version: Some(i as u64 + 1),
                }),
                mutations: vec![wa::SyncdMutation {
                    operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
                    record: Some(record),
                }],
                key_id: Some(wa::KeyId {
                    id: Some(key_id.clone()),
                }),
                ..Default::default()
            };

            let get_keys = |_: &[u8]| Ok(keys.clone());
            let get_prev = |_: &[u8]| Ok(None);

            let result =
                process_patch(&patch, &mut state, get_keys, get_prev, false, "regular").unwrap();
            state = result.state;

            assert_eq!(state.version, i as u64 + 1);
        }

        // Verify final hash is correct (all 3 value MACs added to initial empty hash)
        let expected_hash = WAPATCH_INTEGRITY.subtract_then_add(&[0u8; 128], &[], &all_value_macs);

        assert_eq!(
            state.hash.as_slice(),
            expected_hash.as_slice(),
            "Final hash after sequential patches should match expected"
        );
    }
}
