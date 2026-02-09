//! Pure, synchronous patch and snapshot processing logic for app state.
//!
//! This module provides runtime-agnostic processing of app state patches and snapshots.
//! All functions are synchronous and take callbacks for key lookup, making them
//! suitable for use in both async and sync contexts.

use crate::AppStateError;
use crate::decode::{Mutation, decode_record};
use crate::hash::{HashState, generate_patch_mac};
use crate::keys::ExpandedAppStateKeys;
use log::{debug, trace};
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

    // Update hash state directly from records (no cloning needed)
    initial_state.update_hash_from_records(&snapshot.records);

    debug!(
        target: "AppState",
        "Snapshot {} v{}: {} records, ltHash ends with ...{}",
        collection_name,
        version,
        snapshot.records.len(),
        hex::encode(&initial_state.hash[120..])
    );

    // Validate snapshot MAC if requested
    if validate_macs
        && let (Some(mac_expected), Some(key_id)) = (
            snapshot.mac.as_ref(),
            snapshot.key_id.as_ref().and_then(|k| k.id.as_ref()),
        )
    {
        let keys = get_keys(key_id)?;
        let computed = initial_state.generate_snapshot_mac(collection_name, &keys.snapshot_mac);
        trace!(
            target: "AppState",
            "Snapshot {} v{} MAC validation: computed={}, expected={}",
            collection_name,
            version,
            hex::encode(&computed),
            hex::encode(mac_expected)
        );
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
    // Capture original state before modification - needed for MAC validation logic
    // If original state was empty (version=0, hash all zeros), we cannot validate
    // snapshotMac because we don't have the baseline state the patch was built against.
    // This matches WhatsApp Web behavior which throws a retryable error in this case.
    let original_version = state.version;
    let original_hash_is_empty = state.hash == [0u8; 128];
    let had_no_prior_state = original_version == 0 && original_hash_is_empty;

    state.version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);

    // Update hash state - the closure handles finding previous values
    let (hash_update_result, result) = state.update_hash(&patch.mutations, |index_mac, idx| {
        // First check previous mutations in this patch (for overwrites within same patch)
        for prev in patch.mutations[..idx].iter().rev() {
            if let Some(rec) = &prev.record
                && let Some(ind) = &rec.index
                && let Some(b) = &ind.blob
                && b == index_mac
                && let Some(val) = &rec.value
                && let Some(vb) = &val.blob
                && vb.len() >= 32
            {
                return Ok(Some(vb[vb.len() - 32..].to_vec()));
            }
        }
        // Then check database via callback
        get_prev_value_mac(index_mac).map_err(|e| anyhow::anyhow!(e))
    });
    result.map_err(|_| AppStateError::MismatchingLTHash)?;

    debug!(
        target: "AppState",
        "Patch {} v{}: {} mutations, ltHash ends with ...{}, hasMissingRemove={}",
        collection_name,
        state.version,
        patch.mutations.len(),
        hex::encode(&state.hash[120..]),
        hash_update_result.has_missing_remove
    );

    // Validate MACs if requested
    if validate_macs && let Some(key_id) = patch.key_id.as_ref().and_then(|k| k.id.as_ref()) {
        let keys = get_keys(key_id)?;
        validate_patch_macs(
            patch,
            state,
            &keys,
            collection_name,
            had_no_prior_state,
            hash_update_result.has_missing_remove,
        )?;
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
/// * `has_missing_remove` - If true, a REMOVE mutation was missing its previous value.
///   WhatsApp Web tracks this and makes MAC validation failures non-fatal in this case,
///   because the ltHash is expected to diverge when we can't subtract a value we don't have.
pub fn validate_patch_macs(
    patch: &wa::SyncdPatch,
    state: &HashState,
    keys: &ExpandedAppStateKeys,
    collection_name: &str,
    had_no_prior_state: bool,
    has_missing_remove: bool,
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
        trace!(
            target: "AppState",
            "Patch {} v{} snapshotMAC: computed={}, expected={}",
            collection_name,
            state.version,
            hex::encode(&computed_snap),
            hex::encode(snap_mac)
        );
        if computed_snap != *snap_mac {
            // WhatsApp Web behavior: if hasMissingRemove is true, MAC mismatch is expected
            // because we couldn't subtract the value we don't have. Log and continue.
            if has_missing_remove {
                log::warn!(
                    target: "AppState",
                    "Patch {} v{} snapshotMAC mismatch (expected due to hasMissingRemove=true), continuing",
                    collection_name,
                    state.version
                );
                // Don't fail - WhatsApp Web continues processing in this case
            } else {
                debug!(
                    target: "AppState",
                    "Patch {} v{} snapshotMAC MISMATCH! ltHash=...{}",
                    collection_name,
                    state.version,
                    hex::encode(&state.hash[120..])
                );
                return Err(AppStateError::PatchSnapshotMACMismatch);
            }
        }
    }

    if let Some(patch_mac) = patch.patch_mac.as_ref() {
        let version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);
        let computed_patch = generate_patch_mac(patch, collection_name, &keys.patch_mac, version);
        if computed_patch != *patch_mac {
            // Also skip patchMac validation if hasMissingRemove, since snapshotMac is part of it
            if has_missing_remove {
                log::warn!(
                    target: "AppState",
                    "Patch {} v{} patchMAC mismatch (expected due to hasMissingRemove=true), continuing",
                    collection_name,
                    state.version
                );
            } else {
                return Err(AppStateError::PatchMACMismatch);
            }
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
}
