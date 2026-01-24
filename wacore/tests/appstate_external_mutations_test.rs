//! Integration tests for external mutations and hasMissingRemove handling.
//!
//! These tests verify the behavior when:
//! 1. Patches have external_mutations that need to be downloaded
//! 2. REMOVE mutations reference entries we don't have locally (hasMissingRemove)

use prost::Message;
use wacore::appstate::WAPATCH_INTEGRITY;
use wacore::appstate::hash::{HashState, generate_content_mac};
use wacore::appstate::keys::expand_app_state_keys;
use wacore::appstate::processor::validate_patch_macs;
use waproto::whatsapp as wa;

fn make_mutation(
    op: wa::syncd_mutation::SyncdOperation,
    key_id: &[u8],
    index_mac: Vec<u8>,
    value_blob: Option<Vec<u8>>,
) -> wa::SyncdMutation {
    wa::SyncdMutation {
        operation: Some(op as i32),
        record: Some(wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(index_mac),
            }),
            value: value_blob.map(|b| wa::SyncdValue { blob: Some(b) }),
            key_id: Some(wa::KeyId {
                id: Some(key_id.to_vec()),
            }),
        }),
    }
}

fn create_value_blob(
    keys: &wacore::appstate::keys::ExpandedAppStateKeys,
    key_id: &[u8],
) -> Vec<u8> {
    let iv = [1u8; 16];
    let ciphertext = b"test_content".to_vec();
    let mut content = iv.to_vec();
    content.extend_from_slice(&ciphertext);
    let value_mac = generate_content_mac(
        wa::syncd_mutation::SyncdOperation::Set,
        &content,
        key_id,
        &keys.value_mac,
    );
    let mut value_blob = content;
    value_blob.extend_from_slice(&value_mac);
    value_blob
}

#[test]
fn test_has_missing_remove_flag_set_on_remove_without_previous_value() {
    let mut state = HashState::default();
    let key_id = b"test_key";
    let index_mac = vec![1u8; 32];

    // Create a REMOVE mutation for an entry that doesn't exist locally
    let mutations = vec![make_mutation(
        wa::syncd_mutation::SyncdOperation::Remove,
        key_id,
        index_mac,
        None,
    )];

    // The callback returns None (entry not found locally)
    let (result, err) = state.update_hash(&mutations, |_, _| Ok(None));

    assert!(err.is_ok());
    assert!(
        result.has_missing_remove,
        "has_missing_remove should be true when REMOVE targets missing entry"
    );
}

#[test]
fn test_has_missing_remove_flag_not_set_on_set_without_previous_value() {
    let mut state = HashState::default();
    let key_id = b"test_key";
    let index_mac = vec![1u8; 32];
    let master_key = [7u8; 32];
    let keys = expand_app_state_keys(&master_key);

    let value_blob = create_value_blob(&keys, key_id);

    // Create a SET mutation (new entry, no previous value)
    let mutations = vec![make_mutation(
        wa::syncd_mutation::SyncdOperation::Set,
        key_id,
        index_mac,
        Some(value_blob),
    )];

    let (result, err) = state.update_hash(&mutations, |_, _| Ok(None));

    assert!(err.is_ok());
    assert!(
        !result.has_missing_remove,
        "has_missing_remove should be false for SET without previous value"
    );
}

#[test]
fn test_has_missing_remove_flag_not_set_when_previous_value_exists() {
    let mut state = HashState::default();
    let key_id = b"test_key";
    let index_mac = vec![1u8; 32];
    let previous_value_mac = vec![99u8; 32];

    // Create a REMOVE mutation for an entry that DOES exist locally
    let mutations = vec![make_mutation(
        wa::syncd_mutation::SyncdOperation::Remove,
        key_id,
        index_mac.clone(),
        None,
    )];

    // The callback returns the previous value MAC
    let (result, err) = state.update_hash(&mutations, |idx, _| {
        if idx == index_mac {
            Ok(Some(previous_value_mac.clone()))
        } else {
            Ok(None)
        }
    });

    assert!(err.is_ok());
    assert!(
        !result.has_missing_remove,
        "has_missing_remove should be false when previous value exists"
    );
}

#[test]
fn test_lthash_diverges_on_missing_remove() {
    // When we can't subtract a value (missing remove), our ltHash will diverge
    // from the server's. This test verifies the divergence behavior.

    let master_key = [7u8; 32];
    let keys = expand_app_state_keys(&master_key);
    let key_id = b"test_key";

    // Create initial state with one entry
    let index_mac_1 = vec![1u8; 32];
    let value_blob_1 = create_value_blob(&keys, key_id);
    let value_mac_1 = value_blob_1[value_blob_1.len() - 32..].to_vec();

    let mut state = HashState::default();
    let set_mutation = make_mutation(
        wa::syncd_mutation::SyncdOperation::Set,
        key_id,
        index_mac_1.clone(),
        Some(value_blob_1),
    );
    let (_, err) = state.update_hash(&[set_mutation], |_, _| Ok(None));
    assert!(err.is_ok());

    // Compute expected hash with the entry
    let expected_hash_with_entry =
        WAPATCH_INTEGRITY.subtract_then_add(&[0u8; 128], &[], std::slice::from_ref(&value_mac_1));

    assert_eq!(state.hash.as_slice(), expected_hash_with_entry.as_slice());

    // Now simulate a REMOVE for an entry we DON'T have (index_mac_2)
    let index_mac_2 = vec![2u8; 32];
    let remove_mutation = make_mutation(
        wa::syncd_mutation::SyncdOperation::Remove,
        key_id,
        index_mac_2,
        None,
    );

    let (result, err) = state.update_hash(&[remove_mutation], |_, _| Ok(None));
    assert!(err.is_ok());
    assert!(result.has_missing_remove);

    // Our hash should NOT have changed because we couldn't subtract anything
    // (this is the divergence - server subtracted the value, we didn't)
    assert_eq!(
        state.hash.as_slice(),
        expected_hash_with_entry.as_slice(),
        "Hash should remain unchanged when we can't subtract a missing value"
    );
}

#[test]
fn test_external_mutations_decode_from_syncd_mutations() {
    // Test that SyncdMutations (the wrapper for external mutations) can be decoded
    let key_id = b"test_key";
    let master_key = [7u8; 32];
    let keys = expand_app_state_keys(&master_key);

    let mutation1 = make_mutation(
        wa::syncd_mutation::SyncdOperation::Set,
        key_id,
        vec![1u8; 32],
        Some(create_value_blob(&keys, key_id)),
    );

    let mutation2 = make_mutation(
        wa::syncd_mutation::SyncdOperation::Remove,
        key_id,
        vec![2u8; 32],
        None,
    );

    // Encode as SyncdMutations (what external_mutations downloads return)
    let syncd_mutations = wa::SyncdMutations {
        mutations: vec![mutation1, mutation2],
    };

    let encoded = syncd_mutations.encode_to_vec();

    // Decode back
    let decoded = wa::SyncdMutations::decode(encoded.as_slice()).expect("should decode");

    assert_eq!(decoded.mutations.len(), 2);
    assert_eq!(
        decoded.mutations[0].operation,
        Some(wa::syncd_mutation::SyncdOperation::Set as i32)
    );
    assert_eq!(
        decoded.mutations[1].operation,
        Some(wa::syncd_mutation::SyncdOperation::Remove as i32)
    );
}

#[test]
fn test_validate_patch_macs_skips_on_has_missing_remove() {
    // When has_missing_remove is true, MAC validation should not fail
    // because we expect the hash to diverge

    let master_key = [7u8; 32];
    let keys = expand_app_state_keys(&master_key);
    let key_id = b"test_key";
    let collection_name = "regular_low";

    let state = HashState {
        version: 1,
        hash: [42u8; 128], // arbitrary non-zero hash
        ..Default::default()
    };

    // Create a patch with a snapshot_mac that won't match our state
    let patch = wa::SyncdPatch {
        version: Some(wa::SyncdVersion { version: Some(2) }),
        mutations: vec![],
        external_mutations: None,
        snapshot_mac: Some(vec![0u8; 32]), // This won't match our computed MAC
        patch_mac: None,
        key_id: Some(wa::KeyId {
            id: Some(key_id.to_vec()),
        }),
        exit_code: None,
        device_index: None,
        client_debug_data: None,
    };

    // Without has_missing_remove, this would fail
    let result_without_flag =
        validate_patch_macs(&patch, &state, &keys, collection_name, false, false);
    assert!(
        result_without_flag.is_err(),
        "Should fail MAC validation without has_missing_remove"
    );

    // With has_missing_remove, this should succeed (MAC mismatch is expected)
    let result_with_flag = validate_patch_macs(&patch, &state, &keys, collection_name, false, true);
    assert!(
        result_with_flag.is_ok(),
        "Should pass MAC validation with has_missing_remove=true"
    );
}

#[test]
fn test_mixed_set_and_remove_with_missing_remove() {
    // Test a realistic scenario: a patch with both SET and REMOVE mutations
    // where some REMOVEs target entries we don't have

    let master_key = [7u8; 32];
    let keys = expand_app_state_keys(&master_key);
    let key_id = b"test_key";

    let mut state = HashState::default();

    // First, add an entry that we DO have
    let index_mac_known = vec![1u8; 32];
    let value_blob_known = create_value_blob(&keys, key_id);
    let value_mac_known = value_blob_known[value_blob_known.len() - 32..].to_vec();

    let set_known = make_mutation(
        wa::syncd_mutation::SyncdOperation::Set,
        key_id,
        index_mac_known.clone(),
        Some(value_blob_known),
    );
    let (_, err) = state.update_hash(&[set_known], |_, _| Ok(None));
    assert!(err.is_ok());

    // Now process a batch with:
    // 1. A new SET
    // 2. A REMOVE for the known entry (should work)
    // 3. A REMOVE for an unknown entry (should trigger has_missing_remove)

    let index_mac_new = vec![3u8; 32];
    let value_blob_new = create_value_blob(&keys, key_id);

    let index_mac_unknown = vec![99u8; 32];

    let mutations = vec![
        make_mutation(
            wa::syncd_mutation::SyncdOperation::Set,
            key_id,
            index_mac_new,
            Some(value_blob_new),
        ),
        make_mutation(
            wa::syncd_mutation::SyncdOperation::Remove,
            key_id,
            index_mac_known.clone(),
            None,
        ),
        make_mutation(
            wa::syncd_mutation::SyncdOperation::Remove,
            key_id,
            index_mac_unknown,
            None,
        ),
    ];

    let (result, err) = state.update_hash(&mutations, |idx, _| {
        if idx == index_mac_known {
            Ok(Some(value_mac_known.clone()))
        } else {
            Ok(None)
        }
    });

    assert!(err.is_ok());
    assert!(
        result.has_missing_remove,
        "Should have has_missing_remove due to unknown REMOVE"
    );
}
