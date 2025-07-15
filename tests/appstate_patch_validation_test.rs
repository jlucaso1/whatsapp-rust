use base64::Engine as _;
use base64::prelude::*;
use prost::Message;
use wacore::appstate::{
    hash::HashState,
    keys,
    lthash::WA_PATCH_INTEGRITY,
    processor::{PatchList, ProcessorUtils},
};
use waproto::whatsapp as wa;

#[tokio::test]
async fn test_patch_mac_validation_with_index_value_map() {
    // 1. Setup initial state with some existing data in index_value_map
    let mut initial_state = HashState::default();

    // Add some existing entries to simulate previous SET operations
    let existing_index_mac_bytes = b"existing_index_123";
    let existing_index_mac = BASE64_STANDARD.encode(existing_index_mac_bytes);
    let existing_value_mac = b"existing_value_mac_32_bytes_long".to_vec();
    initial_state
        .index_value_map
        .insert(existing_index_mac.clone(), existing_value_mac.clone());

    // Update the hash to reflect this existing entry
    WA_PATCH_INTEGRITY.subtract_then_add_in_place(
        &mut initial_state.hash,
        &[],
        &[&existing_value_mac],
    );

    // 2. Create a patch with both SET and REMOVE operations
    let key_data = b"some-secret-app-state-key-data-!";
    let keys = keys::expand_app_state_keys(key_data);
    let key_id_bytes = b"my_key_id";

    // Create a REMOVE mutation for the existing entry
    let remove_mutation = create_test_mutation(
        wa::syncd_mutation::SyncdOperation::Remove,
        &keys,
        key_id_bytes,
        b"existing_index_123",
        r#"["existing","entry"]"#,
    );

    // Create a SET mutation for a new entry
    let new_index_mac = b"new_index_456";
    let set_mutation = create_test_mutation(
        wa::syncd_mutation::SyncdOperation::Set,
        &keys,
        key_id_bytes,
        new_index_mac,
        r#"["new","entry"]"#,
    );

    // 3. Calculate the expected patch MAC
    let mut expected_final_hash = initial_state.hash;
    let new_value_mac = extract_value_mac(&set_mutation);

    WA_PATCH_INTEGRITY.subtract_then_add_in_place(
        &mut expected_final_hash,
        &[&existing_value_mac],
        &[&new_value_mac],
    );

    // 4. Create patch with correct MAC
    let patch = wa::SyncdPatch {
        version: Some(wa::SyncdVersion { version: Some(2) }),
        mutations: vec![remove_mutation, set_mutation],
        external_mutations: None,
        snapshot_mac: None,
        patch_mac: Some(expected_final_hash.to_vec()),
        key_id: Some(wa::KeyId {
            id: Some(key_id_bytes.to_vec()),
        }),
        exit_code: None,
        device_index: None,
        client_debug_data: None,
    };

    let patch_list = PatchList {
        name: "test".to_string(),
        has_more_patches: false,
        patches: vec![patch],
        snapshot: None,
    };

    // 5. Create key lookup function
    let key_lookup = |key_id: &[u8]| -> Option<Vec<u8>> {
        if key_id == key_id_bytes {
            Some(key_data.to_vec())
        } else {
            None
        }
    };

    // 6. Test: Decode patches should succeed
    let result =
        ProcessorUtils::decode_patches_core(&patch_list, initial_state.clone(), key_lookup);

    assert!(
        result.is_ok(),
        "Patch decoding should succeed with valid MAC"
    );
    let (mutations, final_state) = result.unwrap();

    // 7. Verify results
    assert_eq!(mutations.len(), 2, "Should have 2 decoded mutations");
    assert_eq!(final_state.version, 2, "Version should be updated");

    // Verify index_value_map was updated correctly
    assert!(
        !final_state
            .index_value_map
            .contains_key(&existing_index_mac),
        "Old entry should be removed"
    );

    let new_index_mac_b64 = BASE64_STANDARD.encode(new_index_mac);
    assert!(
        final_state.index_value_map.contains_key(&new_index_mac_b64),
        "New entry should be added"
    );

    // Verify final hash matches expected
    assert_eq!(
        final_state.hash, expected_final_hash,
        "Final hash should match expected value"
    );
}

#[tokio::test]
async fn test_patch_mac_validation_fails_with_wrong_mac() {
    // Setup similar to above but with wrong MAC
    let mut initial_state = HashState::default();
    let existing_index_mac = BASE64_STANDARD.encode(b"existing_index_123");
    let existing_value_mac = b"existing_value_mac_32_bytes_long".to_vec();
    initial_state
        .index_value_map
        .insert(existing_index_mac, existing_value_mac.clone());

    WA_PATCH_INTEGRITY.subtract_then_add_in_place(
        &mut initial_state.hash,
        &[],
        &[&existing_value_mac],
    );

    let key_data = b"some-secret-app-state-key-data-!";
    let keys = keys::expand_app_state_keys(key_data);
    let key_id_bytes = b"my_key_id";

    let remove_mutation = create_test_mutation(
        wa::syncd_mutation::SyncdOperation::Remove,
        &keys,
        key_id_bytes,
        b"existing_index_123",
        r#"["existing","entry"]"#,
    );

    // Create patch with WRONG MAC
    let wrong_mac = vec![99u8; 128]; // Clearly different from zeros
    let patch = wa::SyncdPatch {
        version: Some(wa::SyncdVersion { version: Some(2) }),
        mutations: vec![remove_mutation],
        external_mutations: None,
        snapshot_mac: None,
        patch_mac: Some(wrong_mac),
        key_id: Some(wa::KeyId {
            id: Some(key_id_bytes.to_vec()),
        }),
        exit_code: None,
        device_index: None,
        client_debug_data: None,
    };

    let patch_list = PatchList {
        name: "test".to_string(),
        has_more_patches: false,
        patches: vec![patch],
        snapshot: None,
    };

    let key_lookup = |key_id: &[u8]| -> Option<Vec<u8>> {
        if key_id == key_id_bytes {
            Some(key_data.to_vec())
        } else {
            None
        }
    };

    // Test: Should fail with mismatching patch MAC
    let result = ProcessorUtils::decode_patches_core(&patch_list, initial_state, key_lookup);

    println!("Test result: {:?}", result);

    assert!(result.is_err(), "Should fail with wrong patch MAC");
    match result.unwrap_err() {
        wacore::appstate::errors::AppStateError::MismatchingPatchMAC => {
            println!("✅ Got expected MismatchingPatchMAC error");
        }
        other => {
            panic!("Expected MismatchingPatchMAC, got: {:?}", other);
        }
    }
}

#[tokio::test]
async fn test_missing_previous_set_value_error() {
    // Test that REMOVE operation fails when there's no previous SET
    let initial_state = HashState::default(); // Empty state

    let key_data = b"some-secret-app-state-key-data-!";
    let keys = keys::expand_app_state_keys(key_data);
    let key_id_bytes = b"my_key_id";

    // Try to remove something that was never set
    let remove_mutation = create_test_mutation(
        wa::syncd_mutation::SyncdOperation::Remove,
        &keys,
        key_id_bytes,
        b"nonexistent_index",
        r#"["nonexistent","entry"]"#,
    );

    let patch = wa::SyncdPatch {
        version: Some(wa::SyncdVersion { version: Some(1) }),
        mutations: vec![remove_mutation],
        external_mutations: None,
        snapshot_mac: None,
        patch_mac: Some(vec![0u8; 128]), // MAC doesn't matter for this test
        key_id: Some(wa::KeyId {
            id: Some(key_id_bytes.to_vec()),
        }),
        exit_code: None,
        device_index: None,
        client_debug_data: None,
    };

    let patch_list = PatchList {
        name: "test".to_string(),
        has_more_patches: false,
        patches: vec![patch],
        snapshot: None,
    };

    let key_lookup = |key_id: &[u8]| -> Option<Vec<u8>> {
        if key_id == key_id_bytes {
            Some(key_data.to_vec())
        } else {
            None
        }
    };

    let result = ProcessorUtils::decode_patches_core(&patch_list, initial_state, key_lookup);

    assert!(
        result.is_err(),
        "Should fail when trying to remove non-existent entry"
    );
    assert!(matches!(
        result.unwrap_err(),
        wacore::appstate::errors::AppStateError::MissingPreviousSetValue(_)
    ));
}

// Helper function to create a test mutation
fn create_test_mutation(
    operation: wa::syncd_mutation::SyncdOperation,
    keys: &wacore::appstate::keys::ExpandedAppStateKeys,
    key_id_bytes: &[u8],
    index_mac: &[u8],
    index_json: &str,
) -> wa::SyncdMutation {
    use wacore::crypto::{cbc, hmac_sha512};

    // Create sync action data
    let sync_action_value = wa::SyncActionValue {
        push_name_setting: Some(wa::sync_action_value::PushNameSetting {
            name: Some("Test User".to_string()),
        }),
        ..Default::default()
    };

    let sync_action_data = wa::SyncActionData {
        index: Some(index_json.as_bytes().to_vec()),
        value: Some(sync_action_value),
        padding: Some(vec![]),
        version: Some(1),
    };

    // Encrypt the content
    let plaintext = sync_action_data.encode_to_vec();
    let iv = [1; 16]; // Fixed IV for testability
    let ciphertext = cbc::encrypt(&keys.value_encryption, &iv, &plaintext).unwrap();

    let mut content = Vec::new();
    content.extend_from_slice(&iv);
    content.extend_from_slice(&ciphertext);

    // Generate value MAC
    let value_mac =
        hmac_sha512::generate_content_mac(operation, &content, key_id_bytes, &keys.value_mac);

    let mut value_blob = content;
    value_blob.extend_from_slice(&value_mac);

    wa::SyncdMutation {
        operation: Some(operation as i32),
        record: Some(wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(index_mac.to_vec()),
            }),
            value: Some(wa::SyncdValue {
                blob: Some(value_blob),
            }),
            key_id: Some(wa::KeyId {
                id: Some(key_id_bytes.to_vec()),
            }),
        }),
    }
}

// Helper function to extract value MAC from a mutation
fn extract_value_mac(mutation: &wa::SyncdMutation) -> Vec<u8> {
    let value_blob = mutation
        .record
        .as_ref()
        .unwrap()
        .value
        .as_ref()
        .unwrap()
        .blob
        .as_ref()
        .unwrap();

    // Last 32 bytes are the value MAC
    value_blob[value_blob.len() - 32..].to_vec()
}
