use wacore::appstate::expand_app_state_keys;
use wacore::appstate::hash::{HashState, generate_content_mac, generate_patch_mac};
use waproto::whatsapp as wa;

// Helper to build a SyncdRecord with provided key id and value blob (iv+ciphertext+valuemac appended later in logic)
fn make_record(key_id: &[u8], value_with_mac: Vec<u8>, index_mac: Vec<u8>) -> wa::SyncdRecord {
    wa::SyncdRecord {
        index: Some(wa::SyncdIndex {
            blob: Some(index_mac),
        }),
        value: Some(wa::SyncdValue {
            blob: Some(value_with_mac),
        }),
        key_id: Some(wa::KeyId {
            id: Some(key_id.to_vec()),
        }),
    }
}

#[test]
fn snapshot_and_patch_mac_roundtrip() {
    // Deterministic pseudo key
    let master_key = [7u8; 32];
    let keys = expand_app_state_keys(&master_key);

    // Build two dummy mutations for a patch: we simulate already encrypted+MACed value blobs.
    // For content MAC we need operation byte (Set=0 -> +1 =1), key id, and data (iv+ciphertext+? but we treat first part as 'data').
    let key_id = b"abc"; // small key id
    let mut state = HashState::default();

    // For simplicity craft value blobs: 16 bytes IV + ciphertext bytes + 32 byte value MAC.
    // We'll not decrypt; we only test MAC calculation consistency.
    let iv = [1u8; 16];
    let ciphertext1 = b"cipher_one".to_vec();
    let mut content1 = iv.to_vec();
    content1.extend_from_slice(&ciphertext1);
    let value_mac1 = generate_content_mac(
        wa::syncd_mutation::SyncdOperation::Set,
        &content1,
        key_id,
        &keys.value_mac,
    );
    let mut value_blob1 = content1.clone();
    value_blob1.extend_from_slice(&value_mac1);

    let ciphertext2 = b"cipher_two".to_vec();
    let mut content2 = iv.to_vec();
    content2.extend_from_slice(&ciphertext2);
    let value_mac2 = generate_content_mac(
        wa::syncd_mutation::SyncdOperation::Set,
        &content2,
        key_id,
        &keys.value_mac,
    );
    let mut value_blob2 = content2.clone();
    value_blob2.extend_from_slice(&value_mac2);

    // Fake index MACs (normally HMAC over JSON index); we just store arbitrary 32 bytes.
    let index_mac1 = vec![9u8; 32];
    let index_mac2 = vec![8u8; 32];

    let mutation1 = wa::SyncdMutation {
        operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
        record: Some(make_record(key_id, value_blob1.clone(), index_mac1.clone())),
    };
    let mutation2 = wa::SyncdMutation {
        operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
        record: Some(make_record(key_id, value_blob2.clone(), index_mac2.clone())),
    };

    let mutations = vec![mutation1.clone(), mutation2.clone()];

    // Update state hash with mutations (simulate snapshot or patch application)
    let (_warn, res) = state.update_hash(&mutations, |_idx, _i| Ok(None));
    res.expect("update hash");
    state.version = 1;

    // Compute snapshot MAC for this state
    let snapshot_mac = state.generate_snapshot_mac("regular_high", &keys.snapshot_mac);

    // Now build a patch referencing snapshot MAC and containing same mutations to compute patch MAC
    let patch = wa::SyncdPatch {
        version: Some(wa::SyncdVersion {
            version: Some(state.version),
        }),
        mutations: mutations.clone(),
        external_mutations: None,
        snapshot_mac: Some(snapshot_mac.clone()),
        patch_mac: None,
        key_id: Some(wa::KeyId {
            id: Some(key_id.to_vec()),
        }),
        exit_code: None,
        device_index: None,
        client_debug_data: None,
    };

    let patch_mac = generate_patch_mac(&patch, "regular_high", &keys.patch_mac, state.version);

    // Basic invariants
    assert_ne!(
        snapshot_mac, patch_mac,
        "snapshot and patch MACs should differ"
    );
    assert_eq!(snapshot_mac.len(), 32); // HMAC-SHA256 length
    assert_eq!(patch_mac.len(), 32);

    // Mutate a value MAC and ensure patch MAC changes
    let mut altered_patch = patch.clone();
    if let Some(rec) = altered_patch.mutations[0].record.as_mut()
        && let Some(val) = rec.value.as_mut()
        && let Some(blob) = val.blob.as_mut()
    {
        let last = blob.len() - 1;
        blob[last] ^= 0x55; // flip a bit inside value MAC
    }
    let altered_patch_mac = generate_patch_mac(
        &altered_patch,
        "regular_high",
        &keys.patch_mac,
        state.version,
    );
    assert_ne!(
        patch_mac, altered_patch_mac,
        "patch MAC must change if a value MAC mutates"
    );
}
