use prost::Message;
use std::sync::Arc;
use whatsapp_proto::whatsapp as wa;
use whatsapp_rust::appstate::{
    keys,
    processor::{Mutation, Processor},
};
use whatsapp_rust::crypto::{cbc, hmac_sha512};
use whatsapp_rust::store::memory::MemoryStore;

#[tokio::test]
async fn test_decode_mutation_success() {
    // 1. Setup
    let store = Arc::new(MemoryStore::new());
    let processor = Processor::new(store.clone(), store.clone());

    // Generate some fake keys
    let key_data = b"some-secret-app-state-key-data-!";
    let expanded_keys = keys::expand_app_state_keys(key_data);
    let key_id_bytes = b"my_key_id";

    // 2. Create a fake mutation to encrypt
    let index_json = r#"["message","12345@c.us","ABCDEFG"]"#;
    let sync_action_value = wa::SyncActionValue {
        push_name_setting: Some(wa::sync_action_value::PushNameSetting {
            name: Some("Test User".to_string()),
        }),
        ..Default::default()
    };
    let sync_action_data = wa::SyncActionData {
        index: Some(index_json.as_bytes().to_vec()),
        value: Some(sync_action_value.clone()),
        padding: Some(vec![]),
        version: Some(1),
    };

    // 3. Encrypt it like the server would
    let plaintext = sync_action_data.encode_to_vec();
    let iv = [1; 16]; // Fixed IV for testability
    let ciphertext = cbc::encrypt(&expanded_keys.value_encryption, &iv, &plaintext).unwrap();

    let mut content = Vec::new();
    content.extend_from_slice(&iv);
    content.extend_from_slice(&ciphertext);

    let value_mac = hmac_sha512::generate_content_mac(
        wa::syncd_mutation::SyncdOperation::Set,
        &content,
        key_id_bytes,
        &expanded_keys.value_mac,
    );

    let mut value_blob = content.clone();
    value_blob.extend_from_slice(&value_mac);

    // 4. Construct the SyncdMutation
    let mutation_proto = wa::SyncdMutation {
        operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
        record: Some(wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(vec![0; 32]), // Fake index mac
            }),
            value: Some(wa::SyncdValue {
                blob: Some(value_blob),
            }),
            key_id: Some(wa::KeyId {
                id: Some(key_id_bytes.to_vec()),
            }),
        }),
        ..Default::default()
    };

    // 5. Run the test
    let mut output_mutations = Vec::<Mutation>::new();
    let result = processor
        .decode_mutation(&expanded_keys, &mutation_proto, &mut output_mutations)
        .await;

    // 6. Assert
    assert!(result.is_ok(), "Decoding failed: {:?}", result.err());
    assert_eq!(output_mutations.len(), 1);

    let decoded = &output_mutations[0];
    assert_eq!(decoded.operation, wa::syncd_mutation::SyncdOperation::Set);
    assert_eq!(decoded.index, vec!["message", "12345@c.us", "ABCDEFG"]);
    assert_eq!(decoded.action, sync_action_value);
}

#[tokio::test]
async fn test_decode_mutation_bad_mac_fails() {
    // Setup is similar to the success test...
    let store = Arc::new(MemoryStore::new());
    let processor = Processor::new(store.clone(), store.clone());
    let key_data = b"some-secret-app-state-key-data-!";
    let expanded_keys = keys::expand_app_state_keys(key_data);
    let key_id_bytes = b"my_key_id";

    let plaintext = b"some fake plaintext".to_vec();
    let iv = [1; 16];
    let ciphertext = cbc::encrypt(&expanded_keys.value_encryption, &iv, &plaintext).unwrap();

    let mut content = Vec::new();
    content.extend_from_slice(&iv);
    content.extend_from_slice(&ciphertext);

    // Use an INCORRECT MAC
    let mut value_mac = hmac_sha512::generate_content_mac(
        wa::syncd_mutation::SyncdOperation::Set,
        &content,
        key_id_bytes,
        &expanded_keys.value_mac,
    );
    value_mac[0] ^= 0xFF; // Flip a bit to make it invalid

    let mut value_blob = content.clone();
    value_blob.extend_from_slice(&value_mac);

    let mutation_proto = wa::SyncdMutation {
        operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
        record: Some(wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(vec![0; 32]),
            }),
            value: Some(wa::SyncdValue {
                blob: Some(value_blob),
            }),
            key_id: Some(wa::KeyId {
                id: Some(key_id_bytes.to_vec()),
            }),
        }),
        ..Default::default()
    };

    let mut output_mutations = Vec::new();
    let result = processor
        .decode_mutation(&expanded_keys, &mutation_proto, &mut output_mutations)
        .await;

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        whatsapp_rust::appstate::errors::AppStateError::MismatchingContentMAC
    ));
    assert!(output_mutations.is_empty());
}
