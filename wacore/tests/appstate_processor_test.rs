use hkdf::hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use wacore::appstate::{
    errors::AppStateError,
    keys,
    processor::{Mutation, ProcessorUtils},
};
use wacore::crypto::{cbc, hmac_sha512};
use waproto::whatsapp as wa;

#[test]
fn test_decode_mutation_success_with_valid_macs() {
    let key_data = b"a-correct-32-byte-secret-key-!!";
    let expanded_keys = keys::expand_app_state_keys(key_data);
    let key_id_bytes = b"key_id_1";

    let index_json = r#"["archive","1234567890@s.whatsapp.net"]"#;
    let sync_action_value = wa::SyncActionValue {
        archive_chat_action: Some(wa::sync_action_value::ArchiveChatAction {
            archived: Some(true),
            message_range: None,
        }),
        ..Default::default()
    };
    let sync_action_data = wa::SyncActionData {
        index: Some(index_json.as_bytes().to_vec()),
        value: Some(sync_action_value.clone()),
        padding: Some(vec![]),
        version: Some(1),
    };
    let plaintext = sync_action_data.encode_to_vec();

    let iv = [1; 16];
    let ciphertext = cbc::encrypt(&expanded_keys.value_encryption, &iv, &plaintext).unwrap();
    let mut encrypted_content_with_iv = Vec::new();
    encrypted_content_with_iv.extend_from_slice(&iv);
    encrypted_content_with_iv.extend_from_slice(&ciphertext);

    let value_mac = hmac_sha512::generate_content_mac(
        wa::syncd_mutation::SyncdOperation::Set,
        &encrypted_content_with_iv,
        key_id_bytes,
        &expanded_keys.value_mac,
    );
    let mut value_blob = encrypted_content_with_iv.clone();
    value_blob.extend_from_slice(&value_mac);

    let mut index_mac_hasher = Hmac::<Sha256>::new_from_slice(&expanded_keys.index).unwrap();
    index_mac_hasher.update(index_json.as_bytes());
    let index_mac = index_mac_hasher.finalize().into_bytes().to_vec();

    let mutation_proto = wa::SyncdMutation {
        operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
        record: Some(wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(index_mac.clone()),
            }),
            value: Some(wa::SyncdValue {
                blob: Some(value_blob),
            }),
            key_id: Some(wa::KeyId {
                id: Some(key_id_bytes.to_vec()),
            }),
        }),
    };

    let mut output_mutations = Vec::<Mutation>::new();
    let result =
        ProcessorUtils::decode_mutation(&expanded_keys, &mutation_proto, &mut output_mutations);

    assert!(
        result.is_ok(),
        "Decoding failed unexpectedly: {:?}",
        result.err()
    );
    assert_eq!(output_mutations.len(), 1);

    let decoded = &output_mutations[0];
    assert_eq!(decoded.operation, wa::syncd_mutation::SyncdOperation::Set);
    assert_eq!(decoded.index, vec!["archive", "1234567890@s.whatsapp.net"]);
    assert_eq!(decoded.action, sync_action_value);

    assert_eq!(decoded.index_mac, index_mac.as_slice());
    assert_eq!(decoded.value_mac, value_mac.as_slice());
}

#[test]
fn test_decode_mutation_bad_value_mac_fails() {
    let key_data = b"a-correct-32-byte-secret-key-!!";
    let expanded_keys = keys::expand_app_state_keys(key_data);
    let key_id_bytes = b"key_id_1";

    let index_json = r#"["archive","1234567890@s.whatsapp.net"]"#;
    let sync_action_data = wa::SyncActionData {
        index: Some(index_json.as_bytes().to_vec()),
        ..Default::default()
    };
    let plaintext = sync_action_data.encode_to_vec();
    let iv = [1; 16];
    let ciphertext = cbc::encrypt(&expanded_keys.value_encryption, &iv, &plaintext).unwrap();
    let mut encrypted_content_with_iv = Vec::new();
    encrypted_content_with_iv.extend_from_slice(&iv);
    encrypted_content_with_iv.extend_from_slice(&ciphertext);

    let mut value_mac = hmac_sha512::generate_content_mac(
        wa::syncd_mutation::SyncdOperation::Set,
        &encrypted_content_with_iv,
        key_id_bytes,
        &expanded_keys.value_mac,
    );
    value_mac[0] ^= 0xFF;

    let mut value_blob = encrypted_content_with_iv.clone();
    value_blob.extend_from_slice(&value_mac);

    let mut index_mac_hasher = Hmac::<Sha256>::new_from_slice(&expanded_keys.index).unwrap();
    index_mac_hasher.update(index_json.as_bytes());
    let index_mac = index_mac_hasher.finalize().into_bytes().to_vec();

    let mutation_proto = wa::SyncdMutation {
        operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
        record: Some(wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(index_mac),
            }),
            value: Some(wa::SyncdValue {
                blob: Some(value_blob),
            }),
            key_id: Some(wa::KeyId {
                id: Some(key_id_bytes.to_vec()),
            }),
        }),
    };

    let mut output_mutations = Vec::new();
    let result =
        ProcessorUtils::decode_mutation(&expanded_keys, &mutation_proto, &mut output_mutations);

    assert!(
        result.is_err(),
        "Decoding should have failed due to bad Value MAC"
    );
    assert!(matches!(
        result.unwrap_err(),
        AppStateError::MismatchingContentMAC(_)
    ));
    assert!(output_mutations.is_empty());
}

#[test]
fn test_decode_mutation_bad_index_mac_fails() {
    let key_data = b"a-correct-32-byte-secret-key-!!";
    let expanded_keys = keys::expand_app_state_keys(key_data);
    let key_id_bytes = b"key_id_1";

    let index_json = r#"["archive","1234567890@s.whatsapp.net"]"#;
    let sync_action_data = wa::SyncActionData {
        index: Some(index_json.as_bytes().to_vec()),
        ..Default::default()
    };
    let plaintext = sync_action_data.encode_to_vec();
    let iv = [1; 16];
    let ciphertext = cbc::encrypt(&expanded_keys.value_encryption, &iv, &plaintext).unwrap();
    let mut encrypted_content_with_iv = Vec::new();
    encrypted_content_with_iv.extend_from_slice(&iv);
    encrypted_content_with_iv.extend_from_slice(&ciphertext);

    let value_mac = hmac_sha512::generate_content_mac(
        wa::syncd_mutation::SyncdOperation::Set,
        &encrypted_content_with_iv,
        key_id_bytes,
        &expanded_keys.value_mac,
    );
    let mut value_blob = encrypted_content_with_iv.clone();
    value_blob.extend_from_slice(&value_mac);

    let mut index_mac_hasher = Hmac::<Sha256>::new_from_slice(&expanded_keys.index).unwrap();
    index_mac_hasher.update(index_json.as_bytes());
    let mut index_mac = index_mac_hasher.finalize().into_bytes().to_vec();
    index_mac[5] ^= 0xFF;

    let mutation_proto = wa::SyncdMutation {
        operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
        record: Some(wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(index_mac),
            }),
            value: Some(wa::SyncdValue {
                blob: Some(value_blob),
            }),
            key_id: Some(wa::KeyId {
                id: Some(key_id_bytes.to_vec()),
            }),
        }),
    };

    let mut output_mutations = Vec::new();
    let result =
        ProcessorUtils::decode_mutation(&expanded_keys, &mutation_proto, &mut output_mutations);

    assert!(
        result.is_err(),
        "Decoding should have failed due to bad Index MAC"
    );
    assert!(matches!(
        result.unwrap_err(),
        AppStateError::MismatchingIndexMAC
    ));
    assert!(output_mutations.is_empty());
}
