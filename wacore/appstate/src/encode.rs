//! Mutation encoding and encryption for app state sync actions.
//!
//! This module provides functionality to encode and encrypt sync action mutations
//! for pushing to WhatsApp servers.

use crate::hash::generate_content_mac;
use crate::keys::ExpandedAppStateKeys;
use prost::Message;
use rand::RngCore;
use wacore_libsignal::crypto::aes_256_cbc_encrypt_into;
use waproto::whatsapp as wa;

/// Encrypted mutation ready to be included in a patch.
#[derive(Debug, Clone)]
pub struct EncryptedMutation {
    /// The MAC of the index (used as the index blob).
    pub index_mac: Vec<u8>,
    /// The encrypted value blob (IV || ciphertext || value_mac).
    pub value_blob: Vec<u8>,
    /// The MAC of the value (last 32 bytes of value_blob).
    pub value_mac: Vec<u8>,
}

/// Error during mutation encoding.
#[derive(Debug, thiserror::Error)]
pub enum EncodeError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    #[error("JSON serialization failed: {0}")]
    JsonFailed(#[from] serde_json::Error),
}

/// Generate padding for sync action data.
/// Note: whatsmeow uses empty padding, so we follow that pattern.
fn generate_padding() -> Vec<u8> {
    Vec::new()
}

/// Generate a random 16-byte IV for AES-256-CBC.
fn generate_iv() -> [u8; 16] {
    let mut iv = [0u8; 16];
    rand::rng().fill_bytes(&mut iv);
    iv
}

/// Generate the index MAC from the index JSON bytes.
pub fn generate_index_mac(index_json: &[u8], key: &[u8; 32]) -> Vec<u8> {
    use wacore_libsignal::crypto::CryptographicMac;
    let mut mac =
        CryptographicMac::new("HmacSha256", key).expect("HmacSha256 is a valid algorithm");
    mac.update(index_json);
    mac.finalize()
}

/// Encrypt a sync action mutation.
///
/// This function takes the action components and produces an encrypted mutation
/// that can be included in a SyncdPatch.
///
/// # Arguments
/// * `index` - The index array (e.g., `["deleteMessageForMe", chatJid, msgId, fromMe, participant]`)
/// * `value` - The SyncActionValue protobuf
/// * `keys` - The expanded app state keys for encryption
/// * `key_id` - The key ID bytes
/// * `operation` - The operation type (SET or REMOVE)
/// * `version` - The action version number (different actions have different versions)
pub fn encrypt_mutation(
    index: &[String],
    value: &wa::SyncActionValue,
    keys: &ExpandedAppStateKeys,
    key_id: &[u8],
    operation: wa::syncd_mutation::SyncdOperation,
    version: i32,
) -> Result<EncryptedMutation, EncodeError> {
    // 1. Encode index to JSON
    let index_json = serde_json::to_vec(index)?;

    // 2. Generate index MAC
    let index_mac = generate_index_mac(&index_json, &keys.index);

    // 3. Build SyncActionData
    let action_data = wa::SyncActionData {
        index: Some(index_json),
        value: Some(value.clone()),
        padding: Some(generate_padding()),
        version: Some(version),
    };
    let plaintext = action_data.encode_to_vec();

    // 4. Encrypt with AES-256-CBC
    let iv = generate_iv();
    let mut ciphertext = Vec::new();
    aes_256_cbc_encrypt_into(&plaintext, &keys.value_encryption, &iv, &mut ciphertext)
        .map_err(|e| EncodeError::EncryptionFailed(format!("{:?}", e)))?;

    // 5. Build value blob: IV || ciphertext
    let mut value_with_iv = iv.to_vec();
    value_with_iv.extend_from_slice(&ciphertext);

    // 6. Generate value MAC
    let value_mac = generate_content_mac(operation, &value_with_iv, key_id, &keys.value_mac);

    // 7. Append value MAC to blob
    let mut value_blob = value_with_iv;
    value_blob.extend_from_slice(&value_mac);

    Ok(EncryptedMutation {
        index_mac,
        value_blob,
        value_mac,
    })
}

/// Build a SyncdMutation proto from an encrypted mutation.
pub fn build_syncd_mutation(
    encrypted: &EncryptedMutation,
    key_id: &[u8],
    operation: wa::syncd_mutation::SyncdOperation,
) -> wa::SyncdMutation {
    wa::SyncdMutation {
        operation: Some(operation as i32),
        record: Some(wa::SyncdRecord {
            index: Some(wa::SyncdIndex {
                blob: Some(encrypted.index_mac.clone()),
            }),
            value: Some(wa::SyncdValue {
                blob: Some(encrypted.value_blob.clone()),
            }),
            key_id: Some(wa::KeyId {
                id: Some(key_id.to_vec()),
            }),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode_record;
    use crate::keys::expand_app_state_keys;

    #[test]
    fn test_encrypt_mutation_roundtrip() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id".to_vec();

        let index = vec![
            "deleteMessageForMe".to_string(),
            "1234567890@s.whatsapp.net".to_string(),
            "msg123".to_string(),
            "1".to_string(),
            "0".to_string(),
        ];

        let value = wa::SyncActionValue {
            timestamp: Some(chrono::Utc::now().timestamp_millis()),
            delete_message_for_me_action: Some(wa::sync_action_value::DeleteMessageForMeAction {
                delete_media: Some(true),
                message_timestamp: Some(chrono::Utc::now().timestamp_millis()),
            }),
            ..Default::default()
        };

        let encrypted = encrypt_mutation(
            &index,
            &value,
            &keys,
            &key_id,
            wa::syncd_mutation::SyncdOperation::Set,
            2, // version for deleteMessageForMe
        )
        .expect("encryption should succeed");

        // Build the SyncdMutation and verify we can decode it back
        let syncd_mutation =
            build_syncd_mutation(&encrypted, &key_id, wa::syncd_mutation::SyncdOperation::Set);

        let record = syncd_mutation.record.as_ref().expect("should have record");
        let decoded = decode_record(
            wa::syncd_mutation::SyncdOperation::Set,
            record,
            &keys,
            &key_id,
            true, // validate MACs
        )
        .expect("decoding should succeed");

        // Verify the decoded values match
        assert_eq!(decoded.index, index);
        assert!(decoded.action_value.is_some());
        let decoded_value = decoded.action_value.unwrap();
        assert!(decoded_value.delete_message_for_me_action.is_some());
        assert_eq!(
            decoded_value
                .delete_message_for_me_action
                .unwrap()
                .delete_media,
            Some(true)
        );
    }

    #[test]
    fn test_index_mac_generation() {
        let key = [1u8; 32];
        let index = vec!["test".to_string()];
        let index_json = serde_json::to_vec(&index).unwrap();
        let mac = generate_index_mac(&index_json, &key);
        assert_eq!(mac.len(), 32);

        // Same input should produce same MAC
        let mac2 = generate_index_mac(&index_json, &key);
        assert_eq!(mac, mac2);
    }

    /// Test index MAC generation against known good values from whatsmeow.
    /// These values were verified by running identical Go code.
    #[test]
    fn test_index_mac_matches_whatsmeow() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);

        // Test with a pin action index
        let index = vec!["pin_v1".to_string(), "123456789@s.whatsapp.net".to_string()];
        let index_json = serde_json::to_vec(&index).unwrap();

        // Verify JSON format matches Go's json.Marshal
        assert_eq!(
            String::from_utf8_lossy(&index_json),
            r#"["pin_v1","123456789@s.whatsapp.net"]"#
        );

        let index_mac = generate_index_mac(&index_json, &keys.index);

        // Expected value verified against whatsmeow Go implementation
        assert_eq!(
            hex::encode(&index_mac),
            "0b2ddc797081ee121781a9dade1ce6367a34a050a0057ac72555400d267a04a2",
            "Index MAC mismatch"
        );
    }
}
