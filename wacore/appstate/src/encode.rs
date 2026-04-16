use crate::hash::generate_content_mac;
use crate::keys::ExpandedAppStateKeys;
use buffa::Message;
use wacore_libsignal::crypto::{CryptographicMac, aes_256_cbc_encrypt_into};
use waproto::whatsapp as wa;

/// Encode and encrypt a mutation into a SyncdRecord.
///
/// This is the reverse of `decode_record` — it takes plaintext data and produces
/// an encrypted record ready for sending.
///
/// # Returns
/// A tuple of (SyncdMutation, value_mac_bytes) where value_mac is needed for
/// hash state updates and persistence.
pub fn encode_record(
    operation: wa::syncd_mutation::SyncdOperation,
    index: &[u8],
    value: &wa::SyncActionValue,
    keys: &ExpandedAppStateKeys,
    key_id: &[u8],
    iv: &[u8; 16],
) -> (wa::SyncdMutation, [u8; 32]) {
    // 1. Build SyncActionData
    let action_data = wa::SyncActionData {
        index: Some(index.to_vec()),
        value: buffa::MessageField::some(value.clone()),
        padding: Some(vec![]),
        version: Some(1),
        ..Default::default()
    };
    let plaintext = action_data.encode_to_vec();

    // 2. AES-256-CBC encrypt
    let mut ciphertext = Vec::new();
    aes_256_cbc_encrypt_into(&plaintext, &keys.value_encryption, iv, &mut ciphertext)
        .expect("AES encryption should not fail with valid 32-byte key and 16-byte IV");

    // 3. Build IV || ciphertext
    let mut iv_and_cipher = Vec::with_capacity(16 + ciphertext.len());
    iv_and_cipher.extend_from_slice(iv);
    iv_and_cipher.extend_from_slice(&ciphertext);

    // 4. Generate content MAC
    let value_mac = generate_content_mac(operation, &iv_and_cipher, key_id, &keys.value_mac);

    // 5. Complete value blob: IV || ciphertext || MAC
    let mut value_blob = iv_and_cipher;
    value_blob.extend_from_slice(&value_mac);

    // 6. Generate index MAC
    let index_mac = {
        let mut mac = CryptographicMac::new("HmacSha256", &keys.index)
            .expect("HmacSha256 is a valid algorithm");
        mac.update(index);
        mac.finalize()
    };

    // 7. Build the record
    let record = wa::SyncdRecord {
        index: buffa::MessageField::some(wa::SyncdIndex {
            blob: Some(index_mac),
            ..Default::default()
        }),
        value: buffa::MessageField::some(wa::SyncdValue {
            blob: Some(value_blob),
            ..Default::default()
        }),
        key_id: buffa::MessageField::some(wa::KeyId {
            id: Some(key_id.to_vec()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let mutation = wa::SyncdMutation {
        operation: Some(operation),
        record: buffa::MessageField::some(record),
        ..Default::default()
    };

    (mutation, value_mac)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode_record;
    use crate::keys::expand_app_state_keys;

    #[test]
    fn test_encode_then_decode_roundtrip() {
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);
        let key_id = b"test_key_id";
        let iv = [0u8; 16];

        let index = b"[\"setting_pushName\"]";
        let value = wa::SyncActionValue {
            push_name_setting: buffa::MessageField::some(wa::sync_action_value::PushNameSetting {
                name: Some("Test User".to_string()),
                ..Default::default()
            }),
            timestamp: Some(1234567890),
            ..Default::default()
        };

        let (mutation, _value_mac) = encode_record(
            wa::syncd_mutation::SyncdOperation::SET,
            index,
            &value,
            &keys,
            key_id,
            &iv,
        );

        // Decode the encoded record
        let record = &*mutation.record;
        let decoded = decode_record(
            wa::syncd_mutation::SyncdOperation::SET,
            record,
            &keys,
            key_id,
            true, // validate MACs
        )
        .expect("roundtrip decode should succeed");

        assert_eq!(
            decoded.action_value.as_ref().and_then(|v| v.timestamp),
            Some(1234567890)
        );
        assert_eq!(
            decoded
                .action_value
                .as_ref()
                .and_then(|v| v.push_name_setting.as_option())
                .and_then(|p| p.name.as_deref()),
            Some("Test User")
        );
        assert_eq!(decoded.index, vec!["setting_pushName"]);
        assert_eq!(decoded.operation, wa::syncd_mutation::SyncdOperation::SET);
    }
}
