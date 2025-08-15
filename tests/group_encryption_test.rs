#[cfg(test)]
mod tests {
    use base64::Engine;
    use wacore::libsignal::protocol::{
        DeviceId, ProtocolAddress, SenderKeyMessage, SenderKeyRecord, SenderKeyStore, group_encrypt,
    };
    use prost::Message;
    use rand::TryRngCore;
    use serde::Deserialize;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use waproto::whatsapp as wa;
    use whatsapp_rust::store::Device;
    use whatsapp_rust::store::sqlite_store::SqliteStore;

    /// A helper struct to deserialize the specific JSON format for the SenderKeyRecord
    /// that was captured from the Go implementation.
    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct GoSenderKeyRecord {
        sender_key_states: Vec<GoSenderKeyState>,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct GoSenderKeyState {
        #[serde(rename = "KeyID")]
        key_id: u32,
        sender_chain_key: GoSenderChainKey,
        signing_key_public: String,
        signing_key_private: String,
    }

    #[derive(Deserialize, Debug)]
    #[serde(rename_all = "PascalCase")]
    struct GoSenderChainKey {
        iteration: u32,
        chain_key: String, // This is a base64 encoded string, equivalent to the 'seed'
    }

    #[tokio::test]
    async fn test_group_encryption_against_go_capture() {
        // 1. --- SETUP: Load all necessary files from the capture directory ---
        let base_path = Path::new("tests/captured_sent_group/20250811_193308");

        // 1a. Load and parse the sender key name to identify the session.
        let name_content = fs::read_to_string(base_path.join("sender_key_name.txt"))
            .unwrap_or_else(|e| {
                panic!(
                    "Failed to read sender_key_name.txt at {:?}: {}",
                    base_path, e
                )
            });

        let mut group_id = "";
        let mut sender_id_str = "";
        for line in name_content.lines() {
            if let Some(val) = line.strip_prefix("GroupID: ") {
                group_id = val;
            } else if let Some(val) = line.strip_prefix("Sender: ") {
                sender_id_str = val;
            }
        }
        assert!(
            !group_id.is_empty(),
            "GroupID not found in sender_key_name.txt"
        );
        assert!(
            !sender_id_str.is_empty(),
            "Sender not found in sender_key_name.txt"
        );

        // Manually parse the sender_id_str (e.g., "user_1:42") into its components.
        let sender_parts: Vec<&str> = sender_id_str.split(':').collect();
        assert_eq!(
            sender_parts.len(),
            2,
            "Sender ID format should be 'name:device_id'"
        );
        let sender_name = sender_parts[0].to_string();
        let sender_device_id: u32 = sender_parts[1].parse().expect("Failed to parse device ID");

        // The group sender address is a composite of the group ID and the sender's own address.
        let sender_address = ProtocolAddress::new(sender_name, DeviceId::from(sender_device_id));
        let group_sender_address =
            ProtocolAddress::new(format!("{}\n{}", group_id, sender_address), 0.into());

        // 1b. Load and deserialize the SenderKeyRecord from the JSON file.
        let record_json_str = fs::read_to_string(base_path.join("sender_key_record.bin"))
            .expect("Failed to read sender_key_record.bin");

        let go_record: GoSenderKeyRecord = serde_json::from_str(&record_json_str)
            .expect("Failed to parse Go SenderKeyRecord JSON");

        // Convert the Go structure to the Rust libsignal protobuf structure.
        let mut sender_key_states = Vec::new();
        for go_state in go_record.sender_key_states {
            let signing_key_public = base64::prelude::BASE64_STANDARD
                .decode(go_state.signing_key_public)
                .expect("Failed to decode signing key public");
            let signing_key_private = base64::prelude::BASE64_STANDARD
                .decode(go_state.signing_key_private)
                .expect("Failed to decode signing key private");
            let chain_key_seed = base64::prelude::BASE64_STANDARD
                .decode(go_state.sender_chain_key.chain_key)
                .expect("Failed to decode chain key seed");

            let state_structure = wa::SenderKeyStateStructure {
                sender_key_id: Some(go_state.key_id),
                sender_chain_key: Some(wa::sender_key_state_structure::SenderChainKey {
                    iteration: Some(go_state.sender_chain_key.iteration),
                    seed: Some(chain_key_seed),
                }),
                sender_signing_key: Some(wa::sender_key_state_structure::SenderSigningKey {
                    public: Some(signing_key_public),
                    private: Some(signing_key_private),
                }),
                sender_message_keys: Vec::new(),
            };
            sender_key_states.push(state_structure);
        }

        let record_proto = wa::SenderKeyRecordStructure { sender_key_states };
        let record_proto_bytes = record_proto.encode_to_vec();
        let mut sender_key_record = SenderKeyRecord::deserialize(&record_proto_bytes)
            .expect("Failed to deserialize SenderKeyRecord protobuf from constructed bytes");

        // The Rust libsignal implementation expects a message key to be present, but the
        // captured Go state doesn't have one yet. We need to manually add a message key
        // for the *current* iteration without advancing the chain key. The group_encrypt
        // function will then use this key and advance the chain itself.
        let state = sender_key_record
            .sender_key_state_mut()
            .expect("SenderKeyRecord must have at least one state");

        let current_chain_key = state
            .sender_chain_key()
            .expect("State must have a chain key"); // Unwraps the Option

        // Derive the message key from the *current* chain key but do NOT advance the chain key state.
        let new_message_key = current_chain_key.sender_message_key();
        state.add_sender_message_key(&new_message_key);

        // 1c. Load the plaintext input and the expected ciphertext output.
        let plaintext =
            fs::read(base_path.join("plaintext.bin")).expect("Failed to read plaintext.bin");
        let expected_ciphertext_bytes = fs::read(base_path.join("expected_ciphertext.bin"))
            .expect("Failed to read expected_ciphertext.bin");

        // 2. --- SETUP STORE: Initialize an in-memory store and load the state ---
        let store_backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
        let mut device = Device::new(store_backend);
        device
            .store_sender_key(&group_sender_address, &sender_key_record)
            .await
            .expect("Failed to store sender key record");

        // 3. --- EXECUTE: Perform the encryption using the loaded state ---
        let encrypted_message = group_encrypt(
            &mut device,
            &group_sender_address,
            &plaintext,
            &mut rand::rngs::OsRng.unwrap_err(),
        )
        .await
        .expect("Group encryption failed");

        // 4. --- ASSERT: Validate the generated ciphertext ---

        // 4a. Deserialize the expected ciphertext from the Go capture
        let expected_skm = SenderKeyMessage::try_from(expected_ciphertext_bytes.as_slice())
            .expect("Failed to deserialize expected ciphertext");

        // 4b. Compare the deterministic fields
        assert_eq!(
            encrypted_message.chain_id(),
            expected_skm.chain_id(),
            "SenderKeyMessage ID mismatch"
        );
        assert_eq!(
            encrypted_message.iteration(),
            expected_skm.iteration(),
            "SenderKeyMessage iteration mismatch"
        );
        assert_eq!(
            encrypted_message.ciphertext(),
            expected_skm.ciphertext(),
            "SenderKeyMessage AES ciphertext mismatch"
        );

        // 4c. Verify the signature of the Rust-generated message
        let signing_key_public = sender_key_record
            .sender_key_state()
            .unwrap()
            .signing_key_public()
            .unwrap();
        let verification_result = encrypted_message.verify_signature(&signing_key_public);
        assert!(
            verification_result.is_ok(),
            "Signature verification failed for the Rust-generated ciphertext: {:?}",
            verification_result.err()
        );

        println!("✅ Test passed: Rust group encryption matches the Go implementation!");
    }
}
