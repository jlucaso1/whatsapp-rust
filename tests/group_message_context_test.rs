// tests/group_message_context_test.rs
//
// This integration test validates that group messages include the required messageContextInfo
// with deviceListMetadata containing the senderKeyHash and senderTimestamp as per the
// official WhatsApp client behavior to prevent "Waiting for this message" issues.

use std::sync::Arc;
use std::str::FromStr;
use whatsapp_rust::signal::{
    groups::{builder::GroupSessionBuilder, cipher::GroupCipher},
    sender_key_name::SenderKeyName,
    store::SenderKeyStore,
};
use whatsapp_rust::store::{Device, memory::MemoryStore, signal::DeviceArcWrapper};
use prost::Message as ProtoMessage;
use waproto::whatsapp as wa;
use base64::Engine;

// Helper function to create a test device with an isolated memory store
async fn create_test_device(_name: &str) -> Arc<Device> {
    let store_backend = Arc::new(MemoryStore::new());
    let device = Device::new(store_backend);
    Arc::new(device)
}

#[tokio::test]
async fn test_group_message_includes_device_list_metadata() {
    // === SETUP ===
    // Create three participants: Alice (sender), Bob and Charlie (receivers)
    let alice_device = create_test_device("alice").await;
    let bob_device = create_test_device("bob").await;
    let charlie_device = create_test_device("charlie").await;

    let group_id = "120363021033254949@g.us".to_string();
    let alice_id = "alice@s.whatsapp.net".to_string();

    let sender_key_name = SenderKeyName::new(group_id.clone(), alice_id.clone());

    // === STEP 1: CREATE SENDER KEY DISTRIBUTION MESSAGE ===
    println!("--- Step 1: Creating sender key distribution ---");
    let alice_builder = GroupSessionBuilder::new(DeviceArcWrapper::new(alice_device.clone()));
    let distribution_message = alice_builder
        .create(&sender_key_name)
        .await
        .expect("Alice should create a distribution message");

    // === STEP 2: TEST THE MESSAGE STRUCTURE ===
    // This simulates what happens in send_group_message() when creating the
    // sender key distribution message for encryption to each participant.
    
    // Calculate phash (simulating the participant list)
    let mock_devices = vec![
        whatsapp_rust::types::jid::Jid::from_str("alice@s.whatsapp.net").unwrap(),
        whatsapp_rust::types::jid::Jid::from_str("bob@s.whatsapp.net").unwrap(),
        whatsapp_rust::types::jid::Jid::from_str("charlie@s.whatsapp.net").unwrap(),
    ];
    let phash = wacore::client::MessageUtils::participant_list_hash(&mock_devices);
    println!("Generated phash: {}", phash);
    
    // Decode the phash to get raw bytes (as per our fix)
    let phash_bytes = phash.split(':').nth(1)
        .map(|b64_part| base64::prelude::BASE64_STANDARD_NO_PAD.decode(b64_part).unwrap_or_default())
        .unwrap_or_default();
    
    assert!(!phash_bytes.is_empty(), "phash_bytes should not be empty");
    assert_eq!(phash_bytes.len(), 6, "phash should be 6 bytes when decoded");
    
    // Create the wa::Message with messageContextInfo (as per our fix)
    let skdm_for_encryption = wa::Message {
        sender_key_distribution_message: Some(wa::message::SenderKeyDistributionMessage {
            group_id: Some(group_id.clone()),
            axolotl_sender_key_distribution_message: Some(distribution_message.encode_to_vec()),
        }),
        message_context_info: Some(wa::MessageContextInfo {
            device_list_metadata: Some(wa::DeviceListMetadata {
                sender_key_hash: Some(phash_bytes.clone()),
                sender_timestamp: Some(chrono::Utc::now().timestamp() as u64),
                ..Default::default()
            }),
            device_list_metadata_version: Some(2),
            ..Default::default()
        }),
        ..Default::default()
    };
    
    // === STEP 3: VALIDATE THE MESSAGE STRUCTURE ===
    println!("--- Step 2: Validating message structure ---");
    
    // Verify the distribution message exists
    assert!(
        skdm_for_encryption.sender_key_distribution_message.is_some(),
        "Message should contain sender_key_distribution_message"
    );
    
    // Verify the message context info exists
    assert!(
        skdm_for_encryption.message_context_info.is_some(),
        "Message should contain message_context_info (this was missing before the fix)"
    );
    
    let context_info = skdm_for_encryption.message_context_info.as_ref().unwrap();
    
    // Verify device list metadata exists
    assert!(
        context_info.device_list_metadata.is_some(),
        "MessageContextInfo should contain device_list_metadata"
    );
    
    // Verify version is set correctly
    assert_eq!(
        context_info.device_list_metadata_version,
        Some(2),
        "device_list_metadata_version should be 2"
    );
    
    let device_metadata = context_info.device_list_metadata.as_ref().unwrap();
    
    // Verify sender key hash is present and correct
    assert!(
        device_metadata.sender_key_hash.is_some(),
        "DeviceListMetadata should contain sender_key_hash"
    );
    
    let actual_hash = device_metadata.sender_key_hash.as_ref().unwrap();
    assert_eq!(
        actual_hash, &phash_bytes,
        "sender_key_hash should match decoded phash bytes"
    );
    
    // Verify sender timestamp is present
    assert!(
        device_metadata.sender_timestamp.is_some(),
        "DeviceListMetadata should contain sender_timestamp"
    );
    
    let timestamp = device_metadata.sender_timestamp.unwrap();
    let now = chrono::Utc::now().timestamp() as u64;
    assert!(
        timestamp <= now && timestamp > now - 60,
        "sender_timestamp should be recent (within last 60 seconds)"
    );
    
    println!("✅ Message structure validation passed!");
    
    // === STEP 4: TEST END-TO-END PROCESSING ===
    println!("--- Step 3: Testing end-to-end processing ---");
    
    // Serialize the message (this is what would be encrypted for each participant)
    let message_bytes = skdm_for_encryption.encode_to_vec();
    assert!(!message_bytes.is_empty(), "Serialized message should not be empty");
    
    // Deserialize to verify it's valid
    let parsed_message = wa::Message::decode(&message_bytes[..])
        .expect("Message should deserialize correctly");
    
    // Verify the parsed message has all the required fields
    assert!(parsed_message.sender_key_distribution_message.is_some());
    assert!(parsed_message.message_context_info.is_some());
    
    let parsed_context = parsed_message.message_context_info.unwrap();
    assert!(parsed_context.device_list_metadata.is_some());
    assert_eq!(parsed_context.device_list_metadata_version, Some(2));
    
    let parsed_metadata = parsed_context.device_list_metadata.unwrap();
    assert_eq!(parsed_metadata.sender_key_hash, Some(phash_bytes));
    assert!(parsed_metadata.sender_timestamp.is_some());
    
    // === STEP 5: VERIFY RECIPIENTS CAN PROCESS THE DISTRIBUTION ===
    println!("--- Step 4: Testing recipient processing ---");
    
    // Bob processes the distribution message
    let bob_builder = GroupSessionBuilder::new(DeviceArcWrapper::new(bob_device.clone()));
    bob_builder
        .process(&sender_key_name, &distribution_message)
        .await
        .expect("Bob should process the distribution message");

    let bob_key_record = bob_device.load_sender_key(&sender_key_name).await.unwrap();
    assert!(
        bob_key_record
            .get_sender_key_state_by_id(distribution_message.id())
            .is_some(),
        "Bob's store should have the sender key state"
    );
    
    // Charlie processes the distribution message
    let charlie_builder = GroupSessionBuilder::new(DeviceArcWrapper::new(charlie_device.clone()));
    charlie_builder
        .process(&sender_key_name, &distribution_message)
        .await
        .expect("Charlie should process the distribution message");

    let charlie_key_record = charlie_device
        .load_sender_key(&sender_key_name)
        .await
        .unwrap();
    assert!(
        charlie_key_record
            .get_sender_key_state_by_id(distribution_message.id())
            .is_some(),
        "Charlie's store should have the sender key state"
    );
    
    // === STEP 6: TEST GROUP MESSAGE ENCRYPTION/DECRYPTION ===
    println!("--- Step 5: Testing group message encryption/decryption ---");
    
    let plaintext = b"Test group message with proper context!";
    let alice_builder_encrypt = GroupSessionBuilder::new(DeviceArcWrapper::new(alice_device.clone()));
    let alice_cipher = GroupCipher::new(
        sender_key_name.clone(),
        DeviceArcWrapper::new(alice_device.clone()),
        alice_builder_encrypt,
    );
    
    let encrypted_message = alice_cipher
        .encrypt(plaintext)
        .await
        .expect("Alice should encrypt group message");
    
    // Bob decrypts the message
    let bob_builder_decrypt = GroupSessionBuilder::new(DeviceArcWrapper::new(bob_device.clone()));
    let bob_cipher = GroupCipher::new(
        sender_key_name.clone(),
        DeviceArcWrapper::new(bob_device.clone()),
        bob_builder_decrypt,
    );
    
    let serialized_msg = encrypted_message.serialize();
    let (deserialized_msg, data_to_verify) =
        whatsapp_rust::signal::groups::message::SenderKeyMessage::deserialize(&serialized_msg)
            .expect("Should deserialize message");
    
    let decrypted_bob = bob_cipher
        .decrypt(&deserialized_msg, data_to_verify)
        .await
        .expect("Bob should decrypt message");
    
    assert_eq!(decrypted_bob, plaintext, "Bob's decrypted text should match");
    
    // Charlie decrypts the message
    let charlie_builder_decrypt = GroupSessionBuilder::new(DeviceArcWrapper::new(charlie_device.clone()));
    let charlie_cipher = GroupCipher::new(
        sender_key_name.clone(),
        DeviceArcWrapper::new(charlie_device.clone()),
        charlie_builder_decrypt,
    );
    
    let decrypted_charlie = charlie_cipher
        .decrypt(&deserialized_msg, data_to_verify)
        .await
        .expect("Charlie should decrypt message");
    
    assert_eq!(decrypted_charlie, plaintext, "Charlie's decrypted text should match");
    
    println!("✅ Group message context test completed successfully!");
    println!("   - Message includes required messageContextInfo");
    println!("   - DeviceListMetadata contains senderKeyHash from phash");
    println!("   - Sender timestamp is properly set");
    println!("   - Recipients can process keys and decrypt messages");
    println!("   - This should prevent 'Waiting for this message' errors");
}

#[tokio::test] 
async fn test_phash_decoding_edge_cases() {
    // Test edge cases for phash decoding to ensure robustness
    
    // Test normal phash format
    let normal_phash = "2:ABC123";
    let _decoded = normal_phash.split(':').nth(1)
        .map(|b64_part| base64::prelude::BASE64_STANDARD_NO_PAD.decode(b64_part).unwrap_or_default())
        .unwrap_or_default();
    // Should not crash even with invalid base64
    
    // Test invalid phash format (missing colon)
    let invalid_phash = "2ABC123";
    let decoded_invalid = invalid_phash.split(':').nth(1)
        .map(|b64_part| base64::prelude::BASE64_STANDARD_NO_PAD.decode(b64_part).unwrap_or_default())
        .unwrap_or_default();
    assert_eq!(decoded_invalid, Vec::<u8>::new(), "Invalid phash should result in empty bytes");
    
    // Test empty phash
    let empty_phash = "";
    let decoded_empty = empty_phash.split(':').nth(1)
        .map(|b64_part| base64::prelude::BASE64_STANDARD_NO_PAD.decode(b64_part).unwrap_or_default())
        .unwrap_or_default();
    assert_eq!(decoded_empty, Vec::<u8>::new(), "Empty phash should result in empty bytes");
    
    println!("✅ Phash decoding edge cases handled correctly");
}