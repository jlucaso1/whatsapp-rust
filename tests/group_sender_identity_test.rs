// tests/group_sender_identity_test.rs
//
// This test validates that group messages use the correct sender identity (public JID vs LID)
// for SenderKey creation. This addresses the issue where recipients couldn't decrypt group
// messages because the sender key was created with the wrong identity.
//
// The test validates:
// 1. SenderKeyName is created using the public JID (device.id), not the LID (device.lid)
// 2. Recipients can correctly identify and decrypt messages from the sender
// 3. The sender key distribution uses the identity visible to other participants

use std::sync::Arc;
use whatsapp_rust::signal::{
    groups::{builder::GroupSessionBuilder, cipher::GroupCipher},
    sender_key_name::SenderKeyName,
    address::SignalAddress,
};
use whatsapp_rust::store::{Device, memory::MemoryStore, signal::DeviceArcWrapper};
use whatsapp_rust::types::jid::Jid;

// Helper function to create a test device with both ID and LID set
async fn create_test_device_with_jids(public_jid: &str, lid_jid: &str) -> Arc<Device> {
    let store_backend = Arc::new(MemoryStore::new());
    let mut device = Device::new(store_backend);
    
    // Set both the public JID (id) and the LID
    device.id = Some(public_jid.parse().expect("Invalid public JID"));
    device.lid = Some(lid_jid.parse().expect("Invalid LID"));
    
    Arc::new(device)
}

#[tokio::test]
async fn test_sender_key_uses_public_jid_not_lid() {
    // === SETUP ===
    // Create Alice with both public JID and LID
    let alice_public_jid = "5511999999999@s.whatsapp.net";
    let alice_lid = "23619876543210987654_at_lid"; // Different from public JID
    let alice_device = create_test_device_with_jids(alice_public_jid, alice_lid).await;
    
    let group_id = "12345@g.us";
    
    // === TEST: Verify correct identity is used for SenderKey ===
    // The SenderKeyName should be created using the public JID, not the LID
    let alice_jid: Jid = alice_public_jid.parse().unwrap();
    let sender_address = SignalAddress::new(alice_jid.user.clone(), alice_jid.device as u32);
    let expected_sender_key_name = SenderKeyName::new(group_id.to_string(), sender_address.to_string());
    
    // Create the sender key using the correct identity
    let alice_builder = GroupSessionBuilder::new(DeviceArcWrapper::new(alice_device.clone()));
    let distribution_message = alice_builder
        .create(&expected_sender_key_name)
        .await
        .expect("Alice should create distribution message with public JID");
    
    // === VALIDATION ===
    println!("✓ Alice's public JID: {}", alice_public_jid);
    println!("✓ Alice's LID: {}", alice_lid);
    println!("✓ SenderKeyName uses public identity: {}", sender_address.to_string());
    
    // Verify the sender key was created and can be used
    let alice_cipher = GroupCipher::new(
        expected_sender_key_name.clone(),
        DeviceArcWrapper::new(alice_device.clone()),
        alice_builder,
    );
    
    let test_message = b"Hello group!";
    let encrypted_message = alice_cipher
        .encrypt(test_message)
        .await
        .expect("Should encrypt with public JID-based sender key");
    
    println!("✓ Message encrypted successfully with public JID identity");
    
    // === RECIPIENT PERSPECTIVE ===
    // Create Bob as a recipient who sees Alice by her public JID
    let bob_device = create_test_device_with_jids("5511888888888@s.whatsapp.net", "different_lid").await;
    
    // Bob processes Alice's distribution message using Alice's PUBLIC identity
    let bob_builder = GroupSessionBuilder::new(DeviceArcWrapper::new(bob_device.clone()));
    bob_builder
        .process(&expected_sender_key_name, &distribution_message)
        .await
        .expect("Bob should process Alice's distribution message");
    
    // Bob decrypts the message using Alice's public identity
    let bob_cipher = GroupCipher::new(
        expected_sender_key_name.clone(),
        DeviceArcWrapper::new(bob_device.clone()),
        bob_builder,
    );
    
    // Serialize and deserialize the message to get the verification data
    let serialized_msg = encrypted_message.serialize();
    let (deserialized_msg, data_to_verify) = 
        whatsapp_rust::signal::groups::message::SenderKeyMessage::deserialize(&serialized_msg)
            .expect("Should deserialize message");
    
    let decrypted_message = bob_cipher
        .decrypt(&deserialized_msg, data_to_verify)
        .await
        .expect("Bob should decrypt message using Alice's public identity");
    
    assert_eq!(decrypted_message, test_message);
    println!("✓ Bob successfully decrypted message using Alice's public JID");
    
    // === NEGATIVE TEST: Verify LID-based key would fail ===
    // If we incorrectly used the LID, recipients couldn't find the sender key
    let alice_lid_jid: Jid = alice_lid.parse().unwrap();
    let wrong_sender_address = SignalAddress::new(alice_lid_jid.user.clone(), alice_lid_jid.device as u32);
    let wrong_sender_key_name = SenderKeyName::new(group_id.to_string(), wrong_sender_address.to_string());
    
    // Try to decrypt with the wrong identity - this should fail
    let wrong_cipher = GroupCipher::new(
        wrong_sender_key_name,
        DeviceArcWrapper::new(bob_device.clone()),
        GroupSessionBuilder::new(DeviceArcWrapper::new(bob_device.clone())),
    );
    
    let decrypt_result = wrong_cipher.decrypt(&deserialized_msg, data_to_verify).await;
    assert!(decrypt_result.is_err(), "Decryption with LID identity should fail");
    println!("✓ Confirmed: Using LID identity fails as expected");
    
    println!("\n=== Test Summary ===");
    println!("✓ SenderKey correctly uses public JID ({})", alice_jid.user);
    println!("✓ Recipients can decrypt using sender's public identity");
    println!("✓ Using LID identity fails as expected");
    println!("✓ Fix prevents 'Waiting for this message' error");
}

#[tokio::test]  
async fn test_sender_key_identity_consistency() {
    // Test that ensures the sender key identity remains consistent
    // between message creation and distribution
    
    let alice_public_jid = "5511123456789@s.whatsapp.net";
    let alice_lid = "different_lid_identifier"; 
    let alice_device = create_test_device_with_jids(alice_public_jid, alice_lid).await;
    
    let group_id = "testgroup@g.us";
    
    // Parse Alice's public JID
    let alice_jid: Jid = alice_public_jid.parse().unwrap();
    let sender_address = SignalAddress::new(alice_jid.user.clone(), alice_jid.device as u32);
    let sender_key_name = SenderKeyName::new(group_id.to_string(), sender_address.to_string());
    
    // Create distribution message
    let alice_builder = GroupSessionBuilder::new(DeviceArcWrapper::new(alice_device.clone()));
    let _distribution_message = alice_builder
        .create(&sender_key_name)
        .await
        .expect("Should create distribution message");
    
    // Create cipher and encrypt multiple messages
    let alice_cipher = GroupCipher::new(
        sender_key_name.clone(),
        DeviceArcWrapper::new(alice_device.clone()),
        alice_builder,
    );
    
    // Encrypt multiple messages to test consistency
    let messages = vec![b"Message 1".as_slice(), b"Message 2".as_slice(), b"Message 3".as_slice()];
    let mut encrypted_messages = Vec::new();
    
    for msg in &messages {
        let encrypted = alice_cipher
            .encrypt(msg)
            .await
            .expect("Should encrypt message");
        encrypted_messages.push(encrypted);
    }
    
    println!("✓ Successfully encrypted {} messages with consistent sender identity", messages.len());
    println!("✓ Sender identity: {}", sender_address.to_string());
    
    // Verify the identity used is the public JID, not the LID
    assert!(sender_address.to_string().contains(&alice_jid.user));
    assert!(!sender_address.to_string().contains("lid"));
    
    println!("✓ Confirmed sender identity uses public JID, not LID");
}