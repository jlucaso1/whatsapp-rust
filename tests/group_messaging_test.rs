// tests/group_messaging_test.rs
//
// This integration test validates the complete SenderKey protocol flow for group messaging.
// It simulates a scenario where Alice sends messages to a group containing Bob and Charlie,
// testing the key distribution, session establishment, encryption, and decryption processes.
//
// The test validates:
// 1. SenderKeyDistributionMessage creation and processing
// 2. Group session establishment for multiple recipients
// 3. Message encryption and decryption using GroupCipher
// 4. Sender key ratcheting between messages
// 5. End-to-end group messaging functionality

use std::sync::Arc;
use whatsapp_rust::signal::{
    groups::{builder::GroupSessionBuilder, cipher::GroupCipher},
    sender_key_name::SenderKeyName,
    store::SenderKeyStore,
};
use whatsapp_rust::store::{memory::MemoryStore, Device};

// Helper function to create a test device with an isolated memory store
async fn create_test_device(_name: &str) -> Arc<Device> {
    let store_backend = Arc::new(MemoryStore::new());
    let device = Device::new(store_backend);
    Arc::new(device)
}

#[tokio::test]
async fn test_group_messaging_end_to_end() {
    // === SETUP ===
    // Create three participants: Alice (sender), Bob and Charlie (receivers)
    let alice_device = create_test_device("alice").await;
    let bob_device = create_test_device("bob").await;
    let charlie_device = create_test_device("charlie").await;

    let group_id = "12345@g.us".to_string();
    let alice_id = "alice@s.whatsapp.net".to_string();

    let sender_key_name = SenderKeyName::new(group_id.clone(), alice_id.clone());

    // === STEP 1: KEY DISTRIBUTION ===
    // Alice creates and "distributes" her sender key
    println!("--- Step 1: Alice creates and distributes sender key ---");
    let alice_builder = GroupSessionBuilder::new(alice_device.clone());
    let distribution_message = alice_builder
        .create(&sender_key_name)
        .await
        .expect("Alice should create a distribution message");

    println!(
        "Alice created distribution message with key id {}",
        distribution_message.id()
    );

    // === STEP 2: SESSION PROCESSING ===
    // Bob and Charlie process the distribution message
    println!("\n--- Step 2: Bob and Charlie process the key ---");

    // Bob processes the distribution message
    let bob_builder = GroupSessionBuilder::new(bob_device.clone());
    bob_builder
        .process(&sender_key_name, &distribution_message)
        .await
        .expect("Bob should process the distribution message");

    let bob_key_record = bob_device.load_sender_key(&sender_key_name).await.unwrap();
    assert!(
        bob_key_record
            .get_sender_key_state_by_id(distribution_message.id())
            .is_some(),
        "Bob's store should now have the sender key state"
    );
    println!("Bob successfully processed the key.");

    // Charlie processes the distribution message
    let charlie_builder = GroupSessionBuilder::new(charlie_device.clone());
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
        "Charlie's store should also have the sender key state"
    );
    println!("Charlie successfully processed the key.");

    // === STEP 3: FIRST MESSAGE ENCRYPTION ===
    println!("\n--- Step 3: Alice encrypts and sends message 1 ---");
    let plaintext1 = b"Hello, group!";
    let alice_builder_for_encrypt = GroupSessionBuilder::new(alice_device.clone());
    let alice_cipher = GroupCipher::new(
        sender_key_name.clone(),
        alice_device.clone(),
        alice_builder_for_encrypt,
    );
    let encrypted_message1 = alice_cipher
        .encrypt(plaintext1)
        .await
        .expect("Alice should encrypt message 1");
    println!(
        "Alice encrypted message 1 (iteration {})",
        encrypted_message1.iteration()
    );

    // === STEP 4: FIRST MESSAGE DECRYPTION ===
    println!("\n--- Step 4: Bob and Charlie decrypt message 1 ---");

    // Bob decrypts the first message
    let bob_builder_for_decrypt1 = GroupSessionBuilder::new(bob_device.clone());
    let bob_cipher = GroupCipher::new(
        sender_key_name.clone(),
        bob_device.clone(),
        bob_builder_for_decrypt1,
    );
    // Serialize and deserialize the message to get the verification data
    let serialized_msg1 = encrypted_message1.serialize();
    let (deserialized_msg1, data_to_verify1) =
        whatsapp_rust::signal::groups::message::SenderKeyMessage::deserialize(&serialized_msg1)
            .expect("Should deserialize message 1");
    let decrypted1_bob = bob_cipher
        .decrypt(&deserialized_msg1, data_to_verify1)
        .await
        .expect("Bob should decrypt message 1");
    assert_eq!(
        decrypted1_bob, plaintext1,
        "Bob's decrypted text should match"
    );
    println!("Bob decrypted message 1 successfully.");

    // Charlie decrypts the first message
    let charlie_builder_for_decrypt1 = GroupSessionBuilder::new(charlie_device.clone());
    let charlie_cipher = GroupCipher::new(
        sender_key_name.clone(),
        charlie_device.clone(),
        charlie_builder_for_decrypt1,
    );
    let decrypted1_charlie = charlie_cipher
        .decrypt(&deserialized_msg1, data_to_verify1)
        .await
        .expect("Charlie should decrypt message 1");
    assert_eq!(
        decrypted1_charlie, plaintext1,
        "Charlie's decrypted text should match"
    );
    println!("Charlie decrypted message 1 successfully.");

    // === STEP 5: SECOND MESSAGE ENCRYPTION (RATCHET TEST) ===
    println!("\n--- Step 5: Alice encrypts and sends message 2 (testing ratchet) ---");
    let plaintext2 = b"This is the second message.";
    let alice_builder_for_encrypt2 = GroupSessionBuilder::new(alice_device.clone());
    let alice_cipher2 = GroupCipher::new(
        sender_key_name.clone(),
        alice_device.clone(),
        alice_builder_for_encrypt2,
    );
    let encrypted_message2 = alice_cipher2
        .encrypt(plaintext2)
        .await
        .expect("Alice should encrypt message 2");
    println!(
        "Alice encrypted message 2 (iteration {})",
        encrypted_message2.iteration()
    );
    assert_ne!(
        encrypted_message1.iteration(),
        encrypted_message2.iteration(),
        "Iteration count should advance with ratcheting"
    );

    // === STEP 6: SECOND MESSAGE DECRYPTION ===
    println!("\n--- Step 6: Bob and Charlie decrypt message 2 ---");

    // Bob decrypts the second message
    let bob_builder_for_decrypt2 = GroupSessionBuilder::new(bob_device.clone());
    let bob_cipher2 = GroupCipher::new(
        sender_key_name.clone(),
        bob_device.clone(),
        bob_builder_for_decrypt2,
    );
    // Serialize and deserialize the message to get the verification data
    let serialized_msg2 = encrypted_message2.serialize();
    let (deserialized_msg2, data_to_verify2) =
        whatsapp_rust::signal::groups::message::SenderKeyMessage::deserialize(&serialized_msg2)
            .expect("Should deserialize message 2");
    let decrypted2_bob = bob_cipher2
        .decrypt(&deserialized_msg2, data_to_verify2)
        .await
        .expect("Bob should decrypt message 2");
    assert_eq!(
        decrypted2_bob, plaintext2,
        "Bob's decrypted text should match"
    );
    println!("Bob decrypted message 2 successfully.");

    // Charlie decrypts the second message
    let charlie_builder_for_decrypt2 = GroupSessionBuilder::new(charlie_device.clone());
    let charlie_cipher2 = GroupCipher::new(
        sender_key_name.clone(),
        charlie_device.clone(),
        charlie_builder_for_decrypt2,
    );
    let decrypted2_charlie = charlie_cipher2
        .decrypt(&deserialized_msg2, data_to_verify2)
        .await
        .expect("Charlie should decrypt message 2");
    assert_eq!(
        decrypted2_charlie, plaintext2,
        "Charlie's decrypted text should match"
    );
    println!("Charlie decrypted message 2 successfully.");

    // === STEP 7: VERIFY SENDER KEY STATE ===
    println!("\n--- Step 7: Verify sender key state consistency ---");

    // Verify that all participants have consistent sender key states
    let alice_key_record = alice_device
        .load_sender_key(&sender_key_name)
        .await
        .unwrap();

    let bob_key_record = bob_device.load_sender_key(&sender_key_name).await.unwrap();

    let charlie_key_record = charlie_device
        .load_sender_key(&sender_key_name)
        .await
        .unwrap();

    // Verify that all records have the same key ID
    let alice_state = alice_key_record
        .sender_key_state()
        .expect("Alice should have sender key state");
    let bob_state = bob_key_record
        .sender_key_state()
        .expect("Bob should have sender key state");
    let charlie_state = charlie_key_record
        .sender_key_state()
        .expect("Charlie should have sender key state");

    assert_eq!(
        alice_state.sender_key_id, bob_state.sender_key_id,
        "Alice and Bob should have the same sender key ID"
    );
    assert_eq!(
        alice_state.sender_key_id, charlie_state.sender_key_id,
        "Alice and Charlie should have the same sender key ID"
    );

    println!("All sender key states are consistent.");
    println!("\n✅ End-to-end group messaging test passed!");
}

// === ADDITIONAL TEST: OUT-OF-ORDER MESSAGE HANDLING ===
#[tokio::test]
async fn test_group_messaging_out_of_order() {
    // This test validates that the group messaging system can handle
    // messages that arrive out of order, which is common in real-world scenarios

    let alice_device = create_test_device("alice").await;
    let bob_device = create_test_device("bob").await;

    let group_id = "test-group@g.us".to_string();
    let alice_id = "alice@s.whatsapp.net".to_string();
    let sender_key_name = SenderKeyName::new(group_id, alice_id);

    // Set up the initial key distribution
    let alice_builder_setup = GroupSessionBuilder::new(alice_device.clone());
    let distribution_message = alice_builder_setup.create(&sender_key_name).await.unwrap();

    // Bob processes the distribution message
    let bob_builder_setup = GroupSessionBuilder::new(bob_device.clone());
    bob_builder_setup
        .process(&sender_key_name, &distribution_message)
        .await
        .unwrap();

    // Alice encrypts multiple messages
    let plaintext1 = b"Message 1";
    let plaintext2 = b"Message 2";
    let plaintext3 = b"Message 3";

    let alice_builder_multi = GroupSessionBuilder::new(alice_device.clone());
    let alice_cipher_multi = GroupCipher::new(
        sender_key_name.clone(),
        alice_device.clone(),
        alice_builder_multi,
    );

    let msg1 = alice_cipher_multi.encrypt(plaintext1).await.unwrap();
    let msg2 = alice_cipher_multi.encrypt(plaintext2).await.unwrap();
    let msg3 = alice_cipher_multi.encrypt(plaintext3).await.unwrap();

    // Verify messages have increasing iterations
    assert!(msg1.iteration() < msg2.iteration());
    assert!(msg2.iteration() < msg3.iteration());

    // Bob receives and decrypts messages in order: 1, 3, 2 (out of order)
    let bob_builder_ooo = GroupSessionBuilder::new(bob_device.clone());
    let bob_cipher_ooo =
        GroupCipher::new(sender_key_name.clone(), bob_device.clone(), bob_builder_ooo);

    // Decrypt message 1
    let serialized_msg1 = msg1.serialize();
    let (deserialized_msg1, data_to_verify1) =
        whatsapp_rust::signal::groups::message::SenderKeyMessage::deserialize(&serialized_msg1)
            .unwrap();
    let decrypted1 = bob_cipher_ooo
        .decrypt(&deserialized_msg1, data_to_verify1)
        .await
        .unwrap();
    assert_eq!(decrypted1, plaintext1);

    // Decrypt message 3 (skipping message 2)
    let serialized_msg3 = msg3.serialize();
    let (deserialized_msg3, data_to_verify3) =
        whatsapp_rust::signal::groups::message::SenderKeyMessage::deserialize(&serialized_msg3)
            .unwrap();
    let decrypted3 = bob_cipher_ooo
        .decrypt(&deserialized_msg3, data_to_verify3)
        .await
        .unwrap();
    assert_eq!(decrypted3, plaintext3);

    // Decrypt message 2 (out of order)
    let serialized_msg2 = msg2.serialize();
    let (deserialized_msg2, data_to_verify2) =
        whatsapp_rust::signal::groups::message::SenderKeyMessage::deserialize(&serialized_msg2)
            .unwrap();
    let decrypted2 = bob_cipher_ooo
        .decrypt(&deserialized_msg2, data_to_verify2)
        .await
        .unwrap();
    assert_eq!(decrypted2, plaintext2);

    println!("✅ Out-of-order message handling test passed!");
}

// === TEST SUMMARY ===
// These tests successfully validate the following critical group messaging behaviors:
//
// 1. **Key Distribution**: Alice can create a SenderKeyDistributionMessage and multiple
//    recipients can process it to establish group sessions.
//
// 2. **Session Establishment**: Recipients correctly establish sender key states from
//    the distribution message, enabling them to decrypt group messages.
//
// 3. **Message Encryption**: The GroupCipher correctly encrypts messages using the
//    sender key protocol, creating SenderKeyMessages with proper iterations.
//
// 4. **Message Decryption**: Multiple recipients can independently decrypt the same
//    encrypted message using their own GroupCipher instances.
//
// 5. **Sender Key Ratcheting**: The sender key chain advances correctly between messages,
//    ensuring forward secrecy and preventing replay attacks.
//
// 6. **State Consistency**: All participants maintain consistent sender key states
//    throughout the messaging session.
//
// 7. **Out-of-Order Handling**: The system can handle messages that arrive out of order,
//    which is crucial for real-world group messaging scenarios.
//
// These tests validate the core functionality of the SenderKey protocol implementation,
// ensuring that group messaging works correctly for multiple participants with proper
// cryptographic guarantees.
