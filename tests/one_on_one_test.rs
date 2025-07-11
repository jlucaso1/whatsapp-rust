// Integration test: Simulates a full 1-on-1 conversation using Double Ratchet
// Covers session establishment, message exchange, and ratchet state updates.

use std::sync::Arc;
use tokio::sync::RwLock;

use whatsapp_rust::signal::store::IdentityKeyStore;
use whatsapp_rust::signal::{
    SessionBuilder, SessionCipher,
    address::SignalAddress,
    ecc::keys::{DjbEcPublicKey, EcPublicKey},
    protocol::{Ciphertext, PREKEY_TYPE, WHISPER_TYPE},
    state::{prekey_bundle::PreKeyBundle, record},
    store::{PreKeyStore, SessionStore},
    util::keyhelper,
};
use whatsapp_rust::store::{Device, memory::MemoryStore, signal::DeviceRwLockWrapper};

// Helper: Create a test device with isolated memory store
async fn create_test_device(_name: &str) -> Arc<RwLock<Device>> {
    let store_backend = Arc::new(MemoryStore::new());
    let device = Device::new(store_backend);
    Arc::new(RwLock::new(device))
}

// Helper: Create a PreKeyBundle from a device's state
async fn create_bundle_for_device(
    device_arc: &Arc<RwLock<Device>>,
    device_address: &SignalAddress,
) -> PreKeyBundle {
    let device = device_arc.read().await;

    // Use a pre-key for the bundle
    let prekey = device
        .load_prekey(1)
        .await
        .unwrap()
        .expect("PreKey #1 should exist");
    let signed_prekey = device.signed_pre_key.clone();
    let identity_key_pair = device.get_identity_key_pair().await.unwrap();

    PreKeyBundle {
        registration_id: device.registration_id,
        device_id: device_address.device_id(),
        pre_key_id: Some(prekey.id()),
        pre_key_public: Some(DjbEcPublicKey::new(
            record::pre_key_record_key_pair(&prekey)
                .public_key
                .public_key(),
        )),
        signed_pre_key_id: signed_prekey.key_id,
        signed_pre_key_public: DjbEcPublicKey::new(signed_prekey.key_pair.public_key),
        signed_pre_key_signature: signed_prekey.signature.unwrap(),
        identity_key: identity_key_pair.public_key().clone(),
    }
}

#[tokio::test]
async fn test_one_on_one_conversation() {
    // === 1. SETUP ===

    // Create two participants: Alice and Bob
    let alice_device = create_test_device("alice").await;
    let bob_device = create_test_device("bob").await;

    let alice_address = SignalAddress::new("alice".to_string(), 1);
    let bob_address = SignalAddress::new("bob".to_string(), 1);

    // Populate Bob's store with a pre-key so Alice can build a session.
    {
        let bob = bob_device.read().await;
        let prekeys = keyhelper::generate_pre_keys(1, 1);
        bob.store_prekey(1, prekeys.into_iter().next().unwrap())
            .await
            .unwrap();
    }

    // === 2. SESSION ESTABLISHMENT (ALICE -> BOB) ===

    // Alice gets Bob's prekey bundle (simulating a fetch from the server)
    let bob_bundle = create_bundle_for_device(&bob_device, &bob_address).await;

    // Alice processes the bundle to create a session for Bob
    {
        let alice_store = alice_device.clone();
        let mut alice_session_record = alice_store
            .read()
            .await
            .load_session(&bob_address)
            .await
            .unwrap();
        let alice_builder = SessionBuilder::new(
            DeviceRwLockWrapper::new(alice_store.clone()),
            bob_address.clone(),
        );

        alice_builder
            .process_bundle(&mut alice_session_record, &bob_bundle)
            .await
            .expect("Alice should process Bob's bundle successfully");

        // Alice stores the new session
        alice_store
            .write()
            .await
            .store_session(&bob_address, &alice_session_record)
            .await
            .unwrap();
    }

    // === 3. ALICE SENDS FIRST MESSAGE ===

    let plaintext1 = b"Hello Bob!";
    let ciphertext1: Vec<u8>;
    {
        let alice_store = alice_device.clone();
        let mut alice_session_record = alice_store
            .read()
            .await
            .load_session(&bob_address)
            .await
            .unwrap();
        let alice_cipher = SessionCipher::new(
            DeviceRwLockWrapper::new(alice_store.clone()),
            bob_address.clone(),
        );

        let encrypted_msg = alice_cipher
            .encrypt(&mut alice_session_record, plaintext1)
            .await
            .expect("Alice should encrypt message 1");

        // The first message must be a PreKeySignalMessage
        assert_eq!(
            encrypted_msg.q_type(),
            PREKEY_TYPE,
            "First message should be of type pkmsg"
        );
        ciphertext1 = encrypted_msg.serialize();

        alice_store
            .write()
            .await
            .store_session(&bob_address, &alice_session_record)
            .await
            .unwrap();
    }
    // After Alice sends her first message, clear the pending pre-key so subsequent messages are SignalMessages
    {
        let alice_store = alice_device.clone();
        let mut alice_session_record = alice_store
            .read()
            .await
            .load_session(&bob_address)
            .await
            .unwrap();
        alice_session_record
            .session_state_mut()
            .clear_unacknowledged_prekey_message();
        alice_store
            .write()
            .await
            .store_session(&bob_address, &alice_session_record)
            .await
            .unwrap();
    }

    // === 4. BOB DECRYPTS FIRST MESSAGE ===

    {
        let bob_store = bob_device.clone();
        let bob_cipher = SessionCipher::new(
            DeviceRwLockWrapper::new(bob_store.clone()),
            alice_address.clone(),
        );
        let pkmsg = whatsapp_rust::signal::protocol::PreKeySignalMessage::deserialize(&ciphertext1)
            .unwrap();

        let decrypted1 = bob_cipher
            .decrypt(Ciphertext::PreKey(pkmsg))
            .await
            .expect("Bob should decrypt message 1 successfully");

        assert_eq!(
            decrypted1, plaintext1,
            "Decrypted text should match original"
        );

        // After this, Bob should also have a session for Alice
        let bob_session_for_alice = bob_store
            .read()
            .await
            .load_session(&alice_address)
            .await
            .unwrap();

        assert!(
            !bob_session_for_alice.is_fresh(),
            "Bob's session for Alice should now be active"
        );
    }

    // === 5. BOB SENDS A REPLY ===

    let plaintext2 = b"Hello Alice, I got your message!";
    let ciphertext2: Vec<u8>;
    {
        let bob_store = bob_device.clone();
        let mut bob_session_record = bob_store
            .read()
            .await
            .load_session(&alice_address)
            .await
            .unwrap();
        let bob_cipher = SessionCipher::new(
            DeviceRwLockWrapper::new(bob_store.clone()),
            alice_address.clone(),
        );

        let encrypted_msg = bob_cipher
            .encrypt(&mut bob_session_record, plaintext2)
            .await
            .expect("Bob should encrypt the reply");

        // Subsequent messages should be regular SignalMessages
        assert_eq!(
            encrypted_msg.q_type(),
            WHISPER_TYPE,
            "Reply message should be of type msg"
        );
        ciphertext2 = encrypted_msg.serialize();

        bob_store
            .write()
            .await
            .store_session(&alice_address, &bob_session_record)
            .await
            .unwrap();
    }

    // === 6. ALICE DECRYPTS THE REPLY ===

    {
        let alice_store = alice_device.clone();
        let alice_cipher = SessionCipher::new(
            DeviceRwLockWrapper::new(alice_store.clone()),
            bob_address.clone(),
        );
        let whisper_msg =
            whatsapp_rust::signal::protocol::SignalMessage::deserialize(&ciphertext2).unwrap();

        let decrypted2 = alice_cipher
            .decrypt(Ciphertext::Whisper(whisper_msg))
            .await
            .expect("Alice should decrypt Bob's reply");

        assert_eq!(
            decrypted2, plaintext2,
            "Decrypted reply should match original"
        );

        // Print Alice's session state after decrypting Bob's reply
    }

    // === 7. ALICE SENDS ANOTHER MESSAGE TO TEST RATCHET ===

    let plaintext3 = b"How are you doing?";
    let ciphertext3: Vec<u8>;
    {
        let alice_store = alice_device.clone();
        // Print Alice's session state before encrypting her follow-up

        // Reload Alice's session record after decrypting Bob's reply to ensure ratchet state is up-to-date
        let mut alice_session_record = alice_store
            .read()
            .await
            .load_session(&bob_address)
            .await
            .unwrap();
        let alice_cipher = SessionCipher::new(
            DeviceRwLockWrapper::new(alice_store.clone()),
            bob_address.clone(),
        );

        let encrypted_msg = alice_cipher
            .encrypt(&mut alice_session_record, plaintext3)
            .await
            .expect("Alice should encrypt message 3");

        ciphertext3 = encrypted_msg.serialize();

        alice_store
            .write()
            .await
            .store_session(&bob_address, &alice_session_record)
            .await
            .unwrap();
    }

    // === 8. BOB DECRYPTS THE FOLLOW-UP ===

    {
        let bob_store = bob_device.clone();
        let bob_cipher = SessionCipher::new(
            DeviceRwLockWrapper::new(bob_store.clone()),
            alice_address.clone(),
        );

        let whisper_msg =
            whatsapp_rust::signal::protocol::SignalMessage::deserialize(&ciphertext3).unwrap();

        let decrypted3 = bob_cipher
            .decrypt(Ciphertext::Whisper(whisper_msg))
            .await
            .expect("Bob should decrypt message 3");

        assert_eq!(
            decrypted3, plaintext3,
            "Decrypted follow-up should match original"
        );
    }
}
