// tests/conversation_e2e_test.rs
//
// End-to-end test simulating a conversation between two users.

use log::info;
use std::sync::Arc;
use tokio::sync::mpsc;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::memory::MemoryStore;
use whatsapp_rust::store::Device;
use whatsapp_rust::types::events::Event;

/// TestHarness manages the state for a single conversation test.
struct TestHarness {
    // Client A
    client_a: Arc<Client>,
    // Client B
    client_b: Arc<Client>,
    // A channel to receive events from Client A.
    #[allow(dead_code)]
    client_a_events_rx: mpsc::UnboundedReceiver<Event>,
    // A channel to receive events from Client B.
    #[allow(dead_code)]
    client_b_events_rx: mpsc::UnboundedReceiver<Event>,
}

impl TestHarness {
    /// Creates a new test harness.
    async fn new() -> Self {
        // Setup Client A
        let client_a_store_backend = Arc::new(MemoryStore::new());
        let client_a_store = Device::new(client_a_store_backend.clone());
        let client_a = Arc::new(Client::new(client_a_store));

        // Setup Client B
        let client_b_store_backend = Arc::new(MemoryStore::new());
        let client_b_store = Device::new(client_b_store_backend.clone());
        let client_b = Arc::new(Client::new(client_b_store));

        // Create event channels
        let (tx_a, rx_a) = mpsc::unbounded_channel();
        client_a
            .add_event_handler(Box::new(move |evt| {
                let _ = tx_a.send((*evt).clone());
            }))
            .await;

        let (tx_b, rx_b) = mpsc::unbounded_channel();
        client_b
            .add_event_handler(Box::new(move |evt| {
                let _ = tx_b.send((*evt).clone());
            }))
            .await;

        Self {
            client_a,
            client_b,
            client_a_events_rx: rx_a,
            client_b_events_rx: rx_b,
        }
    }
}

#[tokio::test]
async fn test_conversation_setup() {
    // Initialize logging for better debugging
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    // 1. Setup
    let harness = TestHarness::new().await;

    // 2. Simulate pairing for Client A
    // For simplicity, we'll mock the JID and assume pairing is successful.
    // A more comprehensive test would involve QR code generation and processing.
    {
        let mut store_a = harness.client_a.store.write().await;
        if store_a.id.is_none() {
            let jid_a = "client_a@s.whatsapp.net".parse().unwrap();
            store_a.id = Some(jid_a);
            // Simulate successful registration/pairing by setting registration ID
            store_a.registration_id = 12345;
        }
        assert!(store_a.id.is_some(), "Client A should have a JID after pairing");
        assert_ne!(store_a.registration_id, 0, "Client A should have a valid registration ID");
    }

    // 3. Simulate pairing for Client B
    {
        let mut store_b = harness.client_b.store.write().await;
        if store_b.id.is_none() {
            let jid_b = "client_b@s.whatsapp.net".parse().unwrap();
            store_b.id = Some(jid_b);
            // Simulate successful registration/pairing by setting registration ID
            store_b.registration_id = 67890;
        }
        assert!(store_b.id.is_some(), "Client B should have a JID after pairing");
        assert_ne!(store_b.registration_id, 0, "Client B should have a valid registration ID");
    }

    info!("✅ Conversation setup test completed - clients A and B paired (simulated).");
}

use whatsapp_rust::signal::{
    address::SignalAddress,
    ecc::keys::{DjbEcPublicKey, EcPublicKey},
    protocol::{Ciphertext, PREKEY_TYPE, WHISPER_TYPE},
    state::{prekey_bundle::PreKeyBundle, record},
    util::keyhelper,
    SessionBuilder, SessionCipher,
};
use whatsapp_rust::signal::store::{PreKeyStore, SessionStore, IdentityKeyStore}; // Added IdentityKeyStore

// Helper to create a PreKeyBundle, adapted from one_on_one_test.rs
async fn create_bundle_for_client(
    client_arc: Arc<Client>, // Changed to Arc<Client>
    client_address: &SignalAddress,
) -> PreKeyBundle {
    let device_store = client_arc.store.read().await; // Access store via client

    // Use a pre-key for the bundle
    let prekey = device_store
        .load_prekey(1) // Assuming prekey ID 1 for simplicity
        .await
        .unwrap()
        .expect("PreKey #1 should exist for bundle creation");
    let signed_prekey = device_store.signed_pre_key.clone();
    let identity_key_pair = device_store.get_identity_key_pair().await.unwrap();

    PreKeyBundle {
        registration_id: device_store.registration_id,
        device_id: client_address.device_id(),
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
async fn test_send_receive_message() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    // 1. Setup
    let harness = TestHarness::new().await;

    // Mock JIDs and registration IDs directly on the Device store
    let client_a_jid_str = "client_a@s.whatsapp.net";
    let client_b_jid_str = "client_b@s.whatsapp.net";
    let client_a_address = SignalAddress::new(client_a_jid_str.to_string(), 1);
    let client_b_address = SignalAddress::new(client_b_jid_str.to_string(), 1);

    {
        let mut store_a = harness.client_a.store.write().await;
        store_a.id = Some(client_a_jid_str.parse().unwrap());
        store_a.registration_id = 111;
        // Generate and store prekeys for Client A
        let prekeys_a = keyhelper::generate_pre_keys(1, 1); // Generate one prekey with ID 1
        store_a.store_prekey(1, prekeys_a.into_iter().next().unwrap()).await.unwrap();
        // Generate and store signed prekey for Client A
        let signed_pre_key_a = store_a.identity_key.create_signed_prekey(1).unwrap();
        store_a.signed_pre_key = signed_pre_key_a;


        let mut store_b = harness.client_b.store.write().await;
        store_b.id = Some(client_b_jid_str.parse().unwrap());
        store_b.registration_id = 222;
        // Generate and store prekeys for Client B
        let prekeys_b = keyhelper::generate_pre_keys(1, 1);
        store_b.store_prekey(1, prekeys_b.into_iter().next().unwrap()).await.unwrap();
        // Generate and store signed prekey for Client B
        let signed_pre_key_b = store_b.identity_key.create_signed_prekey(1).unwrap();
        store_b.signed_pre_key = signed_pre_key_b;

    }
    info!("Simulated pairing complete for Client A ({}) and Client B ({}).", client_a_address, client_b_address);


    // 2. SESSION ESTABLISHMENT (CLIENT A -> CLIENT B)
    // Client A gets Client B's prekey bundle (simulating a fetch from the server)
    let bundle_b = create_bundle_for_client(harness.client_b.clone(), &client_b_address).await;
    info!("Created bundle for Client B");

    // Client A processes the bundle to create a session for Client B
    {
        let store_a_for_session = harness.client_a.store.clone();
        let mut session_record_a_for_b = store_a_for_session.load_session(&client_b_address).await.unwrap();
        let builder_a = SessionBuilder::new(store_a_for_session.clone(), client_b_address.clone());

        builder_a
            .process_bundle(&mut session_record_a_for_b, &bundle_b)
            .await
            .expect("Client A should process Client B's bundle successfully");
        store_a_for_session
            .store_session(&client_b_address, &session_record_a_for_b)
            .await
            .unwrap();
        info!("Client A processed Client B's bundle and stored session.");
    }

    // 3. CLIENT A SENDS FIRST MESSAGE TO CLIENT B
    let plaintext_a_to_b = b"Hello from Client A!";
    let ciphertext_a_to_b: Vec<u8>;
    {
        let store_a_for_send = harness.client_a.store.clone();
        let mut session_record_a_for_b = store_a_for_send.load_session(&client_b_address).await.unwrap();
        let cipher_a = SessionCipher::new(store_a_for_send.clone(), client_b_address.clone());

        let encrypted_msg = cipher_a
            .encrypt(&mut session_record_a_for_b, plaintext_a_to_b)
            .await
            .expect("Client A should encrypt message 1 to B");
        assert_eq!(encrypted_msg.q_type(), PREKEY_TYPE, "First message from A to B should be pkmsg");
        ciphertext_a_to_b = encrypted_msg.serialize();
        store_a_for_send
            .store_session(&client_b_address, &session_record_a_for_b)
            .await
            .unwrap();
        // Clear unacknowledged prekey message
        let mut updated_session_record = store_a_for_send.load_session(&client_b_address).await.unwrap();
        updated_session_record.session_state_mut().clear_unacknowledged_prekey_message();
        store_a_for_send.store_session(&client_b_address, &updated_session_record).await.unwrap();

        info!("Client A sent first message to Client B.");
    }

    // 4. CLIENT B DECRYPTS FIRST MESSAGE FROM CLIENT A
    {
        let store_b_for_recv = harness.client_b.store.clone();
        let cipher_b = SessionCipher::new(store_b_for_recv.clone(), client_a_address.clone());
        let pkmsg = whatsapp_rust::signal::protocol::PreKeySignalMessage::deserialize(&ciphertext_a_to_b).unwrap();

        let decrypted_b_from_a = cipher_b
            .decrypt(Ciphertext::PreKey(pkmsg))
            .await
            .expect("Client B should decrypt message 1 from A successfully");
        assert_eq!(decrypted_b_from_a, plaintext_a_to_b, "Decrypted text for B should match original from A");
        info!("Client B decrypted first message from Client A.");

        // After this, Client B should also have a session for Client A
        let session_b_for_a = store_b_for_recv.load_session(&client_a_address).await.unwrap();
        assert!(!session_b_for_a.is_fresh(), "Client B's session for Client A should now be active");
    }

    // 5. CLIENT B SENDS A REPLY TO CLIENT A
    let plaintext_b_to_a = b"Hi Client A, I got your message!";
    let ciphertext_b_to_a: Vec<u8>;
    {
        let store_b_for_send = harness.client_b.store.clone();
        let mut session_record_b_for_a = store_b_for_send.load_session(&client_a_address).await.unwrap();
        let cipher_b = SessionCipher::new(store_b_for_send.clone(), client_a_address.clone());

        let encrypted_msg = cipher_b
            .encrypt(&mut session_record_b_for_a, plaintext_b_to_a)
            .await
            .expect("Client B should encrypt reply to A");
        assert_eq!(encrypted_msg.q_type(), WHISPER_TYPE, "Reply message from B to A should be whisper_type");
        ciphertext_b_to_a = encrypted_msg.serialize();
        store_b_for_send
            .store_session(&client_a_address, &session_record_b_for_a)
            .await
            .unwrap();
        info!("Client B sent reply to Client A.");
    }

    // 6. CLIENT A DECRYPTS THE REPLY FROM CLIENT B
    {
        let store_a_for_recv = harness.client_a.store.clone();
        let cipher_a = SessionCipher::new(store_a_for_recv.clone(), client_b_address.clone());
        let whisper_msg = whatsapp_rust::signal::protocol::SignalMessage::deserialize(&ciphertext_b_to_a).unwrap();

        let decrypted_a_from_b = cipher_a
            .decrypt(Ciphertext::Whisper(whisper_msg))
            .await
            .expect("Client A should decrypt reply from B");
        assert_eq!(decrypted_a_from_b, plaintext_b_to_a, "Decrypted reply for A should match original from B");
        info!("Client A decrypted reply from Client B.");
    }

    info!("✅ test_send_receive_message completed successfully!");
}
