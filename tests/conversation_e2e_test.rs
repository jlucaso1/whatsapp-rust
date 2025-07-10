// tests/conversation_e2e_test.rs
//
// End-to-end test simulating a conversation between two users.

use log::info;
use std::sync::Arc;
use tempfile::TempDir; // For temporary store paths
use tokio::sync::mpsc;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::persistence_manager::PersistenceManager; // Use PersistenceManager
                                                                   // use whatsapp_rust::store::memory::MemoryStore; // PM uses FileStore by default
                                                                   // use whatsapp_rust::store::Device; // Device is managed by PM
use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::types::events::Event; // For direct store manipulation in tests

/// TestHarness manages the state for a single conversation test.
struct TestHarness {
    // Client A
    #[allow(dead_code)]
    // These are used by the test functions, not directly by harness methods after init
    client_a: Arc<Client>,
    pm_a: Arc<PersistenceManager>, // Keep PM for direct store manipulation if needed for test setup
    // Client B
    #[allow(dead_code)]
    // These are used by the test functions, not directly by harness methods after init
    client_b: Arc<Client>,
    pm_b: Arc<PersistenceManager>, // Keep PM for direct store manipulation
    // A channel to receive events from Client A.
    #[allow(dead_code)]
    client_a_events_rx: mpsc::UnboundedReceiver<Event>,
    // A channel to receive events from Client B.
    #[allow(dead_code)]
    client_b_events_rx: mpsc::UnboundedReceiver<Event>,
    _temp_dir_a: TempDir, // Keep TempDir in scope to prevent premature deletion
    _temp_dir_b: TempDir,
}

impl TestHarness {
    /// Creates a new test harness.
    async fn new() -> Self {
        let temp_dir_a = TempDir::new().unwrap();
        let store_path_a = temp_dir_a.path().join("client_a_store");
        let pm_a = Arc::new(
            PersistenceManager::new(store_path_a)
                .await
                .expect("Failed to create PersistenceManager for Client A"),
        );
        let client_a = Arc::new(Client::new(pm_a.clone()));

        let temp_dir_b = TempDir::new().unwrap();
        let store_path_b = temp_dir_b.path().join("client_b_store");
        let pm_b = Arc::new(
            PersistenceManager::new(store_path_b)
                .await
                .expect("Failed to create PersistenceManager for Client B"),
        );
        let client_b = Arc::new(Client::new(pm_b.clone()));

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
            pm_a,
            client_b,
            pm_b,
            client_a_events_rx: rx_a,
            client_b_events_rx: rx_b,
            _temp_dir_a: temp_dir_a,
            _temp_dir_b: temp_dir_b,
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
    let jid_a = "client_a@s.whatsapp.net".parse().unwrap();
    harness
        .pm_a
        .process_command(DeviceCommand::SetId(Some(jid_a)))
        .await;
    // Simulate successful registration/pairing by setting registration ID via modify_device
    // This is a bit more direct than a command, but suitable for test setup.
    harness
        .pm_a
        .modify_device(|device| {
            device.registration_id = 12345;
        })
        .await;

    let snapshot_a = harness.pm_a.get_device_snapshot().await;
    assert!(
        snapshot_a.id.is_some(),
        "Client A should have a JID after pairing"
    );
    assert_ne!(
        snapshot_a.registration_id, 0,
        "Client A should have a valid registration ID"
    );

    // 3. Simulate pairing for Client B
    let jid_b = "client_b@s.whatsapp.net".parse().unwrap();
    harness
        .pm_b
        .process_command(DeviceCommand::SetId(Some(jid_b)))
        .await;
    harness
        .pm_b
        .modify_device(|device| {
            device.registration_id = 67890;
        })
        .await;

    let snapshot_b = harness.pm_b.get_device_snapshot().await;
    assert!(
        snapshot_b.id.is_some(),
        "Client B should have a JID after pairing"
    );
    assert_ne!(
        snapshot_b.registration_id, 0,
        "Client B should have a valid registration ID"
    );

    info!("✅ Conversation setup test completed - clients A and B paired (simulated).");
}

use whatsapp_rust::signal::store::{IdentityKeyStore, PreKeyStore, SessionStore};
use whatsapp_rust::signal::{
    address::SignalAddress,
    ecc::keys::{DjbEcPublicKey, EcPublicKey},
    protocol::{Ciphertext, PREKEY_TYPE, WHISPER_TYPE},
    state::{prekey_bundle::PreKeyBundle, record},
    util::keyhelper,
    SessionBuilder, SessionCipher,
}; // Added IdentityKeyStore

// Helper to create a PreKeyBundle, adapted from one_on_one_test.rs
async fn create_bundle_for_client(
    pm: Arc<PersistenceManager>, // Use PersistenceManager
    client_address: &SignalAddress,
) -> PreKeyBundle {
    let device_snapshot = pm.get_device_snapshot().await;

    // Use a pre-key for the bundle
    // Device itself implements PreKeyStore, so we can call load_prekey on it.
    // The blanket impl for Arc<Mutex<Device>> will handle the locking.
    let device_store_for_signal = pm.get_device_arc().await;

    let prekey = device_store_for_signal
        .load_prekey(1) // Assuming prekey ID 1 for simplicity
        .await
        .unwrap()
        .expect("PreKey #1 should exist for bundle creation");

    // Access fields from the snapshot for other parts
    let signed_prekey = device_snapshot.signed_pre_key.clone();
    let identity_key_pair = device_store_for_signal
        .get_identity_key_pair()
        .await
        .unwrap();

    PreKeyBundle {
        registration_id: device_snapshot.registration_id,
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

    // Setup Client A's store
    harness
        .pm_a
        .process_command(DeviceCommand::SetId(Some(
            client_a_jid_str.parse().unwrap(),
        )))
        .await;
    harness
        .pm_a
        .modify_device(|device| {
            device.registration_id = 111;
            // For prekeys and signed prekey, direct modification or specific commands might be needed
            // if not handled by general Device initialization or PersistenceManager.
            // Assuming Device::new already creates some initial prekeys and a signed prekey.
            // If specific test prekeys are needed, Device might need methods to set them,
            // then call modify_device.
            let _prekeys_a = keyhelper::generate_pre_keys(1, 1);
            // This part is tricky as store_prekey is on the Backend trait, not directly on Device.
            // Device's PreKeyStore impl delegates to device.backend.
            // So, we'd need to call this on the Arc<Mutex<Device>>.
        })
        .await;
    // Store prekey for A (must be done on the Arc<Mutex<Device>>)
    let device_a_store_signal = harness.pm_a.get_device_arc().await;
    // Ensure _prekeys_a is used in a way the compiler definitely sees
    let mut _prekeys_a = keyhelper::generate_pre_keys(1, 1);
    device_a_store_signal
        .store_prekey(1, _prekeys_a.remove(0))
        .await
        .unwrap(); // Use remove(0) to consume
    harness
        .pm_a
        .modify_device(|d| {
            // For signed prekey, if Device holds it directly
            d.signed_pre_key = d.identity_key.create_signed_prekey(1).unwrap();
        })
        .await;

    // Setup Client B's store
    harness
        .pm_b
        .process_command(DeviceCommand::SetId(Some(
            client_b_jid_str.parse().unwrap(),
        )))
        .await;
    harness
        .pm_b
        .modify_device(|device| {
            device.registration_id = 222;
        })
        .await;
    let device_b_store_signal = harness.pm_b.get_device_arc().await;
    let prekeys_b = keyhelper::generate_pre_keys(1, 1);
    device_b_store_signal
        .store_prekey(1, prekeys_b.into_iter().next().unwrap())
        .await
        .unwrap();
    harness
        .pm_b
        .modify_device(|d| {
            d.signed_pre_key = d.identity_key.create_signed_prekey(1).unwrap();
        })
        .await;

    info!(
        "Simulated pairing complete for Client A ({}) and Client B ({}).",
        client_a_address, client_b_address
    );

    // 2. SESSION ESTABLISHMENT (CLIENT A -> CLIENT B)
    // Client A gets Client B's prekey bundle (simulating a fetch from the server)
    let bundle_b = create_bundle_for_client(harness.pm_b.clone(), &client_b_address).await; // Pass PM
    info!("Created bundle for Client B");

    // Client A processes the bundle to create a session for Client B
    {
        let device_a_store_signal = harness.pm_a.get_device_arc().await;
        let mut session_record_a_for_b = device_a_store_signal
            .load_session(&client_b_address)
            .await
            .unwrap();
        let builder_a =
            SessionBuilder::new(device_a_store_signal.clone(), client_b_address.clone());

        builder_a
            .process_bundle(&mut session_record_a_for_b, &bundle_b)
            .await
            .expect("Client A should process Client B's bundle successfully");
        device_a_store_signal // Use Arc<Mutex<Device>>
            .store_session(&client_b_address, &session_record_a_for_b)
            .await
            .unwrap();
        info!("Client A processed Client B's bundle and stored session.");
    }

    // 3. CLIENT A SENDS FIRST MESSAGE TO CLIENT B
    let plaintext_a_to_b = b"Hello from Client A!";
    let ciphertext_a_to_b: Vec<u8>;
    {
        let device_a_store_signal = harness.pm_a.get_device_arc().await; // Use Arc<Mutex<Device>>
        let mut session_record_a_for_b = device_a_store_signal
            .load_session(&client_b_address)
            .await
            .unwrap();
        let cipher_a = SessionCipher::new(device_a_store_signal.clone(), client_b_address.clone());

        let encrypted_msg = cipher_a
            .encrypt(&mut session_record_a_for_b, plaintext_a_to_b)
            .await
            .expect("Client A should encrypt message 1 to B");
        assert_eq!(
            encrypted_msg.q_type(),
            PREKEY_TYPE,
            "First message from A to B should be pkmsg"
        );
        ciphertext_a_to_b = encrypted_msg.serialize();
        device_a_store_signal // Use Arc<Mutex<Device>>
            .store_session(&client_b_address, &session_record_a_for_b)
            .await
            .unwrap();
        // Clear unacknowledged prekey message
        let mut updated_session_record = device_a_store_signal
            .load_session(&client_b_address)
            .await
            .unwrap();
        updated_session_record
            .session_state_mut()
            .clear_unacknowledged_prekey_message();
        device_a_store_signal
            .store_session(&client_b_address, &updated_session_record)
            .await
            .unwrap(); // Use Arc<Mutex<Device>>

        info!("Client A sent first message to Client B.");
    }

    // 4. CLIENT B DECRYPTS FIRST MESSAGE FROM CLIENT A
    {
        let device_b_store_signal = harness.pm_b.get_device_arc().await; // Use Arc<Mutex<Device>>
        let cipher_b = SessionCipher::new(device_b_store_signal.clone(), client_a_address.clone());
        let pkmsg =
            whatsapp_rust::signal::protocol::PreKeySignalMessage::deserialize(&ciphertext_a_to_b)
                .unwrap();

        let decrypted_b_from_a = cipher_b
            .decrypt(Ciphertext::PreKey(pkmsg))
            .await
            .expect("Client B should decrypt message 1 from A successfully");
        assert_eq!(
            decrypted_b_from_a, plaintext_a_to_b,
            "Decrypted text for B should match original from A"
        );
        info!("Client B decrypted first message from Client A.");

        // After this, Client B should also have a session for Client A
        let session_b_for_a = device_b_store_signal
            .load_session(&client_a_address)
            .await
            .unwrap(); // Use Arc<Mutex<Device>>
        assert!(
            !session_b_for_a.is_fresh(),
            "Client B's session for Client A should now be active"
        );
    }

    // 5. CLIENT B SENDS A REPLY TO CLIENT A
    let plaintext_b_to_a = b"Hi Client A, I got your message!";
    let ciphertext_b_to_a: Vec<u8>;
    {
        let device_b_store_signal = harness.pm_b.get_device_arc().await; // Use Arc<Mutex<Device>>
        let mut session_record_b_for_a = device_b_store_signal
            .load_session(&client_a_address)
            .await
            .unwrap();
        let cipher_b = SessionCipher::new(device_b_store_signal.clone(), client_a_address.clone());

        let encrypted_msg = cipher_b
            .encrypt(&mut session_record_b_for_a, plaintext_b_to_a)
            .await
            .expect("Client B should encrypt reply to A");
        assert_eq!(
            encrypted_msg.q_type(),
            WHISPER_TYPE,
            "Reply message from B to A should be whisper_type"
        );
        ciphertext_b_to_a = encrypted_msg.serialize();
        device_b_store_signal // Use Arc<Mutex<Device>>
            .store_session(&client_a_address, &session_record_b_for_a)
            .await
            .unwrap();
        info!("Client B sent reply to Client A.");
    }

    // 6. CLIENT A DECRYPTS THE REPLY FROM CLIENT B
    {
        let device_a_store_signal = harness.pm_a.get_device_arc().await; // Use Arc<Mutex<Device>>
        let cipher_a = SessionCipher::new(device_a_store_signal.clone(), client_b_address.clone());
        let whisper_msg =
            whatsapp_rust::signal::protocol::SignalMessage::deserialize(&ciphertext_b_to_a)
                .unwrap();

        let decrypted_a_from_b = cipher_a
            .decrypt(Ciphertext::Whisper(whisper_msg))
            .await
            .expect("Client A should decrypt reply from B");
        assert_eq!(
            decrypted_a_from_b, plaintext_b_to_a,
            "Decrypted reply for A should match original from B"
        );
        info!("Client A decrypted reply from Client B.");
    }

    info!("✅ test_send_receive_message completed successfully!");
}
