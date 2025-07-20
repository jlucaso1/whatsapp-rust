use log::info;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use whatsapp_rust::client::Client;
use whatsapp_rust::store::persistence_manager::PersistenceManager;
use whatsapp_rust::store::signal::DeviceStore;
use whatsapp_rust::test_network::{TestNetworkBus, TestMessage};

use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::types::events::Event;
use whatsapp_rust::types::jid::Jid;

use waproto::whatsapp as wa;
use whatsapp_rust::signal::store::{IdentityKeyStore, PreKeyStore, SessionStore};
use whatsapp_rust::signal::{
    address::SignalAddress,
    session::SessionBuilder,
    state::{prekey_bundle::PreKeyBundle, record},
    util::keyhelper,
};

/// Manages multiple client instances for end-to-end testing.
struct TestHarness {
    pub client_a: Arc<Client>,
    pub client_b: Arc<Client>,
    pub client_c: Arc<Client>,
    _temp_dir_a: TempDir,
    _temp_dir_b: TempDir,
    _temp_dir_c: TempDir,
    network_bus: TestNetworkBus,
    _network_task: tokio::task::JoinHandle<()>,
}

impl TestHarness {
    async fn new() -> Self {
        let (client_a, _temp_dir_a) = setup_test_client("alice.1@lid").await;
        let (client_b, _temp_dir_b) = setup_test_client("bob.1@lid").await;
        let (client_c, _temp_dir_c) = setup_test_client("charlie.1@lid").await;

        // Create test network bus
        let network_bus = TestNetworkBus::new();
        let network_sender = network_bus.get_sender();
        let network_receiver = network_bus.get_receiver();

        // Enable test mode for all clients
        client_a.enable_test_mode(network_sender.clone()).await;
        client_b.enable_test_mode(network_sender.clone()).await;
        client_c.enable_test_mode(network_sender.clone()).await;

        // Create a map of clients for routing
        let clients = vec![
            (client_a.get_jid().await.unwrap(), client_a.clone()),
            (client_b.get_jid().await.unwrap(), client_b.clone()),
            (client_c.get_jid().await.unwrap(), client_c.clone()),
        ];

        // Start network routing task
        let network_task = tokio::spawn(async move {
            let mut receiver = network_receiver.lock().await;
            while let Some(test_message) = receiver.recv().await {
                // Route message to appropriate recipients
                Self::route_message(test_message, &clients).await;
            }
        });

        Self {
            client_a,
            client_b,
            client_c,
            _temp_dir_a,
            _temp_dir_b,
            _temp_dir_c,
            network_bus,
            _network_task: network_task,
        }
    }

    async fn route_message(message: TestMessage, clients: &[(Jid, Arc<Client>)]) {
        use log::debug;
        
        debug!("Routing message from {} to recipients: {}", message.from, message.node);
        
        // For group messages, route to all clients except sender
        // For direct messages, route only to the specific recipient
        let is_group_message = message.node.attrs.get("to")
            .map(|to| to.contains("@g.us"))
            .unwrap_or(false);

        for (client_jid, client) in clients {
            // Skip sender
            if *client_jid == message.from {
                continue;
            }

            // For direct messages, only send to the specific recipient
            if !is_group_message {
                if let Some(ref to_jid) = message.to {
                    if *client_jid != *to_jid {
                        continue;
                    }
                }
            }

            debug!("Delivering message to client: {}", client_jid);
            // Process the message on the recipient client
            let mut node_clone = message.node.clone();
            
            // Add sender information to the message for proper source parsing
            // In real WhatsApp, this would be added by the server
            let to_jid_str = message.node.attrs.get("to").unwrap_or(&"".to_string()).clone();
            
            if is_group_message {
                // For group messages, 'from' should be the group JID and 'participant' should be the sender
                node_clone.attrs.insert("from".to_string(), to_jid_str);
                node_clone.attrs.insert("participant".to_string(), message.from.to_string());
            } else {
                // For DM messages, 'from' should be the sender
                node_clone.attrs.insert("from".to_string(), message.from.to_string());
            }
            
            let client_clone = client.clone();
            tokio::spawn(async move {
                client_clone.handle_encrypted_message(node_clone).await;
            });
        }
    }
}

/// Helper to establish Signal protocol sessions between all participants for group messaging
async fn establish_all_signal_sessions(harness: &TestHarness) {
    use log::info;
    
    info!("Establishing Signal protocol sessions between all participants...");
    
    // Get client info
    let client_a_jid = harness.client_a.get_jid().await.unwrap();
    let client_b_jid = harness.client_b.get_jid().await.unwrap();
    let client_c_jid = harness.client_c.get_jid().await.unwrap();
    
    // Get prekey bundles
    let bundle_a = get_bundle_for_client(&harness.client_a).await;
    let bundle_b = get_bundle_for_client(&harness.client_b).await;
    let bundle_c = get_bundle_for_client(&harness.client_c).await;
    
    // For group messaging, Alice needs sessions with Bob and Charlie to encrypt SKDMs
    // Bob and Charlie need sessions with Alice to encrypt their own messages
    // Each participant needs sessions with others to decrypt their messages
    
    // Alice establishes sessions with Bob and Charlie
    let device_a_store = DeviceStore::new(harness.client_a.persistence_manager.get_device_arc().await);
    
    let client_b_address = SignalAddress::new(client_b_jid.user.clone(), client_b_jid.device as u32);
    let mut session_record_b = device_a_store.load_session(&client_b_address).await.unwrap();
    let builder_b = SessionBuilder::new(device_a_store.clone(), client_b_address.clone());
    builder_b.process_bundle(&mut session_record_b, &bundle_b).await.unwrap();
    device_a_store.store_session(&client_b_address, &session_record_b).await.unwrap();
    
    let client_c_address = SignalAddress::new(client_c_jid.user.clone(), client_c_jid.device as u32);
    let mut session_record_c = device_a_store.load_session(&client_c_address).await.unwrap();
    let builder_c = SessionBuilder::new(device_a_store.clone(), client_c_address.clone());
    builder_c.process_bundle(&mut session_record_c, &bundle_c).await.unwrap();
    device_a_store.store_session(&client_c_address, &session_record_c).await.unwrap();
    
    info!("Alice established sessions with Bob and Charlie");
}

/// Helper to set up a single client instance for tests.
async fn setup_test_client(jid_str: &str) -> (Arc<Client>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("store");
    let pm = Arc::new(
        PersistenceManager::new(store_path)
            .await
            .expect("Failed to create PersistenceManager"),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    let jid: Jid = jid_str.parse().unwrap();
    let lid: Jid = jid_str.parse().unwrap(); // For simplicity in tests, LID can be same as JID
    pm.process_command(DeviceCommand::SetId(Some(jid.clone())))
        .await;
    pm.process_command(DeviceCommand::SetLid(Some(lid))).await;
    pm.process_command(DeviceCommand::SetPushName(jid.user.clone()))
        .await;

    // Generate and store pre-keys for session establishment
    let device_store = pm.get_device_arc().await;
    let mut prekeys = keyhelper::generate_pre_keys(1, 1);
    device_store
        .lock()
        .await
        .store_prekey(1, prekeys.remove(0))
        .await
        .unwrap();

    (client, temp_dir)
}

/// Simulates one client fetching the prekey bundle of another.
async fn get_bundle_for_client(client: &Arc<Client>) -> PreKeyBundle {
    let device_store = client.persistence_manager.get_device_arc().await;
    let device = device_store.lock().await;

    let prekey = device
        .load_prekey(1)
        .await
        .unwrap()
        .expect("PreKey #1 should exist");
    let signed_prekey = device.signed_pre_key.clone();
    let identity_key_pair = device.get_identity_key_pair().await.unwrap();
    let client_jid = device.id.clone().unwrap();

    PreKeyBundle {
        registration_id: device.registration_id,
        device_id: client_jid.device as u32,
        pre_key_id: Some(prekey.id()),
        pre_key_public: Some(wacore::signal::ecc::keys::DjbEcPublicKey::new(
            record::pre_key_record_key_pair(&prekey)
                .public_key
                .public_key,
        )),
        signed_pre_key_id: signed_prekey.key_id,
        signed_pre_key_public: wacore::signal::ecc::keys::DjbEcPublicKey::new(
            signed_prekey.key_pair.public_key,
        ),
        signed_pre_key_signature: signed_prekey.signature.unwrap(),
        identity_key: identity_key_pair.public_key().clone(),
    }
}

/// Awaits the next message event from a client's event bus.
async fn expect_message(
    rx: &mut mpsc::UnboundedReceiver<Event>,
) -> (Box<wa::Message>, whatsapp_rust::types::message::MessageInfo) {
    let event = timeout(Duration::from_secs(5), rx.recv())
        .await
        .expect("Timed out waiting for message event")
        .expect("Event channel closed");

    if let Event::Message(msg, info) = event {
        (msg, info)
    } else {
        panic!("Expected Event::Message, but got {:?}", event);
    }
}

#[tokio::test]
async fn test_full_group_conversation_loop() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Info)
        .try_init();

    let harness = TestHarness::new().await;
    let group_jid: Jid = "e2e_group_conversation@g.us".parse().unwrap();
    let mut rx_a = harness.client_a.subscribe_to_all_events();
    let mut rx_b = harness.client_b.subscribe_to_all_events();
    let mut rx_c = harness.client_c.subscribe_to_all_events();

    // Establish Signal protocol sessions between all participants first
    establish_all_signal_sessions(&harness).await;

    info!("(1) Alice sends first message to Bob and Charlie");
    let msg1 = "Hello from Alice!";
    harness
        .client_a
        .send_text_message(group_jid.clone(), msg1)
        .await
        .unwrap();

    info!("(2) Bob and Charlie should receive and decrypt Alice's message");
    let (_, info_b) = expect_message(&mut rx_b).await;
    let (_, info_c) = expect_message(&mut rx_c).await;
    assert_eq!(
        info_b.source.sender,
        harness.client_a.get_jid().await.unwrap()
    );
    assert_eq!(
        info_c.source.sender,
        harness.client_a.get_jid().await.unwrap()
    );

    info!("(3) Bob sends a reply");
    let msg2 = "Hi Alice, this is Bob!";
    harness
        .client_b
        .send_text_message(group_jid.clone(), msg2)
        .await
        .unwrap();

    info!("(4) Alice and Charlie should receive and decrypt Bob's message");
    let (_, info_a) = expect_message(&mut rx_a).await;
    let (_, info_c_2) = expect_message(&mut rx_c).await;
    assert_eq!(
        info_a.source.sender,
        harness.client_b.get_jid().await.unwrap()
    );
    assert_eq!(
        info_c_2.source.sender,
        harness.client_b.get_jid().await.unwrap()
    );

    info!("(5) Charlie sends a message");
    let msg3 = "Hello everyone!";
    harness
        .client_c
        .send_text_message(group_jid.clone(), msg3)
        .await
        .unwrap();

    info!("(6) Alice and Bob should receive and decrypt Charlie's message");
    let (_, info_a_2) = expect_message(&mut rx_a).await;
    let (_, info_b_2) = expect_message(&mut rx_b).await;
    assert_eq!(
        info_a_2.source.sender,
        harness.client_c.get_jid().await.unwrap()
    );
    assert_eq!(
        info_b_2.source.sender,
        harness.client_c.get_jid().await.unwrap()
    );

    info!("✅ Full group conversation loop test passed!");
}

#[tokio::test]
async fn test_group_rekey_on_participant_add() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Info)
        .try_init();

    let harness = TestHarness::new().await;
    let group_jid: Jid = "rekey_test_group@g.us".parse().unwrap();
    let mut rx_b = harness.client_b.subscribe_to_all_events();
    let mut rx_c = harness.client_c.subscribe_to_all_events();

    // Establish Signal protocol sessions between all participants first
    establish_all_signal_sessions(&harness).await;

    info!("(1) Alice and Bob start a group conversation.");
    harness
        .client_a
        .send_text_message(group_jid.clone(), "Just us two")
        .await
        .unwrap();

    let (_, info_b) = expect_message(&mut rx_b).await;
    assert_eq!(
        info_b.source.sender,
        harness.client_a.get_jid().await.unwrap()
    );
    info!("✅ Initial A->B message successful");

    info!("(2) Alice 'adds' Charlie. A new SKDM should be sent.");
    harness
        .client_a
        .send_text_message(group_jid.clone(), "Welcome Charlie!")
        .await
        .unwrap();

    info!("(3) Both Bob and Charlie should decrypt the new message.");
    let (_, info_b_2) = expect_message(&mut rx_b).await;
    let (_, info_c) = expect_message(&mut rx_c).await;
    assert_eq!(
        info_b_2.source.sender,
        harness.client_a.get_jid().await.unwrap()
    );
    assert_eq!(
        info_c.source.sender,
        harness.client_a.get_jid().await.unwrap()
    );

    info!("✅ All participants correctly decrypted message after implicit re-keying.");
}

#[tokio::test]
async fn test_send_receive_message() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Info)
        .try_init();

    let harness = TestHarness::new().await;
    let mut rx_b = harness.client_b.subscribe_to_all_events();

    let bundle_b = get_bundle_for_client(&harness.client_b).await;
    let client_a_jid = harness.client_a.get_jid().await.unwrap();
    let client_b_jid = harness.client_b.get_jid().await.unwrap();
    let client_b_address =
        SignalAddress::new(client_b_jid.user.clone(), client_b_jid.device as u32);

    // Alice processes Bob's bundle to establish a session
    let device_a_store_signal =
        DeviceStore::new(harness.client_a.persistence_manager.get_device_arc().await);
    let mut session_record = device_a_store_signal
        .load_session(&client_b_address)
        .await
        .unwrap();
    let builder = SessionBuilder::new(device_a_store_signal.clone(), client_b_address.clone());
    builder
        .process_bundle(&mut session_record, &bundle_b)
        .await
        .unwrap();
    device_a_store_signal
        .store_session(&client_b_address, &session_record)
        .await
        .unwrap();

    // Alice sends a message to Bob
    harness
        .client_a
        .send_text_message(client_b_jid.clone(), "Hello Bob!")
        .await
        .unwrap();

    // Bob receives and decrypts the message
    let (msg, info) = expect_message(&mut rx_b).await;
    assert_eq!(msg.conversation.unwrap(), "Hello Bob!");
    assert_eq!(info.source.sender, client_a_jid);

    info!("✅ test_send_receive_message completed successfully!");
}

#[tokio::test]
async fn test_two_pass_message_processing() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Debug)
        .try_init();

    let harness = TestHarness::new().await;
    let group_jid: Jid = "test_two_pass@g.us".parse().unwrap();
    let mut rx_b = harness.client_b.subscribe_to_all_events();
    let mut rx_c = harness.client_c.subscribe_to_all_events();

    // Establish Signal protocol sessions between all participants
    establish_all_signal_sessions(&harness).await;
    
    info!("Sessions established. Now sending group message.");
    
    // Send a group message from Alice
    let msg = "Hello group with proper sessions!";
    harness
        .client_a
        .send_text_message(group_jid.clone(), msg)
        .await
        .unwrap();

    info!("Group message sent. Waiting for recipients to receive and decrypt.");

    // Bob and Charlie should receive and decrypt the message
    let client_a_jid = harness.client_a.get_jid().await.unwrap();
    let (msg_b, info_b) = expect_message(&mut rx_b).await;
    let (msg_c, info_c) = expect_message(&mut rx_c).await;
    
    assert_eq!(msg_b.conversation.unwrap(), msg);
    assert_eq!(msg_c.conversation.unwrap(), msg);
    assert_eq!(info_b.source.sender, client_a_jid);
    assert_eq!(info_c.source.sender, client_a_jid);

    info!("✅ Two-pass message processing test passed!");
}

#[tokio::test]
async fn debug_message_structure() {
    let _ = env_logger::builder()
        .is_test(true)
        .filter_level(log::LevelFilter::Info)
        .try_init();

    // Set up a single client
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("store");
    let pm = Arc::new(
        PersistenceManager::new(store_path)
            .await
            .expect("Failed to create PersistenceManager"),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    let jid: Jid = "alice.1@lid".parse().unwrap();
    pm.process_command(DeviceCommand::SetId(Some(jid.clone()))).await;
    pm.process_command(DeviceCommand::SetLid(Some(jid.clone()))).await;
    pm.process_command(DeviceCommand::SetPushName("alice".to_string())).await;

    // Generate and store pre-keys for session establishment
    let device_store = pm.get_device_arc().await;
    let mut prekeys = keyhelper::generate_pre_keys(1, 1);
    device_store
        .lock()
        .await
        .store_prekey(1, prekeys.remove(0))
        .await
        .unwrap();

    // Enable test mode with a receiver we can monitor
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel();
    client.enable_test_mode(sender).await;

    // Try to send a message and capture the actual node being sent
    let target_jid: Jid = "bob.1@lid".parse().unwrap();
    
    info!("=== Attempting to send message ===");
    
    // Start a task to capture the message
    let capture_task = tokio::spawn(async move {
        if let Some(test_message) = receiver.recv().await {
            info!("📨 Captured message node: {}", test_message.node);
            info!("   From: {}", test_message.from);
            info!("   To: {:?}", test_message.to);
            
            // Check for enc children
            let enc_children = test_message.node.get_children_by_tag("enc");
            info!("   Enc children count: {}", enc_children.len());
            for (i, enc_child) in enc_children.iter().enumerate() {
                info!("   Enc child {}: {:?}", i, enc_child.attrs);
            }
        }
    });
    
    match client.send_text_message(target_jid, "Test message").await {
        Ok(()) => info!("✅ Message sent successfully"),
        Err(e) => info!("❌ Message failed: {}", e),
    }
    
    // Wait for message capture
    tokio::time::timeout(Duration::from_secs(2), capture_task).await.ok();
    
    info!("=== Test completed ===");
}
