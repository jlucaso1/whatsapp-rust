use log::info;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use whatsapp_rust::client::Client;
use whatsapp_rust::store::persistence_manager::PersistenceManager;
use whatsapp_rust::store::signal::DeviceStore;

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
}

impl TestHarness {
    async fn new() -> Self {
        let (client_a, _temp_dir_a) = setup_test_client("alice.1@lid").await;
        let (client_b, _temp_dir_b) = setup_test_client("bob.1@lid").await;
        let (client_c, _temp_dir_c) = setup_test_client("charlie.1@lid").await;

        Self {
            client_a,
            client_b,
            client_c,
            _temp_dir_a,
            _temp_dir_b,
            _temp_dir_c,
        }
    }
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
