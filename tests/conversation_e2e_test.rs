// tests/conversation_e2e_test.rs
//
// End-to-end test simulating a conversation between two users.

use log::info;
use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir; // For temporary store paths
use tokio::sync::mpsc;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::persistence_manager::PersistenceManager; // Use PersistenceManager
use whatsapp_rust::store::signal::DeviceStore; // Import DeviceStore
use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::types::events::Event; // For direct store manipulation in tests
use wacore::binary::node::Node;
use wacore::types::Jid;

struct MockClient {
    client: Arc<Client>,
    network_tx: mpsc::Sender<(Jid, Node)>,
    jid: Jid,
}

use whatsapp_rust::send::send_text_message;

impl MockClient {
    async fn send_text_message(
        &self,
        to: Jid,
        text: &str,
    ) -> Result<(), whatsapp_rust::client::ClientError> {
        let (node, _id) = send_text_message(self.client.clone(), to, text).await.unwrap();
        info!("MockClient for {} sending node: {:?}", self.jid, node);
        self.network_tx
            .send((self.jid.clone(), node))
            .await
            .unwrap();
        Ok(())
    }
}

/// TestHarness manages the state for a single conversation test.
struct TestHarness {
    clients: HashMap<Jid, Arc<Client>>,
    pms: HashMap<Jid, Arc<PersistenceManager>>,
    event_rxs: HashMap<Jid, mpsc::UnboundedReceiver<Event>>,
    _temp_dirs: Vec<TempDir>,
    network_tx: mpsc::Sender<(Jid, Node)>,
    network_rx: mpsc::Receiver<(Jid, Node)>,
}

impl TestHarness {
    /// Creates a new test harness.
    async fn new() -> Self {
        let (network_tx, network_rx) = mpsc::channel(100);
        Self {
            clients: HashMap::new(),
            pms: HashMap::new(),
            event_rxs: HashMap::new(),
            _temp_dirs: Vec::new(),
            network_tx,
            network_rx,
        }
    }
}

#[tokio::test]
async fn test_conversation_setup() {
    // Initialize logging for better debugging
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    // 1. Setup
    let mut harness = TestHarness::new().await;
    let jid_a = "client_a@s.whatsapp.net".parse().unwrap();
    let jid_b = "client_b@s.whatsapp.net".parse().unwrap();

    // 2. Add clients to the harness
    harness.add_client(jid_a.clone()).await;
    harness.add_client(jid_b.clone()).await;

    // 3. Simulate pairing for Client A
    let pm_a = harness.pms.get(&jid_a).unwrap();
    pm_a.process_command(DeviceCommand::SetId(Some(jid_a.clone())))
        .await;
    pm_a.modify_device(|device| {
        device.registration_id = 12345;
    })
    .await;

    let snapshot_a = pm_a.get_device_snapshot().await;
    assert!(
        snapshot_a.id.is_some(),
        "Client A should have a JID after pairing"
    );
    assert_ne!(
        snapshot_a.registration_id, 0,
        "Client A should have a valid registration ID"
    );

    // 4. Simulate pairing for Client B
    let pm_b = harness.pms.get(&jid_b).unwrap();
    pm_b.process_command(DeviceCommand::SetId(Some(jid_b.clone())))
        .await;
    pm_b.modify_device(|device| {
        device.registration_id = 67890;
    })
    .await;

    let snapshot_b = pm_b.get_device_snapshot().await;
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

impl TestHarness {
    async fn add_client(&mut self, jid: Jid) {
        let temp_dir = TempDir::new().unwrap();
        let store_path = temp_dir.path().join(format!("{}_store", jid.user));
        let pm = Arc::new(
            PersistenceManager::new(store_path)
                .await
                .expect("Failed to create PersistenceManager"),
        );
        let client = Arc::new(Client::new(pm.clone()).await);
        let event_rx = client.subscribe_to_all_events();

        let mock_client = MockClient {
            client: client.clone(),
            network_tx: self.network_tx.clone(),
            jid: jid.clone(),
        };

        self.clients.insert(jid.clone(), client);
        self.pms.insert(jid.clone(), pm);
        self.event_rxs.insert(jid, event_rx);
        self._temp_dirs.push(temp_dir);
    }

    async fn route_one(&mut self) {
        let (_sender_jid, node) = self.network_rx.recv().await.unwrap();
        let to_jid_str = node.attrs.get("to").unwrap();
        let to_jid: Jid = to_jid_str.parse().unwrap();
        let client = self.clients.get(&to_jid).unwrap();
        client.process_node(node).await;
    }

    async fn route_all(&mut self, count: usize) {
        for _ in 0..count {
            self.route_one().await;
        }
    }
}

use whatsapp_rust::signal::store::{IdentityKeyStore, PreKeyStore, SessionStore};
use whatsapp_rust::signal::{
    SessionBuilder, SessionCipher,
    address::SignalAddress,
    ecc::keys::{DjbEcPublicKey, EcPublicKey},
    protocol::{Ciphertext, PREKEY_TYPE, WHISPER_TYPE},
    state::{prekey_bundle::PreKeyBundle, record},
    util::keyhelper,
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
        .lock()
        .await
        .load_prekey(1) // Assuming prekey ID 1 for simplicity
        .await
        .unwrap()
        .expect("PreKey #1 should exist for bundle creation");

    // Access fields from the snapshot for other parts
    let signed_prekey = device_snapshot.signed_pre_key.clone();
    let identity_key_pair = device_store_for_signal
        .lock()
        .await
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

use tokio::time::{timeout, Duration};

#[tokio::test]
async fn test_send_receive_message() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    // 1. Setup
    let mut harness = TestHarness::new().await;
    let client_a_jid: Jid = "client_a@s.whatsapp.net".parse().unwrap();
    let client_b_jid: Jid = "client_b@s.whatsapp.net".parse().unwrap();
    harness.add_client(client_a_jid.clone()).await;
    harness.add_client(client_b_jid.clone()).await;

    let pm_a = harness.pms.get(&client_a_jid).unwrap();
    let pm_b = harness.pms.get(&client_b_jid).unwrap();
    let client_a = harness.clients.get(&client_a_jid).unwrap();
    let _client_b = harness.clients.get(&client_b_jid).unwrap();
    let event_rx_b = harness.event_rxs.get_mut(&client_b_jid).unwrap();

    // Setup stores and establish session (simplified)
    // In a real scenario, this would involve QR pairing or login
    pm_a.process_command(DeviceCommand::SetId(Some(client_a_jid.clone())))
        .await;
    pm_b.process_command(DeviceCommand::SetId(Some(client_b_jid.clone())))
        .await;
    client_a.pair_with(client_b_jid.clone()).await.unwrap();

    // 2. SEND MESSAGE (A -> B)
    let mock_client_a = MockClient {
        client: client_a.clone(),
        network_tx: harness.network_tx.clone(),
        jid: client_a_jid.clone(),
    };
    let message_text = "Hello, World!";
    mock_client_a
        .send_text_message(client_b_jid.clone(), message_text)
        .await
        .unwrap();
    info!("Client A sent message to Client B.");

    // 3. ROUTE AND VERIFY
    harness.route_one().await;

    let event = timeout(Duration::from_secs(5), event_rx_b.recv())
        .await
        .expect("Timed out waiting for message event");
    match event.unwrap() {
        Event::Message(msg, _info) => {
            assert_eq!(msg.conversation, Some(message_text.to_string()));
            info!("Client B received and decrypted message successfully.");
        }
        _ => panic!("Expected a Message event"),
    }

    info!("✅ test_send_receive_message completed successfully!");
}
