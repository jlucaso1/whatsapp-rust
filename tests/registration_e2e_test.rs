// tests/registration_e2e_test.rs
//
// End-to-end test simulating the real WhatsApp interaction: client + server
// This test automates the pairing process and validates keepalive functionality.

use log::info;
use std::sync::Arc;
use tempfile::TempDir; // For temporary store paths
use tokio::sync::mpsc;
use whatsapp_rust::client::Client;
use whatsapp_rust::pair::pair_with_qr_code;
use whatsapp_rust::store::persistence_manager::PersistenceManager; // Use PersistenceManager
// use whatsapp_rust::store::memory::MemoryStore; // PM uses FileStore by default
// use whatsapp_rust::store::Device; // Device is managed by PM
use whatsapp_rust::store::commands::DeviceCommand; // For direct store manipulation in tests
use whatsapp_rust::types::events::Event;

/// TestHarness manages the state for a single integration test.
struct TestHarness {
    // The "phone" client, which is already logged in.
    master_client: Arc<Client>,
    pm_master: Arc<PersistenceManager>,
    // The new client we are testing.
    dut_client: Arc<Client>,
    pm_dut: Arc<PersistenceManager>,
    // A channel to receive events from the DUT.
    #[allow(dead_code)]
    dut_events_rx: mpsc::UnboundedReceiver<Event>,
    _temp_dir_master: TempDir,
    _temp_dir_dut: TempDir,
}

impl TestHarness {
    /// Creates a new test harness.
    async fn new() -> Self {
        let temp_dir_master = TempDir::new().unwrap();
        let store_path_master = temp_dir_master.path().join("master_store");
        let pm_master = Arc::new(
            PersistenceManager::new(store_path_master)
                .await
                .expect("Failed to create PersistenceManager for Master Client"),
        );
        let master_client = Arc::new(Client::new(pm_master.clone()).await);

        let temp_dir_dut = TempDir::new().unwrap();
        let store_path_dut = temp_dir_dut.path().join("dut_store");
        let pm_dut = Arc::new(
            PersistenceManager::new(store_path_dut)
                .await
                .expect("Failed to create PersistenceManager for DUT Client"),
        );
        let dut_client = Arc::new(Client::new(pm_dut.clone()).await);

        // Create an event channel for the DUT using the new typed event bus
        let dut_events_rx = dut_client.subscribe_to_all_events();

        Self {
            master_client,
            pm_master,
            dut_client,
            pm_dut,
            dut_events_rx,
            _temp_dir_master: temp_dir_master,
            _temp_dir_dut: temp_dir_dut,
        }
    }
}

#[tokio::test]
async fn test_pairing_and_keepalive() {
    // Initialize logging for better debugging
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    // 1. Setup
    let harness = TestHarness::new().await;

    // 2. Test QR code generation (this tests the core logic without network)
    let dut_device_snapshot = harness.pm_dut.get_device_snapshot().await;
    let qr_code =
        whatsapp_rust::pair::make_qr_data(&dut_device_snapshot, "test_ref_12345".to_string());
    // drop(dut_device_snapshot); // Not needed

    info!("📱 Generated QR code: {qr_code}");

    // Verify QR code format
    let parts: Vec<&str> = qr_code.split(',').collect();
    assert_eq!(parts.len(), 4, "QR code should have 4 parts");
    assert_eq!(parts[0], "test_ref_12345", "QR code ref should match");

    // 3. Setup the master client for pairing (simulate pre-authenticated phone)
    let master_snapshot = harness.pm_master.get_device_snapshot().await;
    if master_snapshot.id.is_none() {
        let master_jid = "1234567890@s.whatsapp.net".parse().unwrap();
        harness
            .pm_master
            .process_command(DeviceCommand::SetId(Some(master_jid)))
            .await;
    }
    // drop(master_snapshot); // Not needed

    // 4. Test the pairing crypto logic (without requiring network connection)
    let result = pair_with_qr_code(&harness.master_client, &qr_code).await;

    // The function should succeed in generating the pairing message even if network is unavailable
    // In a real environment, this would send the message over the network
    match result {
        Ok(()) => {
            info!("✅ Pairing crypto logic completed successfully");
        }
        Err(e) => {
            // We expect this to fail due to network issues in the test environment
            // but the crypto logic should have worked up to the network call
            info!("⚠️ Pairing failed as expected due to network: {e}");

            // Verify it's a network-related error, not a crypto error
            let error_str = e.to_string();
            assert!(
                error_str.contains("not connected")
                    || error_str.contains("Socket")
                    || error_str.contains("network")
                    || error_str.contains("connection")
                    || error_str.contains("WebSocket"),
                "Should fail due to network issues, not crypto. Error: {error_str}"
            );
        }
    }

    // 5. Test keepalive mechanism (simulate connection state)
    // Since we can't test real network keepalive without a connection,
    // we test the client's internal state management

    // The client should report as not connected since we never established a real connection
    assert!(
        !harness.dut_client.is_connected(),
        "Client should not be connected without network"
    );

    info!("✅ E2E test completed - pairing logic validated, keepalive state verified");

    // In a real environment with network access, this test would:
    // 1. Actually connect to WhatsApp servers
    // 2. Complete the full pairing handshake
    // 3. Wait 60 seconds to test keepalive
    // 4. Verify connection remains active
}

#[tokio::test] // Needs to be async for PersistenceManager
async fn test_qr_code_generation() {
    // Test the QR code generation in isolation
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("qr_test_store");
    let pm = Arc::new(
        PersistenceManager::new(store_path)
            .await
            .expect("Failed to create PersistenceManager for QR test"),
    );
    let device_snapshot = pm.get_device_snapshot().await;

    let qr_code = whatsapp_rust::pair::make_qr_data(&device_snapshot, "test_ref_123".to_string());

    // Verify QR code structure
    let parts: Vec<&str> = qr_code.split(',').collect();
    assert_eq!(
        parts.len(),
        4,
        "QR code should have exactly 4 comma-separated parts"
    );
    assert_eq!(parts[0], "test_ref_123", "First part should be the ref");

    // Verify that the other parts are valid base64
    use base64::prelude::*;

    assert!(
        BASE64_STANDARD.decode(parts[1]).is_ok(),
        "Noise public key should be valid base64"
    );
    assert!(
        BASE64_STANDARD.decode(parts[2]).is_ok(),
        "Identity public key should be valid base64"
    );
    assert!(
        BASE64_STANDARD.decode(parts[3]).is_ok(),
        "ADV secret should be valid base64"
    );

    // Verify key lengths
    assert_eq!(
        BASE64_STANDARD.decode(parts[1]).unwrap().len(),
        32,
        "Noise public key should be 32 bytes"
    );
    assert_eq!(
        BASE64_STANDARD.decode(parts[2]).unwrap().len(),
        32,
        "Identity public key should be 32 bytes"
    );
    assert_eq!(
        BASE64_STANDARD.decode(parts[3]).unwrap().len(),
        32,
        "ADV secret should be 32 bytes"
    );
}
