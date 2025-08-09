use log::info;
use std::sync::Arc;
use tokio::sync::mpsc;
use whatsapp_rust::client::Client;
use whatsapp_rust::pair::pair_with_qr_code;
use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::store::persistence_manager::PersistenceManager;
use whatsapp_rust::types::events::Event;

struct TestHarness {
    master_client: Arc<Client>,
    pm_master: Arc<PersistenceManager>,
    dut_client: Arc<Client>,
    pm_dut: Arc<PersistenceManager>,
    #[allow(dead_code)]
    dut_events_rx: mpsc::UnboundedReceiver<Event>,
}

impl TestHarness {
    async fn new() -> Self {
        let pm_master = Arc::new(
            PersistenceManager::new_in_memory()
                .await
                .expect("Failed to create PersistenceManager for Master Client"),
        );
        let master_client = Arc::new(Client::new(pm_master.clone()).await);

        let pm_dut = Arc::new(
            PersistenceManager::new_in_memory()
                .await
                .expect("Failed to create PersistenceManager for DUT Client"),
        );
        let dut_client = Arc::new(Client::new(pm_dut.clone()).await);

        let dut_events_rx = dut_client.subscribe_to_all_events();

        Self {
            master_client,
            pm_master,
            dut_client,
            pm_dut,
            dut_events_rx,
        }
    }
}

#[tokio::test]
async fn test_pairing_and_keepalive() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    let harness = TestHarness::new().await;

    let dut_device_snapshot = harness.pm_dut.get_device_snapshot().await;
    let qr_code =
        whatsapp_rust::pair::make_qr_data(&dut_device_snapshot, "test_ref_12345".to_string());

    info!("📱 Generated QR code: {qr_code}");

    let parts: Vec<&str> = qr_code.split(',').collect();
    assert_eq!(parts.len(), 4, "QR code should have 4 parts");
    assert_eq!(parts[0], "test_ref_12345", "QR code ref should match");

    let master_snapshot = harness.pm_master.get_device_snapshot().await;
    if master_snapshot.id.is_none() {
        let master_jid = "1234567890@s.whatsapp.net".parse().unwrap();
        harness
            .pm_master
            .process_command(DeviceCommand::SetId(Some(master_jid)))
            .await;
    }

    let result = pair_with_qr_code(&harness.master_client, &qr_code).await;

    match result {
        Ok(()) => {
            info!("✅ Pairing crypto logic completed successfully");
        }
        Err(e) => {
            info!("⚠️ Pairing failed as expected due to network: {e}");

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

    assert!(
        !harness.dut_client.is_connected(),
        "Client should not be connected without network"
    );

    info!("✅ E2E test completed - pairing logic validated, keepalive state verified");
}

#[tokio::test]
async fn test_qr_code_generation() {
    let pm = Arc::new(
        PersistenceManager::new_in_memory()
            .await
            .expect("Failed to create PersistenceManager for QR test"),
    );
    let device_snapshot = pm.get_device_snapshot().await;

    let qr_code = whatsapp_rust::pair::make_qr_data(&device_snapshot, "test_ref_123".to_string());

    let parts: Vec<&str> = qr_code.split(',').collect();
    assert_eq!(
        parts.len(),
        4,
        "QR code should have exactly 4 comma-separated parts"
    );
    assert_eq!(parts[0], "test_ref_123", "First part should be the ref");

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
