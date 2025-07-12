use std::sync::Arc;
use tempfile::TempDir;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::commands::DeviceCommand;
use whatsapp_rust::store::persistence_manager::PersistenceManager; // Use PM // Use Commands
// use whatsapp_rust::store; // No longer needed directly
// use whatsapp_rust::store::filestore::FileStore; // Handled by PM
use whatsapp_rust::types::presence::Presence;

#[tokio::test]
async fn test_push_name_persistence() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store_persistence");
    let store_path_str = store_path.to_str().unwrap().to_string();
    log::info!("[test_push_name_persistence] Store path: {store_path_str}");

    // Phase 1: Setup and save
    {
        log::info!("[test_push_name_persistence] Initializing pm1 for path: {store_path_str}");
        let pm1 = Arc::new(
            PersistenceManager::new(store_path_str.clone())
                .await
                .unwrap(),
        );
        log::info!("[test_push_name_persistence] Setting push name 'Test User' on pm1");
        pm1.process_command(DeviceCommand::SetPushName("Test User".to_string()))
            .await;
        log::info!("[test_push_name_persistence] Setting ID on pm1");
        pm1.process_command(DeviceCommand::SetId(Some(
            "1234567890@s.whatsapp.net".parse().unwrap(),
        )))
        .await;

        log::info!("[test_push_name_persistence] Calling save_now on pm1");
        pm1.save_now().await.expect("Failed to save PM1 state");
        log::info!("[test_push_name_persistence] pm1 save_now complete. Dropping pm1.");
    }

    // Phase 2: Reload
    log::info!("[test_push_name_persistence] Initializing pm_reloaded for path: {store_path_str}");
    let pm_reloaded = Arc::new(
        PersistenceManager::new(store_path_str.clone())
            .await
            .unwrap(),
    );
    let reloaded_snapshot = pm_reloaded.get_device_snapshot().await;
    log::info!(
        "[test_push_name_persistence] Reloaded device push_name from snapshot: '{}'",
        reloaded_snapshot.push_name
    );
    log::info!(
        "[test_push_name_persistence] Reloaded device ID from snapshot: {:?}",
        reloaded_snapshot.id
    );

    let client = Arc::new(Client::new(pm_reloaded.clone()).await);

    // Test that push name is set correctly
    let current_push_name = client.get_push_name().await;
    log::info!(
        "[test_push_name_persistence] Push name from client.get_push_name(): '{current_push_name}'"
    );
    assert_eq!(current_push_name, "Test User");
    assert!(client.is_ready_for_presence().await);

    // Test that we can send presence (this should not fail)
    // Note: This will fail in the actual send because we're not connected,
    // but it should pass the push_name validation
    match client.send_presence(Presence::Available).await {
        Err(e) => {
            // The error should NOT be about missing push_name
            assert!(
                !e.to_string()
                    .contains("Cannot send presence without a push name set")
            );
        }
        Ok(_) => {
            // This shouldn't happen in a test environment without a real connection
            panic!("send_presence should fail due to no connection, not succeed");
        }
    }
}

#[tokio::test]
async fn test_push_name_empty_validation() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store_empty");

    // Initialize PersistenceManager, device will be new and empty
    let pm = Arc::new(
        PersistenceManager::new(store_path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    // Test that push name is empty
    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);

    // Test that send_presence fails with empty push_name
    match client.send_presence(Presence::Available).await {
        Err(e) => {
            assert!(
                e.to_string()
                    .contains("Cannot send presence without a push name set")
            );
        }
        Ok(_) => {
            panic!("send_presence should fail with empty push_name");
        }
    }
}

#[tokio::test]
async fn test_push_name_set_and_get() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store_set_get");

    // Initialize PersistenceManager
    let pm = Arc::new(
        PersistenceManager::new(store_path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    // Test setting push name
    client
        .set_push_name("Updated User".to_string())
        .await
        .unwrap();

    // Test getting push name
    assert_eq!(client.get_push_name().await, "Updated User");
}

#[tokio::test]
async fn test_device_state_reload() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store_reload");
    let store_path_str = store_path.to_str().unwrap().to_string();

    // Phase 1: Setup and save device info with PersistenceManager
    {
        let pm1 = Arc::new(
            PersistenceManager::new(store_path_str.clone())
                .await
                .unwrap(),
        );
        pm1.process_command(DeviceCommand::SetPushName("Original User".to_string()))
            .await;
        pm1.process_command(DeviceCommand::SetId(Some(
            "1234567890@s.whatsapp.net".parse().unwrap(),
        )))
        .await;

        // Explicitly save or ensure PM saves. For tests, a direct save is more reliable.
        pm1.save_now().await.expect("Failed to save PM1 state"); // Use save_now

        // To be robust, best to ensure save completes. We can drop pm1 and re-initialize.
    } // pm1 is dropped.

    // Phase 2: Create a new PersistenceManager instance to reload from the same path
    let pm2 = Arc::new(PersistenceManager::new(store_path_str).await.unwrap());
    let client = Arc::new(Client::new(pm2.clone()).await);

    // Test that push name was persisted and reloaded correctly
    assert_eq!(client.get_push_name().await, "Original User");
    assert!(client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_debug_info() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store_debug");

    // Initialize PersistenceManager
    let pm = Arc::new(
        PersistenceManager::new(store_path.to_str().unwrap())
            .await
            .unwrap(),
    );

    // Set up device info using commands
    pm.process_command(DeviceCommand::SetPushName("Debug User".to_string()))
        .await;
    pm.process_command(DeviceCommand::SetId(Some(
        "1234567890@s.whatsapp.net".parse().unwrap(),
    )))
    .await;

    let client = Arc::new(Client::new(pm.clone()).await);

    // Test debug info
    let debug_info = client.get_device_debug_info().await;
    println!("Debug info: {debug_info}");
    assert!(debug_info.contains("Debug User"));
    assert!(debug_info.contains("1234567890"));
    assert!(debug_info.contains("Ready for Presence: true"));
}
