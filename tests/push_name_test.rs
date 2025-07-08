use std::sync::Arc;
use tempfile::TempDir;
use whatsapp_rust::client::Client;
use whatsapp_rust::store;
use whatsapp_rust::store::filestore::FileStore;
use whatsapp_rust::types::presence::Presence;

#[tokio::test]
async fn test_push_name_persistence() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let mut device = store::Device::new(store_backend.clone());

    // Set up basic device info (simulating what happens during pairing)
    device.push_name = "Test User".to_string();
    device.id = Some("1234567890@s.whatsapp.net".parse().unwrap());

    // Save the device data
    store_backend
        .save_device_data(&device.to_serializable())
        .await
        .unwrap();

    // Create a client with the device
    let client = Arc::new(Client::new(device));

    // Test that push name is set correctly
    assert_eq!(client.get_push_name().await, "Test User");
    assert!(client.is_ready_for_presence().await);

    // Test that we can send presence (this should not fail)
    // Note: This will fail in the actual send because we're not connected,
    // but it should pass the push_name validation
    match client.send_presence(Presence::Available).await {
        Err(e) => {
            // The error should NOT be about missing push_name
            assert!(!e
                .to_string()
                .contains("Cannot send presence without a push name set"));
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
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let device = store::Device::new(store_backend.clone());

    // Create a client with the device (push_name should be empty)
    let client = Arc::new(Client::new(device));

    // Test that push name is empty
    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);

    // Test that send_presence fails with empty push_name
    match client.send_presence(Presence::Available).await {
        Err(e) => {
            assert!(e
                .to_string()
                .contains("Cannot send presence without a push name set"));
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
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let device = store::Device::new(store_backend.clone());

    // Create a client with the device
    let client = Arc::new(Client::new(device));

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
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let mut device = store::Device::new(store_backend.clone());

    // Set up device info and save it
    device.push_name = "Original User".to_string();
    device.id = Some("1234567890@s.whatsapp.net".parse().unwrap());
    store_backend
        .save_device_data(&device.to_serializable())
        .await
        .unwrap();

    // Create a new store instance (simulating app restart)
    let store_backend2 = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());

    // Load the device data
    let loaded_data = store_backend2.load_device_data().await.unwrap().unwrap();
    let mut device2 = store::Device::new(store_backend2.clone());
    device2.load_from_serializable(loaded_data);

    // Create a client with the reloaded device
    let client = Arc::new(Client::new(device2));

    // Test that push name was persisted and reloaded correctly
    assert_eq!(client.get_push_name().await, "Original User");
    assert!(client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_debug_info() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let mut device = store::Device::new(store_backend.clone());

    // Set up device info
    device.push_name = "Debug User".to_string();
    device.id = Some("1234567890@s.whatsapp.net".parse().unwrap());

    // Create a client with the device
    let client = Arc::new(Client::new(device));

    // Test debug info
    let debug_info = client.get_device_debug_info().await;
    println!("Debug info: {}", debug_info);
    assert!(debug_info.contains("Debug User"));
    assert!(debug_info.contains("1234567890"));
    assert!(debug_info.contains("Ready for Presence: true"));
}
