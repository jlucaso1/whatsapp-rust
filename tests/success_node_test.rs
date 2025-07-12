use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use whatsapp_rust::binary::node::Node;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::{commands::DeviceCommand, persistence_manager::PersistenceManager}; // Added PM and Command, removed self
// use whatsapp_rust::store::filestore::FileStore; // FileStore is managed by PM

#[tokio::test]
async fn test_success_node_with_pushname() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Initialize PersistenceManager
    let pm = Arc::new(
        PersistenceManager::new(store_path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    // Create a success node with pushname attribute
    let mut attrs = HashMap::new();
    attrs.insert("pushname".to_string(), "Test User Name".to_string());
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    // Verify push name is initially empty
    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);

    // Call the actual handle_success method (making it pub(crate) or using a helper if needed)
    // For now, directly invoking the logic within client that processes this.
    // Client::handle_success is async, and it will use persistence_manager internally.
    client.process_node(success_node).await; // Assuming process_node routes to handle_success

    // Verify push name was updated
    assert_eq!(client.get_push_name().await, "Test User Name");

    // Set a JID to make it ready for presence using PersistenceManager command
    pm.process_command(DeviceCommand::SetId(Some(
        "1234567890@s.whatsapp.net".parse().unwrap(),
    )))
    .await;

    assert!(client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_without_pushname() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Initialize PersistenceManager
    let pm = Arc::new(
        PersistenceManager::new(store_path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    // Create a success node without pushname attribute
    let mut attrs = HashMap::new();
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    // Verify push name is initially empty
    assert_eq!(client.get_push_name().await, "");

    // Simulate the handle_success call logic
    client.process_node(success_node).await; // Assuming process_node routes to handle_success

    // Verify push name remains empty (no pushname attribute in success node)
    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_empty_pushname() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Initialize PersistenceManager
    let pm = Arc::new(
        PersistenceManager::new(store_path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    // Create a success node with empty pushname attribute
    let mut attrs = HashMap::new();
    attrs.insert("pushname".to_string(), "".to_string());
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    // Verify push name is initially empty
    assert_eq!(client.get_push_name().await, "");

    // Simulate the handle_success call logic
    client.process_node(success_node.clone()).await; // Assuming process_node routes to handle_success

    // Verify push name remains empty (empty pushname attribute)
    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_pushname_update() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Initialize PersistenceManager
    let pm = Arc::new(
        PersistenceManager::new(store_path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    // Set an initial push name
    client
        .set_push_name("Initial Name".to_string())
        .await
        .unwrap();
    assert_eq!(client.get_push_name().await, "Initial Name");

    // Create a success node with a different pushname
    let mut attrs = HashMap::new();
    attrs.insert("pushname".to_string(), "Updated Name".to_string());
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    // Simulate the handle_success call logic
    client.process_node(success_node).await; // Assuming process_node routes to handle_success

    // Verify push name was updated
    assert_eq!(client.get_push_name().await, "Updated Name");
}

#[tokio::test]
async fn test_success_node_no_update_same_pushname() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Initialize PersistenceManager
    let pm = Arc::new(
        PersistenceManager::new(store_path.to_str().unwrap())
            .await
            .unwrap(),
    );
    let client = Arc::new(Client::new(pm.clone()).await);

    // Set an initial push name
    client.set_push_name("Same Name".to_string()).await.unwrap();
    assert_eq!(client.get_push_name().await, "Same Name");

    // Create a success node with the same pushname
    let mut attrs = HashMap::new();
    attrs.insert("pushname".to_string(), "Same Name".to_string());
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    // Simulate the handle_success call logic
    client.process_node(success_node).await; // Assuming process_node routes to handle_success

    // Verify push name remains the same
    assert_eq!(client.get_push_name().await, "Same Name");
}
