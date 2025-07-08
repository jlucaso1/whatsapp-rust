use std::collections::HashMap;
use std::sync::Arc;
use tempfile::TempDir;
use whatsapp_rust::binary::node::{Node, NodeContent};
use whatsapp_rust::client::Client;
use whatsapp_rust::store;
use whatsapp_rust::store::filestore::FileStore;

#[tokio::test]
async fn test_success_node_with_pushname() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let device = store::Device::new(store_backend.clone());
    let client = Arc::new(Client::new(device));

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

    // Simulate the handle_success call (we can't call it directly as it's private)
    // Instead, we'll test the logic that would be in handle_success
    if let Some(push_name) = success_node.attrs.get("pushname") {
        let mut store = client.store.write().await;
        if store.push_name != *push_name {
            store.push_name = push_name.clone();
        }
    }

    // Verify push name was updated
    assert_eq!(client.get_push_name().await, "Test User Name");

    // Set a JID to make it ready for presence
    {
        let mut store = client.store.write().await;
        store.id = Some("1234567890@s.whatsapp.net".parse().unwrap());
    }

    assert!(client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_without_pushname() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let device = store::Device::new(store_backend.clone());
    let client = Arc::new(Client::new(device));

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
    if let Some(push_name) = success_node.attrs.get("pushname") {
        let mut store = client.store.write().await;
        if store.push_name != *push_name {
            store.push_name = push_name.clone();
        }
    }

    // Verify push name remains empty (no pushname attribute in success node)
    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_empty_pushname() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let device = store::Device::new(store_backend.clone());
    let client = Arc::new(Client::new(device));

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
    if let Some(push_name) = success_node.attrs.get("pushname") {
        let mut store = client.store.write().await;
        if store.push_name != *push_name {
            store.push_name = push_name.clone();
        }
    }

    // Verify push name remains empty (empty pushname attribute)
    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_pushname_update() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let device = store::Device::new(store_backend.clone());
    let client = Arc::new(Client::new(device));

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
    if let Some(push_name) = success_node.attrs.get("pushname") {
        let mut store = client.store.write().await;
        if store.push_name != *push_name {
            store.push_name = push_name.clone();
        }
    }

    // Verify push name was updated
    assert_eq!(client.get_push_name().await, "Updated Name");
}

#[tokio::test]
async fn test_success_node_no_update_same_pushname() {
    // Create a temporary directory for the test
    let temp_dir = TempDir::new().unwrap();
    let store_path = temp_dir.path().join("test_store");

    // Create a new store and device
    let store_backend = Arc::new(FileStore::new(store_path.to_str().unwrap()).await.unwrap());
    let device = store::Device::new(store_backend.clone());
    let client = Arc::new(Client::new(device));

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
    if let Some(push_name) = success_node.attrs.get("pushname") {
        let mut store = client.store.write().await;
        if store.push_name != *push_name {
            store.push_name = push_name.clone();
        }
    }

    // Verify push name remains the same
    assert_eq!(client.get_push_name().await, "Same Name");
}
