use std::collections::HashMap;
use std::sync::Arc;
use whatsapp_rust::binary::node::Node;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::{commands::DeviceCommand, persistence_manager::PersistenceManager};

#[tokio::test]
async fn test_success_node_with_pushname() {
    let pm = Arc::new(PersistenceManager::new_in_memory().await.unwrap());
    let client = Arc::new(Client::new(pm.clone()).await);

    let mut attrs = HashMap::new();
    attrs.insert("pushname".to_string(), "Test User Name".to_string());
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);

    client.process_node(success_node).await;

    assert_eq!(client.get_push_name().await, "Test User Name");

    pm.process_command(DeviceCommand::SetId(Some(
        "1234567890@s.whatsapp.net".parse().unwrap(),
    )))
    .await;

    assert!(client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_without_pushname() {
    let pm = Arc::new(PersistenceManager::new_in_memory().await.unwrap());
    let client = Arc::new(Client::new(pm.clone()).await);

    let mut attrs = HashMap::new();
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    assert_eq!(client.get_push_name().await, "");

    client.process_node(success_node).await;

    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_empty_pushname() {
    let pm = Arc::new(PersistenceManager::new_in_memory().await.unwrap());
    let client = Arc::new(Client::new(pm.clone()).await);

    let mut attrs = HashMap::new();
    attrs.insert("pushname".to_string(), "".to_string());
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    assert_eq!(client.get_push_name().await, "");

    client.process_node(success_node.clone()).await;

    assert_eq!(client.get_push_name().await, "");
    assert!(!client.is_ready_for_presence().await);
}

#[tokio::test]
async fn test_success_node_pushname_update() {
    let pm = Arc::new(PersistenceManager::new_in_memory().await.unwrap());
    let client = Arc::new(Client::new(pm.clone()).await);

    client
        .set_push_name("Initial Name".to_string())
        .await
        .unwrap();
    assert_eq!(client.get_push_name().await, "Initial Name");

    let mut attrs = HashMap::new();
    attrs.insert("pushname".to_string(), "Updated Name".to_string());
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    client.process_node(success_node).await;

    assert_eq!(client.get_push_name().await, "Updated Name");
}

#[tokio::test]
async fn test_success_node_no_update_same_pushname() {
    let pm = Arc::new(PersistenceManager::new_in_memory().await.unwrap());
    let client = Arc::new(Client::new(pm.clone()).await);

    client.set_push_name("Same Name".to_string()).await.unwrap();
    assert_eq!(client.get_push_name().await, "Same Name");

    let mut attrs = HashMap::new();
    attrs.insert("pushname".to_string(), "Same Name".to_string());
    attrs.insert("status".to_string(), "200".to_string());

    let success_node = Node {
        tag: "success".to_string(),
        attrs,
        content: None,
    };

    client.process_node(success_node).await;

    assert_eq!(client.get_push_name().await, "Same Name");
}
