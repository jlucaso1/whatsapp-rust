use std::sync::Arc;
use tokio;
use wacore::types::jid::Jid;
use whatsapp_rust::client::{Client, RecentMessageKey};
use whatsapp_rust::store::persistence_manager::PersistenceManager;

#[tokio::test]
async fn test_processed_message_deduplication() {
    // Create a temporary directory for the test
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let store_path = temp_dir.path().join("test_store");

    // Create PersistenceManager
    let persistence_manager = Arc::new(
        PersistenceManager::new(&store_path)
            .await
            .expect("Failed to create PersistenceManager"),
    );

    // Create a test client
    let client = Arc::new(Client::new(persistence_manager).await);

    // Create test message keys
    let test_jid: Jid = "test@s.whatsapp.net".parse().expect("Failed to parse JID");
    let message_key1 = RecentMessageKey {
        to: test_jid.clone(),
        id: "msg_001".to_string(),
    };
    let message_key2 = RecentMessageKey {
        to: test_jid.clone(),
        id: "msg_002".to_string(),
    };

    // Initially, no messages should be processed
    assert!(!client.has_message_been_processed(&message_key1).await);
    assert!(!client.has_message_been_processed(&message_key2).await);

    // Mark first message as processed
    client.mark_message_as_processed(message_key1.clone()).await;

    // First message should now be detected as processed
    assert!(client.has_message_been_processed(&message_key1).await);
    // Second message should still not be processed
    assert!(!client.has_message_been_processed(&message_key2).await);

    // Mark second message as processed
    client.mark_message_as_processed(message_key2.clone()).await;

    // Both messages should now be detected as processed
    assert!(client.has_message_been_processed(&message_key1).await);
    assert!(client.has_message_been_processed(&message_key2).await);

    // Test persistence: create a new client with the same persistence manager
    let client2 = Arc::new(Client::new(client.persistence_manager.clone()).await);

    // The new client should still recognize both messages as processed
    assert!(client2.has_message_been_processed(&message_key1).await);
    assert!(client2.has_message_been_processed(&message_key2).await);

    println!("✅ Event buffer deduplication test passed!");
}

#[tokio::test]
async fn test_processed_message_cap() {
    // Create a temporary directory for the test
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let store_path = temp_dir.path().join("test_store");

    // Create PersistenceManager
    let persistence_manager = Arc::new(
        PersistenceManager::new(&store_path)
            .await
            .expect("Failed to create PersistenceManager"),
    );

    // Create a test client
    let client = Arc::new(Client::new(persistence_manager).await);

    let test_jid: Jid = "test@s.whatsapp.net".parse().expect("Failed to parse JID");

    // Add more than the cap (2000) messages
    let num_messages = 2005;
    let mut message_keys = Vec::new();

    for i in 0..num_messages {
        let message_key = RecentMessageKey {
            to: test_jid.clone(),
            id: format!("msg_{:04}", i),
        };
        message_keys.push(message_key.clone());
        client.mark_message_as_processed(message_key).await;
    }

    // The first few messages should no longer be in the cache due to the cap
    assert!(!client.has_message_been_processed(&message_keys[0]).await);
    assert!(!client.has_message_been_processed(&message_keys[1]).await);
    assert!(!client.has_message_been_processed(&message_keys[2]).await);
    assert!(!client.has_message_been_processed(&message_keys[3]).await);
    assert!(!client.has_message_been_processed(&message_keys[4]).await);

    // But the recent messages should still be processed
    assert!(
        client
            .has_message_been_processed(&message_keys[num_messages - 1])
            .await
    );
    assert!(
        client
            .has_message_been_processed(&message_keys[num_messages - 2])
            .await
    );
    assert!(
        client
            .has_message_been_processed(&message_keys[num_messages - 10])
            .await
    );

    println!("✅ Event buffer capping test passed!");
}
