use std::sync::Arc;
use wacore::types::jid::Jid;
use whatsapp_rust::client::{Client, RecentMessageKey};
use whatsapp_rust::store::persistence_manager::PersistenceManager;

#[tokio::test]
async fn test_processed_message_deduplication() {
    let persistence_manager = Arc::new(
        PersistenceManager::new_in_memory()
            .await
            .expect("Failed to create PersistenceManager"),
    );

    let client = Arc::new(Client::new(persistence_manager).await);

    let test_jid: Jid = "test@s.whatsapp.net".parse().expect("Failed to parse JID");
    let message_key1 = RecentMessageKey {
        to: test_jid.clone(),
        id: "msg_001".to_string(),
    };
    let message_key2 = RecentMessageKey {
        to: test_jid.clone(),
        id: "msg_002".to_string(),
    };

    assert!(!client.has_message_been_processed(&message_key1).await);
    assert!(!client.has_message_been_processed(&message_key2).await);

    client.mark_message_as_processed(message_key1.clone()).await;

    assert!(client.has_message_been_processed(&message_key1).await);
    assert!(!client.has_message_been_processed(&message_key2).await);

    client.mark_message_as_processed(message_key2.clone()).await;

    assert!(client.has_message_been_processed(&message_key1).await);
    assert!(client.has_message_been_processed(&message_key2).await);

    let client2 = Arc::new(Client::new(client.persistence_manager.clone()).await);

    assert!(client2.has_message_been_processed(&message_key1).await);
    assert!(client2.has_message_been_processed(&message_key2).await);

    println!("✅ Event buffer deduplication test passed!");
}

#[tokio::test]
async fn test_processed_message_cap() {
    let persistence_manager = Arc::new(
        PersistenceManager::new_in_memory()
            .await
            .expect("Failed to create PersistenceManager"),
    );

    let client = Arc::new(Client::new(persistence_manager).await);

    let test_jid: Jid = "test@s.whatsapp.net".parse().expect("Failed to parse JID");

    let num_messages = 2005;
    let mut message_keys = Vec::new();

    for i in 0..num_messages {
        let message_key = RecentMessageKey {
            to: test_jid.clone(),
            id: format!("msg_{i:04}"),
        };
        message_keys.push(message_key.clone());
        client.mark_message_as_processed(message_key).await;
    }

    assert!(!client.has_message_been_processed(&message_keys[0]).await);
    assert!(!client.has_message_been_processed(&message_keys[1]).await);
    assert!(!client.has_message_been_processed(&message_keys[2]).await);
    assert!(!client.has_message_been_processed(&message_keys[3]).await);
    assert!(!client.has_message_been_processed(&message_keys[4]).await);

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
