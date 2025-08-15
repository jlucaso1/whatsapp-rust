use std::sync::Arc;

use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

#[tokio::test]
async fn test_recent_message_cache_insert_and_take() {
    let _ = env_logger::builder().is_test(true).try_init();

    let pm = Arc::new(PersistenceManager::new(":memory:").await.unwrap());
    let client = Arc::new(Client::new(pm.clone()).await);

    let chat: Jid = "120363021033254949@g.us".parse().unwrap();
    let msg_id = "ABC123".to_string();
    let msg = wa::Message {
        conversation: Some("hello".into()),
        ..Default::default()
    };

    client
        .add_recent_message(chat.clone(), msg_id.clone(), Arc::new(msg.clone()))
        .await;

    // First take should return the message and remove it from cache
    let taken = client
        .take_recent_message(chat.clone(), msg_id.clone())
        .await;
    assert!(taken.is_some(), "expected to retrieve cached message");
    assert_eq!(taken.unwrap().conversation.as_deref(), Some("hello"));

    // Second take should return None (consumed)
    let taken_again = client.take_recent_message(chat, msg_id).await;
    assert!(
        taken_again.is_none(),
        "expected cache miss after first take"
    );
}
