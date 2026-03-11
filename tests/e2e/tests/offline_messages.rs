//! Tests for offline message queuing and delivery.
//!
//! These tests verify that the mock server properly queues messages for offline
//! clients and delivers them on reconnection, matching real WhatsApp server behavior.

use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::waproto::whatsapp as wa;

/// Test that a message sent while the recipient is offline is delivered on reconnect.
///
/// Flow:
/// 1. client_a and client_b connect
/// 2. client_b reconnects (drops connection, auto-reconnects with same identity)
/// 3. While client_b is reconnecting, client_a sends a message
/// 4. After client_b reconnects, it should receive the message from the offline queue
#[tokio::test]
async fn test_offline_message_delivery_on_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_offline_recon_a").await?;
    let mut client_b = TestClient::connect("e2e_offline_recon_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    info!("Client B JID: {jid_b}");

    // Drop client_b's connection (triggers auto-reconnect)
    client_b.client.reconnect().await;
    info!("Client B connection dropped, will auto-reconnect");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Send a message while client_b is reconnecting
    let text = "Hello from offline queue!";
    let message = wa::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    };

    let msg_id = client_a.client.send_message(jid_b.clone(), message).await?;
    info!("Client A sent message to reconnecting B: {msg_id}");

    // Client B should receive the message after reconnecting (from offline queue)
    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;

    if let Event::Message(msg, _) = event {
        assert_eq!(msg.conversation.as_deref(), Some(text));
        info!("Client B received offline message after reconnect");
    } else {
        panic!("Expected Message event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

/// Test that messages are delivered in order when recipient reconnects.
///
/// Sends multiple messages to an offline recipient and verifies they
/// arrive in the correct order after reconnection.
#[tokio::test]
async fn test_offline_message_ordering() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_offline_order_a").await?;
    let mut client_b = TestClient::connect("e2e_offline_order_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // Drop client_b's connection
    client_b.client.reconnect().await;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Send 3 messages in sequence
    let messages = vec!["first", "second", "third"];
    for text in &messages {
        let message = wa::Message {
            conversation: Some(text.to_string()),
            ..Default::default()
        };
        client_a.client.send_message(jid_b.clone(), message).await?;
        info!("Sent: {text}");
    }

    // Receive messages and verify order
    let mut received = Vec::new();
    for _ in 0..messages.len() {
        let event = client_b
            .wait_for_event(
                30,
                |e| matches!(e, Event::Message(msg, _) if msg.conversation.is_some()),
            )
            .await?;

        if let Event::Message(msg, _) = event {
            let text = msg.conversation.unwrap();
            info!("Received: {text}");
            received.push(text);
        }
    }

    assert_eq!(
        received, messages,
        "Messages should arrive in the order they were sent"
    );

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

/// Test that messages are delivered when the recipient is online (baseline).
#[tokio::test]
async fn test_message_delivery_when_online() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_offline_online_a").await?;
    let mut client_b = TestClient::connect("e2e_offline_online_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    let text = "Hello online B!";
    let message = wa::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    };

    client_a.client.send_message(jid_b.clone(), message).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;

    if let Event::Message(msg, _) = event {
        assert_eq!(msg.conversation.as_deref(), Some(text));
    } else {
        panic!("Expected Message event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

/// Test that the server accepts multiple messages for an offline recipient
/// without error (sender-side acceptance only — does not verify delivery).
#[tokio::test]
async fn test_server_accepts_messages_for_offline_recipient() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_offline_multi_a").await?;
    let client_b = TestClient::connect("e2e_offline_multi_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // Disconnect client_b fully
    client_b.disconnect().await;
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Send 5 messages to the offline client
    let mut msg_ids = Vec::new();
    for i in 1..=5 {
        let text = format!("Offline message {}", i);
        let message = wa::Message {
            conversation: Some(text),
            ..Default::default()
        };

        let msg_id = client_a.client.send_message(jid_b.clone(), message).await?;
        info!("Sent message {} to offline B: {}", i, msg_id);
        msg_ids.push(msg_id);
    }

    assert_eq!(
        msg_ids.len(),
        5,
        "All 5 messages should be accepted by the server"
    );

    client_a.disconnect().await;

    Ok(())
}
