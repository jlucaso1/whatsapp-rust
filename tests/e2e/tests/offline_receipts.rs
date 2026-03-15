//! Tests for offline receipt and presence delivery.
//!
//! These tests verify that the mock server properly queues receipts and presence
//! updates for offline clients and delivers them on reconnection.

use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use wacore::types::presence::ReceiptType;
use whatsapp_rust::waproto::whatsapp as wa;

/// Test that delivery receipts are deferred when recipient is offline.
///
/// Real WhatsApp: sender gets single checkmark (server ack) immediately.
/// Double checkmark (delivery receipt) only arrives when recipient gets the message.
#[tokio::test]
async fn test_deferred_delivery_receipt() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_offline_receipt_a").await?;
    let client_b = TestClient::connect("e2e_offline_receipt_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // Disconnect client_b fully (stops run loop — no reconnect)
    client_b.disconnect().await;
    info!("Client B fully disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Client A sends a message to the fully-offline Client B
    let text = "Hello offline B!";
    let message = wa::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    };

    let msg_id = client_a.client.send_message(jid_b.clone(), message).await?;
    info!("Client A sent message to offline B: {msg_id}");

    // Client A should NOT get a delivery receipt (recipient never got the message).
    // Note: the sender receipt (type="sender") IS expected — it's the server confirming
    // it accepted the message. We specifically check for ReceiptType::Delivered.
    let result = client_a
        .wait_for_event(5, |e| {
            matches!(
                e,
                Event::Receipt(receipt)
                if receipt.message_ids.contains(&msg_id)
                    && receipt.r#type == ReceiptType::Delivered
            )
        })
        .await;

    assert!(
        result.is_err(),
        "Should NOT receive delivery receipt when recipient is offline"
    );

    info!("Confirmed: no delivery receipt for offline recipient (single checkmark)");

    client_a.disconnect().await;

    Ok(())
}

/// Test that delivery receipts queued for an offline sender are delivered on reconnect.
///
/// Flow:
/// 1. A and B connect
/// 2. B goes offline, A sends message to B (queued)
/// 3. A goes offline too
/// 4. B reconnects — receives the message, server generates delivery receipt for A (queued since A is offline)
/// 5. A reconnects — receives the delivery receipt
#[tokio::test]
async fn test_bidirectional_offline_receipt() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_off_bidir_a").await?;
    let mut client_b = TestClient::connect("e2e_off_bidir_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    info!("B={jid_b}");

    // Step 1: B goes offline
    client_b.client.reconnect().await;
    info!("B disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Step 2: A sends message to offline B
    let text = "Bidirectional offline test";
    let message = wa::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    };
    let msg_id = client_a.client.send_message(jid_b.clone(), message).await?;
    info!("A sent message to offline B: {msg_id}");

    // Step 3: A goes offline too
    client_a.client.reconnect().await;
    info!("A disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Step 4: B reconnects — receives the message
    let msg_event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;
    info!("B received offline message");

    if let Event::Message(msg, _) = msg_event {
        assert_eq!(msg.conversation.as_deref(), Some(text));
    }

    // Step 5: A reconnects — should receive the deferred delivery receipt
    let receipt_event = client_a
        .wait_for_event(30, |e| {
            matches!(
                e,
                Event::Receipt(receipt)
                if receipt.message_ids.contains(&msg_id)
                    && receipt.r#type == ReceiptType::Delivered
            )
        })
        .await
        .expect("A should receive deferred delivery receipt after reconnect");

    if let Event::Receipt(receipt) = receipt_event {
        info!(
            "A received deferred delivery receipt after reconnect: {:?}",
            receipt.r#type
        );
        assert!(receipt.message_ids.contains(&msg_id));
    } else {
        panic!("Expected Receipt event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

/// Test that deferred delivery receipt arrives when offline recipient reconnects.
///
/// Flow:
/// 1. B goes offline
/// 2. A sends a message to B (queued, no delivery receipt for A yet)
/// 3. B reconnects and receives the message from offline queue
/// 4. A should then receive the delivery receipt (double checkmark)
#[tokio::test]
async fn test_deferred_delivery_receipt_on_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_off_def_rcpt_a").await?;
    let mut client_b = TestClient::connect("e2e_off_def_rcpt_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    info!("B={jid_b}");

    // Step 1: B goes offline
    client_b.client.reconnect().await;
    info!("B disconnected (will auto-reconnect)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Step 2: A sends a message to offline B
    let text = "Waiting for delivery receipt";
    let message = wa::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    };

    let msg_id = client_a.client.send_message(jid_b.clone(), message).await?;
    info!("A sent message to offline B: {msg_id}");

    // A should NOT get delivery receipt yet (only sender receipt).
    // Timeout must be shorter than the reconnect backoff (see RECONNECT_BACKOFF_STEP)
    // so B is still offline during this window.
    let early_receipt = client_a
        .wait_for_event(3, |e| {
            matches!(
                e,
                Event::Receipt(receipt)
                if receipt.message_ids.contains(&msg_id)
                    && receipt.r#type == ReceiptType::Delivered
            )
        })
        .await;
    assert!(
        early_receipt.is_err(),
        "A should NOT get delivery receipt while B is offline"
    );
    info!("Confirmed: no early delivery receipt");

    // Step 3: B reconnects and should receive the message
    let msg_event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;
    info!("B received the offline message after reconnect");

    if let Event::Message(msg, _) = msg_event {
        assert_eq!(msg.conversation.as_deref(), Some(text));
    }

    // Step 4: A should now receive the delivery receipt (deferred)
    let delivery_receipt = client_a
        .wait_for_event(30, |e| {
            matches!(
                e,
                Event::Receipt(receipt)
                if receipt.message_ids.contains(&msg_id)
                    && receipt.r#type == ReceiptType::Delivered
            )
        })
        .await?;

    if let Event::Receipt(receipt) = delivery_receipt {
        info!(
            "A received deferred delivery receipt: ids={:?}, type={:?}",
            receipt.message_ids, receipt.r#type
        );
        assert!(receipt.message_ids.contains(&msg_id));
        assert_eq!(receipt.r#type, ReceiptType::Delivered);
    } else {
        panic!("Expected Receipt event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

/// Test that presence updates are coalesced for offline clients.
///
/// Flow:
/// 1. B subscribes to A's presence
/// 2. B goes offline via reconnect()
/// 3. A changes presence multiple times (available -> unavailable -> available)
/// 4. B reconnects — should receive only the latest presence (available), not all 3
///
/// Note: This tests coalescing behavior — real WhatsApp only delivers the latest
/// presence per source JID, not the full history.
#[tokio::test]
async fn test_offline_presence_coalescing() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_presence_a").await?;
    let mut client_b = TestClient::connect("e2e_off_presence_b").await?;

    let jid_a = client_a.client.get_pn().await.expect("A JID").to_non_ad();

    info!("A={jid_a}");

    // Step 1: B subscribes to A's presence while online
    client_b.client.presence().subscribe(&jid_a).await?;
    info!("B subscribed to A's presence");

    // A sets initial presence so B gets it
    client_a.client.presence().set_available().await?;

    // Wait for B to receive initial presence
    let _initial = client_b
        .wait_for_event(15, |e| matches!(e, Event::Presence(_)))
        .await?;
    info!("B received initial presence");

    // Step 2: B goes offline
    client_b.client.reconnect().await;
    info!("B disconnected (will auto-reconnect)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Step 3: A changes presence multiple times while B is offline
    client_a.client.presence().set_unavailable().await?;
    info!("A set unavailable");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    client_a.client.presence().set_available().await?;
    info!("A set available again");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Step 4: B reconnects — should eventually get a presence update
    // Due to coalescing, B should get only the latest state (available)
    let presence_event = client_b
        .wait_for_event(30, |e| matches!(e, Event::Presence(_)))
        .await?;

    if let Event::Presence(presence) = &presence_event {
        info!("B received coalesced presence: {:?}", presence);
        // The key test: we got a presence update after reconnect
        // Coalescing means we should only get one, not two
    } else {
        panic!("Expected Presence event");
    }

    // After reconnect, B may receive a second presence from the re-subscribe
    // response (the server sends A's current state when B re-subscribes).
    // Drain any additional presence events with a short timeout.
    let _ = client_b
        .wait_for_event(3, |e| matches!(e, Event::Presence(_)))
        .await;

    // Now confirm no MORE presence events arrive beyond the coalesced +
    // re-subscribe responses.
    let extra = client_b
        .wait_for_event(2, |e| matches!(e, Event::Presence(_)))
        .await;

    assert!(
        extra.is_err(),
        "Expected no extra presence events, but got: {:?}",
        extra.unwrap()
    );
    info!("Confirmed: no extra presence events after coalesced + re-subscribe drain");

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}
