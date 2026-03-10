//! Tests for receipt routing (delivery, read, played) in both online and offline flows.
//!
//! These tests verify that the mock server correctly forwards client-sent receipts
//! to the intended recipient, matching real WhatsApp server behavior:
//! - Delivery receipts (no type) → double check ✓✓
//! - Read receipts (type="read") → blue checks ✓✓
//! - Receipts are queued when the target is offline and delivered on reconnect.

use e2e_tests::TestClient;
use log::info;
use std::time::Duration;
use wacore::types::events::Event;
use wacore::types::presence::ReceiptType;
use whatsapp_rust::features::{GroupCreateOptions, GroupParticipantOptions};
use whatsapp_rust::waproto::whatsapp as wa;

// ── Delivery Receipts (online) ──────────────────────────────────────────────

/// Both clients online: A sends message to B, A should receive a delivery receipt
/// after B processes the message.
#[tokio::test]
async fn test_delivery_receipt_online() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_online_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_online_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    let msg_id = client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some("Hello B!".to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent message: {msg_id}");

    // B should receive the message
    client_b
        .wait_for_event(
            15,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some("Hello B!")),
        )
        .await?;
    info!("B received message");

    // A should receive the delivery receipt (B's client sends it automatically)
    let event = client_a
        .wait_for_event(15, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await?;

    if let Event::Receipt(r) = event {
        info!("A received delivery receipt: {:?}", r.r#type);
        assert!(r.message_ids.contains(&msg_id));
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ── Read Receipts (online) ──────────────────────────────────────────────────

/// Both clients online: A sends message to B, B marks it as read, A gets read receipt.
#[tokio::test]
async fn test_read_receipt_online() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_read_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_read_b").await?;

    let jid_a = client_a.client.get_pn().await.expect("A JID").to_non_ad();
    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    let msg_id = client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some("Read me!".to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent message: {msg_id}");

    // B receives the message
    client_b
        .wait_for_event(
            15,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some("Read me!")),
        )
        .await?;

    // B sends read receipt
    client_b
        .client
        .mark_as_read(&jid_a, None, vec![msg_id.clone()])
        .await?;
    info!("B marked message as read");

    // A should receive the read receipt
    let event = client_a
        .wait_for_event(15, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Read
            )
        })
        .await?;

    if let Event::Receipt(r) = event {
        info!("A received read receipt: {:?}", r.r#type);
        assert_eq!(r.r#type, ReceiptType::Read);
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ── Delivery Receipts (offline → reconnect) ─────────────────────────────────

/// B offline, A sends message, B reconnects → A gets deferred delivery receipt.
#[tokio::test]
async fn test_delivery_receipt_offline_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_off_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_off_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    // B goes offline
    client_b.client.reconnect().await;
    info!("B disconnected (will auto-reconnect)");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let msg_id = client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some("Offline delivery test".to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent message to offline B: {msg_id}");

    // A should NOT get delivery receipt while B is offline
    let early = client_a
        .wait_for_event(3, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await;
    assert!(
        early.is_err(),
        "Should NOT receive delivery receipt while B is offline"
    );
    info!("Confirmed: no early delivery receipt");

    // B reconnects and receives the message
    client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some("Offline delivery test")),
        )
        .await?;
    info!("B received offline message after reconnect");

    // A should now receive the delivery receipt
    let event = client_a
        .wait_for_event(15, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await?;

    if let Event::Receipt(r) = event {
        info!("A received deferred delivery receipt: {:?}", r.r#type);
        assert!(r.message_ids.contains(&msg_id));
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ── Read Receipts (offline sender) ──────────────────────────────────────────

/// A sends to B, A goes offline, B reads, A reconnects → A gets queued read receipt.
#[tokio::test]
async fn test_read_receipt_queued_for_offline_sender() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_read_off_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_read_off_b").await?;

    let jid_a = client_a.client.get_pn().await.expect("A JID").to_non_ad();
    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    // A sends message to B (both online)
    let msg_id = client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some("Read while I'm away".to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent message: {msg_id}");

    // B receives the message
    client_b
        .wait_for_event(
            15,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some("Read while I'm away")),
        )
        .await?;
    info!("B received message");

    // Drain A's delivery receipt first
    let _ = client_a
        .wait_for_event(10, |e| {
            matches!(
                e,
                Event::Receipt(r) if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await;

    // A goes offline
    client_a.client.reconnect().await;
    info!("A disconnected (will auto-reconnect)");
    tokio::time::sleep(Duration::from_millis(500)).await;

    // B sends read receipt while A is offline
    client_b
        .client
        .mark_as_read(&jid_a, None, vec![msg_id.clone()])
        .await?;
    info!("B marked message as read (A is offline)");

    // A reconnects and should get the queued read receipt
    let event = client_a
        .wait_for_event(30, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Read
            )
        })
        .await?;

    if let Event::Receipt(r) = event {
        info!(
            "A received queued read receipt after reconnect: {:?}",
            r.r#type
        );
        assert_eq!(r.r#type, ReceiptType::Read);
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ── Bidirectional offline ───────────────────────────────────────────────────

/// Both go offline at different times: B offline → A sends → A offline → B reconnects →
/// A reconnects → A gets delivery receipt.
#[tokio::test]
async fn test_delivery_receipt_bidirectional_offline() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_bidir_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_bidir_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    // B goes offline
    client_b.client.reconnect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    info!("B offline");

    // A sends message to offline B
    let msg_id = client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some("Bidirectional test".to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent to offline B: {msg_id}");

    // A goes offline too
    client_a.client.reconnect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    info!("A offline");

    // B reconnects → receives message → sends delivery receipt → A is offline → queued
    let msg_event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some("Bidirectional test")),
        )
        .await?;
    assert!(matches!(msg_event, Event::Message(..)));
    info!("B received offline message");

    // A reconnects → should get queued delivery receipt
    let receipt = client_a
        .wait_for_event(30, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await?;

    if let Event::Receipt(r) = receipt {
        info!("A received queued delivery receipt: {:?}", r.r#type);
        assert!(r.message_ids.contains(&msg_id));
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ── No receipt when fully offline ───────────────────────────────────────────

/// B disconnects fully (no reconnect). A should NOT get delivery receipt.
#[tokio::test]
async fn test_no_delivery_receipt_for_fully_offline() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_no_a").await?;
    let client_b = TestClient::connect("e2e_rcpt_no_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    // B disconnects fully (no reconnect)
    client_b.disconnect().await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    info!("B fully disconnected");

    let msg_id = client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some("No receipt expected".to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent to fully-offline B: {msg_id}");

    // A should NOT receive delivery receipt
    let result = client_a
        .wait_for_event(5, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await;

    assert!(
        result.is_err(),
        "Should NOT receive delivery receipt when B never reconnects"
    );
    info!("Confirmed: no delivery receipt for fully-offline recipient");

    client_a.disconnect().await;
    Ok(())
}

// ── Group delivery receipt ──────────────────────────────────────────────────

/// Group message: A sends to group, B (participant) sends delivery receipt back to A.
#[tokio::test]
async fn test_group_delivery_receipt() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_grp_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_grp_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    // Create group with A and B
    let group_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Receipt Test Group".to_string(),
            participants: vec![GroupParticipantOptions::new(jid_b.clone())],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group created: {group_jid}");

    // Wait for B to receive group create notification
    client_b
        .wait_for_event(10, |e| {
            matches!(e, Event::Notification(node) if node.attrs().optional_string("type") == Some("w:gp2"))
        })
        .await?;

    // A sends group message
    let msg_id = client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some("Group receipt test".to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent group message: {msg_id}");

    // B receives the group message
    client_b
        .wait_for_event(
            15,
            |e| matches!(e, Event::Message(msg, info) if msg.conversation.as_deref() == Some("Group receipt test") && info.source.chat == group_jid),
        )
        .await?;
    info!("B received group message");

    // A should receive delivery receipt from B
    let event = client_a
        .wait_for_event(15, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await?;

    if let Event::Receipt(r) = event {
        info!(
            "A received group delivery receipt: type={:?}, from={:?}",
            r.r#type, r.source.chat
        );
        assert!(r.message_ids.contains(&msg_id));
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
