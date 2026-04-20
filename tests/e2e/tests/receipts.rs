//! Tests for receipt routing (delivery, read, played) in both online and offline flows.
//!
//! These tests verify that the mock server correctly forwards client-sent receipts
//! to the intended recipient, matching real WhatsApp server behavior:
//! - Delivery receipts (no type) → double check ✓✓
//! - Read receipts (type="read") → blue checks ✓✓
//! - Receipts are queued when the target is offline and delivered on reconnect.

use e2e_tests::{TestClient, text_msg};
use log::info;
use std::time::Duration;
use wacore::types::events::Event;
use wacore::types::presence::ReceiptType;
use whatsapp_rust::features::{GroupCreateOptions, GroupParticipantOptions};

/// Both clients online: A sends message to B, A should receive a delivery receipt.
#[tokio::test]
async fn test_delivery_receipt_online() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_online_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_online_b").await?;

    let jid_b = client_b.jid().await;

    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg("Hello B!"))
        .await?
        .message_id;
    info!("A sent message: {msg_id}");

    client_b.wait_for_text("Hello B!", 15).await?;
    info!("B received message");

    // B's client sends delivery receipt automatically
    client_a
        .wait_for_event(15, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await?;
    info!("A received delivery receipt");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Both clients online: A sends message to B, B marks it as read, A gets read receipt.
#[tokio::test]
async fn test_read_receipt_online() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_read_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_read_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;

    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg("Read me!"))
        .await?
        .message_id;
    info!("A sent message: {msg_id}");

    client_b.wait_for_text("Read me!", 15).await?;

    client_b
        .client
        .mark_as_read(&jid_a, None, vec![msg_id.clone()])
        .await?;
    info!("B marked message as read");

    client_a
        .wait_for_event(15, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Read
            )
        })
        .await?;
    info!("A received read receipt");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// B offline, A sends message, B reconnects -> A gets deferred delivery receipt.
#[tokio::test]
async fn test_delivery_receipt_offline_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_off_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_off_b").await?;

    let jid_b = client_b.jid().await;

    client_b.client.reconnect().await;
    info!("B disconnected (will auto-reconnect)");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg("Offline delivery test"))
        .await?
        .message_id;
    info!("A sent message to offline B: {msg_id}");

    // No delivery receipt while B is offline
    client_a
        .assert_no_event(
            3,
            |e| {
                matches!(
                    e,
                    Event::Receipt(r)
                    if r.message_ids.contains(&msg_id)
                        && r.r#type == ReceiptType::Delivered
                )
            },
            "Should NOT receive delivery receipt while B is offline",
        )
        .await?;
    info!("Confirmed: no early delivery receipt");

    client_b.wait_for_text("Offline delivery test", 30).await?;
    info!("B received offline message after reconnect");

    client_a
        .wait_for_event(15, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await?;
    info!("A received deferred delivery receipt");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// A sends to B, A goes offline, B reads, A reconnects -> A gets queued read receipt.
#[tokio::test]
async fn test_read_receipt_queued_for_offline_sender() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_read_off_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_read_off_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;

    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg("Read while I'm away"))
        .await?
        .message_id;
    info!("A sent message: {msg_id}");

    client_b.wait_for_text("Read while I'm away", 15).await?;
    info!("B received message");

    // Drain A's delivery receipt before going offline
    let _ = client_a
        .wait_for_event(10, |e| {
            matches!(
                e,
                Event::Receipt(r) if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await;

    client_a.client.reconnect().await;
    info!("A disconnected (will auto-reconnect)");
    tokio::time::sleep(Duration::from_millis(100)).await;

    client_b
        .client
        .mark_as_read(&jid_a, None, vec![msg_id.clone()])
        .await?;
    info!("B marked message as read (A is offline)");

    // A reconnects and gets the queued read receipt
    client_a
        .wait_for_event(30, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Read
            )
        })
        .await?;
    info!("A received queued read receipt after reconnect");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Both go offline at different times: B offline -> A sends -> A offline -> B reconnects ->
/// A reconnects -> A gets delivery receipt.
#[tokio::test]
async fn test_delivery_receipt_bidirectional_offline() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_bidir_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_bidir_b").await?;

    let jid_b = client_b.jid().await;

    client_b.client.reconnect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    info!("B offline");

    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg("Bidirectional test"))
        .await?
        .message_id;
    info!("A sent to offline B: {msg_id}");

    client_a.client.reconnect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    info!("A offline");

    // B reconnects, receives message, sends delivery receipt (queued since A is offline)
    client_b.wait_for_text("Bidirectional test", 30).await?;
    info!("B received offline message");

    // A reconnects and gets queued delivery receipt
    client_a
        .wait_for_event(30, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await?;
    info!("A received queued delivery receipt");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// B disconnects fully (no reconnect). A should NOT get delivery receipt.
#[tokio::test]
async fn test_no_delivery_receipt_for_fully_offline() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_no_a").await?;
    let client_b = TestClient::connect("e2e_rcpt_no_b").await?;

    let jid_b = client_b.jid().await;

    client_b.disconnect().await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    info!("B fully disconnected");

    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg("No receipt expected"))
        .await?
        .message_id;
    info!("A sent to fully-offline B: {msg_id}");

    client_a
        .assert_no_event(
            5,
            |e| {
                matches!(
                    e,
                    Event::Receipt(r)
                    if r.message_ids.contains(&msg_id)
                        && r.r#type == ReceiptType::Delivered
                )
            },
            "Should NOT receive delivery receipt when B never reconnects",
        )
        .await?;
    info!("Confirmed: no delivery receipt for fully-offline recipient");

    client_a.disconnect().await;
    Ok(())
}

/// Group message: A sends to group, B (participant) sends delivery receipt back to A.
#[tokio::test]
async fn test_group_delivery_receipt() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_grp_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_grp_b").await?;

    let jid_b = client_b.jid().await;

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

    client_b.wait_for_group_notification(10).await?;

    let msg_id = client_a
        .client
        .send_message(group_jid.clone(), text_msg("Group receipt test"))
        .await?
        .message_id;
    info!("A sent group message: {msg_id}");

    client_b
        .wait_for_group_text(&group_jid, "Group receipt test", 15)
        .await?;
    info!("B received group message");

    client_a
        .wait_for_event(15, |e| {
            matches!(
                e,
                Event::Receipt(r)
                if r.message_ids.contains(&msg_id)
                    && r.r#type == ReceiptType::Delivered
            )
        })
        .await?;
    info!("A received group delivery receipt");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Regression test for issue #571: disconnect must flush in-flight delivery
/// receipts so they don't race the transport tear-down. Burst of N messages
/// reliably hits the race window for at least one receipt.
#[tokio::test]
async fn test_delivery_receipts_flushed_on_disconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_rcpt_flush_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_flush_b").await?;

    let jid_b = client_b.jid().await;

    const N: usize = 5;
    let mut msg_ids: Vec<String> = Vec::with_capacity(N);
    for i in 0..N {
        let text = format!("flush burst {i}");
        let id = client_a
            .client
            .send_message(jid_b.clone(), text_msg(&text))
            .await?
            .message_id;
        msg_ids.push(id);
    }
    info!("A sent {N} messages: {msg_ids:?}");

    // Wait for every message event so later-arriving ones can't slip past the
    // disconnect. Event::Message dispatches right after the receipt task is
    // spawned, so by then the receipt may still be queued on the runtime.
    let mut seen = std::collections::HashSet::<usize>::new();
    while seen.len() < N {
        let event = client_b
            .wait_for_event(15, |e| {
                matches!(e, Event::Message(m, _) if m
                    .conversation
                    .as_deref()
                    .and_then(|c| c.strip_prefix("flush burst "))
                    .and_then(|s| s.parse::<usize>().ok())
                    .is_some_and(|i| i < N))
            })
            .await?;
        if let Event::Message(m, _) = &*event
            && let Some(i) = m
                .conversation
                .as_deref()
                .and_then(|c| c.strip_prefix("flush burst "))
                .and_then(|s| s.parse::<usize>().ok())
        {
            seen.insert(i);
        }
    }
    info!("B saw all {N} message events");

    client_b.disconnect().await;
    info!("B disconnected");

    // Dedupe by message_id — server may coalesce or split receipt stanzas.
    let mut pending: std::collections::HashSet<String> = msg_ids.iter().cloned().collect();
    while !pending.is_empty() {
        let event = client_a
            .wait_for_event(15, |e| {
                matches!(
                    e,
                    Event::Receipt(r)
                    if r.r#type == ReceiptType::Delivered
                        && r.message_ids.iter().any(|id| pending.contains(id))
                )
            })
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "Timed out waiting for delivery receipts, still pending: {:?} ({e})",
                    pending
                )
            })?;
        if let Event::Receipt(r) = &*event {
            for id in &r.message_ids {
                pending.remove(id);
            }
        }
    }
    info!("A received all {N} delivery receipts");

    client_a.disconnect().await;
    Ok(())
}

/// Performance regression guard for issue #571 / PR #573: `disconnect()`
/// must not pad latency when there are no pending receipt tasks. Cold
/// disconnect (just connected, never received a message) should complete
/// in milliseconds, not anywhere near the 5s drain cap.
#[tokio::test]
async fn test_disconnect_is_fast_with_no_pending_receipts() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_rcpt_cold_disconnect").await?;

    let start = std::time::Instant::now();
    client.client.disconnect().await;
    let elapsed = start.elapsed();

    info!("cold disconnect took {elapsed:?}");
    assert!(
        elapsed < Duration::from_millis(500),
        "disconnect with zero pending receipts took {elapsed:?}, expected well under 500ms — \
         likely waiting on the receipt-drain cap"
    );
    Ok(())
}

/// Hot disconnect: B receives a burst of messages from A and disconnects
/// immediately. The drain SHOULD complete fast (each receipt is a single
/// `<receipt>` send) — significantly faster than the 5s cap. Padding here
/// would compound across every test that creates+tears-down a client.
#[tokio::test]
async fn test_disconnect_is_fast_with_pending_receipts() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_rcpt_hot_a").await?;
    let mut client_b = TestClient::connect("e2e_rcpt_hot_b").await?;
    let jid_b = client_b.jid().await;

    const N: usize = 5;
    for i in 0..N {
        client_a
            .client
            .send_message(jid_b.clone(), text_msg(&format!("burst {i}")))
            .await?;
    }

    // Wait until B observes the LAST message — receipt tasks are spawned
    // by then but may still be in-flight on the runtime.
    client_b.wait_for_text(&format!("burst {}", N - 1), 15).await?;

    let start = std::time::Instant::now();
    client_b.client.disconnect().await;
    let elapsed = start.elapsed();

    info!("hot disconnect with {N} pending receipts took {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(1),
        "disconnect with {N} pending receipts took {elapsed:?}, expected <1s — \
         drain is hitting the 5s cap on every call"
    );

    client_a.disconnect().await;
    Ok(())
}
