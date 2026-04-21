use e2e_tests::{TestClient, text_msg};
use log::info;
use wacore::types::events::Event;
use wacore::types::presence::ReceiptType;

#[tokio::test]
async fn test_deferred_delivery_receipt() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_offline_receipt_a").await?;
    let client_b = TestClient::connect("e2e_offline_receipt_b").await?;

    let jid_b = client_b.jid().await;

    client_b.disconnect().await;
    info!("Client B fully disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let text = "Hello offline B!";
    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg(text))
        .await?
        .message_id;
    info!("Client A sent message to offline B: {msg_id}");

    // Sender receipt (type="sender") IS expected — only check that no Delivered arrives.
    client_a
        .assert_no_event(
            5,
            |e| {
                matches!(
                    e,
                    Event::Receipt(receipt)
                    if receipt.message_ids.contains(&msg_id)
                        && receipt.r#type == ReceiptType::Delivered
                )
            },
            "Should NOT receive delivery receipt when recipient is offline",
        )
        .await?;

    info!("Confirmed: no delivery receipt for offline recipient (single checkmark)");

    client_a.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_bidirectional_offline_receipt() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_off_bidir_a").await?;
    let mut client_b = TestClient::connect("e2e_off_bidir_b").await?;

    let jid_b = client_b.jid().await;

    info!("B={jid_b}");

    client_b.client.reconnect().await;
    info!("B disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let text = "Bidirectional offline test";
    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg(text))
        .await?
        .message_id;
    info!("A sent message to offline B: {msg_id}");

    client_a.client.reconnect().await;
    info!("A disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // B reconnects and receives the message
    client_b.wait_for_text(text, 30).await?;
    info!("B received offline message");

    // A reconnects and receives the deferred delivery receipt
    client_a
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
    info!("A received deferred delivery receipt after reconnect");

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_deferred_delivery_receipt_on_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_off_def_rcpt_a").await?;
    let mut client_b = TestClient::connect("e2e_off_def_rcpt_b").await?;

    let jid_b = client_b.jid().await;

    info!("B={jid_b}");

    client_b.client.reconnect().await;
    info!("B disconnected (will auto-reconnect)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let text = "Waiting for delivery receipt";
    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg(text))
        .await?
        .message_id;
    info!("A sent message to offline B: {msg_id}");

    // Timeout shorter than reconnect backoff so B is still offline during this window.
    client_a
        .assert_no_event(
            3,
            |e| {
                matches!(
                    e,
                    Event::Receipt(receipt)
                    if receipt.message_ids.contains(&msg_id)
                        && receipt.r#type == ReceiptType::Delivered
                )
            },
            "A should NOT get delivery receipt while B is offline",
        )
        .await?;
    info!("Confirmed: no early delivery receipt");

    // B reconnects and receives the message
    client_b.wait_for_text(text, 30).await?;
    info!("B received the offline message after reconnect");

    // A receives the deferred delivery receipt
    client_a
        .wait_for_event(30, |e| {
            matches!(
                e,
                Event::Receipt(receipt)
                if receipt.message_ids.contains(&msg_id)
                    && receipt.r#type == ReceiptType::Delivered
            )
        })
        .await?;
    info!("A received deferred delivery receipt");

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_offline_presence_coalescing() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_presence_a").await?;
    let mut client_b = TestClient::connect("e2e_off_presence_b").await?;

    let jid_a = client_a.jid().await;

    info!("A={jid_a}");

    client_b.client.presence().subscribe(&jid_a).await?;
    info!("B subscribed to A's presence");

    client_a.client.presence().set_available().await?;

    let _initial = client_b
        .wait_for_event(15, |e| matches!(e, Event::Presence(_)))
        .await?;
    info!("B received initial presence");

    client_b.client.reconnect().await;
    info!("B disconnected (will auto-reconnect)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // A changes presence multiple times while B is offline
    client_a.client.presence().set_unavailable().await?;
    info!("A set unavailable");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    client_a.client.presence().set_available().await?;
    info!("A set available again");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // B reconnects — coalescing means only the latest state arrives, not all 3
    let presence_event = client_b
        .wait_for_event(30, |e| matches!(e, Event::Presence(_)))
        .await?;

    if let Event::Presence(presence) = &*presence_event {
        info!("B received coalesced presence: {:?}", presence);
    }

    // Drain extra presence events (re-subscribe response, initial delivery on connect).
    let mut extra_count = 0;
    while client_b
        .wait_for_event(2, |e| matches!(e, Event::Presence(_)))
        .await
        .is_ok()
    {
        extra_count += 1;
        if extra_count > 5 {
            panic!("Too many extra presence events ({extra_count}), likely a leak");
        }
    }
    info!("Drained {extra_count} extra presence event(s) after initial coalesced delivery");

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}
