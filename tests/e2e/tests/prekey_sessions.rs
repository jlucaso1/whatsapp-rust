//! Regression test for prekey ID collision bug.
//!
//! The bug: `upload_pre_keys` scanned sequentially from ID 1 and broke at the
//! first gap. After consuming prekeys (creating gaps via remove_pre_key), the
//! scan stopped early and generated new prekeys that overwrote existing ones
//! with DIFFERENT key pairs. Messages encrypted with the old public keys would
//! fail decryption (MAC verification failure).
//!
//! This test verifies the fix by:
//! 1. Online senders consume prekeys (creating gaps in local store)
//! 2. Saving remaining prekey data from local store
//! 3. Draining server prekey count below MIN via offline senders
//! 4. Triggering reconnect → upload_pre_keys runs
//! 5. Verifying remaining prekeys were NOT overwritten with different key pairs

use std::sync::Arc;

use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::waproto::whatsapp as wa;

/// Regression test: prekey ID collision on re-upload after non-sequential consumption.
///
/// MUST fail on main (before fix) and pass on the fix branch.
///
/// After consuming prekeys (creating gaps), forces upload_pre_keys to trigger.
/// Then verifies that remaining prekeys in the local store were NOT overwritten.
/// On main: sequential scan breaks at first gap → overwrites remaining prekeys.
/// On fix: persistent counter starts from max+1 → no collision.
#[tokio::test]
async fn test_prekey_collision_regression() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 41 online + 5 offline = 46 total. Server starts with 50 prekeys.
    // After 46 consumed: 4 left < MIN_PRE_KEY_COUNT (5) → triggers upload_pre_keys.
    const ONLINE_SENDERS: usize = 41;
    const OFFLINE_SENDERS: usize = 5;

    // --- Phase 1: Recipient connects (uploads 50 prekeys) ---
    let mut recipient = TestClient::connect("e2e_pkcol_recv").await?;
    let recipient_jid = recipient
        .client
        .get_pn()
        .await
        .expect("Recipient should have a JID")
        .to_non_ad();
    info!("Recipient JID: {recipient_jid}");

    // --- Phase 2: Online senders consume prekeys from server AND local store ---
    // Sequential to avoid signal store race conditions with parallel PreKeyMessages.
    for i in 0..ONLINE_SENDERS {
        let sender = TestClient::connect(&format!("e2e_pkcol_on{i}")).await?;
        let text = format!("online-{i}");
        sender
            .client
            .send_message(
                recipient_jid.clone(),
                wa::Message {
                    conversation: Some(text.clone()),
                    ..Default::default()
                },
            )
            .await?;
        recipient
            .wait_for_event(30, |e| {
                matches!(
                    e,
                    Event::Message(msg, _) if msg.conversation.as_deref() == Some(text.as_str())
                )
            })
            .await?;
        sender.disconnect().await;
        if (i + 1) % 10 == 0 {
            info!("Online: {}/{ONLINE_SENDERS} sent and received", i + 1);
        }
    }
    info!("All {ONLINE_SENDERS} online messages decrypted (prekeys consumed from local store)");

    // --- Phase 3: Snapshot remaining prekeys before reconnect ---
    // After 41 consumed, remaining prekeys should be at IDs 42-50 (9 keys).
    // Save their key data so we can verify they weren't overwritten after upload.
    let backend = recipient.client.persistence_manager().backend();
    let mut saved_prekeys = Vec::new();
    for id in 1..=100u32 {
        if let Ok(Some(data)) = backend.load_prekey(id).await {
            saved_prekeys.push((id, data));
        }
    }
    info!(
        "Saved {} remaining prekeys from local store (IDs: {:?})",
        saved_prekeys.len(),
        saved_prekeys.iter().map(|(id, _)| *id).collect::<Vec<_>>()
    );
    assert!(
        !saved_prekeys.is_empty(),
        "Should have remaining prekeys after consuming {ONLINE_SENDERS}"
    );

    // --- Phase 4: Pre-create offline senders while recipient is still online ---
    info!("Creating {OFFLINE_SENDERS} offline senders...");
    let mut offline_senders = Vec::with_capacity(OFFLINE_SENDERS);
    for i in 0..OFFLINE_SENDERS {
        let sender = TestClient::connect(&format!("e2e_pkcol_off{i}")).await?;
        offline_senders.push(sender);
    }
    info!("All {OFFLINE_SENDERS} offline senders ready");

    // --- Phase 5: Disconnect recipient via reconnect ---
    while recipient.event_rx.try_recv().is_ok() {}
    info!("Disconnecting recipient (auto-reconnect in ~4s)...");
    recipient.client.reconnect().await;

    // --- Phase 6: Offline senders fire in parallel (drains server below MIN) ---
    let mut send_handles = Vec::with_capacity(OFFLINE_SENDERS);
    for (i, sender) in offline_senders.iter().enumerate() {
        let client = Arc::clone(&sender.client);
        let jid = recipient_jid.clone();
        let text = format!("offline-{i}");
        send_handles.push(tokio::spawn(async move {
            client
                .send_message(
                    jid,
                    wa::Message {
                        conversation: Some(text),
                        ..Default::default()
                    },
                )
                .await
        }));
    }
    for (i, handle) in send_handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => anyhow::bail!("Offline sender {i} send_message failed: {e}"),
            Err(e) => anyhow::bail!("Offline sender {i} task panicked: {e}"),
        }
    }
    info!("All offline sends complete");

    // Disconnect offline senders
    for sender in offline_senders {
        sender.disconnect().await;
    }

    // --- Phase 7: Wait for reconnect + upload_pre_keys to complete ---
    // Wait for Connected event (fires after upload_pre_keys + app state sync).
    // Consume and discard any message events that arrive before Connected.
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(30);
    let mut got_connected = false;
    while !got_connected {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            break;
        }
        match tokio::time::timeout(remaining, recipient.event_rx.recv()).await {
            Ok(Ok(Event::Connected(_))) => {
                got_connected = true;
            }
            Ok(Ok(_)) => {} // Skip messages, undecryptable, etc.
            Ok(Err(_)) => break,
            Err(_) => break,
        }
    }
    assert!(got_connected, "Recipient should have reconnected");
    info!("Recipient reconnected — upload_pre_keys should have completed");

    // --- Phase 8: Verify prekeys were NOT overwritten ---
    // On main (bug): upload_pre_keys generates IDs starting from 1 (first gap),
    //   overwriting existing prekeys at IDs 42-50 with DIFFERENT key pairs.
    // On fix: persistent counter generates IDs starting from 51+, no collision.
    let mut overwritten_count = 0;
    for (id, original_data) in &saved_prekeys {
        match backend.load_prekey(*id).await {
            Ok(Some(current_data)) => {
                if current_data != *original_data {
                    overwritten_count += 1;
                    log::error!(
                        "PREKEY COLLISION: ID {id} was overwritten with different key data! \
                         (original {} bytes, new {} bytes)",
                        original_data.len(),
                        current_data.len()
                    );
                }
            }
            Ok(None) => {
                // Prekey was consumed (expected for prekeys used by offline senders)
                info!("Prekey {id} was consumed (expected)");
            }
            Err(e) => {
                log::warn!("Failed to load prekey {id}: {e}");
            }
        }
    }

    info!(
        "Results: {overwritten_count}/{} prekeys were overwritten",
        saved_prekeys.len()
    );

    assert_eq!(
        overwritten_count,
        0,
        "{overwritten_count}/{} prekeys were overwritten with different key pairs — \
         upload_pre_keys generated colliding IDs instead of using a monotonic counter",
        saved_prekeys.len(),
    );

    recipient.disconnect().await;
    Ok(())
}
