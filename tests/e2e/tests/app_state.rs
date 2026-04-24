use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::waproto::whatsapp as wa;

// ─── Initial Sync Tests ─────────────────────────────────────────────

/// Verify that the initial app state sync delivers a push name from the mock server.
/// This is a regression test for the app state key decryption fix (multi-key storage,
/// per-record lookup, fingerprint matching). If keys are broken, the client cannot
/// decrypt critical_block and push name will be empty.
#[tokio::test]
async fn test_initial_sync_delivers_push_name() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_as_init_sync").await?;
    client.wait_for_app_state_sync().await?;

    let push_name = client.client.get_push_name().await;
    assert!(
        !push_name.is_empty(),
        "Push name should be set from initial critical_block sync (got empty — app state keys may be broken)"
    );
    info!("Initial sync delivered push name: '{push_name}'");

    client.disconnect().await;
    Ok(())
}

// ─── Reconnection Persistence Tests ─────────────────────────────────

/// Verify that push name persists across reconnects via SQLite storage.
#[tokio::test]
async fn test_push_name_survives_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_as_pushname_reconnect").await?;
    client.wait_for_app_state_sync().await?;

    let name = "ReconnectTest";
    client.client.profile().set_push_name(name).await?;
    assert_eq!(client.client.get_push_name().await, name);
    info!("Push name set to '{name}'");

    client.reconnect_and_wait().await?;

    let after = client.client.get_push_name().await;
    assert_eq!(after, name, "Push name should survive reconnect");
    info!("Push name after reconnect: '{after}'");

    client.disconnect().await;
    Ok(())
}

/// Verify that app state encryption keys survive reconnect — mutations still work.
/// After reconnect, the client reloads keys from SQLite. If key persistence is broken,
/// sending a mutation will fail with an encryption error.
#[tokio::test]
async fn test_mutation_works_after_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_as_mut_recon_a").await?;
    let client_b = TestClient::connect("e2e_as_mut_recon_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // Reconnect — keys must survive via SQLite
    client_a.reconnect_and_wait().await?;
    info!("Client A reconnected");

    // This mutation requires app state sync keys for encryption.
    // If keys didn't persist, this will fail.
    client_a.client.chat_actions().pin_chat(&jid_b).await?;
    info!("Pin mutation succeeded after reconnect — keys persisted correctly");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Verify that app state versioning works across sessions: pin, reconnect, then unpin.
/// The unpin must use the correct base version from the previous session's pin.
#[tokio::test]
async fn test_undo_mutation_after_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_as_undo_recon_a").await?;
    let client_b = TestClient::connect("e2e_as_undo_recon_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // Pin the chat
    client_a.client.chat_actions().pin_chat(&jid_b).await?;
    info!("Pinned chat with {jid_b}");

    // Reconnect — version state must persist
    client_a.reconnect_and_wait().await?;
    info!("Client A reconnected");

    // Unpin — must use correct version from previous session
    client_a.client.chat_actions().unpin_chat(&jid_b).await?;
    info!("Unpinned chat after reconnect — version continuity works");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Cross-Collection Tests ─────────────────────────────────────────

/// Verify mutations work across different app state collections in the same session.
/// Pin uses regular_low, mute uses regular_high — both need working encryption keys.
#[tokio::test]
async fn test_cross_collection_mutations() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_as_cross_coll_a").await?;
    let client_b = TestClient::connect("e2e_as_cross_coll_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // regular_low collection
    client_a.client.chat_actions().pin_chat(&jid_b).await?;
    info!("Pin (regular_low) succeeded");

    client_a
        .client
        .chat_actions()
        .archive_chat(&jid_b, None)
        .await?;
    info!("Archive (regular_low) succeeded");

    // regular_high collection
    client_a.client.chat_actions().mute_chat(&jid_b).await?;
    info!("Mute (regular_high) succeeded");

    // Star requires a message ID — send a message first
    let msg = wa::Message {
        conversation: Some("Cross-collection test".to_string()),
        ..Default::default()
    };
    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), msg)
        .await?
        .message_id;

    client_a
        .client
        .chat_actions()
        .star_message(&jid_b, None, &msg_id, true)
        .await?;
    info!("Star (regular_high) succeeded");

    info!("All cross-collection mutations succeeded");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Star Edge Cases ────────────────────────────────────────────────

/// Verify starring a received message (from_me=false). Existing tests only cover
/// from_me=true. The from_me=false path uses a different index encoding where
/// participant_jid may be set.
#[tokio::test]
async fn test_star_received_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_as_star_recv_a").await?;
    let mut client_b = TestClient::connect("e2e_as_star_recv_b").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("A should have JID")
        .to_non_ad();
    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_b.wait_for_app_state_sync().await?;

    // A sends a message to B
    let msg = wa::Message {
        conversation: Some("Star me from the other side!".to_string()),
        ..Default::default()
    };
    client_a.client.send_message(jid_b.clone(), msg).await?;
    info!("Client A sent message to B");

    // B receives the message and extracts msg_id
    let event = client_b
        .wait_for_event(15, |e| {
            matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some("Star me from the other side!"))
        })
        .await?;

    let msg_id = if let Event::Message(_, info) = &*event {
        info.id.clone()
    } else {
        panic!("Expected Message event");
    };
    info!("Client B received message with id: {msg_id}");

    // B stars the message (from_me=false — B received it, didn't send it)
    client_b
        .client
        .chat_actions()
        .star_message(&jid_a, None, &msg_id, false)
        .await?;
    info!("Client B starred received message {msg_id} (from_me=false)");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Multi-Device Tests ─────────────────────────────────────────────

/// Verify multi-device app state sync via `ib` dirty notification broadcasting.
///
/// Two devices connect with the same push_name (→ same phone number, different device_ids).
/// Device A1 sets its push name — the mock server broadcasts an `ib` dirty notification
/// to A2, which triggers A2 to re-sync critical_block and receive the updated push name.
#[tokio::test]
async fn test_multi_device_app_state_sync() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Both clients use the same push_name → mock server assigns them the same phone
    let push_name = "multidev_test_user";
    let mut client_a1 = TestClient::connect_as("e2e_multidev_a1", push_name).await?;
    let mut client_a2 = TestClient::connect_as("e2e_multidev_a2", push_name).await?;

    // Verify both devices got the same phone number
    let phone_a1 = client_a1.client.get_pn().await.expect("A1 should have JID");
    let phone_a2 = client_a2.client.get_pn().await.expect("A2 should have JID");
    assert_eq!(
        phone_a1.user, phone_a2.user,
        "Both devices should share the same phone number"
    );
    assert_ne!(
        phone_a1.device, phone_a2.device,
        "Devices should have different device IDs"
    );
    info!(
        "Multi-device: A1={} (device {}), A2={} (device {})",
        phone_a1.user, phone_a1.device, phone_a2.user, phone_a2.device
    );

    // Wait for both to complete initial app state sync
    client_a1.wait_for_app_state_sync().await?;
    client_a2.wait_for_app_state_sync().await?;

    // Use a unique push name each run so the test is idempotent even if the
    // mock server persists push_name state across sessions (like the real server).
    let new_name = format!("MultiDev_{}", wacore::time::now_millis());
    client_a1.client.profile().set_push_name(&new_name).await?;
    info!("A1 set push name to '{new_name}'");

    // A2 should receive SelfPushNameUpdated via ib dirty → re-sync → critical_block patch
    let event = client_a2
        .wait_for_event(15, |e| matches!(e, Event::SelfPushNameUpdated(_)))
        .await?;

    if let Event::SelfPushNameUpdated(update) = &*event {
        assert_eq!(
            update.new_name, *new_name,
            "A2 should receive the updated push name from A1"
        );
        info!("A2 received SelfPushNameUpdated: '{}'", update.new_name);
    } else {
        panic!("Expected SelfPushNameUpdated event");
    }

    client_a1.disconnect().await;
    client_a2.disconnect().await;
    Ok(())
}

// ─── Stress Tests ───────────────────────────────────────────────────

/// Verify that rapid successive mutations don't break version state management.
/// Sends 5 mutations quickly without waiting for events between them.
#[tokio::test]
async fn test_rapid_successive_mutations() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_as_rapid_a").await?;
    let client_b = TestClient::connect("e2e_as_rapid_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // Fire mutations rapidly — each increments the version
    client_a.client.chat_actions().pin_chat(&jid_b).await?;
    client_a.client.chat_actions().mute_chat(&jid_b).await?;
    client_a
        .client
        .chat_actions()
        .archive_chat(&jid_b, None)
        .await?;
    client_a.client.chat_actions().unpin_chat(&jid_b).await?;
    client_a.client.chat_actions().unmute_chat(&jid_b).await?;

    info!("All 5 rapid mutations succeeded");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
