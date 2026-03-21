//! Signal session management e2e tests.
//!
//! Validates the full lifecycle of Signal protocol sessions: establishment,
//! message delivery, session reuse after roundtrip, persistence to DB, and
//! survival across reconnects.
//!
//! Key Signal protocol behaviors verified:
//! - `pending_pre_key` stays set until the remote device REPLIES (standard Signal / WA Web)
//! - After bidirectional exchange, the active (LID) session clears `pending_pre_key`
//! - Sessions are flushed to SQLite backend after both sends and receives
//! - Orphaned PN sessions (from pre-LID-migration sends) don't affect correctness

use e2e_tests::TestClient;
use log::info;
use wacore::libsignal::protocol::SessionRecord;
use wacore::types::events::Event;
use whatsapp_rust::waproto::whatsapp as wa;

/// Scan backend for sessions matching a user across device IDs 0..=5.
/// Returns Vec<(address, has_pending_pre_key)> for all found sessions.
async fn scan_sessions(
    backend: &dyn wacore::store::traits::SignalStore,
    user: &str,
    server: &str,
) -> anyhow::Result<Vec<(String, bool)>> {
    let mut results = Vec::new();
    for device_id in 0..=5u16 {
        let addr = if device_id == 0 {
            format!("{user}@{server}.0")
        } else {
            format!("{user}:{device_id}@{server}.0")
        };
        if let Some(data) = backend.get_session(&addr).await? {
            let record = SessionRecord::deserialize(&data)?;
            if let Some(state) = record.session_state() {
                let has_pending = state
                    .unacknowledged_pre_key_message_items()
                    .map_err(|e| anyhow::anyhow!("invalid session state: {e}"))?
                    .is_some();
                results.push((addr, has_pending));
            }
        }
    }
    Ok(results)
}

/// Helper to send a text message and wait for delivery, returning the message ID.
async fn send_and_expect(
    sender: &whatsapp_rust::client::Client,
    receiver: &mut TestClient,
    to: whatsapp_rust::Jid,
    text: &str,
) -> anyhow::Result<String> {
    let msg_id = sender
        .send_message(
            to,
            wa::Message {
                conversation: Some(text.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event = receiver
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;

    if let Event::Message(msg, info) = event {
        assert_eq!(msg.conversation.as_deref(), Some(text));
        assert!(!info.id.is_empty(), "Message ID should not be empty");
        assert!(
            !info.source.sender.user.is_empty(),
            "Sender JID should not be empty"
        );
    } else {
        panic!("Expected Message event for text: {text}");
    }

    Ok(msg_id)
}

/// Multiple sequential sends to the same recipient should all be delivered,
/// even without the recipient replying in between.
///
/// Per Signal protocol, every send before the first reply uses pkmsg because
/// `pending_pre_key` is only cleared on receiving a message from the remote.
#[tokio::test]
async fn test_one_way_multiple_sends() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_sig_oneway_a").await?;
    let mut client_b = TestClient::connect("e2e_sig_oneway_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    let mut sent_ids = Vec::new();
    for i in 1..=5 {
        let text = format!("One-way message {i}");
        let msg_id = send_and_expect(&client_a.client, &mut client_b, jid_b.clone(), &text).await?;
        assert!(
            !sent_ids.contains(&msg_id),
            "Message IDs must be unique, got duplicate: {msg_id}"
        );
        sent_ids.push(msg_id);
        info!("Message {i}/5 delivered");
    }

    assert_eq!(sent_ids.len(), 5, "All 5 messages should have unique IDs");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Bidirectional messaging: alternating sends between A and B.
/// Verifies both directions establish sessions and messages are delivered
/// with correct sender information.
#[tokio::test]
async fn test_bidirectional_exchange() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_sig_bidir_a").await?;
    let mut client_b = TestClient::connect("e2e_sig_bidir_b").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("Client A should have a JID")
        .to_non_ad();
    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // A→B (first contact — pkmsg)
    send_and_expect(&client_a.client, &mut client_b, jid_b.clone(), "A1→B").await?;
    info!("A→B delivered");

    // B→A (first contact from B — pkmsg, clears pending_pre_key on A's LID session for B)
    send_and_expect(&client_b.client, &mut client_a, jid_a.clone(), "B1→A").await?;
    info!("B→A delivered");

    // A→B again (should use established session for device that replied)
    send_and_expect(&client_a.client, &mut client_b, jid_b.clone(), "A2→B").await?;
    info!("A→B (round 2) delivered");

    // B→A again
    send_and_expect(&client_b.client, &mut client_a, jid_a.clone(), "B2→A").await?;
    info!("B→A (round 2) delivered");

    // Rapid alternating
    for i in 3..=5 {
        send_and_expect(
            &client_a.client,
            &mut client_b,
            jid_b.clone(),
            &format!("A{i}→B"),
        )
        .await?;
        send_and_expect(
            &client_b.client,
            &mut client_a,
            jid_a.clone(),
            &format!("B{i}→A"),
        )
        .await?;
    }
    info!("All 10 bidirectional messages delivered");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// After a bidirectional exchange (A→B→A), the active (LID) session
/// should have `pending_pre_key` cleared. This is the core Signal protocol
/// guarantee: after a roundtrip, subsequent sends use the established session.
///
/// PN sessions from before LID migration may retain stale `pending_pre_key`
/// — this is expected since `encrypt_for_devices()` prefers LID sessions.
#[tokio::test]
async fn test_session_state_after_roundtrip() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_sig_state_a").await?;
    let mut client_b = TestClient::connect("e2e_sig_state_b").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("Client A should have a JID")
        .to_non_ad();
    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // Roundtrip: A→B, B→A
    send_and_expect(
        &client_a.client,
        &mut client_b,
        jid_b.clone(),
        "Establishing session",
    )
    .await?;
    send_and_expect(
        &client_b.client,
        &mut client_a,
        jid_a.clone(),
        "Session reply",
    )
    .await?;
    info!("Roundtrip complete");

    // Force cache flush by sending another message (send_message_impl calls flush_signal_cache)
    send_and_expect(
        &client_a.client,
        &mut client_b,
        jid_b.clone(),
        "Post-roundtrip flush",
    )
    .await?;

    // Inspect session state
    let backend = client_a.client.persistence_manager().backend();

    // PN sessions: may exist with stale pending_pre_key (orphaned after LID migration)
    let pn_sessions = scan_sessions(&*backend, &jid_b.user, "c.us").await?;
    for (addr, pending) in &pn_sessions {
        info!("PN session {addr}: pending_pre_key={pending}");
    }

    // LID sessions: the active sessions used by encrypt_for_devices
    let mut lid_sessions = Vec::new();
    if let Some(lid) = client_b.client.get_lid().await {
        lid_sessions = scan_sessions(&*backend, &lid.user, "lid").await?;
        for (addr, pending) in &lid_sessions {
            info!("LID session {addr}: pending_pre_key={pending}");
        }
    }

    // Must have at least one session (PN or LID) for B
    assert!(
        !pn_sessions.is_empty() || !lid_sessions.is_empty(),
        "Should have at least one session for B in A's store"
    );

    // If LID sessions exist (expected with modern mock server), verify the primary
    // device's session has pending_pre_key cleared after roundtrip.
    if !lid_sessions.is_empty() {
        let primary_cleared = lid_sessions
            .iter()
            .any(|(addr, pending)| !addr.contains(':') && !pending);
        assert!(
            primary_cleared,
            "Primary LID session should have pending_pre_key cleared after roundtrip. \
             LID sessions: {lid_sessions:?}"
        );
    }

    // Verify continued delivery works after session inspection
    for i in 1..=3 {
        send_and_expect(
            &client_a.client,
            &mut client_b,
            jid_b.clone(),
            &format!("Post-inspection {i}"),
        )
        .await?;
    }
    info!("Post-inspection messages delivered");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Sessions must be persisted to the SQLite backend after sending.
/// Verifies that `flush_signal_cache()` runs and writes to the DB.
#[tokio::test]
async fn test_session_persistence() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_sig_persist_a").await?;
    let mut client_b = TestClient::connect("e2e_sig_persist_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    let backend = client_a.client.persistence_manager().backend();

    // No session should exist before first contact
    let pre_send = scan_sessions(&*backend, &jid_b.user, "c.us").await?;
    assert!(
        pre_send.is_empty(),
        "No PN session should exist before first send, found: {pre_send:?}"
    );

    // First send creates and persists session
    let msg_id_1 = send_and_expect(
        &client_a.client,
        &mut client_b,
        jid_b.clone(),
        "Persist test 1",
    )
    .await?;
    info!("First message sent: {msg_id_1}");

    let post_send = scan_sessions(&*backend, &jid_b.user, "c.us").await?;
    assert!(
        !post_send.is_empty(),
        "At least one PN session should be persisted after first send"
    );

    // All persisted sessions should have pending_pre_key=true (no reply yet)
    for (addr, pending) in &post_send {
        assert!(
            *pending,
            "Session {addr} should have pending_pre_key=true before any reply"
        );
    }
    info!(
        "Verified {} sessions persisted with pending_pre_key=true",
        post_send.len()
    );

    // Second send reuses sessions (no new session creation needed)
    let msg_id_2 = send_and_expect(
        &client_a.client,
        &mut client_b,
        jid_b.clone(),
        "Persist test 2",
    )
    .await?;
    assert_ne!(
        msg_id_1, msg_id_2,
        "Second message should have a different ID"
    );
    info!("Second message delivered with reused session");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Sessions must survive a reconnect. The in-memory signal cache is cleared
/// on reconnect, so sessions must be loaded from the SQLite backend.
#[tokio::test]
async fn test_session_survives_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_sig_reconnect_a").await?;
    let mut client_b = TestClient::connect("e2e_sig_reconnect_b").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("Client A should have a JID")
        .to_non_ad();
    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // Establish sessions with a full roundtrip
    send_and_expect(
        &client_a.client,
        &mut client_b,
        jid_b.clone(),
        "Pre-reconnect A→B",
    )
    .await?;
    send_and_expect(
        &client_b.client,
        &mut client_a,
        jid_a.clone(),
        "Pre-reconnect B→A",
    )
    .await?;
    info!("Sessions established");

    // Reconnect A — clears in-memory cache, forces DB reload
    client_a.reconnect_and_wait().await?;
    info!("Client A reconnected (cache cleared)");

    // Send after reconnect — must load session from DB
    send_and_expect(
        &client_a.client,
        &mut client_b,
        jid_b.clone(),
        "Post-reconnect 1",
    )
    .await?;
    info!("Post-reconnect message delivered");

    // Multiple messages to confirm session is stable after reload
    for i in 2..=4 {
        send_and_expect(
            &client_a.client,
            &mut client_b,
            jid_b.clone(),
            &format!("Post-reconnect {i}"),
        )
        .await?;
    }
    info!("All post-reconnect messages delivered");

    // Also verify B→A still works after A's reconnect
    send_and_expect(
        &client_b.client,
        &mut client_a,
        jid_a.clone(),
        "B→A after reconnect",
    )
    .await?;
    info!("B→A after A's reconnect delivered");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Verify that MessageInfo fields are correctly populated on received messages.
#[tokio::test]
async fn test_message_info_fields() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_sig_info_a").await?;
    let mut client_b = TestClient::connect("e2e_sig_info_b").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("Client A should have a JID")
        .to_non_ad();
    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // A→B: verify B's MessageInfo
    let text_ab = "Info check A→B";
    client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some(text_ab.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text_ab)),
        )
        .await?;

    if let Event::Message(msg, info) = event {
        assert_eq!(msg.conversation.as_deref(), Some(text_ab));
        assert!(!info.id.is_empty(), "Message ID must not be empty");
        assert!(
            info.timestamp.timestamp() > 0,
            "Timestamp should be positive, got {}",
            info.timestamp
        );
        assert!(
            !info.source.is_from_me,
            "B should see A's message as not from_me"
        );
        assert!(!info.source.is_group, "DM should not be marked as group");
        // Sender should be A (the user part should match A's phone)
        assert_eq!(
            info.source.sender.user, jid_a.user,
            "Sender user should match A's JID user"
        );
        info!(
            "MessageInfo verified: id={}, sender={}, timestamp={}, from_me={}, is_group={}",
            info.id,
            info.source.sender,
            info.timestamp,
            info.source.is_from_me,
            info.source.is_group
        );
    }

    // B→A: verify A's MessageInfo
    let text_ba = "Info check B→A";
    client_b
        .client
        .send_message(
            jid_a.clone(),
            wa::Message {
                conversation: Some(text_ba.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event = client_a
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text_ba)),
        )
        .await?;

    if let Event::Message(_, info) = event {
        assert!(!info.source.is_from_me);
        assert!(!info.source.is_group);
        assert_eq!(info.source.sender.user, jid_b.user);
        info!("Reverse direction MessageInfo verified");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
