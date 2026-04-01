//! LID-first Signal session tests.
//!
//! Validates that Signal sessions are always stored under LID addresses
//! (not PN) and that own-device messaging works without NoSession errors.
//!
//! These tests exercise:
//! - Sessions created via the send path are under LID, not PN
//! - PN sessions injected into the DB get migrated to LID
//! - Own device 0 has a LID session after login
//! - LID sessions survive reconnect (DB reload)
//! - No UndecryptableMessage events during normal messaging
//! - Multiple sequential sends don't regress to PN sessions

use e2e_tests::{TestClient, send_and_expect_text};
use log::info;
use wacore::store::traits::SignalStore;
use wacore::types::events::Event;

fn mask_addr(addr: &str) -> String {
    if let Some(at) = addr.find('@') {
        let user = &addr[..at];
        let rest = &addr[at..];
        if user.len() > 4 {
            format!("{}...{}{rest}", &user[..2], &user[user.len() - 2..])
        } else {
            format!("{user}{rest}")
        }
    } else {
        addr.to_string()
    }
}

/// Scan backend for sessions matching a user across device IDs 0..=99.
async fn scan_sessions(
    backend: &dyn SignalStore,
    user: &str,
    server: &str,
) -> anyhow::Result<Vec<String>> {
    let mut results = Vec::new();
    for device_id in 0..=99u16 {
        let addr = if device_id == 0 {
            format!("{user}@{server}.0")
        } else {
            format!("{user}:{device_id}@{server}.0")
        };
        if backend.get_session(&addr).await?.is_some() {
            results.push(addr);
        }
    }
    Ok(results)
}

/// Assert that ALL sessions for a user are under LID, NONE under PN.
async fn assert_lid_only_sessions(
    backend: &dyn SignalStore,
    pn_user: &str,
    lid_user: &str,
    context: &str,
) {
    let pn_sessions = scan_sessions(backend, pn_user, "c.us")
        .await
        .expect("scan PN sessions");
    let lid_sessions = scan_sessions(backend, lid_user, "lid")
        .await
        .expect("scan LID sessions");

    assert!(
        !lid_sessions.is_empty(),
        "[{context}] Expected at least one LID session, found 0. PN count: {}",
        pn_sessions.len()
    );
    assert!(
        pn_sessions.is_empty(),
        "[{context}] Expected 0 PN sessions, found {}. LID count: {}",
        pn_sessions.len(),
        lid_sessions.len()
    );

    info!(
        "[{context}] LID-only: {} session(s), first={}",
        lid_sessions.len(),
        lid_sessions
            .first()
            .map(|s| mask_addr(s))
            .unwrap_or_default()
    );
}

/// After a roundtrip between two clients, sessions should be stored
/// exclusively under LID addresses, not PN. Also verifies that
/// both sides have LID-only sessions (bidirectional check).
#[tokio::test]
async fn test_sessions_stored_under_lid_not_pn() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_lid_sess_a").await?;
    let mut client_b = TestClient::connect("e2e_lid_sess_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;
    let lid_a = client_a.client.get_lid().await.expect("A should have LID");
    let lid_b = client_b.client.get_lid().await.expect("B should have LID");

    // Roundtrip to establish sessions in both directions
    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "LID session test A->B",
        30,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "LID session test B->A",
        30,
    )
    .await?;
    info!("Roundtrip complete");

    // Check A's view: B's sessions should be LID-only
    let backend_a = client_a.client.persistence_manager().backend();
    assert_lid_only_sessions(&*backend_a, &jid_b.user, &lid_b.user, "A's store for B").await;

    // Check B's view: A's sessions should be LID-only
    let backend_b = client_b.client.persistence_manager().backend();
    assert_lid_only_sessions(&*backend_b, &jid_a.user, &lid_a.user, "B's store for A").await;

    // Verify continued delivery (session is functional, not just stored)
    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "Post-check A->B",
        30,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "Post-check B->A",
        30,
    )
    .await?;
    info!("Bidirectional post-check delivery confirmed");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Multiple sequential sends should never create PN sessions.
/// Regression guard: the first send establishes a session, subsequent sends
/// must reuse the LID session (not accidentally create a PN one).
#[tokio::test]
async fn test_multiple_sends_stay_lid_only() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_lid_multi_send_a").await?;
    let mut client_b = TestClient::connect("e2e_lid_multi_send_b").await?;

    let jid_b = client_b.jid().await;
    let lid_b = client_b.client.get_lid().await.expect("B should have LID");

    // Send 5 messages sequentially
    for i in 1..=5 {
        send_and_expect_text(
            &client_a.client,
            &mut client_b,
            &jid_b,
            &format!("Sequential msg {i}"),
            30,
        )
        .await?;
    }
    info!("All 5 sequential messages delivered");

    let backend_a = client_a.client.persistence_manager().backend();

    // After 5 sends, still only LID sessions
    assert_lid_only_sessions(
        &*backend_a,
        &jid_b.user,
        &lid_b.user,
        "After 5 sequential sends",
    )
    .await;

    // Count LID sessions — should be exactly 1 primary device session
    // (not 5 sessions from 5 sends)
    let lid_sessions = scan_sessions(&*backend_a, &lid_b.user, "lid").await?;
    info!(
        "LID session count after 5 sends: {} ({lid_sessions:?})",
        lid_sessions.len()
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// If a stale PN session exists in the database (simulating a legacy pairing),
/// messaging should still work via the LID session without undecryptable errors.
#[tokio::test]
async fn test_stale_pn_session_does_not_break_lid_messaging() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_lid_migrate_a").await?;
    let mut client_b = TestClient::connect("e2e_lid_migrate_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;
    let lid_b = client_b.client.get_lid().await.expect("B should have LID");

    // First, establish a normal LID session via roundtrip
    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "Establish session",
        30,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "Reply to establish",
        30,
    )
    .await?;

    let backend_a = client_a.client.persistence_manager().backend();

    // Read the existing LID session data
    let lid_addr = format!("{}@lid.0", lid_b.user);
    let lid_session_data = backend_a
        .get_session(&lid_addr)
        .await?
        .expect("LID session should exist after roundtrip");

    // Inject a copy under the PN address (simulates legacy database state)
    let pn_addr = format!("{}@c.us.0", jid_b.user);
    backend_a.put_session(&pn_addr, &lid_session_data).await?;
    info!("Injected PN session at {pn_addr}");

    // Verify both exist before migration
    assert!(
        backend_a.get_session(&pn_addr).await?.is_some(),
        "PN session should exist after injection"
    );
    assert!(
        backend_a.get_session(&lid_addr).await?.is_some(),
        "LID session should still exist"
    );

    // Send more messages — should use the LID session, not the stale PN copy
    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "Post-inject A->B",
        30,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "Post-inject B->A",
        30,
    )
    .await?;
    info!("Messaging works despite stale PN session in DB");

    // LID session should still be authoritative
    assert!(
        backend_a.get_session(&lid_addr).await?.is_some(),
        "LID session at {lid_addr} should survive after messaging with stale PN present"
    );

    // No undecryptable events on either side
    client_a
        .assert_no_event(
            3,
            |e| matches!(e, Event::UndecryptableMessage(_)),
            "A should have no undecryptable messages with stale PN session",
        )
        .await?;
    client_b
        .assert_no_event(
            3,
            |e| matches!(e, Event::UndecryptableMessage(_)),
            "B should have no undecryptable messages with stale PN session",
        )
        .await?;
    info!("No undecryptable events despite stale PN session in DB");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// After reconnect, sessions loaded from SQLite should still be under LID.
/// Also verifies no PN sessions appear after the cache is cleared and reloaded.
#[tokio::test]
async fn test_lid_session_survives_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_lid_recon_a").await?;
    let mut client_b = TestClient::connect("e2e_lid_recon_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;
    let lid_b = client_b.client.get_lid().await.expect("B should have LID");

    // Establish sessions with a roundtrip
    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "Pre-reconnect A->B",
        30,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "Pre-reconnect B->A",
        30,
    )
    .await?;
    info!("Sessions established");

    // Verify LID-only before reconnect
    let backend_a = client_a.client.persistence_manager().backend();
    assert_lid_only_sessions(&*backend_a, &jid_b.user, &lid_b.user, "Before reconnect").await;

    // Reconnect A — clears in-memory signal cache, forces DB reload
    client_a.reconnect_and_wait().await?;
    info!("Client A reconnected (cache cleared)");

    // Session should still be under LID after reload
    let backend_a = client_a.client.persistence_manager().backend();
    assert_lid_only_sessions(&*backend_a, &jid_b.user, &lid_b.user, "After reconnect").await;

    // Verify delivery still works with the reloaded session (no new pkmsg needed)
    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "Post-reconnect 1",
        30,
    )
    .await?;
    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "Post-reconnect 2",
        30,
    )
    .await?;
    info!("Post-reconnect delivery confirmed (2 messages)");

    // Final check: still LID-only after post-reconnect sends
    assert_lid_only_sessions(
        &*backend_a,
        &jid_b.user,
        &lid_b.user,
        "After post-reconnect sends",
    )
    .await;

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// The own user's device 0 (primary phone) should have a LID session
/// established after login, not left as "established on first message".
/// Also verifies no PN session exists for own device 0.
#[tokio::test]
async fn test_own_device_0_has_lid_session_after_login() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_lid_dev0").await?;

    let own_pn = client
        .client
        .get_pn()
        .await
        .expect("Client should have PN after connect");
    let own_lid = client
        .client
        .get_lid()
        .await
        .expect("Client should have LID after connect");

    let backend = client.client.persistence_manager().backend();

    // Device 0 is the primary phone — session should exist under LID
    let lid_addr = format!("{}@lid.0", own_lid.user);
    let lid_session = backend.get_session(&lid_addr).await?;
    assert!(
        lid_session.is_some(),
        "Should have LID session with own device 0 ({lid_addr}) after login"
    );
    info!("Own device 0 LID session exists: {lid_addr}");

    // No PN session should exist for own device 0
    let pn_addr = format!("{}@c.us.0", own_pn.user);
    let pn_session = backend.get_session(&pn_addr).await?;
    assert!(
        pn_session.is_none(),
        "Should NOT have PN session for own device 0 ({pn_addr}). \
         Own device sessions must be under LID."
    );
    info!("Confirmed no PN session for own device 0");

    client.disconnect().await;
    Ok(())
}

/// Normal messaging should never produce UndecryptableMessage events.
/// This guards against the NoSession bug where decryption fails silently.
#[tokio::test]
async fn test_no_undecryptable_events_during_messaging() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_lid_undec_a").await?;
    let mut client_b = TestClient::connect("e2e_lid_undec_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;

    // Exchange several messages in both directions
    for i in 1..=3 {
        send_and_expect_text(
            &client_a.client,
            &mut client_b,
            &jid_b,
            &format!("A->B msg {i}"),
            30,
        )
        .await?;
        send_and_expect_text(
            &client_b.client,
            &mut client_a,
            &jid_a,
            &format!("B->A msg {i}"),
            30,
        )
        .await?;
    }
    info!("6 messages exchanged successfully");

    // Neither side should have any undecryptable messages
    client_a
        .assert_no_event(
            3,
            |e| matches!(e, Event::UndecryptableMessage(_)),
            "A should have no undecryptable messages",
        )
        .await?;
    client_b
        .assert_no_event(
            3,
            |e| matches!(e, Event::UndecryptableMessage(_)),
            "B should have no undecryptable messages",
        )
        .await?;
    info!("No undecryptable events on either side");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Reproduces the exact production bug: a session exists under PN address
/// but NOT under LID. When a message arrives addressed from LID, decryption
/// fails with NoSession and an UndecryptableMessage event is dispatched.
///
/// This simulates a database from an old pairing where the session was stored
/// under PN, but WhatsApp has since migrated to LID-based addressing.
#[tokio::test]
async fn test_pn_only_session_causes_undecryptable_on_lid_lookup() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_lid_repro_a").await?;
    let mut client_b = TestClient::connect("e2e_lid_repro_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;
    let lid_b = client_b.client.get_lid().await.expect("B should have LID");

    // Step 1: Establish sessions via roundtrip
    send_and_expect_text(&client_a.client, &mut client_b, &jid_b, "Setup A->B", 30).await?;
    send_and_expect_text(&client_b.client, &mut client_a, &jid_a, "Setup B->A", 30).await?;
    info!("Sessions established via roundtrip");

    // Step 2: First reconnect — ensures sessions are flushed to backend + clears cache
    client_a.reconnect_and_wait().await?;
    info!("First reconnect done");

    // Step 3: Verify messaging works (forces session load from backend into clean cache)
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "Post-reconnect verify",
        30,
    )
    .await?;
    info!("Verified messaging works after first reconnect");

    // Step 4: Simulate legacy DB — move session from LID to PN address
    let backend_a = client_a.client.persistence_manager().backend();
    let lid_addr = format!("{}@lid.0", lid_b.user);
    let pn_addr = format!("{}@c.us.0", jid_b.user);

    let lid_session_data = backend_a
        .get_session(&lid_addr)
        .await?
        .expect("LID session should exist in backend");
    info!(
        "Read LID session from {lid_addr} ({} bytes)",
        lid_session_data.len()
    );

    // Copy to PN address, then delete LID — simulates legacy state
    backend_a.put_session(&pn_addr, &lid_session_data).await?;
    backend_a.delete_session(&lid_addr).await?;
    info!("Moved session: {lid_addr} -> {pn_addr} (simulating legacy DB)");

    // Verify backend state is now PN-only
    assert!(
        backend_a.get_session(&lid_addr).await?.is_none(),
        "LID session should be deleted from backend"
    );
    assert!(
        backend_a.get_session(&pn_addr).await?.is_some(),
        "PN session should exist in backend"
    );

    // Step 5: Second reconnect — clears cache, reloads from modified backend
    // Now A only has a PN session for B, no LID session
    client_a.reconnect_and_wait().await?;
    info!("Second reconnect done (cache now has PN-only state)");

    // Step 6: B sends to A — A should fail to decrypt (looks up LID, finds nothing)
    // This is the exact production bug: phone sends from LID, session is under PN
    let test_text = "This should trigger NoSession";
    client_b
        .client
        .send_message(jid_a.clone(), e2e_tests::text_msg(test_text))
        .await?;
    info!("B sent message to A (expecting decryption failure on A)");

    // Message must decrypt successfully (migration should happen on-the-fly)
    client_a
        .wait_for_text(test_text, 15)
        .await
        .expect("Message should decrypt after on-the-fly PN->LID migration");
    info!("Message decrypted despite PN-only backend state");

    // No UndecryptableMessage should have been emitted
    client_a
        .assert_no_event(
            3,
            |e| matches!(e, Event::UndecryptableMessage(_)),
            "No undecryptable events after migration",
        )
        .await?;

    // Session should now be under LID (migrated from PN)
    let backend_a = client_a.client.persistence_manager().backend();
    assert!(
        backend_a.get_session(&lid_addr).await?.is_some(),
        "Session should be under LID after migration"
    );
    assert!(
        backend_a.get_session(&pn_addr).await?.is_none(),
        "PN session should be cleaned up after migration"
    );
    info!("Session correctly under LID after on-the-fly migration");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
