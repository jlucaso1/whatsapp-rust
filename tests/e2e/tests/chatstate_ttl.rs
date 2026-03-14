//! Tests for chatstate TTL (typing indicator expiry).
//!
//! The mock server's chatstate TTL is configurable via CHATSTATE_TTL_SECS env var
//! (default 30s). For fast tests, run the mock server with CHATSTATE_TTL_SECS=3.
//!
//! Separated into its own file so the TTL wait doesn't block other test files
//! (cargo runs test files in parallel, tests within a file sequentially).

use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;

/// Test that typing indicators (chatstate) are NOT delivered when they expire.
///
/// Flow:
/// 1. A and B connect
/// 2. B goes offline via reconnect() — creates a ~5s offline window (see `RECONNECT_BACKOFF_STEP`)
/// 3. A sends typing indicator to B (queued with TTL)
/// 4. B auto-reconnects after the TTL expires — chatstate should be filtered out during drain
///
/// Requires mock server with CHATSTATE_TTL_SECS=3 (so TTL expires before the ~4s reconnect).
#[tokio::test]
async fn test_expired_chatstate_not_delivered() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_chatstate_a").await?;
    let mut client_b = TestClient::connect("e2e_off_chatstate_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    info!("B={jid_b}");

    // B goes offline — reconnect() uses RECONNECT_BACKOFF_STEP to create a ~5s
    // offline window. With CHATSTATE_TTL_SECS=3, the chatstate expires at 3s,
    // and B reconnects at ~5s, so the drain filters it out.
    client_b.client.reconnect().await;
    info!("B disconnected (will auto-reconnect after backoff)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // A sends typing indicator while B is offline (queued with short TTL)
    client_a.client.chatstate().send_composing(&jid_b).await?;
    info!("A sent typing indicator to offline B");

    // B auto-reconnects after backoff. Wait for reconnect + event drain.
    // The expired chatstate should NOT be delivered.
    let result = client_b
        .wait_for_event(15, |e| matches!(e, Event::ChatPresence(_)))
        .await;

    assert!(
        result.is_err(),
        "B should NOT receive chatstate after TTL expired, but got: {:?}",
        result.unwrap()
    );
    info!("Confirmed: expired chatstate was NOT delivered to B");

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

/// Test that a fresh chatstate (within TTL) IS delivered on reconnect.
///
/// Flow:
/// 1. B goes offline via reconnect_immediately() — reconnects in <1s
/// 2. A sends typing indicator to B while B is briefly offline (queued with TTL)
/// 3. B reconnects quickly (well within TTL) — chatstate should be delivered
///
/// Uses `reconnect_immediately()` instead of `reconnect()` to ensure B is offline
/// for less than the TTL (3s with CHATSTATE_TTL_SECS=3).
#[tokio::test]
async fn test_fresh_chatstate_delivered_on_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_chatstate_fresh_a").await?;
    let mut client_b = TestClient::connect("e2e_off_chatstate_fresh_b").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    info!("B={jid_b}");

    // B goes offline briefly — reconnect_immediately() causes near-instant reconnect
    client_b.client.reconnect_immediately().await;
    info!("B disconnected (will reconnect immediately)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // A sends typing indicator while B is offline (queued with short TTL)
    client_a.client.chatstate().send_composing(&jid_b).await?;
    info!("A sent typing indicator to offline B");

    // B reconnects almost immediately — chatstate should still be within TTL
    let event = client_b
        .wait_for_event(15, |e| matches!(e, Event::ChatPresence(_)))
        .await
        .expect("B should receive fresh chatstate within TTL");

    info!("B received fresh chatstate: {:?}", event);

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}
