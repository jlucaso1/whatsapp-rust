//! Regression: PR #576 (FlushScope + PDO shutdown signal).
//!
//! Concurrent `disconnect()` on two independent clients must not deadlock.
//! Field report from the `baileyrs` consumer: one of the two clients pins
//! a TLS socket open after logging `"Disconnecting client intentionally"`
//! and never reaches `transport.disconnect()`.

use e2e_tests::{TestClient, text_msg};
use std::sync::Arc;
use std::time::{Duration, Instant};
use wacore::types::events::Event;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_disconnect_does_not_hang_multithread() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let alice = TestClient::connect("e2e_concurrent_disc_mt_a").await?;
    let bob = TestClient::connect("e2e_concurrent_disc_mt_b").await?;

    let alice_client: Arc<_> = Arc::clone(&alice.client);
    let bob_client: Arc<_> = Arc::clone(&bob.client);

    let start = Instant::now();
    tokio::join!(alice_client.disconnect(), bob_client.disconnect());
    let elapsed = start.elapsed();

    // Release the run handles before returning; otherwise Drop aborts may
    // mask the hang we care about.
    drop(alice.run_handle);
    drop(bob.run_handle);

    assert!(
        elapsed < Duration::from_secs(3),
        "multi-thread concurrent disconnect deadlocked: took {:?} (expect < 3s)",
        elapsed
    );
    Ok(())
}

/// Single-threaded variant — closer to the WASM runtime where the bug was
/// originally observed. Single-thread scheduling is more likely to expose
/// lock-ordering / await-order issues that multi-thread hides.
#[tokio::test(flavor = "current_thread")]
async fn concurrent_disconnect_does_not_hang_single_thread() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let alice = TestClient::connect("e2e_concurrent_disc_st_a").await?;
    let bob = TestClient::connect("e2e_concurrent_disc_st_b").await?;

    let alice_client: Arc<_> = Arc::clone(&alice.client);
    let bob_client: Arc<_> = Arc::clone(&bob.client);

    let start = Instant::now();
    tokio::join!(alice_client.disconnect(), bob_client.disconnect());
    let elapsed = start.elapsed();

    drop(alice.run_handle);
    drop(bob.run_handle);

    assert!(
        elapsed < Duration::from_secs(3),
        "single-thread concurrent disconnect deadlocked: took {:?} (expect < 3s)",
        elapsed
    );
    Ok(())
}

/// Like the multi-thread test but with pending receipts in-flight: each
/// client sends + receives messages so `outbound_flush` has real work to
/// drain at disconnect time.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_disconnect_with_pending_receipts_multithread() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut alice = TestClient::connect("e2e_concurrent_disc_load_a").await?;
    let mut bob = TestClient::connect("e2e_concurrent_disc_load_b").await?;

    let alice_jid = alice.jid().await;
    let bob_jid = bob.jid().await;

    const N: usize = 3;
    for i in 0..N {
        let text = format!("a->b #{i}");
        alice
            .client
            .send_message(bob_jid.clone(), text_msg(&text))
            .await?;
        let text = format!("b->a #{i}");
        bob.client
            .send_message(alice_jid.clone(), text_msg(&text))
            .await?;
    }

    // Wait for every message event on both sides so dispatch_parsed_message
    // has fired for every message — outbound_flush has real work queued.
    for i in 0..N {
        let expected = format!("a->b #{i}");
        bob.wait_for_event(10, |e| {
            matches!(e, Event::Message(m, _) if m.conversation.as_deref() == Some(expected.as_str()))
        })
        .await?;
        let expected = format!("b->a #{i}");
        alice
            .wait_for_event(10, |e| {
                matches!(e, Event::Message(m, _) if m.conversation.as_deref() == Some(expected.as_str()))
            })
            .await?;
    }

    let alice_client: Arc<_> = Arc::clone(&alice.client);
    let bob_client: Arc<_> = Arc::clone(&bob.client);

    let start = Instant::now();
    tokio::join!(alice_client.disconnect(), bob_client.disconnect());
    let elapsed = start.elapsed();

    drop(alice.run_handle);
    drop(bob.run_handle);

    assert!(
        elapsed < Duration::from_secs(6),
        "concurrent disconnect with pending receipts deadlocked: took {:?} (expect < 6s)",
        elapsed
    );
    Ok(())
}

/// Spawns extra outbound work (simulated PDO-like traffic) on both clients,
/// then issues a concurrent disconnect. Aimed at exercising the in-flight
/// FlushScope counter + PDO shutdown select path under contention.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_disconnect_under_load() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let alice = TestClient::connect("e2e_concurrent_disc_load2_a").await?;
    let bob = TestClient::connect("e2e_concurrent_disc_load2_b").await?;

    let alice_jid = alice.jid().await;
    let bob_jid = bob.jid().await;

    // Heavier burst: 20 messages each way. Server may batch; the goal is to
    // keep dispatch_parsed_message / outbound_flush counters bumping when
    // disconnect starts.
    const N: usize = 20;
    for i in 0..N {
        let _ = alice
            .client
            .send_message(bob_jid.clone(), text_msg(&format!("a->b #{i}")))
            .await;
        let _ = bob
            .client
            .send_message(alice_jid.clone(), text_msg(&format!("b->a #{i}")))
            .await;
    }

    // Wait only briefly so some receipts are still in-flight on disconnect.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let alice_client: Arc<_> = Arc::clone(&alice.client);
    let bob_client: Arc<_> = Arc::clone(&bob.client);

    let start = Instant::now();
    tokio::join!(alice_client.disconnect(), bob_client.disconnect());
    let elapsed = start.elapsed();

    drop(alice.run_handle);
    drop(bob.run_handle);

    assert!(
        elapsed < Duration::from_secs(7),
        "concurrent disconnect under load deadlocked: took {:?}",
        elapsed
    );
    Ok(())
}

/// Reproduces the pattern from the field report more literally: same client
/// arc used by the test *and* the run handle, disconnect called while the
/// run loop is still actively polling transport events. Repeats N times to
/// catch schedule-dependent hangs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_disconnect_repeated() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    for i in 0..5 {
        let alice = TestClient::connect(&format!("e2e_concurrent_disc_rep_a_{i}")).await?;
        let bob = TestClient::connect(&format!("e2e_concurrent_disc_rep_b_{i}")).await?;

        let alice_client: Arc<_> = Arc::clone(&alice.client);
        let bob_client: Arc<_> = Arc::clone(&bob.client);

        let start = Instant::now();
        tokio::join!(alice_client.disconnect(), bob_client.disconnect());
        let elapsed = start.elapsed();
        drop(alice.run_handle);
        drop(bob.run_handle);

        assert!(
            elapsed < Duration::from_secs(3),
            "iteration {i}: concurrent disconnect deadlocked: took {:?} (expect < 3s)",
            elapsed
        );
    }
    Ok(())
}
