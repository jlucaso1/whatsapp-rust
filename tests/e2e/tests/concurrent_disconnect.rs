//! Regression: concurrent `Client::disconnect()` must not deadlock.
//!
//! Bug shape (field report from the baileyrs consumer over WASM): when two
//! or more independent clients call `disconnect()` at the same time, one
//! hangs after logging `"Disconnecting client intentionally"` and never
//! reaches `transport.disconnect()` — so the underlying socket never gets
//! `close()`d.
//!
//! Root cause: the run loop's graceful-exit path (woken by
//! `notify_connection_shutdown()`) raced into `cleanup_connection_state` and
//! cleared `self.transport = None` before the user-initiated `disconnect()`
//! reached `self.transport.lock().await.as_ref()`. The `if let Some(_)` then
//! saw `None` and silently skipped the close. Fix: `cleanup_connection_state`
//! now owns socket teardown (takes + disconnects) so whichever path clears
//! the transport also closes it.

use std::sync::Arc;
use std::time::{Duration, Instant};

use e2e_tests::{TestClient, text_msg};
use wacore::types::events::Event;

/// Baseline: 2 clients, multi-thread runtime. Should complete nearly
/// instantly (the race window is microseconds in practice), so a generous
/// 3-second budget makes the test fail loudly if the hang regresses.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_disconnect_two_clients_multithread() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let alice = TestClient::connect("e2e_concurrent_disc_2mt_a").await?;
    let bob = TestClient::connect("e2e_concurrent_disc_2mt_b").await?;
    let a = Arc::clone(&alice.client);
    let b = Arc::clone(&bob.client);

    let start = Instant::now();
    tokio::join!(a.disconnect(), b.disconnect());
    let elapsed = start.elapsed();

    drop(alice.run_handle);
    drop(bob.run_handle);
    assert!(
        elapsed < Duration::from_secs(3),
        "2-client concurrent disconnect took {elapsed:?} (budget: 3s)"
    );
    Ok(())
}

/// Single-threaded executor — matches the WASM runtime where the original
/// field report came from. Single-thread scheduling surfaces lock-ordering
/// and await-interleaving issues that multi-thread can paper over.
#[tokio::test(flavor = "current_thread")]
async fn concurrent_disconnect_two_clients_single_thread() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let alice = TestClient::connect("e2e_concurrent_disc_2st_a").await?;
    let bob = TestClient::connect("e2e_concurrent_disc_2st_b").await?;
    let a = Arc::clone(&alice.client);
    let b = Arc::clone(&bob.client);

    let start = Instant::now();
    tokio::join!(a.disconnect(), b.disconnect());
    let elapsed = start.elapsed();

    drop(alice.run_handle);
    drop(bob.run_handle);
    assert!(
        elapsed < Duration::from_secs(3),
        "2-client single-thread disconnect took {elapsed:?} (budget: 3s)"
    );
    Ok(())
}

/// The actual bug repro. Pre-fix, 2 clients would usually squeak through,
/// but 3 concurrent disconnects reliably lost the race for the last one:
/// its run loop's graceful-exit cleanup fired before `disconnect()` could
/// acquire the transport mutex.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_disconnect_three_clients() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let alice = TestClient::connect("e2e_concurrent_disc_3_a").await?;
    let bob = TestClient::connect("e2e_concurrent_disc_3_b").await?;
    let charlie = TestClient::connect("e2e_concurrent_disc_3_c").await?;
    let a = Arc::clone(&alice.client);
    let b = Arc::clone(&bob.client);
    let c = Arc::clone(&charlie.client);

    let start = Instant::now();
    tokio::join!(a.disconnect(), b.disconnect(), c.disconnect());
    let elapsed = start.elapsed();

    drop(alice.run_handle);
    drop(bob.run_handle);
    drop(charlie.run_handle);
    assert!(
        elapsed < Duration::from_secs(3),
        "3-client concurrent disconnect took {elapsed:?} (budget: 3s)"
    );
    Ok(())
}

/// Pending receipts at disconnect time. Guards against breaking the
/// FlushScope / outbound receipt flow while fixing the socket-teardown
/// race — the flush must still complete before the socket closes, otherwise
/// receipts go out against a closed transport and get dropped.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_disconnect_with_pending_receipts() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut alice = TestClient::connect("e2e_concurrent_disc_rx_a").await?;
    let mut bob = TestClient::connect("e2e_concurrent_disc_rx_b").await?;
    let alice_jid = alice.jid().await;
    let bob_jid = bob.jid().await;

    const N: usize = 3;
    for i in 0..N {
        alice
            .client
            .send_message(bob_jid.clone(), text_msg(&format!("a->b #{i}")))
            .await?;
        bob.client
            .send_message(alice_jid.clone(), text_msg(&format!("b->a #{i}")))
            .await?;
    }
    for i in 0..N {
        let expected_ab = format!("a->b #{i}");
        bob.wait_for_event(10, |e| {
            matches!(e, Event::Message(m, _) if m.conversation.as_deref() == Some(expected_ab.as_str()))
        })
        .await?;
        let expected_ba = format!("b->a #{i}");
        alice
            .wait_for_event(10, |e| {
                matches!(e, Event::Message(m, _) if m.conversation.as_deref() == Some(expected_ba.as_str()))
            })
            .await?;
    }

    let a = Arc::clone(&alice.client);
    let b = Arc::clone(&bob.client);
    let start = Instant::now();
    tokio::join!(a.disconnect(), b.disconnect());
    let elapsed = start.elapsed();

    drop(alice.run_handle);
    drop(bob.run_handle);
    // Looser budget: receipts drain up to 5 s (`outbound_flush` ceiling), and
    // we're doing two of them concurrently.
    assert!(
        elapsed < Duration::from_secs(6),
        "disconnect with pending receipts took {elapsed:?} (budget: 6s)"
    );
    Ok(())
}
