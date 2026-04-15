#[cfg(not(feature = "dhat-heap"))]
mod counting_alloc;

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static GLOBAL: dhat::Alloc = dhat::Alloc;

#[cfg(not(feature = "dhat-heap"))]
#[global_allocator]
static GLOBAL: counting_alloc::CountingAlloc = counting_alloc::CountingAlloc;

use std::time::Instant;

use e2e_tests::{TestClient, text_msg};
use serde::Serialize;

// ---------------------------------------------------------------------------
// Measurement helpers
// ---------------------------------------------------------------------------

/// Snapshot-based measurement: runs `f`, returns wall time + alloc delta.
#[cfg(not(feature = "dhat-heap"))]
async fn measure<F, T>(
    mut f: F,
) -> anyhow::Result<(T, std::time::Duration, counting_alloc::AllocDelta)>
where
    F: AsyncFnMut() -> anyhow::Result<T>,
{
    let before = counting_alloc::AllocSnapshot::now();
    let t0 = Instant::now();
    let result = f().await?;
    let elapsed = t0.elapsed();
    let delta = counting_alloc::AllocDelta::between(before, counting_alloc::AllocSnapshot::now());
    Ok((result, elapsed, delta))
}

/// DHAT mode: just runs `f` and returns wall time (DHAT captures everything).
#[cfg(feature = "dhat-heap")]
async fn measure<F, T>(mut f: F) -> anyhow::Result<(T, std::time::Duration)>
where
    F: AsyncFnMut() -> anyhow::Result<T>,
{
    let t0 = Instant::now();
    let result = f().await?;
    let elapsed = t0.elapsed();
    Ok((result, elapsed))
}

// ---------------------------------------------------------------------------
// Results collection
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct BenchEntry {
    name: String,
    unit: String,
    value: u64,
}

struct BenchResults(Vec<BenchEntry>);

impl BenchResults {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn record(&mut self, scenario: &str, metric: &str, unit: &str, value: u64) {
        self.0.push(BenchEntry {
            name: format!("integration::{scenario}::{metric}"),
            unit: unit.to_string(),
            value,
        });
    }

    fn record_wall(&mut self, scenario: &str, elapsed: std::time::Duration) {
        self.record(
            scenario,
            "wall_ms",
            "milliseconds",
            elapsed.as_millis() as u64,
        );
    }

    #[cfg(not(feature = "dhat-heap"))]
    fn record_measured(
        &mut self,
        scenario: &str,
        elapsed: std::time::Duration,
        delta: &counting_alloc::AllocDelta,
    ) {
        self.record(scenario, "alloc_count", "allocations", delta.alloc_count);
        self.record(scenario, "alloc_bytes", "bytes", delta.alloc_bytes);
        self.record_wall(scenario, elapsed);
    }

    #[cfg(not(feature = "dhat-heap"))]
    fn record_measured_amortized(
        &mut self,
        scenario: &str,
        n: u64,
        elapsed: std::time::Duration,
        delta: &counting_alloc::AllocDelta,
    ) {
        self.record(
            scenario,
            "alloc_count",
            "allocations",
            delta.alloc_count / n,
        );
        self.record(scenario, "alloc_bytes", "bytes", delta.alloc_bytes / n);
        self.record(
            scenario,
            "wall_ms",
            "milliseconds",
            elapsed.as_millis() as u64 / n,
        );
    }
}

// ---------------------------------------------------------------------------
// Scenarios
// ---------------------------------------------------------------------------

/// Measure allocations from client creation through Connected (ready).
async fn bench_connect_to_ready(results: &mut BenchResults) -> anyhow::Result<()> {
    let m = measure(async || TestClient::connect("bench_connect").await).await?;

    #[cfg(not(feature = "dhat-heap"))]
    {
        let (client, elapsed, delta) = m;
        results.record_measured("connect_to_ready", elapsed, &delta);
        client.disconnect().await;
    }
    #[cfg(feature = "dhat-heap")]
    {
        let (client, elapsed) = m;
        results.record_wall("connect_to_ready", elapsed);
        client.disconnect().await;
    }
    Ok(())
}

/// Measure allocations for sending a single DM (sender side only).
///
/// Both clients are connected before measurement starts.
/// We track the `send_message` call which covers: protobuf encoding,
/// Signal encrypt, node marshal, and WebSocket write.
async fn bench_send_message(results: &mut BenchResults) -> anyhow::Result<()> {
    let client_a = TestClient::connect("bench_send_a").await?;
    let mut client_b = TestClient::connect("bench_send_b").await?;
    let jid_b = client_b.jid().await;

    // Warm up: establish Signal session with a throwaway message
    client_a
        .client
        .send_message(jid_b.clone(), text_msg("warmup-send"))
        .await?;
    client_b.wait_for_text("warmup-send", 30).await?;

    // -- Single send --
    let m = measure(async || {
        client_a
            .client
            .send_message(jid_b.clone(), text_msg("bench-send-single"))
            .await
    })
    .await?;

    #[cfg(not(feature = "dhat-heap"))]
    {
        let (_, elapsed, delta) = m;
        results.record_measured("send_message", elapsed, &delta);
    }
    #[cfg(feature = "dhat-heap")]
    {
        let (_, elapsed) = m;
        results.record_wall("send_message", elapsed);
    }

    client_b.wait_for_text("bench-send-single", 30).await?;

    // -- Amortized: send N messages --
    const N: u64 = 20;
    let m = measure(async || {
        for i in 0..N {
            client_a
                .client
                .send_message(jid_b.clone(), text_msg(&format!("bench-send-{i}")))
                .await?;
        }
        Ok(())
    })
    .await?;

    #[cfg(not(feature = "dhat-heap"))]
    {
        let (_, elapsed, delta) = m;
        results.record_measured_amortized("send_message_x20_amortized", N, elapsed, &delta);
    }
    #[cfg(feature = "dhat-heap")]
    {
        let (_, elapsed) = m;
        results.record(
            "send_message_x20_amortized",
            "wall_ms",
            "milliseconds",
            elapsed.as_millis() as u64 / N,
        );
    }

    for i in 0..N {
        client_b
            .wait_for_text(&format!("bench-send-{i}"), 30)
            .await?;
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Measure allocations for a full send+receive round-trip.
///
/// Both clients are connected and session is warm before measurement.
async fn bench_receive_message(results: &mut BenchResults) -> anyhow::Result<()> {
    let client_a = TestClient::connect("bench_recv_a").await?;
    let mut client_b = TestClient::connect("bench_recv_b").await?;
    let jid_b = client_b.jid().await;

    // Warm up Signal session
    client_a
        .client
        .send_message(jid_b.clone(), text_msg("warmup-recv"))
        .await?;
    client_b.wait_for_text("warmup-recv", 30).await?;

    // -- Single send+receive --
    let m = measure(async || {
        client_a
            .client
            .send_message(jid_b.clone(), text_msg("bench-recv-single"))
            .await?;
        client_b.wait_for_text("bench-recv-single", 30).await?;
        Ok(())
    })
    .await?;

    #[cfg(not(feature = "dhat-heap"))]
    {
        let (_, elapsed, delta) = m;
        results.record_measured("send_and_receive_message", elapsed, &delta);
    }
    #[cfg(feature = "dhat-heap")]
    {
        let (_, elapsed) = m;
        results.record_wall("send_and_receive_message", elapsed);
    }

    // -- Amortized N round-trips --
    const N: u64 = 20;
    let m = measure(async || {
        for i in 0..N {
            let text = format!("bench-recv-{i}");
            client_a
                .client
                .send_message(jid_b.clone(), text_msg(&text))
                .await?;
            client_b.wait_for_text(&text, 30).await?;
        }
        Ok(())
    })
    .await?;

    #[cfg(not(feature = "dhat-heap"))]
    {
        let (_, elapsed, delta) = m;
        results.record_measured_amortized("send_and_receive_x20_amortized", N, elapsed, &delta);
    }
    #[cfg(feature = "dhat-heap")]
    {
        let (_, elapsed) = m;
        results.record(
            "send_and_receive_x20_amortized",
            "wall_ms",
            "milliseconds",
            elapsed.as_millis() as u64 / N,
        );
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

/// Measure allocations for a reconnect cycle (disconnect -> reconnect -> ready).
async fn bench_reconnect(results: &mut BenchResults) -> anyhow::Result<()> {
    let mut client = TestClient::connect("bench_reconn").await?;

    let m = measure(async || {
        client.reconnect_and_wait().await?;
        Ok(())
    })
    .await?;

    #[cfg(not(feature = "dhat-heap"))]
    {
        let (_, elapsed, delta) = m;
        results.record_measured("reconnect", elapsed, &delta);
    }
    #[cfg(feature = "dhat-heap")]
    {
        let (_, elapsed) = m;
        results.record_wall("reconnect", elapsed);
    }

    client.disconnect().await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn"))
        .try_init()
        .ok();

    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let mut results = BenchResults::new();

    eprintln!("--- bench: connect_to_ready ---");
    bench_connect_to_ready(&mut results).await?;

    eprintln!("--- bench: send_message ---");
    bench_send_message(&mut results).await?;

    eprintln!("--- bench: receive_message ---");
    bench_receive_message(&mut results).await?;

    eprintln!("--- bench: reconnect ---");
    bench_reconnect(&mut results).await?;

    // Output customSmallerIsBetter JSON to stdout
    let json = serde_json::to_string_pretty(&results.0)?;
    println!("{json}");

    eprintln!("--- done: {} metrics collected ---", results.0.len());
    Ok(())
}
