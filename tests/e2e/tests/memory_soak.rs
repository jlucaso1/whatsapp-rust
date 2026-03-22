//! Memory soak tests — aggressive stress tests to detect unbounded memory growth.
//!
//! Track both internal collection sizes and process RSS to catch leaks that
//! escape moka/HashMap tracking.

#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use e2e_tests::TestClient;
use log::info;
use std::io::Read as _;
use wacore::types::events::Event;
use whatsapp_rust::Jid;
use whatsapp_rust::client::MemoryDiagnostics;
use whatsapp_rust::features::{GroupCreateOptions, GroupParticipantOptions};
use whatsapp_rust::waproto::whatsapp as wa;

/// Read an env var as usize, falling back to the given default.
fn env_or(var: &str, default: usize) -> usize {
    std::env::var(var)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Returns current RSS in KiB by parsing /proc/self/status (no page-size assumption).
fn rss_kib() -> usize {
    let mut buf = String::new();
    if std::fs::File::open("/proc/self/status")
        .and_then(|mut f| f.read_to_string(&mut buf))
        .is_ok()
    {
        for line in buf.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:")
                && let Some(kb_str) = rest.trim().strip_suffix("kB").map(str::trim)
            {
                return kb_str.parse().unwrap_or(0);
            }
        }
    }
    0
}

#[derive(Debug, Clone)]
struct Snapshot {
    round: usize,
    diag: MemoryDiagnostics,
    rss_kib: usize,
    #[cfg(feature = "dhat-heap")]
    heap_bytes: usize,
}

async fn snapshot(label: &str, round: usize, client: &whatsapp_rust::client::Client) -> Snapshot {
    let diag = client.memory_diagnostics().await;
    let rss = rss_kib();
    #[cfg(feature = "dhat-heap")]
    let heap_bytes = dhat::HeapStats::get().curr_bytes;

    info!(
        "[round {round:>4}] {label} | RSS={rss}K | moka(recent_msg={},session_locks={},msg_queues={},device_cache={}) | unbounded(signal_sess={},signal_id={},signal_sk={},resp_waiters={},pending_retries={},presence_subs={},app_state_kr={},app_state_sync={})",
        diag.recent_messages,
        diag.session_locks,
        diag.message_queues,
        diag.device_cache,
        diag.signal_cache_sessions,
        diag.signal_cache_identities,
        diag.signal_cache_sender_keys,
        diag.response_waiters,
        diag.pending_retries,
        diag.presence_subscriptions,
        diag.app_state_key_requests,
        diag.app_state_syncing,
    );

    Snapshot {
        round,
        diag,
        rss_kib: rss,
        #[cfg(feature = "dhat-heap")]
        heap_bytes,
    }
}

/// Analyze snapshot series: check both collection growth AND RSS growth.
fn analyze_growth(label: &str, snapshots: &[Snapshot]) {
    assert!(snapshots.len() >= 2, "Need at least 2 snapshots");
    let first = snapshots.first().unwrap();
    let last = snapshots.last().unwrap();

    info!(
        "--- {label} growth analysis (round {} -> {}) ---",
        first.round, last.round
    );

    // Unbounded collections: must not grow beyond a small constant
    let checks: Vec<(&str, usize, usize)> = vec![
        (
            "response_waiters",
            first.diag.response_waiters,
            last.diag.response_waiters,
        ),
        (
            "node_waiters",
            first.diag.node_waiters,
            last.diag.node_waiters,
        ),
        (
            "pending_retries",
            first.diag.pending_retries,
            last.diag.pending_retries,
        ),
        (
            "presence_subscriptions",
            first.diag.presence_subscriptions,
            last.diag.presence_subscriptions,
        ),
        (
            "app_state_key_requests",
            first.diag.app_state_key_requests,
            last.diag.app_state_key_requests,
        ),
        (
            "app_state_syncing",
            first.diag.app_state_syncing,
            last.diag.app_state_syncing,
        ),
        (
            "signal_sessions",
            first.diag.signal_cache_sessions,
            last.diag.signal_cache_sessions,
        ),
        (
            "signal_identities",
            first.diag.signal_cache_identities,
            last.diag.signal_cache_identities,
        ),
        (
            "signal_sender_keys",
            first.diag.signal_cache_sender_keys,
            last.diag.signal_cache_sender_keys,
        ),
        (
            "chatstate_handlers",
            first.diag.chatstate_handlers,
            last.diag.chatstate_handlers,
        ),
        (
            "custom_enc_handlers",
            first.diag.custom_enc_handlers,
            last.diag.custom_enc_handlers,
        ),
    ];

    let mut warnings = Vec::new();
    for (name, first_val, last_val) in &checks {
        if *last_val <= 10 {
            continue;
        }
        // Absolute ceiling: 200 entries for any unbounded collection
        if *last_val > 200 {
            warnings.push(format!(
                "  {name}: {first_val} -> {last_val} (exceeds ceiling 200)"
            ));
            continue;
        }
        // Growth factor: 3x max (generous, since peers add entries)
        if *first_val > 0 {
            let growth = *last_val as f64 / *first_val as f64;
            if growth > 3.0 {
                warnings.push(format!(
                    "  {name}: {first_val} -> {last_val} (growth {growth:.1}x > 3.0x)"
                ));
            }
        }
    }

    // Bounded caches: report but don't fail (TTL handles these)
    let bounded = [
        (
            "recent_messages",
            first.diag.recent_messages,
            last.diag.recent_messages,
        ),
        (
            "session_locks",
            first.diag.session_locks,
            last.diag.session_locks,
        ),
        (
            "message_queues",
            first.diag.message_queues,
            last.diag.message_queues,
        ),
        (
            "message_enqueue_locks",
            first.diag.message_enqueue_locks,
            last.diag.message_enqueue_locks,
        ),
        (
            "device_cache",
            first.diag.device_cache,
            last.diag.device_cache,
        ),
        (
            "device_registry_cache",
            first.diag.device_registry_cache,
            last.diag.device_registry_cache,
        ),
        ("group_cache", first.diag.group_cache, last.diag.group_cache),
    ];
    info!("  Bounded caches:");
    for (name, fv, lv) in &bounded {
        info!("    {name}: {fv} -> {lv}");
    }

    // RSS growth: warn if RSS grew more than 50 MiB (not a hard fail, just FYI)
    let rss_growth_kib = last.rss_kib.saturating_sub(first.rss_kib);
    info!(
        "  RSS: {}K -> {}K (delta: +{}K / +{:.1}M)",
        first.rss_kib,
        last.rss_kib,
        rss_growth_kib,
        rss_growth_kib as f64 / 1024.0
    );
    if rss_growth_kib > 50 * 1024 {
        info!(
            "  NOTE: RSS grew by {:.1} MiB ({}K -> {}K) — informational only, not a test failure",
            rss_growth_kib as f64 / 1024.0,
            first.rss_kib,
            last.rss_kib
        );
    }

    if !warnings.is_empty() {
        let report = warnings.join("\n");
        panic!(
            "Growth issues detected in {label}:\n{report}\n\n\
             First snapshot: round {}, RSS={}K\n{}\n\
             Last snapshot: round {}, RSS={}K\n{}",
            first.round, first.rss_kib, first.diag, last.round, last.rss_kib, last.diag,
        );
    }
    info!("  -> No growth issues detected.");
}

fn make_text_msg(text: &str) -> wa::Message {
    wa::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    }
}

/// Build a larger message (~2KB) with extended text to stress the recent_messages cache.
fn make_large_msg(round: usize) -> wa::Message {
    let body = format!("large-msg-r{round}-{}", "X".repeat(2000));
    wa::Message {
        extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
            text: Some(body),
            ..Default::default()
        })),
        ..Default::default()
    }
}

async fn send_and_recv(
    sender: &TestClient,
    receiver: &mut TestClient,
    to: &Jid,
    msg: wa::Message,
    expected_text: &str,
) -> anyhow::Result<()> {
    sender.client.send_message(to.clone(), msg).await?;
    let t = expected_text.to_string();
    receiver
        .wait_for_event(30, move |e| match e {
            Event::Message(msg, _) => {
                msg.conversation.as_deref() == Some(t.as_str())
                    || msg
                        .extended_text_message
                        .as_ref()
                        .and_then(|ext| ext.text.as_deref())
                        .is_some_and(|txt| txt.starts_with(&t))
            }
            _ => false,
        })
        .await?;
    Ok(())
}

async fn wait_for_group_msg(
    client: &mut TestClient,
    group_jid: &Jid,
    expected_text: &str,
) -> anyhow::Result<()> {
    let gid = group_jid.clone();
    let text = expected_text.to_string();
    client
        .wait_for_event(30, move |e| match e {
            Event::Message(msg, info) if info.source.chat == gid => {
                msg.conversation.as_deref() == Some(text.as_str())
                    || msg
                        .extended_text_message
                        .as_ref()
                        .and_then(|ext| ext.text.as_deref())
                        .is_some_and(|txt| txt.starts_with(&text))
            }
            _ => false,
        })
        .await?;
    Ok(())
}

#[tokio::test]
#[ignore = "stress test — run manually with --ignored"]
async fn test_heavy_dm_soak() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let rounds = env_or("SOAK_DM_ROUNDS", 200);
    let snapshot_every = env_or("SOAK_SNAPSHOT_EVERY", 50);

    info!("=== HEAVY DM SOAK: {rounds} rounds, snapshot every {snapshot_every} ===");

    let mut client_a = TestClient::connect("soak2_dm_a").await?;
    let mut client_b = TestClient::connect("soak2_dm_b").await?;

    let jid_a = client_a.client.get_pn().await.expect("A JID").to_non_ad();
    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    // Warm-up
    for i in 0..5 {
        let t = format!("warmup-{i}");
        send_and_recv(&client_a, &mut client_b, &jid_b, make_text_msg(&t), &t).await?;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let mut snaps: Vec<Snapshot> = Vec::new();
    snaps.push(snapshot("A", 0, &client_a.client).await);

    for round in 1..=rounds {
        // Mix of small and large messages
        if round % 5 == 0 {
            // Large message (~2KB payload)
            let key = format!("large-msg-r{round}");
            let msg = make_large_msg(round);
            send_and_recv(&client_a, &mut client_b, &jid_b, msg, &key).await?;
        } else {
            // A -> B
            let t = format!("dm-a2b-{round}");
            send_and_recv(&client_a, &mut client_b, &jid_b, make_text_msg(&t), &t).await?;
        }

        // B -> A (always small)
        let t = format!("dm-b2a-{round}");
        send_and_recv(&client_b, &mut client_a, &jid_a, make_text_msg(&t), &t).await?;

        if round % snapshot_every == 0 || round == rounds {
            snaps.push(snapshot("A", round, &client_a.client).await);
        }
    }

    info!(
        "DM soak done ({rounds} rounds, {} messages total).",
        rounds * 2
    );
    analyze_growth("heavy_dm A", &snaps);

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
#[ignore = "stress test — run manually with --ignored"]
async fn test_heavy_group_soak() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let rounds = env_or("SOAK_GROUP_ROUNDS", 150);
    let snapshot_every = env_or("SOAK_SNAPSHOT_EVERY", 50);

    info!("=== HEAVY GROUP SOAK: {rounds} rounds, 3 clients, 2 groups ===");

    let mut client_a = TestClient::connect("soak2_grp_a").await?;
    let mut client_b = TestClient::connect("soak2_grp_b").await?;
    let mut client_c = TestClient::connect("soak2_grp_c").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();
    let jid_c = client_c.client.get_pn().await.expect("C JID").to_non_ad();

    // Create group 1: A + B + C
    let g1 = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Soak Group 1".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
            ],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group 1: {g1}");

    // Wait for notifications
    for client in [&mut client_b, &mut client_c] {
        client
            .wait_for_event(15, |e| {
                matches!(e, Event::Notification(node) if node.attrs.get("type").is_some_and(|v| v == "w:gp2"))
            })
            .await?;
    }

    // Create group 2: A + B (no C)
    let g2 = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Soak Group 2".to_string(),
            participants: vec![GroupParticipantOptions::new(jid_b.clone())],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group 2: {g2}");

    client_b
        .wait_for_event(15, |e| {
            matches!(e, Event::Notification(node) if node.attrs.get("type").is_some_and(|v| v == "w:gp2"))
        })
        .await?;

    // Warm-up both groups
    for i in 0..3 {
        let t = format!("g1-warmup-{i}");
        client_a
            .client
            .send_message(g1.clone(), make_text_msg(&t))
            .await?;
        wait_for_group_msg(&mut client_b, &g1, &t).await?;
        wait_for_group_msg(&mut client_c, &g1, &t).await?;

        let t2 = format!("g2-warmup-{i}");
        client_a
            .client
            .send_message(g2.clone(), make_text_msg(&t2))
            .await?;
        wait_for_group_msg(&mut client_b, &g2, &t2).await?;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let mut snaps: Vec<Snapshot> = Vec::new();
    snaps.push(snapshot("A-grp", 0, &client_a.client).await);

    for round in 1..=rounds {
        // Alternate: group1 (3 members) vs group2 (2 members) vs large msg
        match round % 6 {
            0 => {
                // Large message to group1
                let key = format!("large-msg-r{round}");
                let msg = make_large_msg(round);
                client_a.client.send_message(g1.clone(), msg).await?;
                wait_for_group_msg(&mut client_b, &g1, &key).await?;
                wait_for_group_msg(&mut client_c, &g1, &key).await?;
            }
            1 | 3 | 5 => {
                // Group1: A sends, B+C receive
                let t = format!("g1-r{round}");
                client_a
                    .client
                    .send_message(g1.clone(), make_text_msg(&t))
                    .await?;
                wait_for_group_msg(&mut client_b, &g1, &t).await?;
                wait_for_group_msg(&mut client_c, &g1, &t).await?;
            }
            2 => {
                // Group1: B sends, A+C receive
                let t = format!("g1-b-r{round}");
                client_b
                    .client
                    .send_message(g1.clone(), make_text_msg(&t))
                    .await?;
                wait_for_group_msg(&mut client_a, &g1, &t).await?;
                wait_for_group_msg(&mut client_c, &g1, &t).await?;
            }
            _ => {
                // Group2: A sends, B receives
                let t = format!("g2-r{round}");
                client_a
                    .client
                    .send_message(g2.clone(), make_text_msg(&t))
                    .await?;
                wait_for_group_msg(&mut client_b, &g2, &t).await?;
            }
        }

        if round % snapshot_every == 0 || round == rounds {
            snaps.push(snapshot("A-grp", round, &client_a.client).await);
        }
    }

    info!("Group soak done ({rounds} rounds).");
    analyze_growth("heavy_group A", &snaps);

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;
    Ok(())
}

#[tokio::test]
#[ignore = "stress test — run manually with --ignored"]
async fn test_heavy_mixed_soak() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let rounds = env_or("SOAK_MIXED_ROUNDS", 150);
    let reconnect_every = env_or("SOAK_RECONNECT_EVERY", 30);
    let snapshot_every = env_or("SOAK_SNAPSHOT_EVERY", 25);

    info!("=== HEAVY MIXED SOAK: {rounds} rounds, reconnect every {reconnect_every} ===");

    let mut client_a = TestClient::connect("soak2_mix_a").await?;
    let mut client_b = TestClient::connect("soak2_mix_b").await?;
    let mut client_c = TestClient::connect("soak2_mix_c").await?;

    let jid_a = client_a.client.get_pn().await.expect("A JID").to_non_ad();
    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();
    let jid_c = client_c.client.get_pn().await.expect("C JID").to_non_ad();

    // Create group
    let group_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Soak Mixed Group".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
            ],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group: {group_jid}");

    for client in [&mut client_b, &mut client_c] {
        client
            .wait_for_event(15, |e| {
                matches!(e, Event::Notification(node) if node.attrs.get("type").is_some_and(|v| v == "w:gp2"))
            })
            .await?;
    }

    // Warm-up
    for i in 0..3 {
        let t = format!("mix-warmup-{i}");
        client_a
            .client
            .send_message(group_jid.clone(), make_text_msg(&t))
            .await?;
        wait_for_group_msg(&mut client_b, &group_jid, &t).await?;
        wait_for_group_msg(&mut client_c, &group_jid, &t).await?;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let mut snaps: Vec<Snapshot> = Vec::new();
    snaps.push(snapshot("A-mix", 0, &client_a.client).await);

    let mut reconnect_count = 0u32;

    for round in 1..=rounds {
        // --- Reconnect cycle ---
        if round % reconnect_every == 0 {
            reconnect_count += 1;
            info!("[round {round}] Reconnecting A (#{reconnect_count})...");
            client_a.reconnect_and_wait().await?;
            client_a
                .client
                .wait_for_startup_sync(tokio::time::Duration::from_secs(15))
                .await?;
            info!("[round {round}] A reconnected.");

            // Verify session works after reconnect
            let t = format!("post-recon-{reconnect_count}");
            send_and_recv(&client_a, &mut client_b, &jid_b, make_text_msg(&t), &t).await?;
        }

        // --- Mixed operations based on round ---
        match round % 10 {
            0 => {
                // Large message to group
                let key = format!("large-msg-r{round}");
                let msg = make_large_msg(round);
                client_a.client.send_message(group_jid.clone(), msg).await?;
                wait_for_group_msg(&mut client_b, &group_jid, &key).await?;
                wait_for_group_msg(&mut client_c, &group_jid, &key).await?;
            }
            1 | 4 | 7 => {
                // DM: A -> B
                let t = format!("dm-ab-r{round}");
                send_and_recv(&client_a, &mut client_b, &jid_b, make_text_msg(&t), &t).await?;
            }
            2 | 5 => {
                // DM: B -> A
                let t = format!("dm-ba-r{round}");
                send_and_recv(&client_b, &mut client_a, &jid_a, make_text_msg(&t), &t).await?;
            }
            3 | 6 | 9 => {
                // Group message
                let t = format!("grp-r{round}");
                client_a
                    .client
                    .send_message(group_jid.clone(), make_text_msg(&t))
                    .await?;
                wait_for_group_msg(&mut client_b, &group_jid, &t).await?;
                wait_for_group_msg(&mut client_c, &group_jid, &t).await?;
            }
            8 => {
                // Presence + chatstate burst
                // These exercise presence_subscriptions and chatstate handler paths
                let _ = client_a.client.presence().subscribe(&jid_b).await;
                let _ = client_a.client.presence().subscribe(&jid_c).await;
                let _ = client_a.client.chatstate().send_composing(&jid_b).await;
                let _ = client_a.client.chatstate().send_paused(&jid_b).await;
                let _ = client_a.client.chatstate().send_composing(&group_jid).await;
                let _ = client_a.client.chatstate().send_paused(&group_jid).await;
                // Unsubscribe to test cleanup
                let _ = client_a.client.presence().unsubscribe(&jid_c).await;

                // Still send a message to keep the loop producing work
                let t = format!("dm-after-presence-r{round}");
                send_and_recv(&client_a, &mut client_b, &jid_b, make_text_msg(&t), &t).await?;
            }
            _ => unreachable!(),
        }

        if round % snapshot_every == 0 || round == rounds {
            snaps.push(snapshot("A-mix", round, &client_a.client).await);
        }
    }

    info!("Mixed soak done ({rounds} rounds, {reconnect_count} reconnects).");
    analyze_growth("heavy_mixed A", &snaps);

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;
    Ok(())
}

#[tokio::test]
#[ignore = "stress test — run manually with --ignored"]
async fn test_many_peers_soak() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let num_peers = env_or("SOAK_NUM_PEERS", 6);
    let msgs_per_peer = env_or("SOAK_MSGS_PER_PEER", 30);

    info!("=== MANY PEERS SOAK: {num_peers} peers, {msgs_per_peer} msgs each ===");

    // Connect the main client
    let client_a = TestClient::connect("soak2_peers_a").await?;

    // Connect N peer clients
    let mut peers: Vec<TestClient> = Vec::new();
    let mut peer_jids: Vec<Jid> = Vec::new();
    for i in 0..num_peers {
        let peer = TestClient::connect(&format!("soak2_peers_p{i}")).await?;
        let jid = peer.client.get_pn().await.expect("peer JID").to_non_ad();
        peer_jids.push(jid);
        peers.push(peer);
    }

    info!(
        "Connected {} peers: {:?}",
        num_peers,
        peer_jids.iter().map(|j| j.to_string()).collect::<Vec<_>>()
    );

    // Warm-up: send 1 message to each peer
    for (i, peer) in peers.iter_mut().enumerate() {
        let t = format!("peer-warmup-{i}");
        send_and_recv(&client_a, peer, &peer_jids[i], make_text_msg(&t), &t).await?;
    }
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    let mut snaps: Vec<Snapshot> = Vec::new();
    snaps.push(snapshot("A-peers", 0, &client_a.client).await);

    // Fan-out: send msgs_per_peer messages to each peer, round-robin
    let total_msgs = num_peers * msgs_per_peer;
    for msg_idx in 0..total_msgs {
        let peer_idx = msg_idx % num_peers;
        let t = format!("peer{peer_idx}-m{msg_idx}");
        send_and_recv(
            &client_a,
            &mut peers[peer_idx],
            &peer_jids[peer_idx],
            make_text_msg(&t),
            &t,
        )
        .await?;

        // Snapshot every N messages
        if (msg_idx + 1) % (total_msgs / 4).max(1) == 0 || msg_idx == total_msgs - 1 {
            snaps.push(snapshot("A-peers", msg_idx + 1, &client_a.client).await);
        }
    }

    info!("Many-peers soak done ({num_peers} peers, {total_msgs} total messages).");
    analyze_growth("many_peers A", &snaps);

    client_a.disconnect().await;
    for peer in peers {
        peer.disconnect().await;
    }
    Ok(())
}

#[tokio::test]
#[ignore = "stress test — run manually with --ignored"]
async fn test_heavy_reconnect_soak() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    #[cfg(feature = "dhat-heap")]
    let _profiler = dhat::Profiler::new_heap();

    let reconnect_rounds = env_or("SOAK_RECONNECT_ROUNDS", 20);
    let msgs_per_round = env_or("SOAK_MSGS_PER_RECONNECT", 10);

    info!(
        "=== HEAVY RECONNECT SOAK: {reconnect_rounds} reconnects, {msgs_per_round} msgs each ==="
    );

    let mut client_a = TestClient::connect("soak2_recon_a").await?;
    let mut client_b = TestClient::connect("soak2_recon_b").await?;

    let jid_a = client_a.client.get_pn().await.expect("A JID").to_non_ad();
    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();

    let mut snaps: Vec<Snapshot> = Vec::new();
    snaps.push(snapshot("A-recon", 0, &client_a.client).await);

    for round in 1..=reconnect_rounds {
        // Send messages bidirectionally
        for i in 0..msgs_per_round {
            if i % 2 == 0 {
                let t = format!("r{round}-ab-{i}");
                send_and_recv(&client_a, &mut client_b, &jid_b, make_text_msg(&t), &t).await?;
            } else {
                let t = format!("r{round}-ba-{i}");
                send_and_recv(&client_b, &mut client_a, &jid_a, make_text_msg(&t), &t).await?;
            }
        }

        // Reconnect A
        info!("[round {round}/{reconnect_rounds}] Reconnecting A...");
        client_a.reconnect_and_wait().await?;
        client_a
            .client
            .wait_for_startup_sync(tokio::time::Duration::from_secs(15))
            .await?;

        // Verify post-reconnect
        let t = format!("post-recon-{round}");
        send_and_recv(&client_a, &mut client_b, &jid_b, make_text_msg(&t), &t).await?;

        // Also reconnect B every 5 rounds (test both sides cleaning up)
        if round % 5 == 0 {
            info!("[round {round}] Also reconnecting B...");
            client_b.reconnect_and_wait().await?;
            client_b
                .client
                .wait_for_startup_sync(tokio::time::Duration::from_secs(15))
                .await?;
            let t = format!("post-recon-b-{round}");
            send_and_recv(&client_b, &mut client_a, &jid_a, make_text_msg(&t), &t).await?;
        }

        if round % 5 == 0 || round == reconnect_rounds {
            snaps.push(snapshot("A-recon", round, &client_a.client).await);
        }
    }

    info!(
        "Reconnect soak done ({reconnect_rounds} reconnects, {} total messages).",
        reconnect_rounds * (msgs_per_round + 1)
    );
    analyze_growth("heavy_reconnect A", &snaps);

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
