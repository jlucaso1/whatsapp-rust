//! Integration tests for the full Noise handshake orchestration in
//! `whatsapp_rust::handshake::do_handshake`.
//!
//! Each test stands up an in-process Noise responder, drives the client
//! through one or more handshakes, and asserts on the outcome plus any
//! state mutations visible via the `PersistenceManager` (cached cert
//! chain) and the per-process IK failure counter.
//!
//! These tests do NOT depend on the external mock server (bartender) —
//! the responder side is implemented inline using the same primitives
//! that `wacore-noise` exports for unit-test use.
//!
//! Coverage:
//!   - cold-start XX populates the cert chain on disk
//!   - subsequent connect picks IK (via the cached chain) and succeeds
//!   - server rejects IK → client recovers via XX-fallback in one round
//!   - IK with a stale cached static key → counter incremented, cache
//!     cleared, next connect can fall back to XX cleanly
//!
//! The "IK Continue" path is asserted indirectly by checking that the
//! second connect both runs without sending three ClientHello bytes
//! (i.e. it speaks IK shape, not XX shape) AND completes successfully.

use async_trait::async_trait;
use bytes::Bytes;
use prost::Message;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use wacore::handshake::NoiseHandshake;
use wacore::libsignal::protocol::KeyPair;
use wacore_binary::consts::{NOISE_PATTERN_IK, NOISE_PATTERN_XX, WA_CONN_HEADER};
use wacore_noise::test_util::build_cert_chain_bytes;
use whatsapp_rust::waproto::whatsapp as wa;

use whatsapp_rust::handshake::do_handshake;
use whatsapp_rust::transport::{Transport, TransportEvent};

/// In-process responder driving Noise XX or IK from the server side.
/// Holds the long-lived server identity keypair and the cert chain
/// bytes that the client must verify and cache.
struct InProcessServer {
    identity_kp: KeyPair,
    cert_chain_bytes: Vec<u8>,
}

impl InProcessServer {
    fn new() -> Self {
        let identity_kp = KeyPair::generate(&mut rand::rng());
        let server_static_pub: [u8; 32] = identity_kp
            .public_key
            .public_key_bytes()
            .try_into()
            .expect("X25519 pub key is 32 bytes");
        let cert_chain_bytes = build_cert_chain_bytes(&server_static_pub);
        Self {
            identity_kp,
            cert_chain_bytes,
        }
    }

    fn server_static_pub(&self) -> [u8; 32] {
        self.identity_kp
            .public_key
            .public_key_bytes()
            .try_into()
            .expect("X25519 pub key is 32 bytes")
    }
}

/// Strips the leading WA_CONN_HEADER (4 bytes) when present and then
/// parses one length-prefixed frame from the buffer. Returns the inner
/// payload bytes.
fn parse_first_client_frame(raw: &[u8]) -> Vec<u8> {
    // Detect optional WA_CONN_HEADER at the very front.
    let body_start = if raw.starts_with(&WA_CONN_HEADER) {
        WA_CONN_HEADER.len()
    } else {
        0
    };
    parse_one_frame(&raw[body_start..])
}

fn parse_one_frame(buf: &[u8]) -> Vec<u8> {
    assert!(buf.len() >= 3, "frame buffer must hold at least the length");
    let len = ((buf[0] as usize) << 16) | ((buf[1] as usize) << 8) | (buf[2] as usize);
    assert!(buf.len() >= 3 + len, "frame buffer truncated");
    buf[3..3 + len].to_vec()
}

/// Mock transport: capture client→server bytes into a shared Vec; the
/// test drives the server→client side directly via `events_tx`.
#[derive(Clone)]
struct CaptureTransport {
    sent: Arc<StdMutex<Vec<Bytes>>>,
}

#[async_trait]
impl Transport for CaptureTransport {
    async fn send(&self, data: Bytes) -> anyhow::Result<()> {
        self.sent.lock().unwrap().push(data);
        Ok(())
    }
    async fn disconnect(&self) {}
}

fn new_transport_pair() -> (
    Arc<CaptureTransport>,
    async_channel::Sender<TransportEvent>,
    async_channel::Receiver<TransportEvent>,
) {
    let sent = Arc::new(StdMutex::new(Vec::new()));
    let transport = Arc::new(CaptureTransport {
        sent: Arc::clone(&sent),
    });
    let (events_tx, events_rx) = async_channel::unbounded::<TransportEvent>();
    let _ = sent; // used via transport.sent
    (transport, events_tx, events_rx)
}

/// Synchronously serves an XX handshake: consumes the buffered
/// ClientHello frame, builds + signals the ServerHello via events_tx,
/// then consumes the ClientFinish.
async fn xx_serve_full(
    server: &InProcessServer,
    transport: &Arc<CaptureTransport>,
    events_tx: &async_channel::Sender<TransportEvent>,
) {
    // Wait until the client put something on the wire.
    wait_for_send(transport, 1).await;
    let raw_hello = transport.sent.lock().unwrap()[0].to_vec();
    let client_hello_bytes = parse_first_client_frame(&raw_hello);

    let msg = wa::HandshakeMessage::decode(client_hello_bytes.as_slice()).unwrap();
    let client_eph_pub_vec = msg.client_hello.unwrap().ephemeral.unwrap();
    let client_eph_pub: [u8; 32] = client_eph_pub_vec.try_into().unwrap();

    let mut noise = NoiseHandshake::new(NOISE_PATTERN_XX, &WA_CONN_HEADER).unwrap();
    noise.authenticate(&client_eph_pub);

    let server_eph = KeyPair::generate(&mut rand::rng());
    let server_eph_pub: [u8; 32] = server_eph.public_key.public_key_bytes().try_into().unwrap();
    noise.authenticate(&server_eph_pub);
    noise
        .mix_shared_secret(server_eph.private_key.serialize(), &client_eph_pub)
        .unwrap();
    let encrypted_static = noise.encrypt(&server.server_static_pub()).unwrap();
    noise
        .mix_shared_secret(server.identity_kp.private_key.serialize(), &client_eph_pub)
        .unwrap();
    let encrypted_payload = noise.encrypt(&server.cert_chain_bytes).unwrap();

    let server_hello = wa::HandshakeMessage {
        server_hello: Some(wa::handshake_message::ServerHello {
            ephemeral: Some(server_eph_pub.to_vec()),
            r#static: Some(encrypted_static),
            payload: Some(encrypted_payload),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut sh_bytes = Vec::new();
    server_hello.encode(&mut sh_bytes).unwrap();
    let framed = wacore::framing::encode_frame(&sh_bytes, None).unwrap();
    events_tx
        .send(TransportEvent::DataReceived(framed.into()))
        .await
        .unwrap();

    // Consume the ClientFinish. We don't bother completing the responder
    // side — the assertion target is the cipher pair on the client side
    // (and the cached cert chain), both of which are derived before the
    // ClientFinish is consumed by the server.
    wait_for_send(transport, 2).await;
}

/// IK-accept responder: parses the IK ClientHello (e + encrypted s +
/// encrypted payload), and replies with a ServerHello whose `static` is
/// absent (signals IK success).
async fn ik_serve_accept(
    server: &InProcessServer,
    transport: &Arc<CaptureTransport>,
    events_tx: &async_channel::Sender<TransportEvent>,
) {
    wait_for_send(transport, 1).await;
    let raw_hello = transport.sent.lock().unwrap()[0].to_vec();
    let client_hello_bytes = parse_first_client_frame(&raw_hello);

    let msg = wa::HandshakeMessage::decode(client_hello_bytes.as_slice()).unwrap();
    let ch = msg.client_hello.unwrap();
    let client_eph_pub: [u8; 32] = ch.ephemeral.unwrap().try_into().unwrap();
    let encrypted_static = ch.r#static.unwrap();
    let encrypted_payload = ch.payload.unwrap();

    let mut noise = NoiseHandshake::new(NOISE_PATTERN_IK, &WA_CONN_HEADER).unwrap();
    noise.authenticate(&server.server_static_pub());
    noise.authenticate(&client_eph_pub);
    noise
        .mix_shared_secret(server.identity_kp.private_key.serialize(), &client_eph_pub)
        .unwrap();
    let client_static = noise.decrypt(&encrypted_static).unwrap();
    let client_static: [u8; 32] = client_static.try_into().unwrap();
    noise
        .mix_shared_secret(server.identity_kp.private_key.serialize(), &client_static)
        .unwrap();
    let _payload = noise.decrypt(&encrypted_payload).unwrap();

    let server_eph = KeyPair::generate(&mut rand::rng());
    let server_eph_pub: [u8; 32] = server_eph.public_key.public_key_bytes().try_into().unwrap();
    noise.authenticate(&server_eph_pub);
    noise
        .mix_shared_secret(server_eph.private_key.serialize(), &client_eph_pub)
        .unwrap();
    noise
        .mix_shared_secret(server_eph.private_key.serialize(), &client_static)
        .unwrap();
    let encrypted_cert = noise.encrypt(&server.cert_chain_bytes).unwrap();

    let server_hello = wa::HandshakeMessage {
        server_hello: Some(wa::handshake_message::ServerHello {
            ephemeral: Some(server_eph_pub.to_vec()),
            r#static: None,
            payload: Some(encrypted_cert),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut sh_bytes = Vec::new();
    server_hello.encode(&mut sh_bytes).unwrap();
    let framed = wacore::framing::encode_frame(&sh_bytes, None).unwrap();
    events_tx
        .send(TransportEvent::DataReceived(framed.into()))
        .await
        .unwrap();
}

/// Waits up to ~3s for the captured-sent buffer to reach `min_count`
/// entries. Polls every 5 ms; tight enough for unit tests.
async fn wait_for_send(transport: &Arc<CaptureTransport>, min_count: usize) {
    let start = wacore::time::Instant::now();
    let timeout = Duration::from_secs(3);
    loop {
        if transport.sent.lock().unwrap().len() >= min_count {
            return;
        }
        if start.elapsed() >= timeout {
            panic!(
                "transport did not produce {} sends within deadline (got {})",
                min_count,
                transport.sent.lock().unwrap().len()
            );
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

/// Builds a fresh PersistenceManager backed by an in-memory store.
async fn pm() -> Arc<whatsapp_rust::store::persistence_manager::PersistenceManager> {
    let backend: Arc<dyn whatsapp_rust::store::traits::Backend> =
        Arc::new(wacore::store::InMemoryBackend::new());
    Arc::new(
        whatsapp_rust::store::persistence_manager::PersistenceManager::new(backend)
            .await
            .expect("pm init"),
    )
}

/// Builds a PersistenceManager whose Device looks like it has already
/// completed pairing (`pn` is populated). The XX→IK orchestration only
/// runs on registered devices — see `select_pattern` and
/// `should_persist_cert_chain` in `src/handshake.rs`, which mirror
/// `WAWebProcessCertificate.Certificate.js:35`. Tests that exercise the
/// IK path therefore must seed registration state up front.
async fn paired_pm() -> Arc<whatsapp_rust::store::persistence_manager::PersistenceManager> {
    let pm = pm().await;
    pm.process_command(wacore::store::DeviceCommand::SetId(Some(
        "12345@s.whatsapp.net".parse().unwrap(),
    )))
    .await;
    pm
}

fn runtime() -> Arc<dyn wacore::runtime::Runtime> {
    Arc::new(whatsapp_rust::runtime_impl::TokioRuntime)
}

#[tokio::test]
async fn cold_start_xx_then_cached_ik_reconnect() {
    let _ = env_logger::builder().is_test(true).try_init();

    // The XX→IK reconnect path runs only for paired devices; an unpaired
    // device intentionally sticks to XX and never persists the chain (see
    // `should_persist_cert_chain`). Real cold-start happens unpaired and
    // is covered by the unit tests in `src/handshake.rs`.
    let pm = paired_pm().await;
    let counter = Arc::new(AtomicU32::new(0));
    let server = InProcessServer::new();
    let server_static_pub_expected = server.server_static_pub();

    // ── 1. Cold start: no cache → XX
    let (transport, events_tx, mut events_rx) = new_transport_pair();
    let pm2 = pm.clone();
    let counter2 = counter.clone();
    let runtime = runtime();
    let server_t = transport.clone();
    let server_arc = Arc::new(server);
    let server_clone = server_arc.clone();
    let server_task = tokio::spawn(async move {
        xx_serve_full(&server_clone, &server_t, &events_tx).await;
    });

    let result = do_handshake(
        runtime.clone(),
        pm2.as_ref(),
        counter2.as_ref(),
        transport.clone(),
        &mut events_rx,
    )
    .await;

    server_task.await.unwrap();

    // The XX handshake should complete fully, including the cert-chain
    // verification (so the orchestration layer can persist it).
    assert!(
        result.is_ok(),
        "XX handshake should succeed: {:?}",
        result.err()
    );

    // The cert chain must now be cached on the device.
    let device = pm.get_device_snapshot().await;
    let chain = device
        .server_cert_chain
        .as_ref()
        .expect("cert chain must be persisted after XX");
    assert_eq!(
        chain.leaf.key, server_static_pub_expected,
        "cached leaf.key must equal server's actual static pub"
    );

    // Counter must remain at 0 after a successful handshake.
    assert_eq!(counter.load(std::sync::atomic::Ordering::Acquire), 0);

    // ── 2. Reconnect: cache present → IK
    let (transport2, events_tx2, mut events_rx2) = new_transport_pair();
    let pm3 = pm.clone();
    let counter3 = counter.clone();
    let server_clone2 = server_arc.clone();
    let server_t2 = transport2.clone();
    let ik_task = tokio::spawn(async move {
        ik_serve_accept(&server_clone2, &server_t2, &events_tx2).await;
    });

    let result = do_handshake(
        runtime,
        pm3.as_ref(),
        counter3.as_ref(),
        transport2.clone(),
        &mut events_rx2,
    )
    .await;

    ik_task.await.unwrap();

    assert!(
        result.is_ok(),
        "IK handshake on reconnect should succeed: {:?}",
        result.err()
    );

    // After IK Continue, the on-disk cache stays as-is (the orchestrator
    // does NOT issue SetServerCertChain on the IK path).
    let device = pm.get_device_snapshot().await;
    assert_eq!(
        device.server_cert_chain.as_ref().unwrap().leaf.key,
        server_static_pub_expected
    );
    assert_eq!(counter.load(std::sync::atomic::Ordering::Acquire), 0);

    // The IK ClientHello should carry static + payload, not just an
    // ephemeral. Inspect the captured bytes to confirm the path.
    let sent = transport2.sent.lock().unwrap();
    let raw = sent[0].to_vec();
    let body = parse_first_client_frame(&raw);
    let parsed = wa::HandshakeMessage::decode(body.as_slice()).unwrap();
    let ch = parsed.client_hello.unwrap();
    assert!(
        ch.r#static.is_some(),
        "IK ClientHello carries client static"
    );
    assert!(ch.payload.is_some(), "IK ClientHello carries 0-RTT payload");
}

/// Regression: the IK Continue branch in `do_handshake` must NOT issue a
/// `SetServerCertChain` command. The on-disk chain stays authoritative
/// across IK Continue successes (the server demonstrably still owns the
/// cached static, so there is nothing new to cache).
///
/// Captured by tagging the on-disk chain with a sentinel `not_after` value
/// that the responder does NOT serve. After IK Continue, that sentinel
/// must survive — proving the orchestrator did not silently overwrite.
#[tokio::test]
async fn ik_continue_does_not_overwrite_cached_chain() {
    let _ = env_logger::builder().is_test(true).try_init();

    let pm = paired_pm().await;
    let counter = Arc::new(AtomicU32::new(0));
    let server = Arc::new(InProcessServer::new());

    // Sentinel `not_after` that no responder would naturally produce; if the
    // orchestrator overwrites the chain, the responder's `1_899_999_500`
    // value (from `build_cert_chain_bytes`) replaces it.
    const SENTINEL_NOT_AFTER: i64 = 1_899_999_999;
    use wacore::store::{CachedNoiseCert, CachedServerCertChain, DeviceCommand};
    pm.process_command(DeviceCommand::SetServerCertChain(CachedServerCertChain {
        intermediate: CachedNoiseCert {
            key: [0xCC; 32],
            not_before: 1_700_000_000,
            not_after: SENTINEL_NOT_AFTER,
        },
        leaf: CachedNoiseCert {
            key: server.server_static_pub(),
            not_before: 1_700_000_500,
            not_after: SENTINEL_NOT_AFTER,
        },
    }))
    .await;

    let (transport, events_tx, mut events_rx) = new_transport_pair();
    let server_clone = server.clone();
    let server_t = transport.clone();
    let task = tokio::spawn(async move {
        ik_serve_accept(&server_clone, &server_t, &events_tx).await;
    });

    let result = do_handshake(
        runtime(),
        pm.as_ref(),
        counter.as_ref(),
        transport.clone(),
        &mut events_rx,
    )
    .await;
    task.await.unwrap();

    assert!(
        result.is_ok(),
        "IK Continue must succeed: {:?}",
        result.err()
    );

    let device = pm.get_device_snapshot().await;
    let chain = device
        .server_cert_chain
        .as_ref()
        .expect("chain still present");
    assert_eq!(
        chain.leaf.not_after, SENTINEL_NOT_AFTER,
        "IK Continue must leave the cached leaf.not_after untouched"
    );
    assert_eq!(
        chain.intermediate.not_after, SENTINEL_NOT_AFTER,
        "IK Continue must leave the cached intermediate.not_after untouched"
    );
}

/// Regression: post-pair-success, the next XX (triggered by the
/// server-initiated 515 disconnect) MUST persist the cert chain. This is
/// the second half of the WA Web flow: XX-1 unpaired skips persistence,
/// then pair-success populates `pn` over the encrypted channel, then 515
/// reconnect drives XX-2 paired which finally seeds the cache for
/// subsequent IK reconnects.
///
/// We approximate the in-channel pair-success by issuing a `SetId`
/// command between the two `do_handshake` calls — same end-state as the
/// real flow.
#[tokio::test]
async fn xx_after_pair_success_persists_cert_chain() {
    let _ = env_logger::builder().is_test(true).try_init();

    // Step 1: unpaired device, XX, NO persistence.
    let pm = pm().await;
    let counter = Arc::new(AtomicU32::new(0));
    let server = Arc::new(InProcessServer::new());

    let (transport1, events_tx1, mut events_rx1) = new_transport_pair();
    let server_t1 = transport1.clone();
    let server_c1 = server.clone();
    let task1 = tokio::spawn(async move {
        xx_serve_full(&server_c1, &server_t1, &events_tx1).await;
    });
    do_handshake(
        runtime(),
        pm.as_ref(),
        counter.as_ref(),
        transport1.clone(),
        &mut events_rx1,
    )
    .await
    .expect("unpaired XX must succeed");
    task1.await.unwrap();

    let device = pm.get_device_snapshot().await;
    assert!(!device.is_registered(), "still unpaired after first XX");
    assert!(
        device.server_cert_chain.is_none(),
        "unpaired XX must not persist chain"
    );

    // Step 2: pair-success arrives over the encrypted channel; we model
    // its persistent effect by setting `pn` directly.
    pm.process_command(wacore::store::DeviceCommand::SetId(Some(
        "12345@s.whatsapp.net".parse().unwrap(),
    )))
    .await;

    // Step 3: 515 disconnect → reconnect → XX again, this time paired.
    let (transport2, events_tx2, mut events_rx2) = new_transport_pair();
    let server_t2 = transport2.clone();
    let server_c2 = server.clone();
    let task2 = tokio::spawn(async move {
        xx_serve_full(&server_c2, &server_t2, &events_tx2).await;
    });
    do_handshake(
        runtime(),
        pm.as_ref(),
        counter.as_ref(),
        transport2.clone(),
        &mut events_rx2,
    )
    .await
    .expect("paired XX must succeed");
    task2.await.unwrap();

    let device = pm.get_device_snapshot().await;
    assert!(device.is_registered(), "paired after SetId");
    let chain = device
        .server_cert_chain
        .as_ref()
        .expect("paired XX must persist cert chain");
    assert_eq!(
        chain.leaf.key,
        server.server_static_pub(),
        "persisted leaf.key must match server static"
    );
}

/// Regression for the bug behind PR #598's unpaired-then-restart loop:
///
/// 1. Cold start with an UNPAIRED device → XX must succeed.
/// 2. After the handshake, `server_cert_chain` MUST stay `None`. If it
///    were persisted, the next reconnect would pick IK against an
///    unregistered identity, the server would close the channel, and the
///    transient classification would loop forever (see the original
///    `log.txt` symptom of "Will attempt to reconnect ... attempt N").
///
/// Mirrors `WAWebProcessCertificate.Certificate.js:35` (`if (a && ...)`).
#[tokio::test]
async fn unpaired_xx_does_not_persist_cert_chain() {
    let _ = env_logger::builder().is_test(true).try_init();

    let pm = pm().await; // Intentionally NOT paired_pm — that's the point.
    let counter = Arc::new(AtomicU32::new(0));
    let server = Arc::new(InProcessServer::new());

    let (transport, events_tx, mut events_rx) = new_transport_pair();
    let server_clone = server.clone();
    let server_t = transport.clone();
    let task = tokio::spawn(async move {
        xx_serve_full(&server_clone, &server_t, &events_tx).await;
    });

    let result = do_handshake(
        runtime(),
        pm.as_ref(),
        counter.as_ref(),
        transport.clone(),
        &mut events_rx,
    )
    .await;
    task.await.unwrap();

    assert!(
        result.is_ok(),
        "XX handshake on unpaired device should succeed: {:?}",
        result.err()
    );

    let device = pm.get_device_snapshot().await;
    assert!(
        !device.is_registered(),
        "precondition: device must still be unpaired"
    );
    assert!(
        device.server_cert_chain.is_none(),
        "unpaired device must NOT persist the cert chain — that would force \
         IK on the next connect and trigger the unpaired-IK reject loop"
    );
    assert_eq!(counter.load(std::sync::atomic::Ordering::Acquire), 0);
}

/// IK-reject responder: parses the IK ClientHello, then replies with an
/// XX-shaped ServerHello (carrying `static != null`) using the
/// XXfallback pattern. The client must:
///   1. detect `static != null` and fall back without sending another
///      ephemeral
///   2. process the response as XX (in XXfallback mode, reusing the
///      already-sent ephemeral)
///   3. send a ClientFinish carrying its own static + payload
///   4. ultimately persist the cert chain again (because XX-fallback DOES
///      bring back a fresh chain)
async fn ik_serve_force_fallback_then_consume_finish(
    server: &InProcessServer,
    transport: &Arc<CaptureTransport>,
    events_tx: &async_channel::Sender<TransportEvent>,
) {
    wait_for_send(transport, 1).await;
    let raw_hello = transport.sent.lock().unwrap()[0].to_vec();
    let client_hello_bytes = parse_first_client_frame(&raw_hello);

    let msg = wa::HandshakeMessage::decode(client_hello_bytes.as_slice()).unwrap();
    let client_eph_pub: [u8; 32] = msg
        .client_hello
        .unwrap()
        .ephemeral
        .unwrap()
        .try_into()
        .unwrap();

    // Build XXfallback responder state matching what the initiator will
    // construct after seeing `static != null`.
    let mut noise = NoiseHandshake::new(
        wacore_binary::consts::NOISE_PATTERN_XXFALLBACK,
        &WA_CONN_HEADER,
    )
    .unwrap();
    noise.authenticate(&client_eph_pub);

    let server_eph = KeyPair::generate(&mut rand::rng());
    let server_eph_pub: [u8; 32] = server_eph.public_key.public_key_bytes().try_into().unwrap();
    noise.authenticate(&server_eph_pub);
    noise
        .mix_shared_secret(server_eph.private_key.serialize(), &client_eph_pub)
        .unwrap();
    let encrypted_static = noise.encrypt(&server.server_static_pub()).unwrap();
    noise
        .mix_shared_secret(server.identity_kp.private_key.serialize(), &client_eph_pub)
        .unwrap();
    let encrypted_cert = noise.encrypt(&server.cert_chain_bytes).unwrap();

    let server_hello = wa::HandshakeMessage {
        server_hello: Some(wa::handshake_message::ServerHello {
            ephemeral: Some(server_eph_pub.to_vec()),
            r#static: Some(encrypted_static),
            payload: Some(encrypted_cert),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut sh_bytes = Vec::new();
    server_hello.encode(&mut sh_bytes).unwrap();
    let framed = wacore::framing::encode_frame(&sh_bytes, None).unwrap();
    events_tx
        .send(TransportEvent::DataReceived(framed.into()))
        .await
        .unwrap();

    // Wait for the client's XXfallback ClientFinish.
    wait_for_send(transport, 2).await;
}

#[tokio::test]
async fn ik_rejected_recovers_via_xxfallback_and_repopulates_cache() {
    let _ = env_logger::builder().is_test(true).try_init();

    let pm = paired_pm().await;
    let counter = Arc::new(AtomicU32::new(0));
    let server = Arc::new(InProcessServer::new());
    let server_static_pub_expected = server.server_static_pub();

    // Pre-seed the device with the *correct* cert chain (so IK is selected),
    // but the responder will still force fallback (mirrors the case where
    // the server has just rotated and the client's cache is one connect
    // out of date).
    use wacore::store::{CachedNoiseCert, CachedServerCertChain, DeviceCommand};
    pm.process_command(DeviceCommand::SetServerCertChain(CachedServerCertChain {
        intermediate: CachedNoiseCert {
            key: [0xCC; 32],
            not_before: 1_700_000_000,
            not_after: 1_900_000_000,
        },
        leaf: CachedNoiseCert {
            key: server_static_pub_expected,
            not_before: 1_700_000_500,
            not_after: 1_899_999_500,
        },
    }))
    .await;

    let (transport, events_tx, mut events_rx) = new_transport_pair();
    let server_clone = server.clone();
    let transport_clone = transport.clone();
    let task = tokio::spawn(async move {
        ik_serve_force_fallback_then_consume_finish(&server_clone, &transport_clone, &events_tx)
            .await;
    });

    let result = do_handshake(
        runtime(),
        pm.as_ref(),
        counter.as_ref(),
        transport.clone(),
        &mut events_rx,
    )
    .await;
    task.await.unwrap();

    assert!(
        result.is_ok(),
        "IK rejection must be recovered via XXfallback: {:?}",
        result.err()
    );

    // After XXfallback completion: counter zero, cache repopulated with
    // the fresh chain (same key here, but the orchestration MUST emit
    // SetServerCertChain regardless).
    assert_eq!(counter.load(std::sync::atomic::Ordering::Acquire), 0);
    let device = pm.get_device_snapshot().await;
    let chain = device.server_cert_chain.as_ref().expect("cert chain");
    assert_eq!(chain.leaf.key, server_static_pub_expected);
}

#[tokio::test]
async fn ik_with_stale_cache_invalidates_and_increments_counter() {
    let _ = env_logger::builder().is_test(true).try_init();

    let pm = paired_pm().await;
    let counter = Arc::new(AtomicU32::new(0));

    // Pre-seed the device with a STALE cert chain — the leaf.key is wrong
    // (random, not matching any real server static). The next connect
    // will pick IK based on this cache, the responder will fail to
    // process the resulting clientHello (because the server doesn't have
    // the matching private key), and we expect:
    //   - the handshake errors out crypto-fatally (or the responder side
    //     panics, which we catch and surface as a transient channel close
    //     event)
    //   - the orchestrator increments the counter and clears the cache.
    use wacore::store::{CachedNoiseCert, CachedServerCertChain, DeviceCommand};
    let stale_pub = [0xDE; 32];
    pm.process_command(DeviceCommand::SetServerCertChain(CachedServerCertChain {
        intermediate: CachedNoiseCert {
            key: [0xCC; 32],
            not_before: 1_700_000_000,
            not_after: 1_900_000_000,
        },
        leaf: CachedNoiseCert {
            key: stale_pub,
            not_before: 1_700_000_500,
            not_after: 1_899_999_500,
        },
    }))
    .await;

    let (transport, events_tx, mut events_rx) = new_transport_pair();

    // Stand up a real server with a DIFFERENT static keypair than the one
    // cached above. When the client sends an IK ClientHello using
    // stale_pub, the responder's `es` derivation diverges and decryption
    // of the client static fails → we surface that by closing the events
    // channel without sending a ServerHello, which the client interprets
    // as a Disconnected event (transient).
    //
    // To test the *crypto-fatal* path instead, we send a malformed
    // ServerHello so the client's read_server_hello errors out at
    // decrypt of the cert (Core handshake error → invalidation runs).
    let bogus_server_eph = KeyPair::generate(&mut rand::rng()).public_key;
    let bogus_server_eph_bytes: [u8; 32] = bogus_server_eph.public_key_bytes().try_into().unwrap();
    let server_hello = wa::HandshakeMessage {
        server_hello: Some(wa::handshake_message::ServerHello {
            ephemeral: Some(bogus_server_eph_bytes.to_vec()),
            r#static: None,
            // `payload` here is just garbage — AEAD MAC check will fail.
            payload: Some(vec![0xAB; 64]),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mut sh_bytes = Vec::new();
    server_hello.encode(&mut sh_bytes).unwrap();
    let framed = wacore::framing::encode_frame(&sh_bytes, None).unwrap();

    let transport_for_task = transport.clone();
    let driver = tokio::spawn(async move {
        wait_for_send(&transport_for_task, 1).await;
        events_tx
            .send(TransportEvent::DataReceived(framed.into()))
            .await
            .unwrap();
    });

    let result = do_handshake(
        runtime(),
        pm.as_ref(),
        counter.as_ref(),
        transport.clone(),
        &mut events_rx,
    )
    .await;

    driver.await.unwrap();

    assert!(result.is_err(), "IK with bogus server hello must fail");
    let err = result.err().unwrap();
    assert!(
        err.is_crypto_fatal(),
        "decrypt failure must be classified as crypto-fatal: {err:?}"
    );

    // Invalidation policy: counter incremented, cache cleared.
    assert_eq!(
        counter.load(std::sync::atomic::Ordering::Acquire),
        1,
        "ik_handshake_failures must be 1 after one crypto-fatal failure"
    );
    let device = pm.get_device_snapshot().await;
    assert!(
        device.server_cert_chain.is_none(),
        "stale cert chain must be cleared after crypto-fatal IK failure"
    );
}
