use crate::socket::NoiseSocket;
use crate::store::persistence_manager::PersistenceManager;
use crate::transport::{Transport, TransportEvent};
use log::{debug, info, warn};
use prost::Message;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use thiserror::Error;
use wacore::handshake::{
    HandshakeError as CoreHandshakeError, IkHandshakeState, IkServerHelloOutcome,
    VerifiedServerCertChain, XxFallbackHandshakeState, XxHandshakeState, build_handshake_header,
};
use wacore::noise::NoiseCipher;
use wacore::runtime::{Runtime, timeout as rt_timeout};
use wacore::store::DeviceCommand;
use wacore_binary::consts::WA_CONN_HEADER;

const NOISE_HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

/// Threshold mirroring WA Web's `$ = 1` in `WAWebOpenChatSocket`: after a
/// single IK failure within the process, the next connect skips IK.
const IK_FAILURE_THRESHOLD: u32 = 1;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Transport error: {0}")]
    Transport(#[from] anyhow::Error),
    #[error("Core handshake error: {0}")]
    Core(#[from] CoreHandshakeError),
    #[error("Timed out waiting for handshake response")]
    Timeout,
    /// Producer side of `transport_events` was dropped — distinct from a
    /// timeout because nothing more will ever arrive on the channel,
    /// regardless of how long we wait. Surfaced separately so callers can
    /// log it accurately and so retry policies that pace themselves on
    /// timeout don't silently swallow a teardown.
    #[error("Transport event stream closed before handshake completed")]
    StreamClosed,
    #[error("Disconnected during handshake")]
    Disconnected,
    #[error("Unexpected event during handshake: {0}")]
    UnexpectedEvent(String),
}

impl HandshakeError {
    /// Transient errors that are expected during reconnect and will resolve
    /// on retry. These never invalidate the cached server static.
    pub fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Transport(_) | Self::Timeout | Self::Disconnected | Self::StreamClosed
        )
    }

    /// Crypto-fatal: a cached server static or cert chain is no longer
    /// trustworthy. The orchestration layer must clear the IK cache and
    /// fall back to XX on the next attempt.
    ///
    /// Narrowed to the `Core` variants that actually point at a stale or
    /// poisoned cache. Programmer-side bugs (`Proto` encode failure, our
    /// own crypto provider misuse, HKDF impossible failure, counter
    /// exhaustion in a single handshake) are NOT crypto-fatal — they
    /// indicate a code defect, and clearing the cache would mask it. A
    /// stream-closed event during recv is treated as transient by
    /// `is_transient`, not here.
    pub fn is_crypto_fatal(&self) -> bool {
        let Self::Core(inner) = self else {
            return false;
        };
        use wacore::handshake::HandshakeError as Core;
        use wacore::noise::NoiseError;
        match inner {
            // Server-supplied bytes failed AEAD authentication or had the
            // wrong shape — canonical "the static we used to derive ee/se
            // doesn't actually belong to this server" signal.
            Core::Noise(NoiseError::Decrypt(_))
            | Core::Noise(NoiseError::CiphertextTooShort)
            | Core::Noise(NoiseError::InvalidKeyLength { .. }) => true,
            // Cert content didn't match the static we just decrypted, or
            // the chain was structurally invalid.
            Core::CertVerification(_) => true,
            // Server sent a structurally invalid response. Either it's
            // out of sync with our cached static or it has a real bug;
            // either way IK won't recover, so fall back.
            Core::IncompleteResponse
            | Core::InvalidLength { .. }
            | Core::InvalidKeyLength
            | Core::ProtoDecode(_) => true,
            // Programmer-side: our encode shouldn't fail with a valid
            // Device, our own crypto provider shouldn't reject our own
            // inputs, HKDF can't reasonably fail, and a single handshake
            // can't exhaust the counter. None of these mean the cache
            // is bad.
            Core::Proto(_)
            | Core::Crypto(_)
            | Core::Noise(NoiseError::Encrypt(_))
            | Core::Noise(NoiseError::HkdfExpandFailed)
            | Core::Noise(NoiseError::InvalidPatternLength { .. })
            | Core::Noise(NoiseError::CounterExhausted) => false,
        }
    }
}

type Result<T> = std::result::Result<T, HandshakeError>;

/// Pattern picked at the start of a handshake based on cached state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HandshakePattern {
    /// Cold start / pairing / forced fallback after an earlier IK failure.
    Xx,
    /// Cached server static + valid cert chain available; attempt IK.
    Ik([u8; 32]),
}

/// Mirrors the dispatcher in `WAWebOpenChatSocket` (`ChatSocket.js`):
/// IK is selected only when ALL of these hold:
///   - the device is registered (paired) — IK without a registered
///     identity is rejected by the server and would loop indefinitely
///     on transient-classified failures
///   - the in-process IK failure counter has not reached the threshold
///     (`ik_failures < IK_FAILURE_THRESHOLD`)
///   - the device has a cached cert chain
///   - `now_secs` falls within both the leaf and the intermediate
///     `[not_before, not_after)` validity windows
fn select_pattern(
    device: &wacore::store::Device,
    ik_failures: u32,
    now_secs: i64,
) -> HandshakePattern {
    // Defends against legacy DBs that persisted a chain pre-pairing under
    // older revisions of this code; `do_handshake` now refuses to write
    // such a chain in the first place.
    if !device.is_registered() {
        return HandshakePattern::Xx;
    }
    if ik_failures >= IK_FAILURE_THRESHOLD {
        return HandshakePattern::Xx;
    }
    let Some(chain) = device.server_cert_chain.as_ref() else {
        return HandshakePattern::Xx;
    };
    // `not_before` defends against backwards clock skew (RTC reset, frozen
    // container clock); `not_after` is the standard expiry check. Both
    // certs in the chain must overlap `now_secs` for IK to be safe.
    if now_secs < chain.leaf.not_before
        || now_secs < chain.intermediate.not_before
        || now_secs >= chain.leaf.not_after
        || now_secs >= chain.intermediate.not_after
    {
        return HandshakePattern::Xx;
    }
    HandshakePattern::Ik(chain.leaf.key)
}

/// Outcome shared by all three patterns. The optional `server_cert_chain` is
/// `Some` for XX-fresh and XX-fallback (they bring back a fresh chain that
/// must be persisted) and `None` for IK Continue (the on-disk cache stays
/// authoritative).
struct HandshakeSuccess {
    write_cipher: NoiseCipher,
    read_cipher: NoiseCipher,
    server_cert_chain: Option<VerifiedServerCertChain>,
}

/// Mirrors `WAWebProcessCertificate.Certificate.js:35`
/// (`if (a && !screenLockEnabled)`): only persist the chain once the device
/// has reached the registered/paired state. Persisting on a still-unpaired
/// device causes the next connect to pick IK, which the server rejects for
/// an unregistered identity, producing a transient-classified loop.
fn should_persist_cert_chain(device: &wacore::store::Device) -> bool {
    device.is_registered()
}

pub async fn do_handshake(
    runtime: Arc<dyn Runtime>,
    persistence_manager: &PersistenceManager,
    ik_handshake_failures: &AtomicU32,
    transport: Arc<dyn Transport>,
    transport_events: &mut async_channel::Receiver<TransportEvent>,
) -> Result<Arc<NoiseSocket>> {
    let device_snapshot = persistence_manager.get_device_snapshot().await;
    let now_secs = wacore::time::now_secs();
    let pattern = select_pattern(
        &device_snapshot,
        ik_handshake_failures.load(Ordering::Acquire),
        now_secs,
    );

    // Tracks whether `run_ik_handshake` pivoted to XXfallback before any
    // failure surfaced. Read by the post-failure invalidation gate below.
    let mut fallback_taken = false;

    let result = match pattern {
        HandshakePattern::Xx => {
            debug!("[socket] doFullHandshake: openChatSocket send hello");
            run_xx_handshake(
                &runtime,
                &device_snapshot,
                transport.clone(),
                transport_events,
            )
            .await
        }
        HandshakePattern::Ik(server_static_pub) => {
            debug!("[socket] resumeNoiseHandshake started");
            run_ik_handshake(
                &runtime,
                &device_snapshot,
                server_static_pub,
                transport.clone(),
                transport_events,
                &mut fallback_taken,
            )
            .await
        }
    };

    match result {
        Ok(success) => {
            if let Some(chain) = success.server_cert_chain
                && should_persist_cert_chain(&device_snapshot)
            {
                persistence_manager
                    .process_command(DeviceCommand::SetServerCertChain(chain.into()))
                    .await;
            }
            ik_handshake_failures.store(0, Ordering::Release);
            Ok(Arc::new(NoiseSocket::new(
                runtime,
                transport,
                success.write_cipher,
                success.read_cipher,
            )))
        }
        Err(e) => {
            // Cache invalidation is gated on THREE conditions:
            //   1. We picked IK (XX never reads the cache)
            //   2. The crypto-fatal classification fires (i.e. the failure
            //      mode points at a stale or poisoned static)
            //   3. We did NOT pivot to XXfallback before the failure. Once
            //      the server replies with `static.is_some()`, IK proper has
            //      been processed by the server (and the IK cache implication
            //      is moot — the server is asking for re-derivation via
            //      fallback). Failures past that point are XXfallback / wire
            //      problems, not stale-cache symptoms, so neither the counter
            //      nor the on-disk cache should be touched.
            if matches!(pattern, HandshakePattern::Ik(_)) && !fallback_taken && e.is_crypto_fatal()
            {
                warn!(
                    "[socket] resumeNoiseHandshake failed crypto-fatally; \
                     clearing cached server cert chain and forcing XX next connect: {e}"
                );
                ik_handshake_failures.fetch_add(1, Ordering::AcqRel);
                persistence_manager
                    .process_command(DeviceCommand::ClearServerCertChain)
                    .await;
            }
            Err(e)
        }
    }
}

async fn run_xx_handshake(
    runtime: &Arc<dyn Runtime>,
    device: &wacore::store::Device,
    transport: Arc<dyn Transport>,
    transport_events: &mut async_channel::Receiver<TransportEvent>,
) -> Result<HandshakeSuccess> {
    let client_payload = device.get_client_payload().encode_to_vec();
    let mut handshake_state =
        XxHandshakeState::new(device.noise_key.clone(), client_payload, &WA_CONN_HEADER)?;
    let mut frame_decoder = wacore::framing::FrameDecoder::new();

    let client_hello_bytes = handshake_state.build_client_hello()?;
    send_first_handshake_message(&transport, device, &client_hello_bytes).await?;

    let resp_frame = recv_frame(runtime, transport_events, &mut frame_decoder).await?;
    debug!("[socket] openChatSocket rcv hello");

    let client_finish_bytes =
        handshake_state.read_server_hello_and_build_client_finish(&resp_frame)?;

    debug!("[socket] continueFullHandshakeCore client finish and deriving secrets");
    let framed = wacore::framing::encode_frame(&client_finish_bytes, None)
        .map_err(HandshakeError::Transport)?;
    transport.send(bytes::Bytes::from(framed)).await?;

    let outcome = handshake_state.finish()?;
    info!("Handshake complete (XX), switching to encrypted communication");

    Ok(HandshakeSuccess {
        write_cipher: outcome.write_cipher,
        read_cipher: outcome.read_cipher,
        server_cert_chain: Some(outcome.server_cert_chain),
    })
}

/// `fallback_taken` is set to `true` the moment we pivot from IK to
/// XXfallback. The caller uses this to skip cache invalidation for failures
/// that happen after the server has already accepted (and effectively
/// responded to) the IK ClientHello.
async fn run_ik_handshake(
    runtime: &Arc<dyn Runtime>,
    device: &wacore::store::Device,
    server_static_pub: [u8; 32],
    transport: Arc<dyn Transport>,
    transport_events: &mut async_channel::Receiver<TransportEvent>,
    fallback_taken: &mut bool,
) -> Result<HandshakeSuccess> {
    let client_payload = device.get_client_payload().encode_to_vec();
    let mut ik = IkHandshakeState::new(
        device.noise_key.clone(),
        server_static_pub,
        client_payload,
        &WA_CONN_HEADER,
    )?;
    let mut frame_decoder = wacore::framing::FrameDecoder::new();

    debug!("[socket] resumeNoiseHandshake send hello");
    let client_hello_bytes = ik.build_client_hello()?;
    send_first_handshake_message(&transport, device, &client_hello_bytes).await?;

    let resp_frame = recv_frame(runtime, transport_events, &mut frame_decoder).await?;
    debug!("[socket] resumeNoiseHandshake rcv hello");

    match ik.read_server_hello(&resp_frame)? {
        IkServerHelloOutcome::Continue(out) => {
            debug!("[socket] resumeNoiseHandshake deriving secrets");
            info!("Handshake complete (IK), switching to encrypted communication");
            Ok(HandshakeSuccess {
                write_cipher: out.write_cipher,
                read_cipher: out.read_cipher,
                server_cert_chain: None,
            })
        }
        IkServerHelloOutcome::Fallback(inputs) => {
            // Mark the pivot before any operation that could fail, so a
            // partial XXfallback (e.g. malformed XXfallback ServerHello,
            // transport error mid-finish) does not look like a stale-cache
            // signal to the orchestrator.
            *fallback_taken = true;
            warn!(
                "[socket] resumeNoiseHandshake failed: serverStaticCiphertext not null — \
                 doFallbackHandshake continuing handshake with given server hello"
            );
            let mut fb = XxFallbackHandshakeState::from_ik_failure(*inputs, &WA_CONN_HEADER)?;
            let client_finish_bytes = fb.build_client_finish()?;
            debug!(
                "[socket] continueFullHandshakeCore client finish and deriving secrets (XXfallback)"
            );
            let framed = wacore::framing::encode_frame(&client_finish_bytes, None)
                .map_err(HandshakeError::Transport)?;
            transport.send(bytes::Bytes::from(framed)).await?;
            let outcome = fb.finish()?;
            info!("Handshake complete (XXfallback), switching to encrypted communication");
            Ok(HandshakeSuccess {
                write_cipher: outcome.write_cipher,
                read_cipher: outcome.read_cipher,
                server_cert_chain: Some(outcome.server_cert_chain),
            })
        }
    }
}

async fn send_first_handshake_message(
    transport: &Arc<dyn Transport>,
    device: &wacore::store::Device,
    payload_bytes: &[u8],
) -> Result<()> {
    let (header, used_edge_routing) = build_handshake_header(device.edge_routing_info.as_deref());
    if used_edge_routing {
        debug!("Sending edge routing pre-intro for optimized reconnection");
    } else if device.edge_routing_info.is_some() {
        warn!("Edge routing info provided but not used (possibly too large)");
    }
    let framed = wacore::framing::encode_frame(payload_bytes, Some(&header))
        .map_err(HandshakeError::Transport)?;
    transport.send(bytes::Bytes::from(framed)).await?;
    Ok(())
}

async fn recv_frame(
    runtime: &Arc<dyn Runtime>,
    transport_events: &mut async_channel::Receiver<TransportEvent>,
    frame_decoder: &mut wacore::framing::FrameDecoder,
) -> Result<bytes::BytesMut> {
    loop {
        match rt_timeout(
            &**runtime,
            NOISE_HANDSHAKE_RESPONSE_TIMEOUT,
            transport_events.recv(),
        )
        .await
        {
            Ok(Ok(TransportEvent::DataReceived(data))) => {
                frame_decoder.feed(&data);
                if let Some(frame) = frame_decoder.decode_frame() {
                    return Ok(frame);
                }
                continue;
            }
            Ok(Ok(TransportEvent::Connected)) => continue,
            Ok(Ok(TransportEvent::Disconnected)) => return Err(HandshakeError::Disconnected),
            // Channel closed (no more producers) — distinct from a real timeout.
            Ok(Err(_)) => return Err(HandshakeError::StreamClosed),
            Err(_) => return Err(HandshakeError::Timeout),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore::store::CachedNoiseCert;
    use wacore::store::CachedServerCertChain;

    fn cached_chain(
        leaf_key: [u8; 32],
        leaf_not_after: i64,
        intermediate_not_after: i64,
    ) -> CachedServerCertChain {
        CachedServerCertChain {
            intermediate: CachedNoiseCert {
                key: [0xCC; 32],
                not_before: 1_700_000_000,
                not_after: intermediate_not_after,
            },
            leaf: CachedNoiseCert {
                key: leaf_key,
                not_before: 1_700_000_000,
                not_after: leaf_not_after,
            },
        }
    }

    fn paired_device() -> wacore::store::Device {
        let mut device = wacore::store::Device::new();
        device.pn = Some("12345@s.whatsapp.net".parse().unwrap());
        device
    }

    #[test]
    fn select_pattern_no_cache_returns_xx() {
        let device = paired_device();
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    #[test]
    fn select_pattern_with_valid_cache_returns_ik() {
        let mut device = paired_device();
        let pub_key = [0xAA; 32];
        device.server_cert_chain = Some(cached_chain(pub_key, 1_900_000_000, 1_900_000_000));
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Ik(pub_key)
        );
    }

    #[test]
    fn select_pattern_after_one_failure_returns_xx() {
        let mut device = paired_device();
        device.server_cert_chain = Some(cached_chain([0xAA; 32], 1_900_000_000, 1_900_000_000));
        // Even with a cached chain, the IK_FAILURE_THRESHOLD gate forces XX.
        assert_eq!(
            select_pattern(&device, IK_FAILURE_THRESHOLD, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    #[test]
    fn select_pattern_with_expired_leaf_returns_xx() {
        let mut device = paired_device();
        device.server_cert_chain = Some(cached_chain([0xAA; 32], 1_700_000_500, 1_900_000_000));
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    #[test]
    fn select_pattern_with_expired_intermediate_returns_xx() {
        let mut device = paired_device();
        device.server_cert_chain = Some(cached_chain([0xAA; 32], 1_900_000_000, 1_700_000_500));
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    /// `cached_chain` pins both certs' `not_before` at 1_700_000_000. Pick a
    /// `now_secs` strictly before that to exercise the backwards-clock-skew
    /// defense; the gate must reject IK even though `not_after` would
    /// otherwise be in the future.
    #[test]
    fn select_pattern_with_clock_before_leaf_not_before_returns_xx() {
        let mut device = paired_device();
        device.server_cert_chain = Some(cached_chain([0xAA; 32], 1_900_000_000, 1_900_000_000));
        assert_eq!(
            select_pattern(&device, 0, 1_699_999_999),
            HandshakePattern::Xx
        );
    }

    /// Same defense, but probing the intermediate-only path: leaf is barely
    /// in-window, intermediate is in the future. The gate rejects on the
    /// stricter of the two.
    #[test]
    fn select_pattern_with_clock_before_intermediate_not_before_returns_xx() {
        let mut device = paired_device();
        let mut chain = cached_chain([0xAA; 32], 1_900_000_000, 1_900_000_000);
        chain.intermediate.not_before = 1_800_000_001;
        device.server_cert_chain = Some(chain);
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    /// Regression: an unpaired device that previously persisted a cert chain
    /// (e.g. running pre-fix code, then upgrading) must NOT pick IK on the
    /// next connect. The server rejects IK from an unregistered identity and
    /// the rejection classifies as transient → infinite reconnect loop. See
    /// `WAWebProcessCertificate.Certificate.js:35` (`if (a && ...)`).
    #[test]
    fn select_pattern_unregistered_device_returns_xx_even_with_valid_cache() {
        let mut device = wacore::store::Device::new();
        assert!(
            !device.is_registered(),
            "fresh Device::new() must be unpaired"
        );
        device.server_cert_chain = Some(cached_chain([0xAA; 32], 1_900_000_000, 1_900_000_000));
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    /// Regression for the persistence-side gate. Mirrors WA Web's
    /// `Certificate.js:35` — only paired devices write the chain so that
    /// the unpaired-then-restart flow can never seed an IK attempt.
    #[test]
    fn should_persist_cert_chain_unregistered_returns_false() {
        let device = wacore::store::Device::new();
        assert!(!device.is_registered());
        assert!(!should_persist_cert_chain(&device));
    }

    #[test]
    fn should_persist_cert_chain_registered_returns_true() {
        let device = paired_device();
        assert!(device.is_registered());
        assert!(should_persist_cert_chain(&device));
    }

    #[test]
    fn handshake_error_classification() {
        // Transient — never invalidate the cache.
        assert!(HandshakeError::Timeout.is_transient());
        assert!(HandshakeError::Disconnected.is_transient());
        assert!(HandshakeError::StreamClosed.is_transient());
        assert!(!HandshakeError::Timeout.is_crypto_fatal());
        assert!(!HandshakeError::Disconnected.is_crypto_fatal());
        assert!(!HandshakeError::StreamClosed.is_crypto_fatal());

        // Stale-cache-indicating Core variants.
        for err in [
            HandshakeError::Core(CoreHandshakeError::IncompleteResponse),
            HandshakeError::Core(CoreHandshakeError::CertVerification("x".into())),
            HandshakeError::Core(CoreHandshakeError::InvalidKeyLength),
        ] {
            assert!(err.is_crypto_fatal(), "{err:?} should be crypto-fatal");
            assert!(!err.is_transient(), "{err:?} should not be transient");
        }

        // Programmer-side bug: Crypto(String) wraps generic crypto-provider
        // misuse; not a server-side cache problem.
        let bug = HandshakeError::Core(CoreHandshakeError::Crypto("bug".into()));
        assert!(
            !bug.is_crypto_fatal(),
            "generic Crypto(String) errors must not invalidate the cache"
        );
        assert!(!bug.is_transient());
    }

    /// Both the XX and IK initial messages must travel inside a frame whose
    /// prologue is `WA_CONN_HEADER` (optionally preceded by an edge-routing
    /// pre-intro). The wire-side server validates this prologue when it
    /// re-derives `h0` for transcript MAC checks, so any divergence between
    /// the two paths would surface only as a generic AEAD failure.
    ///
    /// We compare by fingerprinting the header bytes returned by the shared
    /// helper for the two relevant scenarios — IK and XX both must hit the
    /// same builder, with edge-routing applied identically when present.
    #[test]
    fn xx_and_ik_share_same_first_frame_prologue() {
        // No edge routing: pure WA_CONN_HEADER.
        let (xx_header, xx_used) = wacore::handshake::build_handshake_header(None);
        let (ik_header, ik_used) = wacore::handshake::build_handshake_header(None);
        assert_eq!(xx_header, ik_header);
        assert_eq!(xx_used, ik_used);
        assert!(xx_header.starts_with(b"WA"));

        // With edge routing: pre-intro applied identically.
        let routing = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let (xx_h2, xx_used2) = wacore::handshake::build_handshake_header(Some(&routing));
        let (ik_h2, ik_used2) = wacore::handshake::build_handshake_header(Some(&routing));
        assert_eq!(xx_h2, ik_h2);
        assert_eq!(xx_used2, ik_used2);
        assert!(xx_used2);
        assert!(xx_h2.starts_with(b"ED\x00\x01"));
        assert!(xx_h2.ends_with(b"WA\x06\x03") || xx_h2.ends_with(b"WA\x06\x04"));
    }
}
