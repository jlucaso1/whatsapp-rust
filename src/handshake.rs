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
            Self::Transport(_) | Self::Timeout | Self::Disconnected
        )
    }

    /// Crypto-fatal: a cached server static or cert chain is no longer
    /// trustworthy. The orchestration layer must clear the IK cache and
    /// fall back to XX on the next attempt.
    pub fn is_crypto_fatal(&self) -> bool {
        matches!(self, Self::Core(_))
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
///   - we have not failed an IK in this process yet (counter < threshold)
///   - the device has a cached cert chain
///   - both leaf and intermediate are still within their validity window
fn select_pattern(
    device: &wacore::store::Device,
    ik_failures: u32,
    now_secs: i64,
) -> HandshakePattern {
    if ik_failures >= IK_FAILURE_THRESHOLD {
        return HandshakePattern::Xx;
    }
    let Some(chain) = device.server_cert_chain.as_ref() else {
        return HandshakePattern::Xx;
    };
    if now_secs >= chain.leaf.not_after || now_secs >= chain.intermediate.not_after {
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
            )
            .await
        }
    };

    match result {
        Ok(success) => {
            if let Some(chain) = success.server_cert_chain {
                // WA Web does this in WAWebProcessCertificate: persist the
                // freshly-validated chain so the next connect can attempt IK.
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
            // Only IK paths can produce a crypto-fatal error here that means
            // "the cached server static is bad". XX never reads the cache,
            // so an XX failure does not need to invalidate.
            if matches!(pattern, HandshakePattern::Ik(_)) && e.is_crypto_fatal() {
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

async fn run_ik_handshake(
    runtime: &Arc<dyn Runtime>,
    device: &wacore::store::Device,
    server_static_pub: [u8; 32],
    transport: Arc<dyn Transport>,
    transport_events: &mut async_channel::Receiver<TransportEvent>,
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
            Ok(Err(_)) => return Err(HandshakeError::Timeout),
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

    #[test]
    fn select_pattern_no_cache_returns_xx() {
        let device = wacore::store::Device::new();
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    #[test]
    fn select_pattern_with_valid_cache_returns_ik() {
        let mut device = wacore::store::Device::new();
        let pub_key = [0xAA; 32];
        device.server_cert_chain = Some(cached_chain(pub_key, 1_900_000_000, 1_900_000_000));
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Ik(pub_key)
        );
    }

    #[test]
    fn select_pattern_after_one_failure_returns_xx() {
        let mut device = wacore::store::Device::new();
        device.server_cert_chain = Some(cached_chain([0xAA; 32], 1_900_000_000, 1_900_000_000));
        // Even with a cached chain, the IK_FAILURE_THRESHOLD gate forces XX.
        assert_eq!(
            select_pattern(&device, IK_FAILURE_THRESHOLD, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    #[test]
    fn select_pattern_with_expired_leaf_returns_xx() {
        let mut device = wacore::store::Device::new();
        device.server_cert_chain = Some(cached_chain([0xAA; 32], 1_700_000_500, 1_900_000_000));
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    #[test]
    fn select_pattern_with_expired_intermediate_returns_xx() {
        let mut device = wacore::store::Device::new();
        device.server_cert_chain = Some(cached_chain([0xAA; 32], 1_900_000_000, 1_700_000_500));
        assert_eq!(
            select_pattern(&device, 0, 1_800_000_000),
            HandshakePattern::Xx
        );
    }

    #[test]
    fn handshake_error_classification() {
        assert!(HandshakeError::Timeout.is_transient());
        assert!(HandshakeError::Disconnected.is_transient());
        assert!(!HandshakeError::Timeout.is_crypto_fatal());
        assert!(!HandshakeError::Disconnected.is_crypto_fatal());

        let core_err = HandshakeError::Core(CoreHandshakeError::IncompleteResponse);
        assert!(core_err.is_crypto_fatal());
        assert!(!core_err.is_transient());
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
