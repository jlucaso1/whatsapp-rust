use crate::socket::NoiseSocket;
use crate::transport::{Transport, TransportEvent};
use log::{debug, info, warn};
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{Duration, timeout};
use wacore::handshake::{
    EdgeRoutingError, HandshakeState, MAX_EDGE_ROUTING_LEN, build_edge_routing_preintro,
    utils::HandshakeError as CoreHandshakeError,
};

const NOISE_HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Transport error: {0}")]
    Transport(#[from] anyhow::Error),
    #[error("Core handshake error: {0}")]
    Core(#[from] CoreHandshakeError),
    #[error("Timed out waiting for handshake response")]
    Timeout,
    #[error("Unexpected event during handshake: {0}")]
    UnexpectedEvent(String),
    #[error("Edge routing error: {0}")]
    EdgeRouting(#[from] EdgeRoutingError),
}

type Result<T> = std::result::Result<T, HandshakeError>;

pub async fn do_handshake(
    device: &crate::store::Device,
    transport: Arc<dyn Transport>,
    transport_events: &mut tokio::sync::mpsc::Receiver<TransportEvent>,
) -> Result<Arc<NoiseSocket>> {
    let mut handshake_state = HandshakeState::new(&device.core)?;
    let mut frame_decoder = wacore::framing::FrameDecoder::new();

    debug!("--> Sending ClientHello");
    let client_hello_bytes = handshake_state.build_client_hello()?;

    // Build the connection header, optionally with edge routing pre-intro
    let header: Vec<u8> = if let Some(ref routing_info) = device.core.edge_routing_info {
        if routing_info.len() > MAX_EDGE_ROUTING_LEN {
            warn!(
                target: "Client",
                "Edge routing info ({} bytes) exceeds the {}-byte limit; falling back to WA_CONN_HEADER",
                routing_info.len(),
                MAX_EDGE_ROUTING_LEN
            );
            wacore_binary::consts::WA_CONN_HEADER.to_vec()
        } else {
            match build_edge_routing_preintro(routing_info) {
                Ok(mut header) => {
                    debug!(
                        target: "Client",
                        "Sending edge routing pre-intro ({} bytes) for optimized reconnection",
                        routing_info.len()
                    );
                    header.extend_from_slice(&wacore_binary::consts::WA_CONN_HEADER);
                    header
                }
                Err(EdgeRoutingError::RoutingInfoTooLarge) => {
                    warn!(
                        target: "Client",
                        "Routing info unexpectedly exceeds {} bytes; skipping pre-intro",
                        MAX_EDGE_ROUTING_LEN
                    );
                    wacore_binary::consts::WA_CONN_HEADER.to_vec()
                }
            }
        }
    } else {
        wacore_binary::consts::WA_CONN_HEADER.to_vec()
    };

    // First message includes the WA connection header (with optional edge routing)
    let framed = wacore::framing::encode_frame(&client_hello_bytes, Some(&header))
        .map_err(HandshakeError::Transport)?;
    transport.send(&framed).await?;

    // Wait for server response frame
    let resp_frame = loop {
        match timeout(NOISE_HANDSHAKE_RESPONSE_TIMEOUT, transport_events.recv()).await {
            Ok(Some(TransportEvent::DataReceived(data))) => {
                // Feed data into decoder
                frame_decoder.feed(&data);

                // Try to decode a frame
                if let Some(frame) = frame_decoder.decode_frame() {
                    break frame;
                }
                // If no complete frame yet, continue waiting for more data
                continue;
            }
            Ok(Some(TransportEvent::Connected)) => {
                // Ignore Connected event, we're already connected
                continue;
            }
            Ok(Some(TransportEvent::Disconnected)) => {
                return Err(HandshakeError::UnexpectedEvent(
                    "Disconnected during handshake".to_string(),
                ));
            }
            Ok(None) => return Err(HandshakeError::Timeout),
            Err(_) => return Err(HandshakeError::Timeout),
        }
    };

    debug!("<-- Received handshake response, building ClientFinish");
    let client_finish_bytes =
        handshake_state.read_server_hello_and_build_client_finish(&resp_frame)?;

    debug!("--> Sending ClientFinish");
    // Subsequent messages don't need the header
    let framed = wacore::framing::encode_frame(&client_finish_bytes, None)
        .map_err(HandshakeError::Transport)?;
    transport.send(&framed).await?;

    let (write_key, read_key) = handshake_state.finish()?;
    info!(target: "Client", "Handshake complete, switching to encrypted communication");

    Ok(Arc::new(NoiseSocket::new(transport, write_key, read_key)))
}
