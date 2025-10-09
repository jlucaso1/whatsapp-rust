use crate::socket::NoiseSocket;
use crate::transport::{Transport, TransportEvent};
use log::{debug, info};
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{Duration, timeout};
use wacore::handshake::{HandshakeState, utils::HandshakeError as CoreHandshakeError};

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
}

type Result<T> = std::result::Result<T, HandshakeError>;

pub async fn do_handshake(
    device: &crate::store::Device,
    transport: Arc<dyn Transport>,
    transport_events: &mut tokio::sync::mpsc::Receiver<TransportEvent>,
) -> Result<Arc<NoiseSocket>> {
    let mut handshake_state = HandshakeState::new(&device.core)?;
    let mut frame_decoder = crate::framing::FrameDecoder::new();

    debug!("--> Sending ClientHello");
    let client_hello_bytes = handshake_state.build_client_hello()?;

    // First message includes the WA connection header
    let header = wacore_binary::consts::WA_CONN_HEADER;
    let framed = crate::framing::encode_frame(&client_hello_bytes, Some(&header))
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
    let framed = crate::framing::encode_frame(&client_finish_bytes, None)
        .map_err(HandshakeError::Transport)?;
    transport.send(&framed).await?;

    let (write_key, read_key) = handshake_state.finish()?;
    info!(target: "Client", "Handshake complete, switching to encrypted communication");

    Ok(Arc::new(NoiseSocket::new(transport, write_key, read_key)))
}
