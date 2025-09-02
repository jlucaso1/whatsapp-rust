use crate::socket::{FrameSocket, NoiseSocket};
use log::{debug, info};
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{Duration, timeout};
use wacore::handshake::{HandshakeState, utils::HandshakeError as CoreHandshakeError};

const NOISE_HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("WebSocket error: {0}")]
    Socket(#[from] crate::socket::error::SocketError),
    #[error("Core handshake error: {0}")]
    Core(#[from] CoreHandshakeError),
    #[error("Timed out waiting for handshake response")]
    Timeout,
}

type Result<T> = std::result::Result<T, HandshakeError>;

pub async fn do_handshake(
    device: &crate::store::Device,
    frame_socket: &mut FrameSocket,
    frames_rx: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>,
) -> Result<Arc<NoiseSocket>> {
    let mut handshake_state = HandshakeState::new(&device.core)?;

    debug!("--> Sending ClientHello");
    let client_hello_bytes = handshake_state.build_client_hello()?;
    let _ = frame_socket.send_frame_owned(client_hello_bytes).await?;

    let resp_frame = timeout(NOISE_HANDSHAKE_RESPONSE_TIMEOUT, frames_rx.recv())
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .ok_or(HandshakeError::Timeout)?;

    debug!("<-- Received handshake response, building ClientFinish");
    let client_finish_bytes =
        handshake_state.read_server_hello_and_build_client_finish(&resp_frame)?;

    debug!("--> Sending ClientFinish");
    let _ = frame_socket.send_frame_owned(client_finish_bytes).await?;

    let (write_key, read_key) = handshake_state.finish()?;
    info!(target: "Client", "Handshake complete, switching to encrypted communication");

    let frame_socket_arc = std::sync::Arc::new(tokio::sync::Mutex::new(std::mem::replace(
        frame_socket,
        FrameSocket::new().0,
    )));

    Ok(Arc::new(NoiseSocket::new(
        frame_socket_arc,
        write_key,
        read_key,
    )))
}
