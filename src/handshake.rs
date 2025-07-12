use crate::socket::{FrameSocket, NoiseHandshake, NoiseSocket, consts};
use log::{debug, info};
use prost::Message;
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{Duration, timeout};
use whatsapp_core::handshake::{HandshakeError as CoreHandshakeError, HandshakeUtils};

const NOISE_HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("WebSocket error: {0}")]
    Socket(#[from] crate::socket::error::SocketError),
    #[error("Core handshake error: {0}")]
    Core(#[from] CoreHandshakeError),
    #[error("Protobuf encoding error: {0}")]
    Proto(#[from] prost::EncodeError),
    #[error("Timed out waiting for handshake response")]
    Timeout,
}

type Result<T> = std::result::Result<T, HandshakeError>;

/// Performs the full Noise handshake and authentication with the server.
pub async fn do_handshake(
    device: &crate::store::Device,
    frame_socket: &mut FrameSocket,
    frames_rx: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>,
) -> Result<Arc<NoiseSocket>> {
    // 1. Initial setup and create ephemeral keys for this session
    let ephemeral_kp = whatsapp_core::crypto::key_pair::KeyPair::new();
    // Use the WhatsApp connection header constant
    let wa_header = &consts::WA_CONN_HEADER;

    let mut nh = NoiseHandshake::new(consts::NOISE_START_PATTERN, wa_header)
        .map_err(|e| HandshakeError::Core(CoreHandshakeError::Crypto(e.to_string())))?;

    // Mix our ephemeral public key into the handshake hash
    nh.authenticate(&ephemeral_kp.public_key);

    // 2. Send ClientHello using core utilities
    info!("--> Sending ClientHello");
    let client_hello = HandshakeUtils::build_client_hello(&ephemeral_kp.public_key);

    // [HANDSHAKE_DEBUG] Log ClientHello.ephemeral
    if let Some(ch) = &client_hello.client_hello {
        if let Some(eph) = &ch.ephemeral {
            debug!(
                "[HANDSHAKE_DEBUG] ClientHello.ephemeral: {}",
                hex::encode(eph)
            );
        }
    }

    let mut buf = Vec::new();
    client_hello.encode(&mut buf)?;
    debug!("--> Sending ClientHello payload ({} bytes)", buf.len());
    frame_socket.send_frame(&buf).await?;

    // 3. Receive and process ServerHello
    let resp_frame = timeout(NOISE_HANDSHAKE_RESPONSE_TIMEOUT, frames_rx.recv())
        .await
        .map_err(|_| HandshakeError::Timeout)?
        .ok_or(HandshakeError::Timeout)?;

    debug!(
        "<-- Received handshake response ({} bytes)",
        resp_frame.len(),
    );

    // 4. Parse ServerHello using core utilities
    let (server_ephemeral_raw, server_static_ciphertext, certificate_ciphertext) =
        HandshakeUtils::parse_server_hello(&resp_frame)?;

    let server_ephemeral: [u8; 32] = server_ephemeral_raw.try_into().unwrap();

    // 5. Noise protocol key mixing
    nh.authenticate(&server_ephemeral);
    nh.mix_shared_secret(&ephemeral_kp.private_key, &server_ephemeral)
        .map_err(|e| HandshakeError::Core(CoreHandshakeError::Crypto(e.to_string())))?;

    debug!(
        "Attempting to decrypt server static key ({} bytes)",
        server_static_ciphertext.len()
    );

    // 6. Decrypt server static key
    let static_decrypted = nh.decrypt(&server_static_ciphertext).map_err(|e| {
        HandshakeError::Core(CoreHandshakeError::Crypto(format!(
            "Failed to decrypt server static: {e}"
        )))
    })?;

    if static_decrypted.len() != 32 {
        return Err(HandshakeError::Core(CoreHandshakeError::InvalidLength {
            name: "decrypted server static key".into(),
            expected: 32,
            got: static_decrypted.len(),
        }));
    }
    let static_decrypted_arr: [u8; 32] = static_decrypted.try_into().unwrap();
    nh.mix_shared_secret(&ephemeral_kp.private_key, &static_decrypted_arr)
        .map_err(|e| HandshakeError::Core(CoreHandshakeError::Crypto(e.to_string())))?;

    debug!(
        "Attempting to decrypt server certificate ({} bytes)",
        certificate_ciphertext.len()
    );

    // 7. Decrypt and verify server certificate
    let cert_decrypted = nh.decrypt(&certificate_ciphertext).map_err(|e| {
        HandshakeError::Core(CoreHandshakeError::Crypto(format!(
            "Failed to decrypt certificate: {e}"
        )))
    })?;

    debug!("Successfully decrypted certificate, verifying...");
    HandshakeUtils::verify_server_cert(&cert_decrypted, &static_decrypted_arr)?;
    info!("Server certificate verified successfully");

    // 8. Send ClientFinish using core utilities
    let encrypted_pubkey = nh
        .encrypt(&device.noise_key.public_key)
        .map_err(|e| HandshakeError::Core(CoreHandshakeError::Crypto(e.to_string())))?;
    nh.mix_shared_secret(&device.noise_key.private_key, &server_ephemeral)
        .map_err(|e| HandshakeError::Core(CoreHandshakeError::Crypto(e.to_string())))?;

    let client_finish_payload_bytes = HandshakeUtils::prepare_client_payload(&device.core);
    // [HANDSHAKE_DEBUG] Log ClientFinish.payload (unencrypted)
    debug!(
        "[HANDSHAKE_DEBUG] ClientFinish.payload (unencrypted): {}",
        hex::encode(&client_finish_payload_bytes)
    );

    let encrypted_client_finish_payload = nh
        .encrypt(&client_finish_payload_bytes)
        .map_err(|e| HandshakeError::Core(CoreHandshakeError::Crypto(e.to_string())))?;

    let client_finish = HandshakeUtils::build_client_finish(
        &device.core,
        encrypted_pubkey,
        encrypted_client_finish_payload,
    );

    let mut buf = Vec::new();
    client_finish.encode(&mut buf)?;
    debug!("--> Sending ClientFinish payload ({} bytes)", buf.len());

    // Wrap frame_socket in Arc<Mutex<>> for NoiseSocket
    let frame_socket_arc = std::sync::Arc::new(tokio::sync::Mutex::new(std::mem::replace(
        frame_socket,
        FrameSocket::new().0,
    )));
    frame_socket_arc.lock().await.send_frame(&buf).await?;

    // 9. Finalize handshake and return the encrypted NoiseSocket
    let noise_socket = Arc::new(
        nh.finish(frame_socket_arc)
            .map_err(|e| HandshakeError::Core(CoreHandshakeError::Crypto(e.to_string())))?,
    );

    info!(target: "Client", "Handshake complete, switching to encrypted communication");
    Ok(noise_socket)
}
