use crate::crypto::key_pair::KeyPair;
use crate::socket::{FrameSocket, NoiseHandshake, NoiseSocket, consts};
use crate::store::WA_CERT_PUB_KEY;
use curve25519_dalek::montgomery::MontgomeryPoint;
use ed25519_dalek::Verifier;
use ed25519_dalek::{Signature, VerifyingKey};
use log::{debug, info};
use prost::Message;
use std::sync::Arc;
use thiserror::Error;
use tokio::time::{Duration, timeout};
use whatsapp_proto::whatsapp::cert_chain::noise_certificate;
use whatsapp_proto::whatsapp::{self as wa, CertChain, HandshakeMessage};

const NOISE_HANDSHAKE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(20);
const WA_CERT_ISSUER_SERIAL: i64 = 0;

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("WebSocket error: {0}")]
    Socket(#[from] crate::socket::error::SocketError),
    #[error("Protobuf encoding/decoding error: {0}")]
    Proto(#[from] prost::EncodeError),
    #[error("Protobuf decoding error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
    #[error("Timed out waiting for handshake response")]
    Timeout,
    #[error("Handshake response is missing required parts")]
    IncompleteResponse,
    #[error("Crypto operation failed: {0}")]
    Crypto(String),
    #[error("Server certificate verification failed: {0}")]
    CertVerification(String),
    #[error("Unexpected data length: expected {expected}, got {got} for {name}")]
    InvalidLength {
        name: String,
        expected: usize,
        got: usize,
    },
}

type Result<T> = std::result::Result<T, HandshakeError>;

/// Performs the full Noise handshake and authentication with the server.
pub async fn do_handshake(
    device: &crate::store::Device, // Changed to pass Device directly
    frame_socket: &mut FrameSocket,
    frames_rx: &mut tokio::sync::mpsc::Receiver<bytes::Bytes>,
) -> Result<Arc<NoiseSocket>> {
    // 1. Initial setup and create ephemeral keys for this session
    let ephemeral_kp = KeyPair::new();
    // Use the WhatsApp connection header constant
    let wa_header = &consts::WA_CONN_HEADER;

    let mut nh = NoiseHandshake::new(consts::NOISE_START_PATTERN, wa_header)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

    // Mix our ephemeral public key into the handshake hash
    nh.authenticate(&ephemeral_kp.public_key);
    // Debug: Hash after client ephemeral authentication

    // 2. Send ClientHello
    info!("--> Sending ClientHello");
    let client_hello = HandshakeMessage {
        client_hello: Some(wa::handshake_message::ClientHello {
            ephemeral: Some(ephemeral_kp.public_key.to_vec()),
            ..Default::default()
        }),
        ..Default::default()
    };

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

    // Use the device directly for client payload
    debug!(
        "<-- Received handshake response ({} bytes)",
        resp_frame.len(),
    );

    let handshake_response = HandshakeMessage::decode(resp_frame.as_ref())?;
    let server_hello = handshake_response
        .server_hello
        .ok_or(HandshakeError::IncompleteResponse)?;

    let server_ephemeral_raw = server_hello
        .ephemeral
        .ok_or(HandshakeError::IncompleteResponse)?;
    let server_static_ciphertext = server_hello
        .r#static
        .ok_or(HandshakeError::IncompleteResponse)?;
    let certificate_ciphertext = server_hello
        .payload
        .ok_or(HandshakeError::IncompleteResponse)?;

    if server_ephemeral_raw.len() != 32 {
        return Err(HandshakeError::InvalidLength {
            name: "server ephemeral key".into(),
            expected: 32,
            got: server_ephemeral_raw.len(),
        });
    }
    let server_ephemeral: [u8; 32] = server_ephemeral_raw.try_into().unwrap();

    // 4. Noise protocol key mixing
    nh.authenticate(&server_ephemeral);
    nh.mix_shared_secret(&ephemeral_kp.private_key, &server_ephemeral)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

    debug!(
        "Attempting to decrypt server static key ({} bytes)",
        server_static_ciphertext.len()
    );

    // 5. Decrypt server static key
    let static_decrypted = nh
        .decrypt(&server_static_ciphertext)
        .map_err(|e| HandshakeError::Crypto(format!("Failed to decrypt server static: {e}")))?;

    if static_decrypted.len() != 32 {
        return Err(HandshakeError::InvalidLength {
            name: "decrypted server static key".into(),
            expected: 32,
            got: static_decrypted.len(),
        });
    }
    let static_decrypted_arr: [u8; 32] = static_decrypted.try_into().unwrap();
    nh.mix_shared_secret(&ephemeral_kp.private_key, &static_decrypted_arr)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

    debug!(
        "Attempting to decrypt server certificate ({} bytes)",
        certificate_ciphertext.len()
    );

    // 6. Decrypt and verify server certificate
    let cert_decrypted = nh
        .decrypt(&certificate_ciphertext)
        .map_err(|e| HandshakeError::Crypto(format!("Failed to decrypt certificate: {e}")))?;

    debug!("Successfully decrypted certificate, verifying...");
    verify_server_cert(&cert_decrypted, &static_decrypted_arr)?;
    info!("Server certificate verified successfully");

    // 7. Send ClientFinish
    // let store_guard = store.read().await; // Removed
    let encrypted_pubkey = nh
        .encrypt(&device.noise_key.public_key) // Use device directly
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
    nh.mix_shared_secret(&device.noise_key.private_key, &server_ephemeral) // Use device directly
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

    let client_payload = device.get_client_payload(); // Use device directly
    let client_finish_payload_bytes = client_payload.encode_to_vec();
    // [HANDSHAKE_DEBUG] Log ClientFinish.payload (unencrypted)
    debug!(
        "[HANDSHAKE_DEBUG] ClientFinish.payload (unencrypted): {}",
        hex::encode(&client_finish_payload_bytes)
    );

    let encrypted_client_finish_payload = nh
        .encrypt(&client_finish_payload_bytes)
        .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

    let client_finish = HandshakeMessage {
        client_finish: Some(wa::handshake_message::ClientFinish {
            r#static: Some(encrypted_pubkey),
            payload: Some(encrypted_client_finish_payload),
        }),
        ..Default::default()
    };

    let mut buf = Vec::new();
    client_finish.encode(&mut buf)?;
    debug!("--> Sending ClientFinish payload ({} bytes)", buf.len());

    // Wrap frame_socket in Arc<Mutex<>> for NoiseSocket
    let frame_socket_arc = std::sync::Arc::new(tokio::sync::Mutex::new(std::mem::replace(
        frame_socket,
        FrameSocket::new().0,
    )));
    frame_socket_arc.lock().await.send_frame(&buf).await?;

    // 8. Finalize handshake and return the encrypted NoiseSocket
    let noise_socket = Arc::new(
        nh.finish(frame_socket_arc)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?,
    );

    info!(target: "Client", "Handshake complete, switching to encrypted communication");
    Ok(noise_socket)
}

/// Verifies the server's certificate chain.
fn verify_server_cert(cert_decrypted: &[u8], static_decrypted: &[u8; 32]) -> Result<()> {
    let cert_chain = CertChain::decode(cert_decrypted)?;

    let intermediate = cert_chain
        .intermediate
        .ok_or_else(|| HandshakeError::CertVerification("Missing intermediate cert".into()))?;
    let leaf = cert_chain
        .leaf
        .ok_or_else(|| HandshakeError::CertVerification("Missing leaf cert".into()))?;

    // Convert WA_CERT_PUB_KEY from Montgomery (Curve25519) to Edwards (Ed25519)
    let montgomery_point = MontgomeryPoint(WA_CERT_PUB_KEY);
    let edwards_point = montgomery_point.to_edwards(0).ok_or_else(|| {
        HandshakeError::CertVerification(
            "Failed to convert WA root key from Montgomery to Edwards".into(),
        )
    })?;
    let wa_root_pk = VerifyingKey::from(edwards_point);
    let intermediate_sig = Signature::from_slice(
        intermediate
            .signature
            .as_ref()
            .ok_or_else(|| HandshakeError::CertVerification("Missing intermediate sig".into()))?,
    )
    .map_err(|e| HandshakeError::CertVerification(format!("Invalid intermediate sig: {e}")))?;

    wa_root_pk
        .verify(
            intermediate.details.as_ref().ok_or_else(|| {
                HandshakeError::CertVerification("Missing intermediate details".into())
            })?,
            &intermediate_sig,
        )
        .map_err(|e| {
            HandshakeError::CertVerification(format!("Intermediate cert verification failed: {e}"))
        })?;

    // Unmarshal details and perform further checks
    let intermediate_details =
        noise_certificate::Details::decode(intermediate.details.as_ref().unwrap().as_slice())?;

    if i64::from(intermediate_details.issuer_serial()) != WA_CERT_ISSUER_SERIAL {
        return Err(HandshakeError::CertVerification(format!(
            "Unexpected intermediate issuer serial: got {}, expected {}",
            intermediate_details.issuer_serial(),
            WA_CERT_ISSUER_SERIAL
        )));
    }

    let intermediate_pk_bytes = intermediate_details.key();
    if intermediate_pk_bytes.is_empty() {
        return Err(HandshakeError::CertVerification(
            "Intermediate details missing key".into(),
        ));
    }
    // Convert intermediate public key from Montgomery (Curve25519) to Edwards (Ed25519)
    if intermediate_pk_bytes.len() != 32 {
        return Err(HandshakeError::CertVerification(
            "Intermediate details key is not 32 bytes".into(),
        ));
    }
    let intermediate_montgomery = MontgomeryPoint(intermediate_pk_bytes.try_into().unwrap());
    let intermediate_edwards = intermediate_montgomery.to_edwards(0).ok_or_else(|| {
        HandshakeError::CertVerification(
            "Failed to convert intermediate key from Montgomery to Edwards".into(),
        )
    })?;
    let intermediate_pk = VerifyingKey::from(intermediate_edwards);

    // Verify leaf cert against the intermediate cert's public key
    let leaf_sig = Signature::from_slice(
        leaf.signature
            .as_ref()
            .ok_or_else(|| HandshakeError::CertVerification("Missing leaf sig".into()))?,
    )
    .map_err(|e| HandshakeError::CertVerification(format!("Invalid leaf sig: {e}")))?;

    intermediate_pk
        .verify(
            leaf.details
                .as_ref()
                .ok_or_else(|| HandshakeError::CertVerification("Missing leaf details".into()))?,
            &leaf_sig,
        )
        .map_err(|e| {
            HandshakeError::CertVerification(format!("Leaf cert verification failed: {e}"))
        })?;

    let leaf_details =
        noise_certificate::Details::decode(leaf.details.as_ref().unwrap().as_slice())?;

    if leaf_details.issuer_serial() != intermediate_details.serial() {
        return Err(HandshakeError::CertVerification(format!(
            "Leaf issuer serial mismatch: got {}, expected {}",
            leaf_details.issuer_serial(),
            intermediate_details.serial()
        )));
    }

    // Finally, check if the leaf cert's key matches the server's static key
    if leaf_details.key() != static_decrypted {
        return Err(HandshakeError::CertVerification(
            "Cert key does not match decrypted static key".into(),
        ));
    }

    Ok(())
}
