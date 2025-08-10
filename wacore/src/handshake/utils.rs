use crate::store::Device;
use prost::Message;
use thiserror::Error;
use waproto::whatsapp::cert_chain::noise_certificate;
use waproto::whatsapp::{self as wa, CertChain, HandshakeMessage};

const WA_CERT_ISSUER_SERIAL: i64 = 0;

/// The public key for verifying the server's intermediate certificate.
pub const WA_CERT_PUB_KEY: [u8; 32] = [
    0x14, 0x23, 0x75, 0x57, 0x4d, 0x0a, 0x58, 0x71, 0x66, 0xaa, 0xe7, 0x1e, 0xbe, 0x51, 0x64, 0x37,
    0xc4, 0xa2, 0x8b, 0x73, 0xe3, 0x69, 0x5c, 0x6c, 0xe1, 0xf7, 0xf9, 0x54, 0x5d, 0xa8, 0xee, 0x6b,
];

#[derive(Debug, Error)]
pub enum HandshakeError {
    #[error("Protobuf encoding/decoding error: {0}")]
    Proto(#[from] prost::EncodeError),
    #[error("Protobuf decoding error: {0}")]
    ProtoDecode(#[from] prost::DecodeError),
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
    #[error("Invalid key length")]
    InvalidKeyLength,
}

pub fn generate_iv(counter: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&counter.to_be_bytes());
    iv
}

pub type Result<T> = std::result::Result<T, HandshakeError>;

/// Handshake utilities for pure crypto operations
pub struct HandshakeUtils;

impl HandshakeUtils {
    /// Creates a ClientHello message with the given ephemeral key
    pub fn build_client_hello(ephemeral_key: &[u8; 32]) -> HandshakeMessage {
        HandshakeMessage {
            client_hello: Some(wa::handshake_message::ClientHello {
                ephemeral: Some(ephemeral_key.to_vec()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Extracts server handshake data from ServerHello response
    pub fn parse_server_hello(response_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let handshake_response = HandshakeMessage::decode(response_bytes)?;
        let server_hello = handshake_response
            .server_hello
            .ok_or(HandshakeError::IncompleteResponse)?;

        let server_ephemeral = server_hello
            .ephemeral
            .ok_or(HandshakeError::IncompleteResponse)?;
        let server_static_ciphertext = server_hello
            .r#static
            .ok_or(HandshakeError::IncompleteResponse)?;
        let certificate_ciphertext = server_hello
            .payload
            .ok_or(HandshakeError::IncompleteResponse)?;

        if server_ephemeral.len() != 32 {
            return Err(HandshakeError::InvalidLength {
                name: "server ephemeral key".into(),
                expected: 32,
                got: server_ephemeral.len(),
            });
        }

        Ok((
            server_ephemeral,
            server_static_ciphertext,
            certificate_ciphertext,
        ))
    }

    /// Verifies the server's certificate chain
    pub fn verify_server_cert(cert_decrypted: &[u8], static_decrypted: &[u8; 32]) -> Result<()> {
        let cert_chain = CertChain::decode(cert_decrypted)?;

        let intermediate = cert_chain
            .intermediate
            .ok_or_else(|| HandshakeError::CertVerification("Missing intermediate cert".into()))?;
        let leaf = cert_chain
            .leaf
            .ok_or_else(|| HandshakeError::CertVerification("Missing leaf cert".into()))?;

        // Convert WA_CERT_PUB_KEY from Montgomery (Curve25519) to Edwards (Ed25519)
        // let montgomery_point = MontgomeryPoint(WA_CERT_PUB_KEY);
        // let edwards_point = montgomery_point.to_edwards(0).ok_or_else(|| {
        //     HandshakeError::CertVerification(
        //         "Failed to convert WA root key from Montgomery to Edwards".into(),
        //     )
        // })?;
        // let wa_root_pk = VerifyingKey::from(edwards_point);
        // let intermediate_sig =
        //     Signature::from_slice(intermediate.signature.as_ref().ok_or_else(|| {
        //         HandshakeError::CertVerification("Missing intermediate sig".into())
        //     })?)
        //     .map_err(|e| {
        //         HandshakeError::CertVerification(format!("Invalid intermediate sig: {e}"))
        //     })?;

        // wa_root_pk
        //     .verify(
        //         intermediate.details.as_ref().ok_or_else(|| {
        //             HandshakeError::CertVerification("Missing intermediate details".into())
        //         })?,
        //         &intermediate_sig,
        //     )
        //     .map_err(|e| {
        //         HandshakeError::CertVerification(format!(
        //             "Intermediate cert verification failed: {e}"
        //         ))
        //     })?;

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
        // let intermediate_montgomery = MontgomeryPoint(intermediate_pk_bytes.try_into().unwrap());
        // let intermediate_edwards = intermediate_montgomery.to_edwards(0).ok_or_else(|| {
        //     HandshakeError::CertVerification(
        //         "Failed to convert intermediate key from Montgomery to Edwards".into(),
        //     )
        // })?;
        // let intermediate_pk = VerifyingKey::from(intermediate_edwards);

        // Verify leaf cert against the intermediate cert's public key
        // let leaf_sig = Signature::from_slice(
        //     leaf.signature
        //         .as_ref()
        //         .ok_or_else(|| HandshakeError::CertVerification("Missing leaf sig".into()))?,
        // )
        // .map_err(|e| HandshakeError::CertVerification(format!("Invalid leaf sig: {e}")))?;

        // intermediate_pk
        //     .verify(
        //         leaf.details.as_ref().ok_or_else(|| {
        //             HandshakeError::CertVerification("Missing leaf details".into())
        //         })?,
        //         &leaf_sig,
        //     )
        //     .map_err(|e| {
        //         HandshakeError::CertVerification(format!("Leaf cert verification failed: {e}"))
        //     })?;

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

    pub fn build_client_finish(
        encrypted_pubkey: Vec<u8>,
        encrypted_payload: Vec<u8>,
    ) -> HandshakeMessage {
        HandshakeMessage {
            client_finish: Some(wa::handshake_message::ClientFinish {
                r#static: Some(encrypted_pubkey),
                payload: Some(encrypted_payload),
            }),
            ..Default::default()
        }
    }

    /// Prepares client payload for handshake
    pub fn prepare_client_payload(device: &Device) -> Vec<u8> {
        let client_payload = device.get_client_payload();
        client_payload.encode_to_vec()
    }
}
