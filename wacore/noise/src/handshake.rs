use crate::error::NoiseError;
use crate::state::{NoiseCipher, NoiseState};
use prost::Message;
use thiserror::Error;
use wacore_libsignal::protocol::{KeyPair, PrivateKey, PublicKey};
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
    #[error("Noise protocol error: {0}")]
    Noise(#[from] NoiseError),
}

pub type Result<T> = std::result::Result<T, HandshakeError>;

/// Handshake utilities for WhatsApp protocol operations
pub struct HandshakeUtils;

impl HandshakeUtils {
    /// Creates a ClientHello message with the given ephemeral key
    pub fn build_client_hello(ephemeral_key: &[u8]) -> HandshakeMessage {
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

        // Unmarshal details and perform further checks
        let intermediate_details_bytes = intermediate.details.as_ref().ok_or_else(|| {
            HandshakeError::CertVerification("Missing intermediate details".into())
        })?;
        let intermediate_details =
            noise_certificate::Details::decode(intermediate_details_bytes.as_slice())?;

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
        if intermediate_pk_bytes.len() != 32 {
            return Err(HandshakeError::CertVerification(
                "Intermediate details key is not 32 bytes".into(),
            ));
        }

        let leaf_details_bytes = leaf
            .details
            .as_ref()
            .ok_or_else(|| HandshakeError::CertVerification("Missing leaf details".into()))?;
        let leaf_details = noise_certificate::Details::decode(leaf_details_bytes.as_slice())?;

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
                extended_ciphertext: None,
            }),
            ..Default::default()
        }
    }
}

/// A WhatsApp-specific Noise handshake wrapper that uses libsignal for DH operations.
///
/// This wraps the generic `NoiseState` and provides the `mix_shared_secret` method
/// that computes DH using libsignal's curve25519 implementation.
pub struct NoiseHandshake {
    inner: NoiseState,
}

impl NoiseHandshake {
    /// Returns the current hash state.
    pub fn hash(&self) -> &[u8; 32] {
        self.inner.hash()
    }

    /// Returns the current salt/chaining key.
    pub fn salt(&self) -> &[u8; 32] {
        self.inner.salt()
    }

    /// Creates a new Noise handshake with the given pattern and prologue.
    pub fn new(pattern: &str, header: &[u8]) -> Result<Self> {
        let inner = NoiseState::new(pattern.as_bytes(), header)?;
        Ok(Self { inner })
    }

    /// Mixes data into the hash state (MixHash operation).
    pub fn authenticate(&mut self, data: &[u8]) {
        self.inner.authenticate(data);
    }

    /// Encrypts plaintext, updates the hash state with the ciphertext.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.inner.encrypt(plaintext).map_err(Into::into)
    }

    /// Zero-allocation encryption that appends the ciphertext to the provided buffer.
    pub fn encrypt_into(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        self.inner.encrypt_into(plaintext, out).map_err(Into::into)
    }

    /// Decrypts ciphertext, updates the hash state.
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.inner.decrypt(ciphertext).map_err(Into::into)
    }

    /// Zero-allocation decryption that appends the plaintext to the provided buffer.
    pub fn decrypt_into(&mut self, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        self.inner.decrypt_into(ciphertext, out).map_err(Into::into)
    }

    /// Mixes key material into the cipher state (MixKey operation).
    ///
    /// This is the generic version that accepts pre-computed key material.
    pub fn mix_into_key(&mut self, data: &[u8]) -> Result<()> {
        self.inner.mix_key(data).map_err(Into::into)
    }

    /// Computes a DH shared secret using libsignal and mixes it into the cipher state.
    ///
    /// This is a convenience method for WhatsApp handshakes that uses libsignal's
    /// curve25519 implementation for key agreement.
    pub fn mix_shared_secret(&mut self, priv_key_bytes: &[u8], pub_key_bytes: &[u8]) -> Result<()> {
        let our_private_key = PrivateKey::deserialize(priv_key_bytes)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
        let their_public_key = PublicKey::from_djb_public_key_bytes(pub_key_bytes)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        let shared_secret = our_private_key
            .calculate_agreement(&their_public_key)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        self.mix_into_key(&shared_secret)
    }

    /// Extracts the final write and read keys from the Noise state.
    pub fn finish(self) -> Result<(NoiseCipher, NoiseCipher)> {
        let keys = self.inner.split()?;
        Ok((keys.write, keys.read))
    }
}

/// Full handshake state machine for WhatsApp Noise XX handshake.
///
/// This orchestrates the complete handshake flow including key generation,
/// message building, and cryptographic operations.
pub struct HandshakeState {
    noise: NoiseHandshake,
    ephemeral_kp: KeyPair,
    static_kp: KeyPair,
    payload: Vec<u8>,
}

impl HandshakeState {
    /// Creates a new handshake state with the given static key pair and client payload.
    ///
    /// # Arguments
    /// * `static_kp` - The device's static Noise key pair
    /// * `client_payload` - The encoded client payload bytes
    /// * `pattern` - The Noise pattern string (e.g., NOISE_START_PATTERN)
    /// * `prologue` - The prologue/header bytes (e.g., WA_CONN_HEADER)
    pub fn new(
        static_kp: KeyPair,
        client_payload: Vec<u8>,
        pattern: &str,
        prologue: &[u8],
    ) -> Result<Self> {
        use rand::TryRngCore;

        let ephemeral_kp = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let mut noise = NoiseHandshake::new(pattern, prologue)?;

        noise.authenticate(ephemeral_kp.public_key.public_key_bytes());

        Ok(Self {
            noise,
            ephemeral_kp,
            static_kp,
            payload: client_payload,
        })
    }

    pub fn build_client_hello(&self) -> Result<Vec<u8>> {
        let client_hello =
            HandshakeUtils::build_client_hello(self.ephemeral_kp.public_key.public_key_bytes());
        let mut buf = Vec::new();
        client_hello.encode(&mut buf)?;
        Ok(buf)
    }

    pub fn read_server_hello_and_build_client_finish(
        &mut self,
        response_bytes: &[u8],
    ) -> Result<Vec<u8>> {
        let (server_ephemeral_raw, server_static_ciphertext, certificate_ciphertext) =
            HandshakeUtils::parse_server_hello(response_bytes).map_err(|e| {
                HandshakeError::CertVerification(format!("Error parsing server hello: {e}"))
            })?;

        let server_ephemeral: [u8; 32] = server_ephemeral_raw
            .try_into()
            .map_err(|_| HandshakeError::InvalidKeyLength)?;

        self.noise.authenticate(&server_ephemeral);
        self.noise
            .mix_shared_secret(self.ephemeral_kp.private_key.serialize(), &server_ephemeral)?;

        let static_decrypted = self.noise.decrypt(&server_static_ciphertext)?;

        let static_decrypted_arr: [u8; 32] = static_decrypted
            .try_into()
            .map_err(|_| HandshakeError::InvalidKeyLength)?;

        self.noise.mix_shared_secret(
            self.ephemeral_kp.private_key.serialize(),
            &static_decrypted_arr,
        )?;

        let cert_decrypted = self.noise.decrypt(&certificate_ciphertext)?;

        HandshakeUtils::verify_server_cert(&cert_decrypted, &static_decrypted_arr).map_err(
            |e| HandshakeError::CertVerification(format!("Error verifying server cert: {e}")),
        )?;

        let encrypted_pubkey = self
            .noise
            .encrypt(self.static_kp.public_key.public_key_bytes())?;

        self.noise
            .mix_shared_secret(self.static_kp.private_key.serialize(), &server_ephemeral)?;

        let encrypted_payload = self.noise.encrypt(&self.payload)?;

        let client_finish =
            HandshakeUtils::build_client_finish(encrypted_pubkey, encrypted_payload);

        let mut buf = Vec::new();
        client_finish.encode(&mut buf)?;
        Ok(buf)
    }

    pub fn finish(self) -> Result<(NoiseCipher, NoiseCipher)> {
        self.noise.finish()
    }
}
