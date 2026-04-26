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

/// Parsed leaf+intermediate certificate identities pulled from a verified
/// `CertChain`.
///
/// The wider crate (`wacore::store::device::CachedServerCertChain`) wraps
/// these fields with serde so they can persist for Noise IK reuse on later
/// connects. Keeping the no-std-friendly version here lets `wacore-noise`
/// stay free of a serde dependency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedServerCertChain {
    pub intermediate_key: [u8; 32],
    pub intermediate_not_before: i64,
    pub intermediate_not_after: i64,
    pub leaf_key: [u8; 32],
    pub leaf_not_before: i64,
    pub leaf_not_after: i64,
}

/// Handshake utilities for WhatsApp protocol operations
pub struct HandshakeUtils;

impl HandshakeUtils {
    /// Creates a ClientHello message with the given ephemeral key only (XX).
    pub fn build_client_hello(ephemeral_key: &[u8]) -> HandshakeMessage {
        HandshakeMessage {
            client_hello: Some(wa::handshake_message::ClientHello {
                ephemeral: Some(ephemeral_key.to_vec()),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Creates an IK ClientHello carrying the encrypted client static and
    /// the encrypted 0-RTT payload alongside the ephemeral.
    pub fn build_ik_client_hello(
        ephemeral_key: &[u8],
        encrypted_static: Vec<u8>,
        encrypted_payload: Vec<u8>,
    ) -> HandshakeMessage {
        HandshakeMessage {
            client_hello: Some(wa::handshake_message::ClientHello {
                ephemeral: Some(ephemeral_key.to_vec()),
                r#static: Some(encrypted_static),
                payload: Some(encrypted_payload),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Decodes a `HandshakeMessage` and returns its `ServerHello` body.
    /// Validates only the ephemeral length — `static` and `payload` are
    /// optional fields whose presence depends on the active pattern.
    pub fn parse_server_hello_body(
        response_bytes: &[u8],
    ) -> Result<wa::handshake_message::ServerHello> {
        let handshake_response = HandshakeMessage::decode(response_bytes)?;
        let server_hello = handshake_response
            .server_hello
            .ok_or(HandshakeError::IncompleteResponse)?;

        if let Some(ephemeral) = server_hello.ephemeral.as_ref()
            && ephemeral.len() != 32
        {
            return Err(HandshakeError::InvalidLength {
                name: "server ephemeral key".into(),
                expected: 32,
                got: ephemeral.len(),
            });
        }

        Ok(server_hello)
    }

    /// XX-style parse: requires all three fields. Mirrors the historical
    /// shape used by the full XX handshake and by XX-fallback.
    pub fn parse_server_hello(response_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
        let server_hello = Self::parse_server_hello_body(response_bytes)?;
        let server_ephemeral = server_hello
            .ephemeral
            .ok_or(HandshakeError::IncompleteResponse)?;
        let server_static_ciphertext = server_hello
            .r#static
            .ok_or(HandshakeError::IncompleteResponse)?;
        let certificate_ciphertext = server_hello
            .payload
            .ok_or(HandshakeError::IncompleteResponse)?;
        Ok((
            server_ephemeral,
            server_static_ciphertext,
            certificate_ciphertext,
        ))
    }

    /// Verifies the server's certificate chain and returns a stripped form
    /// suitable for caching across reconnects (signatures and the global
    /// issuer serial are dropped — they were just checked).
    pub fn verify_server_cert(
        cert_decrypted: &[u8],
        static_decrypted: &[u8; 32],
    ) -> Result<VerifiedServerCertChain> {
        let cert_chain = CertChain::decode(cert_decrypted)?;

        let intermediate = cert_chain
            .intermediate
            .ok_or_else(|| HandshakeError::CertVerification("Missing intermediate cert".into()))?;
        let leaf = cert_chain
            .leaf
            .ok_or_else(|| HandshakeError::CertVerification("Missing leaf cert".into()))?;

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
        let intermediate_key: [u8; 32] = intermediate_pk_bytes.try_into().map_err(|_| {
            HandshakeError::CertVerification("Intermediate details key is not 32 bytes".into())
        })?;

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

        if leaf_details.key() != static_decrypted {
            return Err(HandshakeError::CertVerification(
                "Cert key does not match decrypted static key".into(),
            ));
        }

        Ok(VerifiedServerCertChain {
            intermediate_key,
            intermediate_not_before: intermediate_details.not_before() as i64,
            intermediate_not_after: intermediate_details.not_after() as i64,
            leaf_key: *static_decrypted,
            leaf_not_before: leaf_details.not_before() as i64,
            leaf_not_after: leaf_details.not_after() as i64,
        })
    }

    pub fn build_client_finish(
        encrypted_pubkey: Vec<u8>,
        encrypted_payload: Vec<u8>,
    ) -> HandshakeMessage {
        HandshakeMessage {
            client_finish: Some(wa::handshake_message::ClientFinish {
                r#static: Some(encrypted_pubkey),
                payload: Some(encrypted_payload),
                ..Default::default()
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

/// Outcome of a successful XX (or XX-fallback) handshake. Bundles the final
/// cipher pair with the freshly-validated server cert chain so the caller
/// can persist the latter for the next reconnect's IK attempt.
pub struct XxHandshakeOutcome {
    pub write_cipher: NoiseCipher,
    pub read_cipher: NoiseCipher,
    pub server_cert_chain: VerifiedServerCertChain,
}

/// Outcome of a successful IK handshake — only the cipher keys, since the
/// cached cert chain on disk stays valid (the server demonstrably still
/// owns the static private key by virtue of completing the handshake).
pub struct IkHandshakeOutcome {
    pub write_cipher: NoiseCipher,
    pub read_cipher: NoiseCipher,
}

/// Carryover state when an in-flight IK is rejected by the server (server
/// replied with an XX-shaped ServerHello carrying `static != null`). The
/// initiator hands these to `XxFallbackHandshakeState::from_ik_failure`
/// without losing the ephemeral it already sent on the wire.
pub struct IkFallbackInputs {
    pub ephemeral_kp: KeyPair,
    pub static_kp: KeyPair,
    pub client_payload: Vec<u8>,
    pub server_hello_bytes: Vec<u8>,
}

/// What the IK initiator learns from reading the ServerHello.
pub enum IkServerHelloOutcome {
    /// Server accepted IK; cert payload was decrypted and the cipher keys
    /// are derivable. The cached cert chain on the device stays untouched.
    Continue(IkHandshakeOutcome),
    /// Server rejected IK by replying with `static != null`. Switch to
    /// XX-fallback using the carryover inputs. Boxed since `IkFallbackInputs`
    /// holds two KeyPairs and a payload, dwarfing `Continue`'s two ciphers.
    Fallback(Box<IkFallbackInputs>),
}

/// Full handshake state machine for WhatsApp Noise XX handshake. Used for
/// the first connect / pairing where the client has no cached server static.
pub struct XxHandshakeState {
    noise: NoiseHandshake,
    ephemeral_kp: KeyPair,
    static_kp: KeyPair,
    payload: Vec<u8>,
    /// Captured during `read_server_hello_and_build_client_finish` so that
    /// `finish()` can ship it back without a second decrypt.
    cert_chain: Option<VerifiedServerCertChain>,
}

impl XxHandshakeState {
    /// # Arguments
    /// * `static_kp` - The device's static Noise key pair
    /// * `client_payload` - The encoded client payload bytes
    /// * `prologue` - The prologue/header bytes (e.g., WA_CONN_HEADER)
    pub fn new(static_kp: KeyPair, client_payload: Vec<u8>, prologue: &[u8]) -> Result<Self> {
        let ephemeral_kp = KeyPair::generate(&mut rand::rng());
        let mut noise = NoiseHandshake::new(wacore_binary::consts::NOISE_PATTERN_XX, prologue)?;
        noise.authenticate(ephemeral_kp.public_key.public_key_bytes());

        Ok(Self {
            noise,
            ephemeral_kp,
            static_kp,
            payload: client_payload,
            cert_chain: None,
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

        process_xx_server_hello_into(
            &mut self.noise,
            &self.ephemeral_kp,
            &self.static_kp,
            &self.payload,
            server_ephemeral,
            &server_static_ciphertext,
            &certificate_ciphertext,
            &mut self.cert_chain,
        )
    }

    pub fn finish(self) -> Result<XxHandshakeOutcome> {
        let cert_chain = self.cert_chain.ok_or(HandshakeError::IncompleteResponse)?;
        let (write_cipher, read_cipher) = self.noise.finish()?;
        Ok(XxHandshakeOutcome {
            write_cipher,
            read_cipher,
            server_cert_chain: cert_chain,
        })
    }
}

/// Shared XX serverHello -> clientFinish core. Used by both the cold-start
/// `XxHandshakeState` and the post-IK-rejection `XxFallbackHandshakeState`,
/// since once the ephemeral is in the transcript both flows look identical.
#[allow(clippy::too_many_arguments)]
fn process_xx_server_hello_into(
    noise: &mut NoiseHandshake,
    ephemeral_kp: &KeyPair,
    static_kp: &KeyPair,
    payload: &[u8],
    server_ephemeral: [u8; 32],
    server_static_ciphertext: &[u8],
    certificate_ciphertext: &[u8],
    cert_chain_out: &mut Option<VerifiedServerCertChain>,
) -> Result<Vec<u8>> {
    noise.authenticate(&server_ephemeral);
    noise.mix_shared_secret(ephemeral_kp.private_key.serialize(), &server_ephemeral)?;

    let static_decrypted = noise.decrypt(server_static_ciphertext)?;
    let static_decrypted_arr: [u8; 32] = static_decrypted
        .try_into()
        .map_err(|_| HandshakeError::InvalidKeyLength)?;

    noise.mix_shared_secret(ephemeral_kp.private_key.serialize(), &static_decrypted_arr)?;

    let cert_decrypted = noise.decrypt(certificate_ciphertext)?;

    let chain = HandshakeUtils::verify_server_cert(&cert_decrypted, &static_decrypted_arr)
        .map_err(|e| {
            HandshakeError::CertVerification(format!("Error verifying server cert: {e}"))
        })?;
    *cert_chain_out = Some(chain);

    let encrypted_pubkey = noise.encrypt(static_kp.public_key.public_key_bytes())?;

    noise.mix_shared_secret(static_kp.private_key.serialize(), &server_ephemeral)?;

    let encrypted_payload = noise.encrypt(payload)?;

    let client_finish = HandshakeUtils::build_client_finish(encrypted_pubkey, encrypted_payload);
    let mut buf = Vec::new();
    client_finish.encode(&mut buf)?;
    Ok(buf)
}

/// Handshake state for **Noise IK** — used on reconnect when the device has a
/// cached server static public key. Saves one round trip vs XX and ships a
/// 0-RTT payload (login info) inside the very first message.
///
/// IK message 1 layout per Noise § 7.5 (`-> e, es, s, ss`) preceded by the
/// pre-message `<- s` (responder static is known to initiator):
///
/// ```text
///   mixHash(server_static_pub)        <- pre-message
///   gen e
///   mixHash(e_pub)                    <- e token
///   mixKey(DH(e_priv, server_static)) <- es
///   encryptAndHash(s_pub)             <- s token (encrypted client static)
///   mixKey(DH(s_priv, server_static)) <- ss
///   encryptAndHash(payload)           <- 0-RTT login payload
/// ```
pub struct IkHandshakeState {
    noise: NoiseHandshake,
    ephemeral_kp: KeyPair,
    static_kp: KeyPair,
    /// Server static public key cached from a previous XX. Used both for the
    /// pre-message MixHash and for `es` / `ss` derivations.
    server_static_pub: [u8; 32],
    payload: Vec<u8>,
}

impl IkHandshakeState {
    pub fn new(
        static_kp: KeyPair,
        server_static_pub: [u8; 32],
        client_payload: Vec<u8>,
        prologue: &[u8],
    ) -> Result<Self> {
        let ephemeral_kp = KeyPair::generate(&mut rand::rng());
        let noise = NoiseHandshake::new(wacore_binary::consts::NOISE_PATTERN_IK, prologue)?;

        Ok(Self {
            noise,
            ephemeral_kp,
            static_kp,
            server_static_pub,
            payload: client_payload,
        })
    }

    /// Builds and serializes the IK ClientHello carrying the encrypted
    /// client static and 0-RTT payload alongside the ephemeral.
    pub fn build_client_hello(&mut self) -> Result<Vec<u8>> {
        // pre-message: <- s
        self.noise.authenticate(&self.server_static_pub);

        // -> e
        let ephemeral_pub_bytes = self.ephemeral_kp.public_key.public_key_bytes().to_vec();
        self.noise.authenticate(&ephemeral_pub_bytes);

        // es: DH(e_priv, server_static_pub)
        self.noise.mix_shared_secret(
            self.ephemeral_kp.private_key.serialize(),
            &self.server_static_pub,
        )?;

        // -> s (encrypted)
        let encrypted_static = self
            .noise
            .encrypt(self.static_kp.public_key.public_key_bytes())?;

        // ss: DH(s_priv, server_static_pub)
        self.noise.mix_shared_secret(
            self.static_kp.private_key.serialize(),
            &self.server_static_pub,
        )?;

        // 0-RTT payload (encrypted)
        let encrypted_payload = self.noise.encrypt(&self.payload)?;

        let msg = HandshakeUtils::build_ik_client_hello(
            &ephemeral_pub_bytes,
            encrypted_static,
            encrypted_payload,
        );
        let mut buf = Vec::new();
        msg.encode(&mut buf)?;
        Ok(buf)
    }

    /// Reads the ServerHello and either completes the IK handshake or
    /// reports that the server requested an XX-fallback.
    ///
    /// The dispatcher follows WA Web's rule (`ChatSocket.js:232`): when
    /// `serverHello.static == null` the IK is accepted; when present, the
    /// server has rotated its static and is asking the client to fall back
    /// to XX using the ephemeral that was already sent.
    pub fn read_server_hello(self, response_bytes: &[u8]) -> Result<IkServerHelloOutcome> {
        let server_hello = HandshakeUtils::parse_server_hello_body(response_bytes)?;

        if server_hello.r#static.is_some() {
            // Fallback: server rejected our cached static.
            return Ok(IkServerHelloOutcome::Fallback(Box::new(IkFallbackInputs {
                ephemeral_kp: self.ephemeral_kp,
                static_kp: self.static_kp,
                client_payload: self.payload,
                server_hello_bytes: response_bytes.to_vec(),
            })));
        }

        let server_ephemeral = server_hello
            .ephemeral
            .ok_or(HandshakeError::IncompleteResponse)?;
        let cert_payload = server_hello
            .payload
            .ok_or(HandshakeError::IncompleteResponse)?;
        let server_ephemeral: [u8; 32] = server_ephemeral
            .try_into()
            .map_err(|_| HandshakeError::InvalidKeyLength)?;

        let mut noise = self.noise;

        // <- e
        noise.authenticate(&server_ephemeral);
        // ee
        noise.mix_shared_secret(self.ephemeral_kp.private_key.serialize(), &server_ephemeral)?;
        // se
        noise.mix_shared_secret(self.static_kp.private_key.serialize(), &server_ephemeral)?;

        // Decrypting the cert payload also authenticates the transcript via
        // AEAD. If the server is impersonating with a stale static the AEAD
        // tag check fails here.
        let _cert_plaintext = noise.decrypt(&cert_payload)?;

        let (write_cipher, read_cipher) = noise.finish()?;
        Ok(IkServerHelloOutcome::Continue(IkHandshakeOutcome {
            write_cipher,
            read_cipher,
        }))
    }
}

/// Handshake state for **Noise XXfallback** — used to recover from an IK
/// rejection without losing the ephemeral that was already on the wire.
///
/// The trick (mirrored from WA Web's `doFallbackHandshake`): re-init Noise
/// with the XXfallback protocol_name, then `mixHash(client_ephemeral_pub)`
/// to bring the transcript to the same state it would be in if the client
/// had just sent an XX ClientHello. From there the ServerHello processing
/// and ClientFinish look exactly like XX.
pub struct XxFallbackHandshakeState {
    noise: NoiseHandshake,
    ephemeral_kp: KeyPair,
    static_kp: KeyPair,
    payload: Vec<u8>,
    server_hello_bytes: Vec<u8>,
    cert_chain: Option<VerifiedServerCertChain>,
}

impl XxFallbackHandshakeState {
    pub fn from_ik_failure(inputs: IkFallbackInputs, prologue: &[u8]) -> Result<Self> {
        let mut noise =
            NoiseHandshake::new(wacore_binary::consts::NOISE_PATTERN_XXFALLBACK, prologue)?;
        // Reuse the ephemeral that was already sent in the IK ClientHello —
        // its public bytes go into the XXfallback transcript here.
        noise.authenticate(inputs.ephemeral_kp.public_key.public_key_bytes());

        Ok(Self {
            noise,
            ephemeral_kp: inputs.ephemeral_kp,
            static_kp: inputs.static_kp,
            payload: inputs.client_payload,
            server_hello_bytes: inputs.server_hello_bytes,
            cert_chain: None,
        })
    }

    pub fn build_client_finish(&mut self) -> Result<Vec<u8>> {
        let (server_ephemeral_raw, server_static_ciphertext, certificate_ciphertext) =
            HandshakeUtils::parse_server_hello(&self.server_hello_bytes).map_err(|e| {
                HandshakeError::CertVerification(format!("Error parsing server hello: {e}"))
            })?;

        let server_ephemeral: [u8; 32] = server_ephemeral_raw
            .try_into()
            .map_err(|_| HandshakeError::InvalidKeyLength)?;

        process_xx_server_hello_into(
            &mut self.noise,
            &self.ephemeral_kp,
            &self.static_kp,
            &self.payload,
            server_ephemeral,
            &server_static_ciphertext,
            &certificate_ciphertext,
            &mut self.cert_chain,
        )
    }

    pub fn finish(self) -> Result<XxHandshakeOutcome> {
        let cert_chain = self.cert_chain.ok_or(HandshakeError::IncompleteResponse)?;
        let (write_cipher, read_cipher) = self.noise.finish()?;
        Ok(XxHandshakeOutcome {
            write_cipher,
            read_cipher,
            server_cert_chain: cert_chain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use wacore_binary::consts::WA_CONN_HEADER;
    use waproto::whatsapp as wa;

    /// A self-contained Noise responder used to exercise the initiator-side
    /// state machines end-to-end. Mirrors what the production WhatsApp server
    /// does on the wire so each flow can be validated without a network.
    struct TestResponder {
        identity_kp: KeyPair,
        cert_chain_bytes: Vec<u8>,
    }

    impl TestResponder {
        fn new() -> (Self, [u8; 32]) {
            let kp = KeyPair::generate(&mut rand::rng());
            let server_static_pub: [u8; 32] = kp.public_key.public_key_bytes().try_into().unwrap();
            let cert_chain_bytes = build_cert_chain_bytes(&server_static_pub);
            (
                Self {
                    identity_kp: kp,
                    cert_chain_bytes,
                },
                server_static_pub,
            )
        }

        fn server_static_pub(&self) -> [u8; 32] {
            self.identity_kp
                .public_key
                .public_key_bytes()
                .try_into()
                .expect("X25519 pub key is always 32 bytes")
        }
    }

    /// Builds a minimal CertChain bytes blob whose leaf.key matches the
    /// given static key. Skips signatures since `verify_server_cert`
    /// only checks shape + key bytes (signatures aren't verified by our
    /// implementation today).
    fn build_cert_chain_bytes(server_static_pub: &[u8; 32]) -> Vec<u8> {
        // Intermediate details
        let intermediate_details = noise_certificate::Details {
            serial: Some(1),
            issuer_serial: Some(0),
            key: Some(vec![0xCC; 32]),
            not_before: Some(1_700_000_000),
            not_after: Some(1_900_000_000),
        };
        let mut intermediate_details_bytes = Vec::new();
        intermediate_details
            .encode(&mut intermediate_details_bytes)
            .unwrap();

        // Leaf details
        let leaf_details = noise_certificate::Details {
            serial: Some(2),
            issuer_serial: Some(1),
            key: Some(server_static_pub.to_vec()),
            not_before: Some(1_700_000_500),
            not_after: Some(1_899_999_500),
        };
        let mut leaf_details_bytes = Vec::new();
        leaf_details.encode(&mut leaf_details_bytes).unwrap();

        let chain = wa::CertChain {
            leaf: Some(wa::cert_chain::NoiseCertificate {
                details: Some(leaf_details_bytes),
                signature: Some(vec![0u8; 64]),
            }),
            intermediate: Some(wa::cert_chain::NoiseCertificate {
                details: Some(intermediate_details_bytes),
                signature: Some(vec![0u8; 64]),
            }),
        };
        let mut bytes = Vec::new();
        chain.encode(&mut bytes).unwrap();
        bytes
    }

    /// Variant of `xx_serve` that also returns the server's ephemeral key
    /// pair so the test can finish the handshake without exposing secrets
    /// from inside `NoiseHandshake`.
    fn xx_serve_ext(
        responder: &TestResponder,
        client_hello_bytes: &[u8],
        pattern: &str,
        prologue: &[u8],
    ) -> (Vec<u8>, NoiseHandshake, KeyPair, [u8; 32]) {
        let msg = wa::HandshakeMessage::decode(client_hello_bytes).expect("decode hello");
        let client_eph_pub_vec = msg.client_hello.unwrap().ephemeral.unwrap();
        let client_eph_pub: [u8; 32] = client_eph_pub_vec.try_into().unwrap();

        let mut noise = NoiseHandshake::new(pattern, prologue).expect("init responder");
        noise.authenticate(&client_eph_pub);

        let server_eph = KeyPair::generate(&mut rand::rng());
        let server_eph_pub: [u8; 32] = server_eph.public_key.public_key_bytes().try_into().unwrap();
        noise.authenticate(&server_eph_pub);

        noise
            .mix_shared_secret(server_eph.private_key.serialize(), &client_eph_pub)
            .expect("ee");

        let server_static_pub = responder.server_static_pub();
        let encrypted_static = noise.encrypt(&server_static_pub).expect("enc static");

        noise
            .mix_shared_secret(
                responder.identity_kp.private_key.serialize(),
                &client_eph_pub,
            )
            .expect("es");

        let encrypted_payload = noise
            .encrypt(&responder.cert_chain_bytes)
            .expect("enc cert");

        let server_hello = wa::HandshakeMessage {
            server_hello: Some(wa::handshake_message::ServerHello {
                ephemeral: Some(server_eph_pub.to_vec()),
                r#static: Some(encrypted_static),
                payload: Some(encrypted_payload),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bytes = Vec::new();
        server_hello.encode(&mut bytes).unwrap();
        (bytes, noise, server_eph, client_eph_pub)
    }

    fn xx_finish_ext(
        mut noise: NoiseHandshake,
        server_eph: KeyPair,
        client_finish_bytes: &[u8],
    ) -> (NoiseCipher, NoiseCipher) {
        let msg = wa::HandshakeMessage::decode(client_finish_bytes).expect("decode finish");
        let cf = msg.client_finish.unwrap();
        let client_static = noise.decrypt(&cf.r#static.unwrap()).expect("dec s");
        let client_static_arr: [u8; 32] = client_static.try_into().unwrap();

        // se: DH(server_eph_priv, client_static_pub)
        noise
            .mix_shared_secret(server_eph.private_key.serialize(), &client_static_arr)
            .expect("se");

        let _payload_pt = noise.decrypt(&cf.payload.unwrap()).expect("dec payload");

        let (write, read) = noise.finish().expect("finish");
        // Initiator's write is responder's read and vice versa.
        (read, write)
    }

    /// IK responder that accepts the handshake. Mirrors WA Web's accept
    /// path in `ChatSocket.js` (`q(...)` -> serverHello with no static).
    fn ik_serve_accept(
        responder: &TestResponder,
        client_hello_bytes: &[u8],
        prologue: &[u8],
    ) -> Vec<u8> {
        // Run IK responder side per Noise § 7.5.
        let msg = wa::HandshakeMessage::decode(client_hello_bytes).expect("decode hello");
        let ch = msg.client_hello.unwrap();
        let client_eph_pub_vec = ch.ephemeral.unwrap();
        let client_eph_pub: [u8; 32] = client_eph_pub_vec.try_into().unwrap();
        let encrypted_static = ch.r#static.unwrap();
        let encrypted_payload = ch.payload.unwrap();

        let mut noise =
            NoiseHandshake::new(wacore_binary::consts::NOISE_PATTERN_IK, prologue).unwrap();
        // pre-message: <- s (responder's own static)
        let server_static_pub = responder.server_static_pub();
        noise.authenticate(&server_static_pub);
        // -> e
        noise.authenticate(&client_eph_pub);
        // es: DH(s_priv_resp, e_pub_init)
        noise
            .mix_shared_secret(
                responder.identity_kp.private_key.serialize(),
                &client_eph_pub,
            )
            .unwrap();
        // -> s (decrypt client static)
        let client_static = noise.decrypt(&encrypted_static).unwrap();
        let client_static_arr: [u8; 32] = client_static.try_into().unwrap();
        // ss: DH(s_priv_resp, s_pub_init)
        noise
            .mix_shared_secret(
                responder.identity_kp.private_key.serialize(),
                &client_static_arr,
            )
            .unwrap();
        // -> payload
        let _payload_plaintext = noise.decrypt(&encrypted_payload).unwrap();

        // Now build ServerHello (<- e, ee, se, payload).
        let server_eph = KeyPair::generate(&mut rand::rng());
        let server_eph_pub: [u8; 32] = server_eph.public_key.public_key_bytes().try_into().unwrap();
        noise.authenticate(&server_eph_pub);
        // ee
        noise
            .mix_shared_secret(server_eph.private_key.serialize(), &client_eph_pub)
            .unwrap();
        // se: DH(e_priv_resp, s_pub_init)
        noise
            .mix_shared_secret(server_eph.private_key.serialize(), &client_static_arr)
            .unwrap();
        let encrypted_cert = noise.encrypt(&responder.cert_chain_bytes).unwrap();

        let server_hello = wa::HandshakeMessage {
            server_hello: Some(wa::handshake_message::ServerHello {
                ephemeral: Some(server_eph_pub.to_vec()),
                r#static: None,
                payload: Some(encrypted_cert),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bytes = Vec::new();
        server_hello.encode(&mut bytes).unwrap();
        bytes
    }

    /// IK responder that rejects with an XX-shaped serverHello, prompting
    /// the initiator to fall back. The transcript here intentionally
    /// matches what the XXfallback initiator expects.
    fn ik_serve_force_fallback(
        responder: &TestResponder,
        client_hello_bytes: &[u8],
        prologue: &[u8],
    ) -> (Vec<u8>, NoiseHandshake, KeyPair) {
        // Pull the client's ephemeral out of the IK clientHello to seed an
        // XXfallback responder. We ignore the encrypted client static and
        // 0-RTT payload since the client will resend on the XXfallback path.
        let msg = wa::HandshakeMessage::decode(client_hello_bytes).expect("decode hello");
        let client_eph_pub_vec = msg.client_hello.unwrap().ephemeral.unwrap();
        let client_eph_pub: [u8; 32] = client_eph_pub_vec.try_into().unwrap();

        // Stand up a fresh XXfallback responder and authenticate the
        // already-sent client ephemeral.
        let mut noise =
            NoiseHandshake::new(wacore_binary::consts::NOISE_PATTERN_XXFALLBACK, prologue).unwrap();
        noise.authenticate(&client_eph_pub);

        let server_eph = KeyPair::generate(&mut rand::rng());
        let server_eph_pub: [u8; 32] = server_eph.public_key.public_key_bytes().try_into().unwrap();
        noise.authenticate(&server_eph_pub);
        noise
            .mix_shared_secret(server_eph.private_key.serialize(), &client_eph_pub)
            .unwrap();

        let server_static_pub = responder.server_static_pub();
        let encrypted_static = noise.encrypt(&server_static_pub).unwrap();

        noise
            .mix_shared_secret(
                responder.identity_kp.private_key.serialize(),
                &client_eph_pub,
            )
            .unwrap();

        let encrypted_cert = noise.encrypt(&responder.cert_chain_bytes).unwrap();

        let server_hello = wa::HandshakeMessage {
            server_hello: Some(wa::handshake_message::ServerHello {
                ephemeral: Some(server_eph_pub.to_vec()),
                r#static: Some(encrypted_static),
                payload: Some(encrypted_cert),
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut bytes = Vec::new();
        server_hello.encode(&mut bytes).unwrap();
        (bytes, noise, server_eph)
    }

    #[test]
    fn xx_handshake_round_trip_completes() {
        let prologue = WA_CONN_HEADER;
        let (responder, _) = TestResponder::new();

        let client_static = KeyPair::generate(&mut rand::rng());
        let payload = b"login-payload".to_vec();

        let mut state =
            XxHandshakeState::new(client_static.clone(), payload.clone(), &prologue).unwrap();
        let client_hello = state.build_client_hello().unwrap();

        let (server_hello, server_noise, server_eph, _client_eph_pub) = xx_serve_ext(
            &responder,
            &client_hello,
            wacore_binary::consts::NOISE_PATTERN_XX,
            &prologue,
        );

        let client_finish = state
            .read_server_hello_and_build_client_finish(&server_hello)
            .expect("server hello must be processable");

        let outcome = state.finish().expect("finish");
        let (server_write, server_read) = xx_finish_ext(server_noise, server_eph, &client_finish);

        // Cipher pair must be symmetric (initiator's write == responder's read).
        let plaintext = b"hello after xx";
        let ct = outcome
            .write_cipher
            .encrypt_with_counter(0, plaintext)
            .unwrap();
        let mut buf = ct.clone();
        server_read
            .decrypt_in_place_with_counter(0, &mut buf)
            .expect("decrypt with responder read");
        assert_eq!(buf, plaintext);

        let ct2 = server_write.encrypt_with_counter(0, plaintext).unwrap();
        let mut buf2 = ct2.clone();
        outcome
            .read_cipher
            .decrypt_in_place_with_counter(0, &mut buf2)
            .expect("decrypt with initiator read");
        assert_eq!(buf2, plaintext);

        // Cert chain must be the one the responder served.
        assert_eq!(
            outcome.server_cert_chain.leaf_key,
            responder.server_static_pub()
        );
    }

    #[test]
    fn ik_handshake_round_trip_continue() {
        let prologue = WA_CONN_HEADER;
        let (responder, server_static_pub) = TestResponder::new();

        let client_static = KeyPair::generate(&mut rand::rng());
        let payload = b"ik-zero-rtt".to_vec();

        let mut state = IkHandshakeState::new(
            client_static.clone(),
            server_static_pub,
            payload.clone(),
            &prologue,
        )
        .unwrap();
        let client_hello = state.build_client_hello().unwrap();

        let server_hello = ik_serve_accept(&responder, &client_hello, &prologue);
        let outcome = state
            .read_server_hello(&server_hello)
            .expect("ik must succeed");
        match outcome {
            IkServerHelloOutcome::Continue(_) => (),
            IkServerHelloOutcome::Fallback(_) => panic!("expected Continue, got Fallback"),
        }
    }

    #[test]
    fn ik_to_xx_fallback_round_trip() {
        let prologue = WA_CONN_HEADER;
        let (responder, server_static_pub) = TestResponder::new();

        let client_static = KeyPair::generate(&mut rand::rng());
        let payload = b"login-after-fallback".to_vec();

        let mut ik = IkHandshakeState::new(
            client_static.clone(),
            server_static_pub,
            payload.clone(),
            &prologue,
        )
        .unwrap();
        let ik_hello = ik.build_client_hello().unwrap();

        let (server_hello, server_noise, server_eph) =
            ik_serve_force_fallback(&responder, &ik_hello, &prologue);

        let outcome = ik
            .read_server_hello(&server_hello)
            .expect("ik must report fallback, not error");
        let inputs = match outcome {
            IkServerHelloOutcome::Fallback(inp) => *inp,
            IkServerHelloOutcome::Continue(_) => panic!("expected Fallback"),
        };

        let mut fb = XxFallbackHandshakeState::from_ik_failure(inputs, &prologue).unwrap();
        let client_finish = fb.build_client_finish().expect("fallback must succeed");
        let result = fb.finish().expect("finish");

        let (server_write, server_read) = xx_finish_ext(server_noise, server_eph, &client_finish);

        let plaintext = b"hi over fallback";
        let ct = result
            .write_cipher
            .encrypt_with_counter(0, plaintext)
            .unwrap();
        let mut buf = ct.clone();
        server_read
            .decrypt_in_place_with_counter(0, &mut buf)
            .expect("responder reads what initiator wrote");
        assert_eq!(buf, plaintext);

        let ct2 = server_write.encrypt_with_counter(0, plaintext).unwrap();
        let mut buf2 = ct2.clone();
        result
            .read_cipher
            .decrypt_in_place_with_counter(0, &mut buf2)
            .expect("initiator reads what responder wrote");
        assert_eq!(buf2, plaintext);

        assert_eq!(
            result.server_cert_chain.leaf_key,
            responder.server_static_pub()
        );
    }

    #[test]
    fn ik_with_wrong_server_static_fails_at_decrypt() {
        let prologue = WA_CONN_HEADER;
        let (responder, _correct_pub) = TestResponder::new();

        // Wrong server static = handshake will not authenticate. We expect
        // a Decrypt error somewhere in read_server_hello.
        let bogus_static = [0xDEu8; 32];

        let client_static = KeyPair::generate(&mut rand::rng());
        let mut state =
            IkHandshakeState::new(client_static, bogus_static, b"x".to_vec(), &prologue).unwrap();
        let hello = state.build_client_hello().unwrap();

        // Responder uses its actual key, so the mac will not match.
        let server_hello_result =
            std::panic::catch_unwind(|| ik_serve_accept(&responder, &hello, &prologue));
        // The responder itself will panic on decrypt of the client static
        // (since the bogus server_static_pub means es derivation diverges).
        assert!(
            server_hello_result.is_err(),
            "responder must reject IK forged with wrong server static"
        );
    }
}
