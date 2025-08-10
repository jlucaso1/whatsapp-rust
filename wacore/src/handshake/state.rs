use super::noise::{self, NoiseHandshake};
use crate::{
    binary::consts::NOISE_START_PATTERN,
    crypto::key_pair::KeyPair,
    handshake::utils::{HandshakeError, HandshakeUtils},
};
use aes_gcm::Aes256Gcm;
use prost::Message;

pub type Result<T> = std::result::Result<T, HandshakeError>;

pub struct HandshakeState {
    noise: NoiseHandshake,
    ephemeral_kp: KeyPair,
    static_kp: KeyPair,
    payload: Vec<u8>,
}

impl HandshakeState {
    pub fn new(device: &crate::store::Device) -> Result<Self> {
        let ephemeral_kp = KeyPair::new();
        let wa_header = &crate::binary::consts::WA_CONN_HEADER;

        let mut noise = noise::NoiseHandshake::new(NOISE_START_PATTERN, wa_header)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        noise.authenticate(&ephemeral_kp.public_key);

        Ok(Self {
            noise,
            ephemeral_kp,
            static_kp: device.noise_key.clone(),
            payload: HandshakeUtils::prepare_client_payload(device),
        })
    }

    pub fn build_client_hello(&self) -> Result<Vec<u8>> {
        let client_hello = HandshakeUtils::build_client_hello(&self.ephemeral_kp.public_key);
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
            .mix_shared_secret(&self.ephemeral_kp.private_key, &server_ephemeral)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        let static_decrypted = self
            .noise
            .decrypt(&server_static_ciphertext)
            .map_err(|e| HandshakeError::Crypto(format!("Failed to decrypt server static: {e}")))?;

        let static_decrypted_arr: [u8; 32] = static_decrypted
            .try_into()
            .map_err(|_| HandshakeError::InvalidKeyLength)?;

        self.noise
            .mix_shared_secret(&self.ephemeral_kp.private_key, &static_decrypted_arr)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        let cert_decrypted = self
            .noise
            .decrypt(&certificate_ciphertext)
            .map_err(|e| HandshakeError::Crypto(format!("Failed to decrypt certificate: {e}")))?;

        HandshakeUtils::verify_server_cert(&cert_decrypted, &static_decrypted_arr).map_err(
            |e| HandshakeError::CertVerification(format!("Error verifying server cert: {e}")),
        )?;

        let encrypted_pubkey = self
            .noise
            .encrypt(&self.static_kp.public_key)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        self.noise
            .mix_shared_secret(&self.static_kp.private_key, &server_ephemeral)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        let encrypted_payload = self
            .noise
            .encrypt(&self.payload)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        let client_finish =
            HandshakeUtils::build_client_finish(encrypted_pubkey, encrypted_payload);

        let mut buf = Vec::new();
        client_finish.encode(&mut buf)?;
        Ok(buf)
    }

    pub fn finish(self) -> Result<(Aes256Gcm, Aes256Gcm)> {
        self.noise
            .finish()
            .map_err(|e| HandshakeError::Crypto(e.to_string()))
    }
}
