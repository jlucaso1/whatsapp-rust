use crate::crypto::{gcm, hkdf};
use crate::handshake::state::Result;
use crate::handshake::utils::{HandshakeError, generate_iv};
use crate::libsignal::protocol::{PrivateKey, PublicKey};
use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, Payload};
use sha2::{Digest, Sha256};

pub fn sha256_slice(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub struct NoiseHandshake {
    pub hash: [u8; 32],
    pub salt: [u8; 32],
    pub key: Aes256Gcm,
    pub counter: u32,
}

impl NoiseHandshake {
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    pub fn new(pattern: &str, header: &[u8]) -> Result<Self> {
        let h: [u8; 32] = if pattern.len() == 32 {
            pattern.as_bytes().try_into().unwrap()
        } else {
            sha256_slice(pattern.as_bytes())
        };

        let mut new_self = Self {
            hash: h,
            salt: h,
            key: gcm::prepare(&h).map_err(|e| HandshakeError::Crypto(e.to_string()))?,
            counter: 0,
        };

        new_self.authenticate(header);
        Ok(new_self)
    }

    pub fn authenticate(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.hash);
        hasher.update(data);
        self.hash = hasher.finalize().into();
    }

    fn post_increment_counter(&mut self) -> u32 {
        let count = self.counter;
        self.counter += 1;
        count
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let iv = generate_iv(self.post_increment_counter());
        let payload = Payload {
            msg: plaintext,
            aad: &self.hash,
        };
        let ciphertext = self
            .key
            .encrypt(iv.as_ref().into(), payload)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;
        self.authenticate(&ciphertext);
        Ok(ciphertext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let aad = self.hash;
        let iv = generate_iv(self.post_increment_counter());
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };
        let plaintext = self
            .key
            .decrypt(iv.as_ref().into(), payload)
            .map_err(|e| HandshakeError::Crypto(format!("Noise decrypt failed: {e}")))?;

        self.authenticate(ciphertext);
        Ok(plaintext)
    }

    pub fn mix_into_key(&mut self, data: &[u8]) -> Result<()> {
        self.counter = 0;
        let (write, read) = self.extract_and_expand(Some(data))?;
        self.salt = write;
        self.key = gcm::prepare(&read).map_err(|e| HandshakeError::Crypto(e.to_string()))?;
        Ok(())
    }

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

    fn extract_and_expand(&self, data: Option<&[u8]>) -> Result<([u8; 32], [u8; 32])> {
        let salt = self.salt;
        let ikm = data;

        let okm = hkdf::sha256(ikm.unwrap_or(&[]), Some(&salt), &[], 64)
            .map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        let mut write = [0u8; 32];
        let mut read = [0u8; 32];

        write.copy_from_slice(&okm[..32]);
        read.copy_from_slice(&okm[32..]);

        Ok((write, read))
    }

    pub fn finish(self) -> Result<(Aes256Gcm, Aes256Gcm)> {
        let (write_bytes, read_bytes) = self.extract_and_expand(None)?;
        let write_key =
            gcm::prepare(&write_bytes).map_err(|e| HandshakeError::Crypto(e.to_string()))?;
        let read_key =
            gcm::prepare(&read_bytes).map_err(|e| HandshakeError::Crypto(e.to_string()))?;

        Ok((write_key, read_key))
    }
}
