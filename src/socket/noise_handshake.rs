use crate::crypto::{gcm, hkdf};
use crate::socket::error::{Result, SocketError};
use crate::socket::noise_socket::{generate_iv, NoiseSocket};
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::Aes256Gcm;
use sha2::{Digest, Sha256};
use x25519_dalek::{x25519, StaticSecret};

pub fn sha256_slice(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub struct NoiseHandshake {
    hash: [u8; 32],
    salt: [u8; 32],
    key: Aes256Gcm,
    counter: u32,
}

impl NoiseHandshake {
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }
    pub fn salt(&self) -> &[u8; 32] {
        &self.salt
    }

    pub fn new(pattern: &str, header: &[u8]) -> Result<Self> {
        // This logic now matches the Go implementation one-to-one.
        let h: [u8; 32] = if pattern.as_bytes().len() == 32 {
            // If the pattern is exactly 32 bytes, use it directly as the hash.
            pattern.as_bytes().try_into().unwrap() // Should not fail as we've checked the length
        } else {
            // Otherwise, compute its SHA-256 hash.
            sha256_slice(pattern.as_bytes())
        };

        let mut new_self = Self {
            hash: h,
            salt: h, // The initial salt is the same as the initial hash
            key: gcm::prepare(&h).map_err(|e| SocketError::Crypto(e.to_string()))?,
            counter: 0,
        };

        // Authenticate the WA header, which updates the hash state.
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
            .map_err(|e| SocketError::Crypto(e.to_string()))?;
        self.authenticate(&ciphertext);
        Ok(ciphertext)
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        // Capture the current handshake hash as AAD before decryption
        let aad = self.hash;
        let iv = generate_iv(self.post_increment_counter());
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };
        let plaintext = self
            .key
            .decrypt(iv.as_ref().into(), payload)
            .map_err(|e| SocketError::Crypto(format!("Noise decrypt failed: {}", e)))?;
        // Only after successful decryption, update the handshake hash
        self.authenticate(ciphertext);
        Ok(plaintext)
    }

    pub fn mix_into_key(&mut self, data: &[u8]) -> Result<()> {
        self.counter = 0;
        let (write, read) = self.extract_and_expand(Some(data))?;
        self.salt = write;
        self.key = gcm::prepare(&read).map_err(|e| SocketError::Crypto(e.to_string()))?;
        Ok(())
    }

    pub fn mix_shared_secret(&mut self, priv_key: &[u8; 32], pub_key: &[u8; 32]) -> Result<()> {
        let secret = StaticSecret::from(*priv_key);
        let shared_secret = x25519(secret.to_bytes(), *pub_key);
        self.mix_into_key(&shared_secret)
    }

    fn extract_and_expand(&self, data: Option<&[u8]>) -> Result<([u8; 32], [u8; 32])> {
        let salt = self.salt;
        let ikm = data;

        let okm = hkdf::sha256(ikm.unwrap_or(&[]), Some(&salt), &[], 64)
            .map_err(|e| SocketError::Crypto(e.to_string()))?;

        let mut write = [0u8; 32];
        let mut read = [0u8; 32];

        write.copy_from_slice(&okm[..32]);
        read.copy_from_slice(&okm[32..]);

        Ok((write, read))
    }

    pub fn finish(self) -> Result<NoiseSocket> {
        let (write_bytes, read_bytes) = self.extract_and_expand(None)?;
        let write_key =
            gcm::prepare(&write_bytes).map_err(|e| SocketError::Crypto(e.to_string()))?;
        let read_key = gcm::prepare(&read_bytes).map_err(|e| SocketError::Crypto(e.to_string()))?;

        Ok(NoiseSocket::new(write_key, read_key))
    }
}
