use crate::binary::node::Node;
use crate::socket::error::{Result, SocketError};
use aes_gcm::aead::Aead;
use aes_gcm::Aes256Gcm;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

pub fn generate_iv(counter: u32) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[8..].copy_from_slice(&counter.to_be_bytes());
    iv
}

pub struct NoiseSocket {
    write_key: Aes256Gcm,
    read_key: Aes256Gcm,
    write_counter: Arc<AtomicU32>,
    read_counter: Arc<AtomicU32>,
}

impl NoiseSocket {
    pub fn new(write_key: Aes256Gcm, read_key: Aes256Gcm) -> Self {
        Self {
            write_key,
            read_key,
            write_counter: Arc::new(AtomicU32::new(0)),
            read_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Sends a Node over the socket (stub implementation).
    pub async fn send_node(&self, _node: &Node) -> Result<()> {
        // TODO: Implement actual serialization, encryption, and sending logic.
        Ok(())
    }

    pub fn encrypt_frame(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.write_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        self.write_key
            .encrypt(iv.as_ref().into(), plaintext)
            .map_err(|e| SocketError::Crypto(e.to_string()))
    }

    pub fn decrypt_frame(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.read_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        self.read_key
            .decrypt(iv.as_ref().into(), ciphertext)
            .map_err(|e| SocketError::Crypto(e.to_string()))
    }
}
