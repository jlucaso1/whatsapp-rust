use crate::socket::error::{Result, SocketError};
use crate::transport::Transport;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use wacore::aes_gcm::{Aes256Gcm, aead::Aead};
use wacore::handshake::utils::generate_iv;

pub struct NoiseSocket {
    transport: Arc<dyn Transport>,
    write_key: Aes256Gcm,
    read_key: Aes256Gcm,
    write_counter: Arc<AtomicU32>,
    read_counter: Arc<AtomicU32>,
}

impl NoiseSocket {
    pub fn new(transport: Arc<dyn Transport>, write_key: Aes256Gcm, read_key: Aes256Gcm) -> Self {
        Self {
            transport,
            write_key,
            read_key,
            write_counter: Arc::new(AtomicU32::new(0)),
            read_counter: Arc::new(AtomicU32::new(0)),
        }
    }

    /// Encrypts `plaintext` into the provided `out` buffer (which is cleared first) and
    /// returns a slice view of the ciphertext.
    pub fn encrypt_into<'a>(&self, plaintext: &[u8], out: &'a mut Vec<u8>) -> Result<&'a [u8]> {
        out.clear();
        let counter = self.write_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        let ciphertext = self
            .write_key
            .encrypt(iv.as_ref().into(), plaintext)
            .map_err(|e| SocketError::Crypto(e.to_string()))?;
        out.extend_from_slice(&ciphertext);
        Ok(out.as_slice())
    }

    pub async fn encrypt_and_send(
        &self,
        mut plaintext_buf: Vec<u8>,
        mut out_buf: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.encrypt_into(&plaintext_buf, &mut out_buf)?;
        plaintext_buf.clear();
        
        // Frame the encrypted data with length prefix
        let framed = crate::framing::encode_frame(&out_buf, None)
            .map_err(|e| SocketError::Crypto(e.to_string()))?;
        
        self.transport
            .send(&framed)
            .await
            .map_err(|e| SocketError::Crypto(e.to_string()))?;
        Ok(plaintext_buf)
    }

    pub fn decrypt_frame(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.read_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        self.read_key
            .decrypt(iv.as_ref().into(), ciphertext)
            .map_err(|e| SocketError::Crypto(e.to_string()))
    }
}
