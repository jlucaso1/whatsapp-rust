use crate::socket::error::{Result, SocketError};
use crate::transport::Transport;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use wacore::aes_gcm::{Aes256Gcm, aead::Aead};
use wacore::handshake::utils::generate_iv;

pub struct NoiseSocket {
    transport: Arc<dyn Transport>,
    write_key: Arc<Aes256Gcm>,
    read_key: Arc<Aes256Gcm>,
    write_counter: Arc<AtomicU32>,
    read_counter: Arc<AtomicU32>,
}

impl NoiseSocket {
    pub fn new(transport: Arc<dyn Transport>, write_key: Aes256Gcm, read_key: Aes256Gcm) -> Self {
        Self {
            transport,
            write_key: Arc::new(write_key),
            read_key: Arc::new(read_key),
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
        plaintext_buf: Vec<u8>,
        mut out_buf: Vec<u8>,
    ) -> std::result::Result<(Vec<u8>, Vec<u8>), (SocketError, Vec<u8>, Vec<u8>)> {
        let write_key = self.write_key.clone();
        let counter = self.write_counter.fetch_add(1, Ordering::SeqCst);

        let spawn_result = tokio::task::spawn_blocking(move || {
            let iv = generate_iv(counter);
            let res = write_key.encrypt(iv.as_ref().into(), &plaintext_buf[..]);
            (res, plaintext_buf)
        })
        .await;

        let (ciphertext_result, mut plaintext_buf) = match spawn_result {
            Ok(res) => res,
            Err(join_err) => {
                return Err((
                    SocketError::Crypto(format!("spawn_blocking task failed: {}", join_err)),
                    Vec::new(),
                    out_buf,
                ));
            }
        };

        let ciphertext = match ciphertext_result {
            Ok(c) => c,
            Err(e) => return Err((SocketError::Crypto(e.to_string()), plaintext_buf, out_buf)),
        };

        out_buf.clear();
        out_buf.extend_from_slice(&ciphertext);
        plaintext_buf.clear();

        let framed = match crate::framing::encode_frame(&out_buf, None) {
            Ok(f) => f,
            Err(e) => return Err((SocketError::Crypto(e.to_string()), plaintext_buf, out_buf)),
        };

        if let Err(e) = self.transport.send(&framed).await {
            return Err((SocketError::Crypto(e.to_string()), plaintext_buf, out_buf));
        }

        out_buf.clear();
        Ok((plaintext_buf, out_buf))
    }

    pub fn decrypt_frame(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.read_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        self.read_key
            .decrypt(iv.as_ref().into(), ciphertext)
            .map_err(|e| SocketError::Crypto(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore::aes_gcm::{Aes256Gcm, KeyInit};

    #[tokio::test]
    async fn test_encrypt_and_send_returns_both_buffers() {
        // Create a mock transport
        let transport = Arc::new(crate::transport::mock::MockTransport);

        // Create dummy keys for testing
        let key = [0u8; 32];
        let write_key = Aes256Gcm::new_from_slice(&key).unwrap();
        let read_key = Aes256Gcm::new_from_slice(&key).unwrap();

        let socket = NoiseSocket::new(transport, write_key, read_key);

        // Create buffers with some initial capacity
        let plaintext_buf = Vec::with_capacity(1024);
        let encrypted_buf = Vec::with_capacity(1024);

        // Store the capacities for verification
        let plaintext_capacity = plaintext_buf.capacity();
        let encrypted_capacity = encrypted_buf.capacity();

        // Call encrypt_and_send - this should return both buffers
        let result = socket.encrypt_and_send(plaintext_buf, encrypted_buf).await;

        assert!(result.is_ok(), "encrypt_and_send should succeed");

        let (returned_plaintext, returned_encrypted) = result.unwrap();

        // Verify both buffers are returned
        assert_eq!(
            returned_plaintext.capacity(),
            plaintext_capacity,
            "Plaintext buffer should maintain its capacity"
        );
        assert_eq!(
            returned_encrypted.capacity(),
            encrypted_capacity,
            "Encrypted buffer should maintain its capacity"
        );

        // Verify buffers are cleared
        assert!(
            returned_plaintext.is_empty(),
            "Returned plaintext buffer should be cleared"
        );
        assert!(
            returned_encrypted.is_empty(),
            "Returned encrypted buffer should be cleared"
        );
    }
}
