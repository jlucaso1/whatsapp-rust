use crate::socket::error::{EncryptSendError, Result, SocketError};
use crate::transport::Transport;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use wacore::aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadInPlace},
};
use wacore::handshake::utils::generate_iv;

const INLINE_ENCRYPT_THRESHOLD: usize = 16 * 1024;

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
        out.extend_from_slice(plaintext);
        let counter = self.write_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        self.write_key
            .encrypt_in_place(iv.as_ref().into(), b"", out)
            .map_err(|e| SocketError::Crypto(e.to_string()))?;
        Ok(out.as_slice())
    }

    pub async fn encrypt_and_send(
        &self,
        mut plaintext_buf: Vec<u8>,
        mut out_buf: Vec<u8>,
    ) -> std::result::Result<(Vec<u8>, Vec<u8>), EncryptSendError> {
        // For small messages, encrypt in-place in out_buf to avoid allocation
        if plaintext_buf.len() <= INLINE_ENCRYPT_THRESHOLD {
            // Copy plaintext to out_buf and encrypt in-place
            out_buf.clear();
            out_buf.extend_from_slice(&plaintext_buf);
            plaintext_buf.clear();

            let counter = self.write_counter.fetch_add(1, Ordering::SeqCst);
            let iv = generate_iv(counter);
            if let Err(e) = self
                .write_key
                .encrypt_in_place(iv.as_ref().into(), b"", &mut out_buf)
            {
                return Err(EncryptSendError::crypto(
                    anyhow::anyhow!(e.to_string()),
                    plaintext_buf,
                    out_buf,
                ));
            }

            // Frame the ciphertext - we need a temporary copy since encode_frame_into
            // clears the output buffer
            let ciphertext_len = out_buf.len();
            plaintext_buf.extend_from_slice(&out_buf);
            out_buf.clear();
            if let Err(e) = crate::framing::encode_frame_into(
                &plaintext_buf[..ciphertext_len],
                None,
                &mut out_buf,
            ) {
                plaintext_buf.clear();
                return Err(EncryptSendError::framing(e, plaintext_buf, out_buf));
            }
            plaintext_buf.clear();
        } else {
            // Offload larger messages to a blocking thread
            let write_key = self.write_key.clone();
            let counter = self.write_counter.fetch_add(1, Ordering::SeqCst);

            let plaintext_arc = Arc::new(plaintext_buf);
            let plaintext_arc_for_task = plaintext_arc.clone();

            let spawn_result = tokio::task::spawn_blocking(move || {
                let iv = generate_iv(counter);
                write_key.encrypt(iv.as_ref().into(), &plaintext_arc_for_task[..])
            })
            .await;

            plaintext_buf = Arc::try_unwrap(plaintext_arc).unwrap_or_else(|arc| (*arc).clone());

            let ciphertext = match spawn_result {
                Ok(Ok(c)) => c,
                Ok(Err(e)) => {
                    return Err(EncryptSendError::crypto(
                        anyhow::anyhow!(e.to_string()),
                        plaintext_buf,
                        out_buf,
                    ));
                }
                Err(join_err) => {
                    return Err(EncryptSendError::join(join_err, plaintext_buf, out_buf));
                }
            };

            plaintext_buf.clear();
            out_buf.clear();
            if let Err(e) = crate::framing::encode_frame_into(&ciphertext, None, &mut out_buf) {
                return Err(EncryptSendError::framing(e, plaintext_buf, out_buf));
            }
        }

        if let Err(e) = self.transport.send(&out_buf).await {
            return Err(EncryptSendError::transport(e, plaintext_buf, out_buf));
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
