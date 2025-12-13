use crate::socket::error::{EncryptSendError, Result, SocketError};
use crate::transport::Transport;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use wacore::aes_gcm::{
    Aes256Gcm,
    aead::{Aead, AeadInPlace},
};
use wacore::handshake::utils::generate_iv;

const INLINE_ENCRYPT_THRESHOLD: usize = 16 * 1024;

/// Result type for send operations, returning both buffers for reuse.
type SendResult = std::result::Result<(Vec<u8>, Vec<u8>), EncryptSendError>;

/// A job sent to the dedicated sender task.
struct SendJob {
    plaintext_buf: Vec<u8>,
    out_buf: Vec<u8>,
    response_tx: oneshot::Sender<SendResult>,
}

pub struct NoiseSocket {
    read_key: Arc<Aes256Gcm>,
    read_counter: Arc<AtomicU32>,
    /// Channel to send jobs to the dedicated sender task.
    /// Using a channel instead of a mutex avoids blocking callers while
    /// the current send is in progress - they can enqueue their work and
    /// await the result without holding a lock.
    send_job_tx: mpsc::Sender<SendJob>,
    /// Handle to the sender task. Aborted on drop to prevent resource leaks
    /// if the task is stuck on a slow/hanging network operation.
    sender_task_handle: JoinHandle<()>,
}

impl NoiseSocket {
    pub fn new(transport: Arc<dyn Transport>, write_key: Aes256Gcm, read_key: Aes256Gcm) -> Self {
        let write_key = Arc::new(write_key);
        let read_key = Arc::new(read_key);

        // Create channel for send jobs. Buffer size of 32 allows multiple
        // callers to enqueue work without blocking on channel capacity.
        let (send_job_tx, send_job_rx) = mpsc::channel::<SendJob>(32);

        // Spawn the dedicated sender task
        let transport_clone = transport.clone();
        let write_key_clone = write_key.clone();
        let sender_task_handle = tokio::spawn(Self::sender_task(
            transport_clone,
            write_key_clone,
            send_job_rx,
        ));

        Self {
            read_key,
            read_counter: Arc::new(AtomicU32::new(0)),
            send_job_tx,
            sender_task_handle,
        }
    }

    /// Dedicated sender task that processes send jobs sequentially.
    /// This ensures frames are sent in counter order without requiring a mutex.
    /// The task owns the write counter and processes jobs one at a time.
    async fn sender_task(
        transport: Arc<dyn Transport>,
        write_key: Arc<Aes256Gcm>,
        mut send_job_rx: mpsc::Receiver<SendJob>,
    ) {
        let mut write_counter: u32 = 0;

        while let Some(job) = send_job_rx.recv().await {
            let result = Self::process_send_job(
                &transport,
                &write_key,
                &mut write_counter,
                job.plaintext_buf,
                job.out_buf,
            )
            .await;

            // Send result back to caller. Ignore error if receiver was dropped.
            let _ = job.response_tx.send(result);
        }

        // Channel closed - NoiseSocket was dropped, task exits naturally
    }

    /// Process a single send job: encrypt and send the message.
    async fn process_send_job(
        transport: &Arc<dyn Transport>,
        write_key: &Arc<Aes256Gcm>,
        write_counter: &mut u32,
        mut plaintext_buf: Vec<u8>,
        mut out_buf: Vec<u8>,
    ) -> SendResult {
        let counter = *write_counter;
        *write_counter = write_counter.wrapping_add(1);

        // For small messages, encrypt in-place in out_buf to avoid allocation
        if plaintext_buf.len() <= INLINE_ENCRYPT_THRESHOLD {
            // Copy plaintext to out_buf and encrypt in-place
            out_buf.clear();
            out_buf.extend_from_slice(&plaintext_buf);
            plaintext_buf.clear();

            let iv = generate_iv(counter);
            if let Err(e) = write_key.encrypt_in_place(iv.as_ref().into(), b"", &mut out_buf) {
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
            let write_key = write_key.clone();

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

        if let Err(e) = transport.send(&out_buf).await {
            return Err(EncryptSendError::transport(e, plaintext_buf, out_buf));
        }

        out_buf.clear();
        Ok((plaintext_buf, out_buf))
    }

    pub async fn encrypt_and_send(&self, plaintext_buf: Vec<u8>, out_buf: Vec<u8>) -> SendResult {
        let (response_tx, response_rx) = oneshot::channel();

        let job = SendJob {
            plaintext_buf,
            out_buf,
            response_tx,
        };

        // Send job to the sender task. If channel is closed, sender task has stopped.
        if let Err(send_err) = self.send_job_tx.send(job).await {
            // Recover the buffers from the failed send job so caller can reuse them
            let job = send_err.0;
            return Err(EncryptSendError::channel_closed(
                job.plaintext_buf,
                job.out_buf,
            ));
        }

        // Wait for the sender task to process our job and return the result
        match response_rx.await {
            Ok(result) => result,
            Err(_) => {
                // Sender task dropped without sending a response
                Err(EncryptSendError::channel_closed(Vec::new(), Vec::new()))
            }
        }
    }

    pub fn decrypt_frame(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let counter = self.read_counter.fetch_add(1, Ordering::SeqCst);
        let iv = generate_iv(counter);
        self.read_key
            .decrypt(iv.as_ref().into(), ciphertext)
            .map_err(|e| SocketError::Crypto(e.to_string()))
    }
}

impl Drop for NoiseSocket {
    fn drop(&mut self) {
        // Abort the sender task to prevent resource leaks if it's stuck
        // on a slow/hanging network operation. This ensures cleanup even
        // if transport.send() never returns.
        self.sender_task_handle.abort();
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

    #[tokio::test]
    async fn test_concurrent_sends_maintain_order() {
        use async_trait::async_trait;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        // Create a mock transport that records the order of sends by decrypting
        // the first byte (which contains the task index)
        struct RecordingTransport {
            recorded_order: Arc<Mutex<Vec<u8>>>,
            read_key: Aes256Gcm,
            counter: std::sync::atomic::AtomicU32,
        }

        #[async_trait]
        impl crate::transport::Transport for RecordingTransport {
            async fn send(&self, data: &[u8]) -> std::result::Result<(), anyhow::Error> {
                // Decrypt the data to extract the index (first byte of plaintext)
                if data.len() > 16 {
                    // Skip the noise frame header (3 bytes for length)
                    let ciphertext = &data[3..];
                    let counter = self
                        .counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let iv = super::generate_iv(counter);

                    if let Ok(plaintext) = self.read_key.decrypt(iv.as_ref().into(), ciphertext)
                        && !plaintext.is_empty()
                    {
                        let index = plaintext[0];
                        let mut order = self.recorded_order.lock().await;
                        order.push(index);
                    }
                }
                Ok(())
            }

            async fn disconnect(&self) {}
        }

        let recorded_order = Arc::new(Mutex::new(Vec::new()));
        let key = [0u8; 32];
        let write_key = Aes256Gcm::new_from_slice(&key).unwrap();
        let read_key = Aes256Gcm::new_from_slice(&key).unwrap();

        let transport = Arc::new(RecordingTransport {
            recorded_order: recorded_order.clone(),
            read_key: Aes256Gcm::new_from_slice(&key).unwrap(),
            counter: std::sync::atomic::AtomicU32::new(0),
        });

        let socket = Arc::new(NoiseSocket::new(transport, write_key, read_key));

        // Spawn multiple concurrent sends with their indices
        let mut handles = Vec::new();
        for i in 0..10 {
            let socket = socket.clone();
            handles.push(tokio::spawn(async move {
                // Use index as the first byte of plaintext to identify this send
                let mut plaintext = vec![i as u8];
                plaintext.extend_from_slice(&[0u8; 99]);
                let out_buf = Vec::with_capacity(256);
                socket.encrypt_and_send(plaintext, out_buf).await
            }));
        }

        // Wait for all sends to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "All sends should succeed");
        }

        // Verify all sends completed in FIFO order (0, 1, 2, ..., 9)
        let order = recorded_order.lock().await;
        let expected: Vec<u8> = (0..10).collect();
        assert_eq!(*order, expected, "Sends should maintain FIFO order");
    }
}
