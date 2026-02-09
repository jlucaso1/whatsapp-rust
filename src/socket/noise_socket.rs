use crate::socket::error::{EncryptSendError, Result, SocketError};
use crate::transport::Transport;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use wacore::handshake::NoiseCipher;

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
    read_key: Arc<NoiseCipher>,
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
    pub fn new(
        transport: Arc<dyn Transport>,
        write_key: NoiseCipher,
        read_key: NoiseCipher,
    ) -> Self {
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
        write_key: Arc<NoiseCipher>,
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
        write_key: &Arc<NoiseCipher>,
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

            if let Err(e) = write_key.encrypt_in_place_with_counter(counter, &mut out_buf) {
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
            if let Err(e) = wacore::framing::encode_frame_into(
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
                write_key.encrypt_with_counter(counter, &plaintext_arc_for_task[..])
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
            if let Err(e) = wacore::framing::encode_frame_into(&ciphertext, None, &mut out_buf) {
                return Err(EncryptSendError::framing(e, plaintext_buf, out_buf));
            }
        }

        if let Err(e) = transport.send(out_buf).await {
            return Err(EncryptSendError::transport(e, plaintext_buf, Vec::new()));
        }

        Ok((plaintext_buf, Vec::new()))
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
        self.read_key
            .decrypt_with_counter(counter, ciphertext)
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

    #[tokio::test]
    async fn test_encrypt_and_send_returns_both_buffers() {
        // Create a mock transport
        let transport = Arc::new(crate::transport::mock::MockTransport);

        // Create dummy keys for testing
        let key = [0u8; 32];
        let write_key = NoiseCipher::new(&key).expect("32-byte key should be valid");
        let read_key = NoiseCipher::new(&key).expect("32-byte key should be valid");

        let socket = NoiseSocket::new(transport, write_key, read_key);

        let plaintext_buf = Vec::with_capacity(1024);
        let encrypted_buf = Vec::with_capacity(1024);
        let plaintext_capacity = plaintext_buf.capacity();

        let result = socket.encrypt_and_send(plaintext_buf, encrypted_buf).await;
        assert!(result.is_ok(), "encrypt_and_send should succeed");

        let (returned_plaintext, returned_encrypted) = result.unwrap();

        assert_eq!(
            returned_plaintext.capacity(),
            plaintext_capacity,
            "Plaintext buffer should maintain its capacity"
        );
        assert!(
            returned_encrypted.is_empty(),
            "Encrypted buffer is moved to transport (zero-copy)"
        );
        assert!(
            returned_plaintext.is_empty(),
            "Returned plaintext buffer should be cleared"
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
            read_key: NoiseCipher,
            counter: std::sync::atomic::AtomicU32,
        }

        #[async_trait]
        impl crate::transport::Transport for RecordingTransport {
            async fn send(&self, data: Vec<u8>) -> std::result::Result<(), anyhow::Error> {
                // Decrypt the data to extract the index (first byte of plaintext)
                if data.len() > 16 {
                    // Skip the noise frame header (3 bytes for length)
                    let ciphertext = &data[3..];
                    let counter = self
                        .counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                    if let Ok(plaintext) = self.read_key.decrypt_with_counter(counter, ciphertext)
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
        let write_key = NoiseCipher::new(&key).expect("32-byte key should be valid");
        let read_key = NoiseCipher::new(&key).expect("32-byte key should be valid");

        let transport = Arc::new(RecordingTransport {
            recorded_order: recorded_order.clone(),
            read_key: NoiseCipher::new(&key).expect("32-byte key should be valid"),
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
            let result = handle.await.expect("task should complete");
            assert!(result.is_ok(), "All sends should succeed");
        }

        // Verify all sends completed in FIFO order (0, 1, 2, ..., 9)
        let order = recorded_order.lock().await;
        let expected: Vec<u8> = (0..10).collect();
        assert_eq!(*order, expected, "Sends should maintain FIFO order");
    }

    /// Tests that the encrypted buffer sizing formula (plaintext.len() + 32) is sufficient.
    /// This verifies the optimization in client.rs that sizes the buffer based on payload.
    #[tokio::test]
    async fn test_encrypted_buffer_sizing_is_sufficient() {
        use async_trait::async_trait;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        // Transport that records the actual encrypted data size
        struct SizeRecordingTransport {
            last_size: Arc<AtomicUsize>,
        }

        #[async_trait]
        impl crate::transport::Transport for SizeRecordingTransport {
            async fn send(&self, data: Vec<u8>) -> std::result::Result<(), anyhow::Error> {
                self.last_size.store(data.len(), Ordering::SeqCst);
                Ok(())
            }
            async fn disconnect(&self) {}
        }

        let last_size = Arc::new(AtomicUsize::new(0));
        let transport = Arc::new(SizeRecordingTransport {
            last_size: last_size.clone(),
        });

        let key = [0u8; 32];
        let write_key = NoiseCipher::new(&key).expect("32-byte key should be valid");
        let read_key = NoiseCipher::new(&key).expect("32-byte key should be valid");

        let socket = NoiseSocket::new(transport, write_key, read_key);

        // Test various payload sizes: tiny, small, medium, large, very large
        let test_sizes = [0, 1, 50, 100, 500, 1000, 1024, 2000, 5000, 16384, 20000];

        for size in test_sizes {
            let plaintext = vec![0xABu8; size];
            // This is the formula used in client.rs
            let buffer_capacity = plaintext.len() + 32;
            let encrypted_buf = Vec::with_capacity(buffer_capacity);

            let result = socket
                .encrypt_and_send(plaintext.clone(), encrypted_buf)
                .await;

            assert!(
                result.is_ok(),
                "encrypt_and_send should succeed for payload size {}",
                size
            );

            let actual_encrypted_size = last_size.load(Ordering::SeqCst);

            // Verify the actual encrypted size fits within our allocated capacity
            // Encrypted size = plaintext + 16 (AES-GCM tag) + 3 (frame header) = plaintext + 19
            let expected_max = size + 19;
            assert_eq!(
                actual_encrypted_size, expected_max,
                "Encrypted size for {} byte payload should be {} (got {})",
                size, expected_max, actual_encrypted_size
            );

            // Verify our buffer sizing formula provides enough capacity
            assert!(
                buffer_capacity >= actual_encrypted_size,
                "Buffer capacity {} should be >= encrypted size {} for payload size {}",
                buffer_capacity,
                actual_encrypted_size,
                size
            );
        }
    }

    /// Tests edge cases for buffer sizing
    #[tokio::test]
    async fn test_encrypted_buffer_sizing_edge_cases() {
        use async_trait::async_trait;
        use std::sync::Arc;

        struct NoOpTransport;

        #[async_trait]
        impl crate::transport::Transport for NoOpTransport {
            async fn send(&self, _data: Vec<u8>) -> std::result::Result<(), anyhow::Error> {
                Ok(())
            }
            async fn disconnect(&self) {}
        }

        let transport = Arc::new(NoOpTransport);
        let key = [0u8; 32];
        let write_key = NoiseCipher::new(&key).expect("32-byte key should be valid");
        let read_key = NoiseCipher::new(&key).expect("32-byte key should be valid");

        let socket = NoiseSocket::new(transport, write_key, read_key);

        // Test empty payload
        let result = socket
            .encrypt_and_send(vec![], Vec::with_capacity(32))
            .await;
        assert!(result.is_ok(), "Empty payload should encrypt successfully");

        // Test payload at inline threshold boundary (16KB)
        let at_threshold = vec![0u8; 16 * 1024];
        let result = socket
            .encrypt_and_send(at_threshold, Vec::with_capacity(16 * 1024 + 32))
            .await;
        assert!(
            result.is_ok(),
            "Payload at inline threshold should encrypt successfully"
        );

        // Test payload just above inline threshold
        let above_threshold = vec![0u8; 16 * 1024 + 1];
        let result = socket
            .encrypt_and_send(above_threshold, Vec::with_capacity(16 * 1024 + 33))
            .await;
        assert!(
            result.is_ok(),
            "Payload above inline threshold should encrypt successfully"
        );
    }
}
