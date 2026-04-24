use crate::socket::error::{EncryptSendError, Result, SocketError};
use crate::transport::Transport;
use async_channel;
use bytes::BytesMut;
use futures::channel::oneshot;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use wacore::handshake::NoiseCipher;
use wacore::runtime::{AbortHandle, Runtime};

const INLINE_ENCRYPT_THRESHOLD: usize = 16 * 1024;

/// Result type for send operations.
type SendResult = std::result::Result<(), EncryptSendError>;

/// A job sent to the dedicated sender task.
struct SendJob {
    plaintext: bytes::Bytes,
    response_tx: oneshot::Sender<SendResult>,
}

pub struct NoiseSocket {
    read_key: Arc<NoiseCipher>,
    read_counter: Arc<AtomicU32>,
    /// Channel to send jobs to the dedicated sender task.
    /// Using a channel instead of a mutex avoids blocking callers while
    /// the current send is in progress - they can enqueue their work and
    /// await the result without holding a lock.
    send_job_tx: async_channel::Sender<SendJob>,
    /// Handle to the sender task. Aborted on drop to prevent resource leaks
    /// if the task is stuck on a slow/hanging network operation.
    _sender_task_handle: AbortHandle,
}

impl NoiseSocket {
    pub fn new(
        runtime: Arc<dyn Runtime>,
        transport: Arc<dyn Transport>,
        write_key: NoiseCipher,
        read_key: NoiseCipher,
    ) -> Self {
        let write_key = Arc::new(write_key);
        let read_key = Arc::new(read_key);

        // Small buffer matched to typical steady-state throughput; the sender
        // task is network-bound (awaits `transport.send`), so a transient
        // WebSocket stall will backpressure producers here rather than queue.
        let (send_job_tx, send_job_rx) = async_channel::bounded::<SendJob>(8);

        // Spawn the dedicated sender task
        let transport_clone = transport.clone();
        let write_key_clone = write_key.clone();
        let rt_clone = runtime.clone();
        let sender_task_handle = runtime.spawn(Box::pin(Self::sender_task(
            rt_clone,
            transport_clone,
            write_key_clone,
            send_job_rx,
        )));

        Self {
            read_key,
            read_counter: Arc::new(AtomicU32::new(0)),
            send_job_tx,
            _sender_task_handle: sender_task_handle,
        }
    }

    /// Dedicated sender task that processes send jobs sequentially.
    /// This ensures frames are sent in counter order without requiring a mutex.
    /// The task owns the write counter and processes jobs one at a time.
    async fn sender_task(
        runtime: Arc<dyn Runtime>,
        transport: Arc<dyn Transport>,
        write_key: Arc<NoiseCipher>,
        send_job_rx: async_channel::Receiver<SendJob>,
    ) {
        let mut write_counter: u32 = 0;
        let mut enc_buf = Vec::with_capacity(4096);
        // BytesMut: split().freeze() yields a zero-copy Bytes while retaining
        // the underlying allocation for the next frame.
        let mut out_buf = BytesMut::with_capacity(4096);

        while let Ok(job) = send_job_rx.recv().await {
            let result = Self::process_send_job(
                &runtime,
                &transport,
                &write_key,
                &mut write_counter,
                &job.plaintext,
                &mut enc_buf,
                &mut out_buf,
            )
            .await;

            let _ = job.response_tx.send(result);
        }
    }

    /// Process a single send job: encrypt and send the message.
    async fn process_send_job(
        runtime: &Arc<dyn Runtime>,
        transport: &Arc<dyn Transport>,
        write_key: &Arc<NoiseCipher>,
        write_counter: &mut u32,
        plaintext: &[u8],
        enc_buf: &mut Vec<u8>,
        out_buf: &mut BytesMut,
    ) -> SendResult {
        let counter = *write_counter;

        if plaintext.len() <= INLINE_ENCRYPT_THRESHOLD {
            enc_buf.clear();
            enc_buf.extend_from_slice(plaintext);
            if let Err(e) = write_key.encrypt_in_place_with_counter(counter, enc_buf) {
                return Err(EncryptSendError::crypto(anyhow::anyhow!(e.to_string())));
            }

            if let Err(e) = wacore::framing::encode_frame_into(enc_buf, None, out_buf) {
                return Err(EncryptSendError::framing(e));
            }
        } else {
            let write_key = write_key.clone();
            let plaintext_owned = plaintext.to_vec();

            let encrypt_result = wacore::runtime::blocking(&**runtime, move || {
                write_key.encrypt_with_counter(counter, &plaintext_owned)
            })
            .await;

            let ciphertext = match encrypt_result {
                Ok(c) => c,
                Err(e) => {
                    return Err(EncryptSendError::crypto(anyhow::anyhow!(e.to_string())));
                }
            };

            if let Err(e) = wacore::framing::encode_frame_into(&ciphertext, None, out_buf) {
                return Err(EncryptSendError::framing(e));
            }
        }

        // Zero-copy: split() moves the written data into a new BytesMut,
        // freeze() converts it to Bytes. The original out_buf retains its
        // allocated capacity for the next frame.
        let frame = out_buf.split().freeze();
        if let Err(e) = transport.send(frame).await {
            return Err(EncryptSendError::transport(e));
        }

        *write_counter = write_counter.wrapping_add(1);

        Ok(())
    }

    pub async fn encrypt_and_send(&self, plaintext: bytes::Bytes) -> SendResult {
        let (response_tx, response_rx) = oneshot::channel();

        let job = SendJob {
            plaintext,
            response_tx,
        };

        // Send job to the sender task. If channel is closed, sender task has stopped.
        if let Err(_send_err) = self.send_job_tx.send(job).await {
            return Err(EncryptSendError::channel_closed());
        }

        // Wait for the sender task to process our job and return the result
        match response_rx.await {
            Ok(result) => result,
            Err(_) => {
                // Sender task dropped without sending a response
                Err(EncryptSendError::channel_closed())
            }
        }
    }

    pub fn decrypt_frame(&self, mut ciphertext: BytesMut) -> Result<BytesMut> {
        let counter = self.read_counter.fetch_add(1, Ordering::SeqCst);
        self.read_key
            .decrypt_in_place_with_counter(counter, &mut ciphertext)
            .map_err(|e| SocketError::Crypto(e.to_string()))?;
        Ok(ciphertext)
    }
}

// AbortHandle aborts the sender task on drop automatically, so no manual
// Drop impl is needed — the `sender_task_handle` field's own Drop does the work.

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_encrypt_and_send_succeeds() {
        let transport = Arc::new(crate::transport::mock::MockTransport);

        let key = [0u8; 32];
        let write_key = NoiseCipher::new(&key).expect("32-byte key should be valid");
        let read_key = NoiseCipher::new(&key).expect("32-byte key should be valid");

        let socket = NoiseSocket::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            transport,
            write_key,
            read_key,
        );

        let result = socket.encrypt_and_send(bytes::Bytes::new()).await;
        assert!(result.is_ok(), "encrypt_and_send should succeed");
    }

    #[tokio::test]
    async fn test_concurrent_sends_maintain_order() {
        use async_lock::Mutex;
        use async_trait::async_trait;
        use std::sync::Arc;

        // Create a mock transport that records the order of sends by decrypting
        // the first byte (which contains the task index)
        struct RecordingTransport {
            recorded_order: Arc<Mutex<Vec<u8>>>,
            read_key: NoiseCipher,
            counter: std::sync::atomic::AtomicU32,
        }

        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        impl crate::transport::Transport for RecordingTransport {
            async fn send(&self, data: bytes::Bytes) -> std::result::Result<(), anyhow::Error> {
                if data.len() > 16 {
                    let mut data = data.to_vec();
                    // Strip the 3-byte frame header, then decrypt in place
                    data.drain(..3);
                    let counter = self
                        .counter
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

                    if self
                        .read_key
                        .decrypt_in_place_with_counter(counter, &mut data)
                        .is_ok()
                        && !data.is_empty()
                    {
                        let index = data[0];
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

        let socket = Arc::new(NoiseSocket::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            transport,
            write_key,
            read_key,
        ));

        // Spawn multiple concurrent sends with their indices
        let mut handles = Vec::new();
        for i in 0..10 {
            let socket = socket.clone();
            handles.push(tokio::spawn(async move {
                // Use index as the first byte of plaintext to identify this send
                let mut plaintext = vec![i as u8];
                plaintext.extend_from_slice(&[0u8; 99]);
                socket.encrypt_and_send(bytes::Bytes::from(plaintext)).await
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

        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        impl crate::transport::Transport for SizeRecordingTransport {
            async fn send(&self, data: bytes::Bytes) -> std::result::Result<(), anyhow::Error> {
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

        let socket = NoiseSocket::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            transport,
            write_key,
            read_key,
        );

        // Test various payload sizes: tiny, small, medium, large, very large
        let test_sizes = [0, 1, 50, 100, 500, 1000, 1024, 2000, 5000, 16384, 20000];

        for size in test_sizes {
            let plaintext = vec![0xABu8; size];
            let result = socket
                .encrypt_and_send(bytes::Bytes::from(plaintext.clone()))
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
        }
    }

    /// Tests edge cases for buffer sizing
    #[tokio::test]
    async fn test_encrypted_buffer_sizing_edge_cases() {
        use async_trait::async_trait;
        use std::sync::Arc;

        struct NoOpTransport;

        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        impl crate::transport::Transport for NoOpTransport {
            async fn send(&self, _data: bytes::Bytes) -> std::result::Result<(), anyhow::Error> {
                Ok(())
            }
            async fn disconnect(&self) {}
        }

        let transport = Arc::new(NoOpTransport);
        let key = [0u8; 32];
        let write_key = NoiseCipher::new(&key).expect("32-byte key should be valid");
        let read_key = NoiseCipher::new(&key).expect("32-byte key should be valid");

        let socket = NoiseSocket::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            transport,
            write_key,
            read_key,
        );

        // Test empty payload
        let result = socket.encrypt_and_send(bytes::Bytes::new()).await;
        assert!(result.is_ok(), "Empty payload should encrypt successfully");

        // Test payload at inline threshold boundary (16KB)
        let at_threshold = bytes::Bytes::from(vec![0u8; 16 * 1024]);
        let result = socket.encrypt_and_send(at_threshold).await;
        assert!(
            result.is_ok(),
            "Payload at inline threshold should encrypt successfully"
        );

        // Test payload just above inline threshold
        let above_threshold = bytes::Bytes::from(vec![0u8; 16 * 1024 + 1]);
        let result = socket.encrypt_and_send(above_threshold).await;
        assert!(
            result.is_ok(),
            "Payload above inline threshold should encrypt successfully"
        );
    }
}
