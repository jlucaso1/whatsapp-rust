use crate::socket::error::{EncryptSendError, Result, SocketError};
use crate::transport::Transport;
use std::cmp::Reverse;
use std::collections::BinaryHeap;
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
const DEFAULT_REORDER_BUFFER_SIZE: usize = 64;
const DEFAULT_NUM_WORKERS: usize = 4;

/// Result type for send operations, returning both buffers for reuse.
type SendResult = std::result::Result<(Vec<u8>, Vec<u8>), EncryptSendError>;

/// Job for encryption workers - counter is pre-assigned atomically.
struct EncryptJob {
    counter: u32,
    plaintext_buf: Vec<u8>,
    out_buf: Vec<u8>,
    response_tx: oneshot::Sender<SendResult>,
}

/// Encrypted frame ready for ordered sending.
/// The encrypted data is stored inline in `out_buf` to avoid cloning.
struct EncryptedFrame {
    counter: u32,
    /// Encryption error if any (None = success, data is in out_buf).
    error: Option<EncryptSendError>,
    response_tx: oneshot::Sender<SendResult>,
    /// Original plaintext buffer to return to caller (cleared).
    plaintext_buf: Vec<u8>,
    /// Contains encrypted data on success, to be sent then cleared for reuse.
    out_buf: Vec<u8>,
}

impl PartialEq for EncryptedFrame {
    fn eq(&self, other: &Self) -> bool {
        self.counter == other.counter
    }
}

impl Eq for EncryptedFrame {}

impl PartialOrd for EncryptedFrame {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EncryptedFrame {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.counter.cmp(&other.counter)
    }
}

/// Reorder buffer that collects encrypted frames and drains them in counter order.
/// Uses a min-heap (via Reverse) to efficiently find the next frame to send.
struct ReorderBuffer {
    heap: BinaryHeap<Reverse<EncryptedFrame>>,
    next_to_send: u32,
    max_size: usize,
}

impl ReorderBuffer {
    fn new(max_size: usize) -> Self {
        Self {
            heap: BinaryHeap::new(),
            next_to_send: 0,
            max_size,
        }
    }

    /// Insert a frame and drain all consecutive frames starting from next_to_send.
    fn insert(&mut self, frame: EncryptedFrame) -> Vec<EncryptedFrame> {
        self.heap.push(Reverse(frame));
        self.drain_ready()
    }

    /// Drain all consecutive frames starting from next_to_send.
    fn drain_ready(&mut self) -> Vec<EncryptedFrame> {
        let mut ready = Vec::new();

        while let Some(Reverse(frame)) = self.heap.peek() {
            if frame.counter == self.next_to_send {
                let Reverse(frame) = self.heap.pop().unwrap();
                self.next_to_send = self.next_to_send.wrapping_add(1);
                ready.push(frame);
            } else {
                break;
            }
        }

        ready
    }

    /// Check if the buffer is at capacity.
    #[allow(dead_code)]
    fn is_full(&self) -> bool {
        self.heap.len() >= self.max_size
    }

    /// Drain all remaining frames (for cleanup on disconnect).
    fn drain_all(&mut self) -> Vec<EncryptedFrame> {
        let mut all = Vec::with_capacity(self.heap.len());
        while let Some(Reverse(frame)) = self.heap.pop() {
            all.push(frame);
        }
        all
    }
}

pub struct NoiseSocket {
    read_key: Arc<Aes256Gcm>,
    read_counter: Arc<AtomicU32>,
    /// Atomic counter for pre-assigning counters to encryption jobs.
    /// Counter is assigned FIRST (like WhatsApp Web JS), before queueing the job.
    write_counter: Arc<AtomicU32>,
    /// Channel to send encryption jobs to the orchestrator.
    encrypt_job_tx: mpsc::Sender<EncryptJob>,
    /// Handle to the orchestrator task. Aborted on drop.
    orchestrator_handle: JoinHandle<()>,
}

impl NoiseSocket {
    pub fn new(transport: Arc<dyn Transport>, write_key: Aes256Gcm, read_key: Aes256Gcm) -> Self {
        let write_key = Arc::new(write_key);
        let read_key = Arc::new(read_key);

        // Channel for incoming encryption jobs from encrypt_and_send()
        let (encrypt_job_tx, encrypt_job_rx) = mpsc::channel::<EncryptJob>(32);

        // Spawn the orchestrator that manages parallel encryption and ordered sending
        let orchestrator_handle = tokio::spawn(Self::orchestrator_task(
            transport,
            write_key,
            encrypt_job_rx,
            DEFAULT_NUM_WORKERS,
            DEFAULT_REORDER_BUFFER_SIZE,
        ));

        Self {
            read_key,
            read_counter: Arc::new(AtomicU32::new(0)),
            write_counter: Arc::new(AtomicU32::new(0)),
            encrypt_job_tx,
            orchestrator_handle,
        }
    }

    /// Orchestrator task that coordinates parallel encryption and ordered sending.
    ///
    /// Architecture:
    /// 1. Receives jobs with pre-assigned counters from encrypt_and_send()
    /// 2. Distributes jobs to N encryption workers (parallel encryption)
    /// 3. Collects encrypted frames and reorders them by counter
    /// 4. Sends frames in strict counter order (required by Noise protocol)
    async fn orchestrator_task(
        transport: Arc<dyn Transport>,
        write_key: Arc<Aes256Gcm>,
        mut job_rx: mpsc::Receiver<EncryptJob>,
        num_workers: usize,
        max_reorder_buffer: usize,
    ) {
        // Channel for distributing jobs to workers
        let (worker_tx, worker_rx) = async_channel::bounded::<EncryptJob>(num_workers * 2);
        // Channel for receiving encrypted frames from workers
        let (encrypted_tx, mut encrypted_rx) = mpsc::channel::<EncryptedFrame>(num_workers * 2);

        // Spawn encryption workers
        let mut worker_handles = Vec::with_capacity(num_workers);
        for _ in 0..num_workers {
            let worker_rx = worker_rx.clone();
            let encrypted_tx = encrypted_tx.clone();
            let write_key = write_key.clone();

            worker_handles.push(tokio::spawn(Self::encryption_worker(
                write_key,
                worker_rx,
                encrypted_tx,
            )));
        }
        // Drop our clone so workers can detect shutdown
        drop(encrypted_tx);

        let mut reorder_buffer = ReorderBuffer::new(max_reorder_buffer);

        loop {
            tokio::select! {
                // Receive new jobs and forward to workers
                job = job_rx.recv() => {
                    match job {
                        Some(job) => {
                            if worker_tx.send(job).await.is_err() {
                                // All workers died, exit
                                break;
                            }
                        }
                        None => {
                            // encrypt_and_send channel closed, start shutdown
                            break;
                        }
                    }
                }
                // Receive encrypted frames from workers
                Some(frame) = encrypted_rx.recv() => {
                    // Insert into reorder buffer and send any consecutive ready frames
                    for ready_frame in reorder_buffer.insert(frame) {
                        Self::send_frame(&transport, ready_frame).await;
                    }
                }
            }
        }

        // Graceful shutdown: close worker channel and drain remaining frames
        drop(worker_tx);

        // Wait for workers to finish and collect remaining encrypted frames
        while let Some(frame) = encrypted_rx.recv().await {
            for ready_frame in reorder_buffer.insert(frame) {
                Self::send_frame(&transport, ready_frame).await;
            }
        }

        // Notify any remaining buffered frames that we're shutting down
        for frame in reorder_buffer.drain_all() {
            let _ = frame.response_tx.send(Err(EncryptSendError::channel_closed(
                frame.plaintext_buf,
                frame.out_buf,
            )));
        }

        // Wait for all workers to complete
        for handle in worker_handles {
            let _ = handle.await;
        }
    }

    /// Send a frame to transport and notify the caller.
    async fn send_frame(transport: &Arc<dyn Transport>, mut frame: EncryptedFrame) {
        let result = match frame.error {
            Some(e) => Err(e),
            None => {
                // Encrypted data is in out_buf, send it
                if let Err(e) = transport.send(&frame.out_buf).await {
                    Err(EncryptSendError::transport(
                        e,
                        frame.plaintext_buf,
                        frame.out_buf,
                    ))
                } else {
                    // Clear buffers for reuse and return them
                    frame.out_buf.clear();
                    Ok((frame.plaintext_buf, frame.out_buf))
                }
            }
        };
        let _ = frame.response_tx.send(result);
    }

    /// Encryption worker that processes jobs in parallel.
    async fn encryption_worker(
        write_key: Arc<Aes256Gcm>,
        job_rx: async_channel::Receiver<EncryptJob>,
        encrypted_tx: mpsc::Sender<EncryptedFrame>,
    ) {
        while let Ok(job) = job_rx.recv().await {
            let (error, plaintext_buf, out_buf) =
                Self::encrypt_job(&write_key, job.counter, job.plaintext_buf, job.out_buf).await;

            let frame = EncryptedFrame {
                counter: job.counter,
                error,
                response_tx: job.response_tx,
                plaintext_buf,
                out_buf,
            };

            if encrypted_tx.send(frame).await.is_err() {
                // Orchestrator shut down
                break;
            }
        }
    }

    /// Encrypt a single job. Returns (error, plaintext_buf, out_buf).
    /// On success: error is None, encrypted data is in out_buf.
    /// On failure: error contains the error, buffers may be partially modified.
    async fn encrypt_job(
        write_key: &Arc<Aes256Gcm>,
        counter: u32,
        mut plaintext_buf: Vec<u8>,
        mut out_buf: Vec<u8>,
    ) -> (Option<EncryptSendError>, Vec<u8>, Vec<u8>) {
        // For small messages, encrypt in-place
        if plaintext_buf.len() <= INLINE_ENCRYPT_THRESHOLD {
            out_buf.clear();
            out_buf.extend_from_slice(&plaintext_buf);
            plaintext_buf.clear();

            let iv = generate_iv(counter);
            if let Err(e) = write_key.encrypt_in_place(iv.as_ref().into(), b"", &mut out_buf) {
                return (
                    Some(EncryptSendError::crypto(
                        anyhow::anyhow!(e.to_string()),
                        Vec::new(),
                        Vec::new(),
                    )),
                    plaintext_buf,
                    out_buf,
                );
            }

            // Frame the ciphertext - swap buffers to avoid allocation
            let ciphertext_len = out_buf.len();
            std::mem::swap(&mut plaintext_buf, &mut out_buf);
            out_buf.clear();
            if let Err(e) = wacore::framing::encode_frame_into(
                &plaintext_buf[..ciphertext_len],
                None,
                &mut out_buf,
            ) {
                plaintext_buf.clear();
                return (
                    Some(EncryptSendError::framing(e, Vec::new(), Vec::new())),
                    plaintext_buf,
                    out_buf,
                );
            }
            plaintext_buf.clear();

            // Success: encrypted data is in out_buf
            (None, plaintext_buf, out_buf)
        } else {
            // Offload larger messages to a blocking thread
            let write_key = write_key.clone();
            let plaintext_for_task = std::mem::take(&mut plaintext_buf);

            let spawn_result = tokio::task::spawn_blocking(move || {
                let iv = generate_iv(counter);
                let result = write_key.encrypt(iv.as_ref().into(), &plaintext_for_task[..]);
                (result, plaintext_for_task)
            })
            .await;

            let ciphertext = match spawn_result {
                Ok((Ok(c), returned_buf)) => {
                    plaintext_buf = returned_buf;
                    plaintext_buf.clear();
                    c
                }
                Ok((Err(e), returned_buf)) => {
                    plaintext_buf = returned_buf;
                    return (
                        Some(EncryptSendError::crypto(
                            anyhow::anyhow!(e.to_string()),
                            Vec::new(),
                            Vec::new(),
                        )),
                        plaintext_buf,
                        out_buf,
                    );
                }
                Err(join_err) => {
                    return (
                        Some(EncryptSendError::join(join_err, Vec::new(), Vec::new())),
                        plaintext_buf,
                        out_buf,
                    );
                }
            };

            out_buf.clear();
            if let Err(e) = wacore::framing::encode_frame_into(&ciphertext, None, &mut out_buf) {
                return (
                    Some(EncryptSendError::framing(e, Vec::new(), Vec::new())),
                    plaintext_buf,
                    out_buf,
                );
            }

            // Success: encrypted data is in out_buf
            (None, plaintext_buf, out_buf)
        }
    }

    pub async fn encrypt_and_send(&self, plaintext_buf: Vec<u8>, out_buf: Vec<u8>) -> SendResult {
        // 1. Atomically assign counter FIRST (like WhatsApp Web JS)
        let counter = self.write_counter.fetch_add(1, Ordering::SeqCst);

        let (response_tx, response_rx) = oneshot::channel();

        let job = EncryptJob {
            counter,
            plaintext_buf,
            out_buf,
            response_tx,
        };

        // 2. Submit job with pre-assigned counter
        if let Err(send_err) = self.encrypt_job_tx.send(job).await {
            let job = send_err.0;
            return Err(EncryptSendError::channel_closed(
                job.plaintext_buf,
                job.out_buf,
            ));
        }

        // 3. Wait for ordered send to complete
        match response_rx.await {
            Ok(result) => result,
            Err(_) => Err(EncryptSendError::channel_closed(Vec::new(), Vec::new())),
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
        // Abort the orchestrator task to prevent resource leaks if it's stuck
        // on a slow/hanging network operation. This ensures cleanup even
        // if transport.send() never returns.
        self.orchestrator_handle.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore::aes_gcm::{Aes256Gcm, KeyInit};

    // Helper to create a dummy EncryptedFrame for testing ReorderBuffer
    fn make_frame(counter: u32) -> EncryptedFrame {
        let (tx, _rx) = oneshot::channel();
        EncryptedFrame {
            counter,
            error: None,
            response_tx: tx,
            plaintext_buf: Vec::new(),
            out_buf: vec![counter as u8], // Encrypted data in out_buf
        }
    }

    #[test]
    fn test_reorder_buffer_in_order() {
        let mut buffer = ReorderBuffer::new(64);

        // Insert frames in order: 0, 1, 2
        let ready = buffer.insert(make_frame(0));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].counter, 0);

        let ready = buffer.insert(make_frame(1));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].counter, 1);

        let ready = buffer.insert(make_frame(2));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].counter, 2);
    }

    #[test]
    fn test_reorder_buffer_out_of_order() {
        let mut buffer = ReorderBuffer::new(64);

        // Insert frames out of order: 2, 0, 1
        let ready = buffer.insert(make_frame(2));
        assert!(ready.is_empty(), "Frame 2 should wait for 0 and 1");

        let ready = buffer.insert(make_frame(0));
        assert_eq!(ready.len(), 1, "Frame 0 should be ready");
        assert_eq!(ready[0].counter, 0);

        let ready = buffer.insert(make_frame(1));
        assert_eq!(ready.len(), 2, "Frames 1 and 2 should both be ready");
        assert_eq!(ready[0].counter, 1);
        assert_eq!(ready[1].counter, 2);
    }

    #[test]
    fn test_reorder_buffer_gap() {
        let mut buffer = ReorderBuffer::new(64);

        // Insert 3, 4, 5 - all should wait
        let ready = buffer.insert(make_frame(3));
        assert!(ready.is_empty());
        let ready = buffer.insert(make_frame(4));
        assert!(ready.is_empty());
        let ready = buffer.insert(make_frame(5));
        assert!(ready.is_empty());

        // Insert 0 - only 0 should be ready
        let ready = buffer.insert(make_frame(0));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].counter, 0);

        // Insert 1, 2 - should release 1, 2, 3, 4, 5
        let ready = buffer.insert(make_frame(1));
        assert_eq!(ready.len(), 1);
        let ready = buffer.insert(make_frame(2));
        assert_eq!(ready.len(), 4);
        assert_eq!(
            ready.iter().map(|f| f.counter).collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );
    }

    #[test]
    fn test_reorder_buffer_is_full() {
        let mut buffer = ReorderBuffer::new(3);

        buffer.insert(make_frame(1));
        buffer.insert(make_frame(2));
        assert!(!buffer.is_full());

        buffer.insert(make_frame(3));
        assert!(buffer.is_full());
    }

    #[test]
    fn test_reorder_buffer_drain_all() {
        let mut buffer = ReorderBuffer::new(64);

        buffer.insert(make_frame(5));
        buffer.insert(make_frame(3));
        buffer.insert(make_frame(7));

        let all = buffer.drain_all();
        assert_eq!(all.len(), 3);
        // drain_all returns in heap order (arbitrary), but all should be present
        let counters: std::collections::HashSet<u32> = all.iter().map(|f| f.counter).collect();
        assert!(counters.contains(&3));
        assert!(counters.contains(&5));
        assert!(counters.contains(&7));
    }

    #[test]
    fn test_counter_wraparound() {
        let mut buffer = ReorderBuffer::new(64);
        buffer.next_to_send = u32::MAX - 1;

        // Insert u32::MAX - 1
        let ready = buffer.insert(make_frame(u32::MAX - 1));
        assert_eq!(ready.len(), 1);

        // Insert u32::MAX
        let ready = buffer.insert(make_frame(u32::MAX));
        assert_eq!(ready.len(), 1);

        // Insert 0 (wrapped)
        let ready = buffer.insert(make_frame(0));
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].counter, 0);
    }

    #[tokio::test]
    async fn test_encrypt_and_send_returns_both_buffers() {
        // Create a mock transport
        let transport = Arc::new(crate::transport::mock::MockTransport);

        // Create dummy keys for testing
        let key = [0u8; 32];
        let write_key =
            Aes256Gcm::new_from_slice(&key).expect("32-byte key should be valid for AES-256-GCM");
        let read_key =
            Aes256Gcm::new_from_slice(&key).expect("32-byte key should be valid for AES-256-GCM");

        let socket = NoiseSocket::new(transport, write_key, read_key);

        // Create buffers with some initial capacity and content
        let mut plaintext_buf = Vec::with_capacity(1024);
        plaintext_buf.extend_from_slice(b"test message");
        let encrypted_buf = Vec::with_capacity(1024);

        // Call encrypt_and_send - this should return both buffers
        let result = socket.encrypt_and_send(plaintext_buf, encrypted_buf).await;

        assert!(result.is_ok(), "encrypt_and_send should succeed");

        let (returned_plaintext, returned_encrypted) =
            result.expect("encrypt_and_send result should unwrap after is_ok check");

        // Verify buffers are returned and cleared (ready for reuse)
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
        let write_key =
            Aes256Gcm::new_from_slice(&key).expect("32-byte key should be valid for AES-256-GCM");
        let read_key =
            Aes256Gcm::new_from_slice(&key).expect("32-byte key should be valid for AES-256-GCM");

        let transport = Arc::new(RecordingTransport {
            recorded_order: recorded_order.clone(),
            read_key: Aes256Gcm::new_from_slice(&key)
                .expect("32-byte key should be valid for AES-256-GCM"),
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

    #[tokio::test]
    async fn test_parallel_encryption_with_delayed_workers() {
        use async_trait::async_trait;
        use std::sync::Arc;
        use tokio::sync::Mutex;

        // Transport that records send order
        struct OrderRecordingTransport {
            send_order: Arc<Mutex<Vec<u32>>>,
            read_key: Aes256Gcm,
            counter: AtomicU32,
        }

        #[async_trait]
        impl crate::transport::Transport for OrderRecordingTransport {
            async fn send(&self, data: &[u8]) -> std::result::Result<(), anyhow::Error> {
                if data.len() > 16 {
                    let ciphertext = &data[3..];
                    let counter = self.counter.fetch_add(1, Ordering::SeqCst);
                    let iv = generate_iv(counter);
                    if let Ok(plaintext) = self.read_key.decrypt(iv.as_ref().into(), ciphertext) {
                        // First 4 bytes contain the counter that was used
                        if plaintext.len() >= 4 {
                            let val = u32::from_le_bytes([
                                plaintext[0],
                                plaintext[1],
                                plaintext[2],
                                plaintext[3],
                            ]);
                            self.send_order.lock().await.push(val);
                        }
                    }
                }
                Ok(())
            }

            async fn disconnect(&self) {}
        }

        let send_order = Arc::new(Mutex::new(Vec::new()));
        let key = [0u8; 32];
        let write_key = Aes256Gcm::new_from_slice(&key).unwrap();
        let read_key = Aes256Gcm::new_from_slice(&key).unwrap();

        let transport = Arc::new(OrderRecordingTransport {
            send_order: send_order.clone(),
            read_key: Aes256Gcm::new_from_slice(&key).unwrap(),
            counter: AtomicU32::new(0),
        });

        let socket = Arc::new(NoiseSocket::new(transport, write_key, read_key));

        // Send 20 messages concurrently - they should all complete in counter order
        let mut handles = Vec::new();
        for i in 0u32..20 {
            let socket = socket.clone();
            handles.push(tokio::spawn(async move {
                let mut plaintext = i.to_le_bytes().to_vec();
                plaintext.extend_from_slice(&[0u8; 96]);
                socket.encrypt_and_send(plaintext, Vec::new()).await
            }));
        }

        for handle in handles {
            assert!(handle.await.unwrap().is_ok());
        }

        let order = send_order.lock().await;
        // Verify sends happened in counter order (0, 1, 2, ..., 19)
        let expected: Vec<u32> = (0..20).collect();
        assert_eq!(*order, expected, "Messages must be sent in counter order");
    }
}
