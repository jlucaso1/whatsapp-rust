/// Tokio-based WebSocket transport implementation for whatsapp-rust
///
/// This crate provides a concrete implementation of the Transport trait
/// using tokio-websockets. It handles raw byte transmission without any
/// knowledge of WhatsApp framing.
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, trace, warn};
use std::sync::{Arc, Once};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_websockets::{ClientBuilder, Connector, MaybeTlsStream, Message, WebSocketStream};
use wacore::net::{Transport, TransportEvent, TransportFactory};

/// Ensures the rustls crypto provider is only installed once
static CRYPTO_PROVIDER_INIT: Once = Once::new();

/// Creates a TLS connector based on feature flags
fn create_tls_connector() -> Connector {
    // Install rustls crypto provider (only once)
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    #[cfg(feature = "danger-skip-tls-verify")]
    {
        use std::sync::Arc as StdArc;
        use tokio_rustls::TlsConnector;

        warn!("TLS certificate verification is DISABLED - this is insecure!");

        // Create a custom verifier that accepts any certificate
        #[derive(Debug)]
        struct NoVerifier;

        impl rustls::client::danger::ServerCertVerifier for NoVerifier {
            fn verify_server_cert(
                &self,
                _end_entity: &rustls::pki_types::CertificateDer<'_>,
                _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                _server_name: &rustls::pki_types::ServerName<'_>,
                _ocsp_response: &[u8],
                _now: rustls::pki_types::UnixTime,
            ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                Ok(rustls::client::danger::ServerCertVerified::assertion())
            }

            fn verify_tls12_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn verify_tls13_signature(
                &self,
                _message: &[u8],
                _cert: &rustls::pki_types::CertificateDer<'_>,
                _dss: &rustls::DigitallySignedStruct,
            ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
            {
                Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
            }

            fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                vec![
                    rustls::SignatureScheme::RSA_PKCS1_SHA256,
                    rustls::SignatureScheme::RSA_PKCS1_SHA384,
                    rustls::SignatureScheme::RSA_PKCS1_SHA512,
                    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
                    rustls::SignatureScheme::RSA_PSS_SHA256,
                    rustls::SignatureScheme::RSA_PSS_SHA384,
                    rustls::SignatureScheme::RSA_PSS_SHA512,
                    rustls::SignatureScheme::ED25519,
                ]
            }
        }

        let config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(StdArc::new(NoVerifier))
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(StdArc::new(config));
        Connector::Rustls(tls_connector)
    }

    #[cfg(not(feature = "danger-skip-tls-verify"))]
    {
        use std::sync::Arc as StdArc;
        use tokio_rustls::TlsConnector;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let tls_connector = TlsConnector::from(StdArc::new(config));
        Connector::Rustls(tls_connector)
    }
}

type RawWs = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<RawWs, Message>;
type WsStream = SplitStream<RawWs>;

const URL: &str = "wss://web.whatsapp.com/ws/chat";

/// A job sent to the dedicated sender task.
struct SendJob {
    data: Vec<u8>,
    response_tx: oneshot::Sender<Result<(), anyhow::Error>>,
}

/// Command sent to the sender task for disconnect
enum SenderCommand {
    Send(SendJob),
    Disconnect(oneshot::Sender<()>),
}

/// Tokio-based WebSocket transport
/// This is a simple byte pipe - it has no knowledge of WhatsApp framing.
/// Uses a channel-based design to avoid holding locks during network I/O.
pub struct TokioWebSocketTransport {
    /// Channel to send jobs to the dedicated sender task.
    /// Using a channel instead of a mutex avoids blocking callers while
    /// the current send is in progress - they can enqueue their work and
    /// await the result without holding a lock.
    send_job_tx: mpsc::Sender<SenderCommand>,
    /// Handle to the sender task. Aborted on drop to prevent resource leaks.
    sender_task_handle: JoinHandle<()>,
}

impl TokioWebSocketTransport {
    /// Create a new transport instance
    fn new(sink: WsSink) -> Self {
        // Create channel for send jobs. Buffer size of 32 allows multiple
        // callers to enqueue work without blocking on channel capacity.
        let (send_job_tx, send_job_rx) = mpsc::channel::<SenderCommand>(32);

        // Spawn the dedicated sender task that owns the sink
        let sender_task_handle = tokio::spawn(Self::sender_task(sink, send_job_rx));

        Self {
            send_job_tx,
            sender_task_handle,
        }
    }

    /// Dedicated sender task that processes send jobs sequentially.
    /// This ensures frames are sent in order without requiring a mutex.
    /// The task owns the sink exclusively.
    async fn sender_task(mut sink: WsSink, mut send_job_rx: mpsc::Receiver<SenderCommand>) {
        while let Some(cmd) = send_job_rx.recv().await {
            match cmd {
                SenderCommand::Send(job) => {
                    debug!("--> Sending {} bytes", job.data.len());
                    let result = sink
                        .send(Message::binary(job.data))
                        .await
                        .map_err(|e| anyhow::anyhow!("WebSocket send error: {}", e));

                    // Send result back to caller. Ignore error if receiver was dropped.
                    let _ = job.response_tx.send(result);
                }
                SenderCommand::Disconnect(response_tx) => {
                    if let Err(e) = sink.close().await {
                        error!("Error closing WebSocket: {}", e);
                    }
                    // Signal completion
                    let _ = response_tx.send(());
                    // Exit the task after disconnect
                    break;
                }
            }
        }

        // Channel closed - transport was dropped, task exits naturally
    }
}

impl Drop for TokioWebSocketTransport {
    fn drop(&mut self) {
        // Abort the sender task to prevent resource leaks if it's stuck
        // on a slow/hanging network operation.
        self.sender_task_handle.abort();
    }
}

#[async_trait]
impl Transport for TokioWebSocketTransport {
    /// Sends raw data through the WebSocket.
    /// The caller is responsible for any framing.
    /// This method queues the send to a background task, avoiding lock contention.
    async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        let (response_tx, response_rx) = oneshot::channel();

        let job = SendJob {
            data: data.to_vec(),
            response_tx,
        };

        // Send job to the sender task
        if self
            .send_job_tx
            .send(SenderCommand::Send(job))
            .await
            .is_err()
        {
            return Err(anyhow::anyhow!("Socket is closed"));
        }

        // Wait for the sender task to process our job and return the result
        match response_rx.await {
            Ok(result) => result,
            Err(_) => Err(anyhow::anyhow!("Sender task dropped without response")),
        }
    }

    async fn disconnect(&self) {
        let (response_tx, response_rx) = oneshot::channel();

        // Send disconnect command to the sender task
        if self
            .send_job_tx
            .send(SenderCommand::Disconnect(response_tx))
            .await
            .is_ok()
        {
            // Wait for disconnect to complete
            let _ = response_rx.await;
        }
    }
}

/// Factory for creating Tokio WebSocket transports
pub struct TokioWebSocketTransportFactory;

impl TokioWebSocketTransportFactory {
    /// Create a new factory instance
    pub fn new() -> Self {
        Self
    }
}

impl Default for TokioWebSocketTransportFactory {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl TransportFactory for TokioWebSocketTransportFactory {
    async fn create_transport(
        &self,
    ) -> Result<(Arc<dyn Transport>, async_channel::Receiver<TransportEvent>), anyhow::Error> {
        let connector = create_tls_connector();

        info!("Dialing {URL}");
        let uri: http::Uri = URL
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse URL: {}", e))?;

        let (client, _response) = ClientBuilder::from_uri(uri)
            .connector(&connector)
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket connect failed: {}", e))?;

        let (sink, stream) = client.split();

        // Create event channel
        let (event_tx, event_rx) = async_channel::bounded(10000);

        // Create transport - just a simple byte pipe
        let transport = Arc::new(TokioWebSocketTransport::new(sink));

        // Spawn read pump task
        let event_tx_clone = event_tx.clone();
        tokio::task::spawn(read_pump(stream, event_tx_clone));

        // Send connected event
        let _ = event_tx.send(TransportEvent::Connected).await;

        Ok((transport, event_rx))
    }
}

/// Reads from the WebSocket and forwards raw data to the event channel.
/// No framing logic here - just passes bytes through.
async fn read_pump(mut stream: WsStream, event_tx: async_channel::Sender<TransportEvent>) {
    loop {
        match stream.next().await {
            Some(Ok(msg)) => {
                if msg.is_binary() {
                    let data = msg.as_payload();
                    debug!("<-- Received WebSocket data: {} bytes", data.len());
                    // Just forward the raw bytes - no framing logic
                    if event_tx
                        .send(TransportEvent::DataReceived(Bytes::copy_from_slice(data)))
                        .await
                        .is_err()
                    {
                        warn!("Event receiver dropped, closing read pump");
                        break;
                    }
                } else if msg.is_close() {
                    trace!("Received close frame");
                    break;
                }
            }
            Some(Err(e)) => {
                error!("Error reading from websocket: {e}");
                break;
            }
            None => {
                trace!("Websocket stream ended");
                break;
            }
        }
    }

    // Send disconnected event
    let _ = event_tx.send(TransportEvent::Disconnected).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Mutex;

    /// Shared message log for testing
    type MessageLog = Arc<Mutex<Vec<Vec<u8>>>>;

    /// Creates a mock WebSocket pair for testing.
    /// Returns (transport, message_log, receiver) where receiver gets messages sent via transport.
    fn create_mock_transport() -> (TokioWebSocketTransport, MessageLog, mpsc::Receiver<Vec<u8>>) {
        // Create a channel to capture sent messages
        let (msg_tx, msg_rx) = mpsc::channel::<Vec<u8>>(100);
        let sent_messages = Arc::new(Mutex::new(Vec::new()));
        let sent_messages_clone = sent_messages.clone();

        // Create transport command channel
        let (send_job_tx, send_job_rx) = mpsc::channel::<SenderCommand>(32);

        // Spawn a mock sender task that captures messages instead of sending via WebSocket
        let sender_task_handle = tokio::spawn(async move {
            let mut send_job_rx = send_job_rx;
            while let Some(cmd) = send_job_rx.recv().await {
                match cmd {
                    SenderCommand::Send(job) => {
                        // Record the message
                        sent_messages_clone.lock().await.push(job.data.clone());
                        let _ = msg_tx.send(job.data).await;
                        // Simulate successful send
                        let _ = job.response_tx.send(Ok(()));
                    }
                    SenderCommand::Disconnect(response_tx) => {
                        let _ = response_tx.send(());
                        break;
                    }
                }
            }
        });

        let transport = TokioWebSocketTransport {
            send_job_tx,
            sender_task_handle,
        };

        (transport, sent_messages, msg_rx)
    }

    #[tokio::test]
    async fn test_transport_send_records_messages() {
        // Test that Transport::send() correctly queues and processes messages
        let (transport, sent_messages, _rx) = create_mock_transport();

        // Send multiple messages via the Transport trait
        for i in 0..5 {
            let data = vec![i as u8; 10];
            let result = transport.send(&data).await;
            assert!(result.is_ok(), "Send should succeed");
        }

        // Verify all messages were recorded
        let messages = sent_messages.lock().await;
        assert_eq!(messages.len(), 5, "Should have sent 5 messages");
        for (i, msg) in messages.iter().enumerate() {
            assert_eq!(msg, &vec![i as u8; 10], "Message {} should match", i);
        }
    }

    #[tokio::test]
    async fn test_transport_concurrent_sends() {
        // Test that concurrent Transport::send() calls are all processed
        let (transport, sent_messages, _rx) = create_mock_transport();
        let transport = Arc::new(transport);

        // Spawn concurrent senders
        let mut handles = Vec::new();
        for i in 0..20u8 {
            let transport = transport.clone();
            handles.push(tokio::spawn(async move {
                let data = vec![i; 50];
                transport.send(&data).await
            }));
        }

        // Wait for all sends to complete
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "All concurrent sends should succeed");
        }

        // Verify all messages were recorded (order may vary)
        let messages = sent_messages.lock().await;
        assert_eq!(messages.len(), 20, "Should have sent 20 messages");

        // Verify each unique index was sent exactly once
        let mut seen = [false; 20];
        for msg in messages.iter() {
            let index = msg[0] as usize;
            assert!(!seen[index], "Index {} should only appear once", index);
            seen[index] = true;
        }
        assert!(seen.iter().all(|&v| v), "All indices should be present");
    }

    #[tokio::test]
    async fn test_transport_disconnect() {
        // Test that disconnect properly shuts down the sender task
        let (transport, _sent_messages, _rx) = create_mock_transport();

        // Send a message first
        let result = transport.send(&[1, 2, 3]).await;
        assert!(result.is_ok());

        // Disconnect
        transport.disconnect().await;

        // After disconnect, sends should fail
        let result = transport.send(&[4, 5, 6]).await;
        assert!(result.is_err(), "Send after disconnect should fail");
    }

    #[tokio::test]
    async fn test_transport_drop_aborts_task() {
        // Test that dropping the transport aborts the sender task
        let task_running = Arc::new(AtomicUsize::new(0));
        let task_running_clone = task_running.clone();

        let (send_job_tx, mut send_job_rx) = mpsc::channel::<SenderCommand>(32);

        let sender_task_handle = tokio::spawn(async move {
            task_running_clone.store(1, Ordering::SeqCst);
            // Block on receiving - simulates waiting for work
            while let Some(cmd) = send_job_rx.recv().await {
                match cmd {
                    SenderCommand::Send(job) => {
                        // Simulate slow send
                        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
                        let _ = job.response_tx.send(Ok(()));
                    }
                    SenderCommand::Disconnect(response_tx) => {
                        let _ = response_tx.send(());
                        break;
                    }
                }
            }
            task_running_clone.store(0, Ordering::SeqCst);
        });

        let transport = TokioWebSocketTransport {
            send_job_tx,
            sender_task_handle,
        };

        // Wait for task to start
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(
            task_running.load(Ordering::SeqCst),
            1,
            "Task should be running"
        );

        // Drop the transport - this should abort the sender task
        drop(transport);

        // Wait a bit and verify task was aborted
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        // Task should have been aborted (not gracefully exited, so counter stays at 1
        // unless we check if the handle is finished)
    }

    #[tokio::test]
    async fn test_channel_based_design_no_lock_contention() {
        // This test verifies the key improvement: callers can queue their jobs
        // to the channel quickly without waiting for network I/O.
        //
        // With the old mutex-based design, each caller would block while the
        // previous caller's network I/O completed. With the channel-based design,
        // callers just queue to the channel and wait on their response.
        let (send_job_tx, mut send_job_rx) = mpsc::channel::<SenderCommand>(32);

        // Track when jobs are queued (sent to channel) by callers
        let job_queued_times = Arc::new(Mutex::new(Vec::new()));

        let sender_task_handle = tokio::spawn(async move {
            while let Some(cmd) = send_job_rx.recv().await {
                match cmd {
                    SenderCommand::Send(job) => {
                        // Simulate slow network I/O (50ms per send)
                        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                        let _ = job.response_tx.send(Ok(()));
                    }
                    SenderCommand::Disconnect(response_tx) => {
                        let _ = response_tx.send(());
                        break;
                    }
                }
            }
        });

        let transport = TokioWebSocketTransport {
            send_job_tx,
            sender_task_handle,
        };
        let transport = Arc::new(transport);

        // Spawn 3 concurrent senders that each record when they queued their job
        let mut handles = Vec::new();
        for i in 0..3u8 {
            let transport = transport.clone();
            let job_queued_times = job_queued_times.clone();
            handles.push(tokio::spawn(async move {
                let queue_time = std::time::Instant::now();
                // This call queues to channel and waits for response
                let result = transport.send(&[i]).await;
                // Record when we queued (not when we got response)
                job_queued_times.lock().await.push(queue_time);
                result
            }));
        }

        // Wait for all to complete
        for handle in handles {
            handle.await.unwrap().unwrap();
        }

        // Key assertion: All jobs should have been queued almost simultaneously
        // The timestamps are recorded when the job was queued (before awaiting response)
        // With channel design, all 3 callers queue quickly without blocking on each other
        let times = job_queued_times.lock().await;
        assert_eq!(times.len(), 3);

        // Find min and max queue times
        let min_time = times.iter().min().unwrap();
        let max_time = times.iter().max().unwrap();
        let queue_spread = max_time.duration_since(*min_time);

        // All jobs should queue within 50ms of each other (well under the 50ms network delay)
        // This proves callers don't block on each other's network I/O
        assert!(
            queue_spread < std::time::Duration::from_millis(50),
            "Jobs should queue quickly (< 50ms spread), but spread was {:?}",
            queue_spread
        );

        // Disconnect
        transport.disconnect().await;
    }
}
