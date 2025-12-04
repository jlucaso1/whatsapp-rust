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
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tokio_websockets::{ClientBuilder, MaybeTlsStream, Message, WebSocketStream};
use wacore::net::{Transport, TransportEvent, TransportFactory};

/// Ensures the rustls crypto provider is only installed once
static CRYPTO_PROVIDER_INIT: Once = Once::new();

type RawWs = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<RawWs, Message>;
type WsStream = SplitStream<RawWs>;

const URL: &str = "wss://web.whatsapp.com/ws/chat";

/// Tokio-based WebSocket transport
/// This is a simple byte pipe - it has no knowledge of WhatsApp framing.
pub struct TokioWebSocketTransport {
    ws_sink: Arc<Mutex<Option<WsSink>>>,
    is_connected: Arc<Mutex<bool>>,
}

impl TokioWebSocketTransport {
    /// Create a new transport instance
    fn new(sink: WsSink) -> Self {
        Self {
            ws_sink: Arc::new(Mutex::new(Some(sink))),
            is_connected: Arc::new(Mutex::new(true)),
        }
    }
}

#[async_trait]
impl Transport for TokioWebSocketTransport {
    /// Sends raw data through the WebSocket.
    /// The caller is responsible for any framing.
    async fn send(&self, data: &[u8]) -> Result<(), anyhow::Error> {
        let mut sink_guard = self.ws_sink.lock().await;
        let sink = sink_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Socket is closed"))?;

        debug!("--> Sending {} bytes", data.len());
        sink.send(Message::binary(data.to_vec()))
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket send error: {}", e))?;
        Ok(())
    }

    async fn disconnect(&self) {
        let mut sink_guard = self.ws_sink.lock().await;
        if let Some(mut sink) = sink_guard.take() {
            if let Err(e) = sink.close().await {
                error!("Error closing WebSocket: {}", e);
            }
            // After awaiting the close, set is_connected to false
            let mut is_connected_guard = self.is_connected.lock().await;
            *is_connected_guard = false;
        } else {
            // If no sink, still ensure is_connected is false
            let mut is_connected_guard = self.is_connected.lock().await;
            if *is_connected_guard {
                *is_connected_guard = false;
            }
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
    ) -> Result<(Arc<dyn Transport>, mpsc::Receiver<TransportEvent>), anyhow::Error> {
        // Install rustls crypto provider (only once)
        CRYPTO_PROVIDER_INIT.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });

        info!("Dialing {URL}");
        let uri: http::Uri = URL
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse URL: {}", e))?;

        let (client, _response) = ClientBuilder::from_uri(uri)
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket connect failed: {}", e))?;

        let (sink, stream) = client.split();

        // Create event channel
        let (event_tx, event_rx) = mpsc::channel(100);

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
async fn read_pump(mut stream: WsStream, event_tx: mpsc::Sender<TransportEvent>) {
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
