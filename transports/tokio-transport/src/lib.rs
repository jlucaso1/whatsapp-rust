/// Tokio-based WebSocket transport implementation for whatsapp-rust
///
/// This crate provides a concrete implementation of the Transport trait
/// using tokio-websockets.

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, info, trace, warn};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::sync::Mutex;
use tokio_websockets::{ClientBuilder, MaybeTlsStream, Message, WebSocketStream};

/// An event produced by the transport layer.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// The transport has successfully connected.
    Connected,
    /// A binary frame has been received from the server.
    FrameReceived(Bytes),
    /// The connection was lost.
    Disconnected,
}

/// Represents an active network connection.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Sends a binary frame to the server.
    async fn send_frame(&self, frame: &[u8]) -> Result<(), anyhow::Error>;
    
    /// Closes the connection.
    async fn disconnect(&self);
}

/// A factory responsible for creating new transport instances.
#[async_trait]
pub trait TransportFactory: Send + Sync {
    /// Creates a new transport and returns it, along with a stream of events.
    async fn create_transport(
        &self,
    ) -> Result<(Arc<dyn Transport>, mpsc::Receiver<TransportEvent>), anyhow::Error>;
}

type RawWs = WebSocketStream<MaybeTlsStream<TcpStream>>;
type WsSink = SplitSink<RawWs, Message>;
type WsStream = SplitStream<RawWs>;

const URL: &str = "wss://web.whatsapp.com/ws/chat";
const FRAME_MAX_SIZE: usize = 2 << 23;
const FRAME_LENGTH_SIZE: usize = 3;

/// Tokio-based WebSocket transport
pub struct TokioWebSocketTransport {
    ws_sink: Arc<Mutex<Option<WsSink>>>,
    is_connected: Arc<Mutex<bool>>,
    header: Arc<Mutex<Option<Vec<u8>>>>,
}

impl TokioWebSocketTransport {
    /// Create a new transport instance
    fn new(sink: WsSink, header: Vec<u8>) -> Self {
        Self {
            ws_sink: Arc::new(Mutex::new(Some(sink))),
            is_connected: Arc::new(Mutex::new(true)),
            header: Arc::new(Mutex::new(Some(header))),
        }
    }
}

#[async_trait]
impl Transport for TokioWebSocketTransport {
    async fn send_frame(&self, frame: &[u8]) -> Result<(), anyhow::Error> {
        let mut sink_guard = self.ws_sink.lock().await;
        let sink = sink_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Socket is closed"))?;

        let data_len = frame.len();
        if data_len >= FRAME_MAX_SIZE {
            return Err(anyhow::anyhow!(
                "Frame is too large (max: {}, got: {})",
                FRAME_MAX_SIZE,
                data_len
            ));
        }

        // Take (or empty) the header (conn header only needed once; subsequent calls will get empty vec)
        let frame_header = self.header.lock().await.take().unwrap_or_default();
        let header_len = frame_header.len();
        let prefix_len = header_len + FRAME_LENGTH_SIZE;

        let mut data = Vec::with_capacity(frame.len() + prefix_len);
        data.resize(prefix_len, 0);
        data.extend_from_slice(frame);

        // Write header (if any) and 3-byte length (big-endian, 24-bit)
        if header_len > 0 {
            data[0..header_len].copy_from_slice(&frame_header);
        }
        let len_bytes = u32::to_be_bytes(data_len as u32);
        data[header_len..prefix_len].copy_from_slice(&len_bytes[1..]);

        debug!(
            "--> Sending frame: payload {} bytes, total {} bytes",
            data_len,
            data.len()
        );
        sink.send(Message::binary(data))
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket send error: {}", e))?;
        Ok(())
    }

    async fn disconnect(&self) {
        let mut is_connected = self.is_connected.lock().await;
        if *is_connected {
            *is_connected = false;
            *self.ws_sink.lock().await = None;
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
        // Install rustls crypto provider
        if let Err(e) = rustls::crypto::ring::default_provider().install_default() {
            debug!("rustls crypto provider install: {:?}", e);
        }

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

        // Create transport with WhatsApp connection header
        let header = wacore_binary::consts::WA_CONN_HEADER.to_vec();
        let transport = Arc::new(TokioWebSocketTransport::new(sink, header));

        // Spawn read pump task
        let event_tx_clone = event_tx.clone();
        tokio::task::spawn(read_pump(stream, event_tx_clone));

        // Send connected event
        let _ = event_tx.send(TransportEvent::Connected).await;

        Ok((transport, event_rx))
    }
}

async fn read_pump(mut stream: WsStream, event_tx: mpsc::Sender<TransportEvent>) {
    let mut buffer = BytesMut::new();

    loop {
        match stream.next().await {
            Some(Ok(msg)) => {
                if msg.is_binary() {
                    let data = msg.as_payload();
                    debug!("<-- Received WebSocket message: {} bytes", data.len());
                    buffer.extend_from_slice(data);

                    while buffer.len() >= FRAME_LENGTH_SIZE {
                        let frame_len = ((buffer[0] as usize) << 16)
                            | ((buffer[1] as usize) << 8)
                            | (buffer[2] as usize);

                        if buffer.len() >= FRAME_LENGTH_SIZE + frame_len {
                            buffer.advance(FRAME_LENGTH_SIZE);
                            let frame_data = buffer.split_to(frame_len).freeze();
                            trace!("<-- Assembled frame: {} bytes", frame_data.len());
                            if event_tx
                                .send(TransportEvent::FrameReceived(frame_data))
                                .await
                                .is_err()
                            {
                                warn!("Event receiver dropped, closing read pump");
                                break;
                            }
                        } else {
                            break;
                        }
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

    #[test]
    fn test_frame_encoding() {
        let header = wacore_binary::consts::WA_CONN_HEADER.to_vec();
        let header_len = header.len();
        let payload: Vec<u8> = vec![1, 2, 3, 4, 5];
        let payload_len = payload.len();
        let prefix_len = header_len + FRAME_LENGTH_SIZE;

        let mut data = Vec::with_capacity(payload.len() + prefix_len);
        data.resize(prefix_len, 0);
        data.extend_from_slice(&payload);

        if header_len > 0 {
            data[0..header_len].copy_from_slice(&header);
        }
        let len_bytes = u32::to_be_bytes(payload_len as u32);
        data[header_len..prefix_len].copy_from_slice(&len_bytes[1..]);

        assert_eq!(&data[0..header_len], &header[..]);
        let reported_len = ((data[header_len] as usize) << 16)
            | ((data[header_len + 1] as usize) << 8)
            | (data[header_len + 2] as usize);
        assert_eq!(reported_len, payload_len);
        assert_eq!(&data[prefix_len..prefix_len + payload_len], &payload[..]);
    }
}
