// src/socket/frame_socket.rs
use crate::socket::consts::{FRAME_LENGTH_SIZE, FRAME_MAX_SIZE, URL};
use crate::socket::error::{Result, SocketError};
use bytes::{Buf, BytesMut};
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, StreamExt,
};
use log::{debug, error, info, warn};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::mpsc::{self, Receiver, Sender};
use tokio::sync::Mutex;
use tokio_tungstenite::{
    connect_async, tungstenite::protocol::Message, MaybeTlsStream, WebSocketStream,
};

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>;
type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>;

type OnDisconnectCallback = Box<dyn Fn(bool) + Send>;

pub struct FrameSocket {
    ws_sink: Arc<Mutex<Option<WsSink>>>,
    frames_tx: Sender<bytes::Bytes>,
    on_disconnect: Arc<Mutex<Option<OnDisconnectCallback>>>,
    is_connected: Arc<Mutex<bool>>,
    header: Arc<Mutex<Option<Vec<u8>>>>,
    #[cfg(test)]
    test_frames_rx: Option<Receiver<bytes::Bytes>>,
}

impl FrameSocket {
    pub fn new() -> (Self, Receiver<bytes::Bytes>) {
        let (tx, rx) = mpsc::channel(100);
        let socket = Self {
            ws_sink: Arc::new(Mutex::new(None)),
            frames_tx: tx,
            on_disconnect: Arc::new(Mutex::new(None)),
            is_connected: Arc::new(Mutex::new(false)),
            header: Arc::new(Mutex::new(Some(super::consts::WA_CONN_HEADER.to_vec()))),
            #[cfg(test)]
            test_frames_rx: None,
        };
        (socket, rx)
    }

    #[cfg(test)]
    pub fn new_for_test(
        ws_write: futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::Message,
        >,
        ws_read: futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    ) -> Self {
        let (frames_tx, _frames_rx) = tokio::sync::mpsc::channel(100);
        let socket = Self {
            ws_sink: Arc::new(Mutex::new(Some(ws_write))),
            frames_tx: frames_tx.clone(),
            on_disconnect: Arc::new(Mutex::new(None)),
            is_connected: Arc::new(Mutex::new(true)),
            header: Arc::new(Mutex::new(Some(super::consts::WA_CONN_HEADER.to_vec()))),
            #[cfg(test)]
            test_frames_rx: Some(_frames_rx),
        };
        tokio::spawn(Self::read_pump_for_test(ws_read, frames_tx));
        socket
    }

    /// Public test read pump for integration tests.
    pub async fn read_pump_for_test(
        mut stream: futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
        frames_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    ) {
        while let Some(Ok(msg)) = stream.next().await {
            if let tokio_tungstenite::tungstenite::Message::Binary(data) = msg {
                if frames_tx.send(data).await.is_err() {
                    break;
                }
            }
        }
    }

    /// Test-only: receive a frame from the test receiver.
    #[cfg(test)]
    pub async fn recv_frame_for_test(&mut self) -> anyhow::Result<bytes::Bytes> {
        if let Some(rx) = &mut self.test_frames_rx {
            rx.recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("Test frame channel closed"))
        } else {
            Err(anyhow::anyhow!("Test frame receiver not initialized"))
        }
    }

    pub async fn is_connected(&self) -> bool {
        *self.is_connected.lock().await
    }

    pub async fn set_on_disconnect(&self, cb: OnDisconnectCallback) {
        *self.on_disconnect.lock().await = Some(cb);
    }

    pub async fn connect(&self) -> Result<()> {
        if self.is_connected().await {
            return Err(SocketError::SocketAlreadyOpen);
        }

        let url = URL.read().unwrap().clone();
        info!("Dialing {}", url);
        // Let tokio-tungstenite handle the handshake headers
        let (ws_stream, _response) = connect_async(&url).await?;

        let (sink, stream) = ws_stream.split();
        *self.ws_sink.lock().await = Some(sink);
        *self.is_connected.lock().await = true;

        let frames_tx_clone = self.frames_tx.clone();
        let is_connected_clone = self.is_connected.clone();
        let on_disconnect_clone = self.on_disconnect.clone();

        tokio::spawn(Self::read_pump(
            stream,
            frames_tx_clone,
            is_connected_clone,
            on_disconnect_clone,
        ));

        Ok(())
    }

    pub async fn send_frame(&self, data: &[u8]) -> Result<()> {
        let mut sink_guard = self.ws_sink.lock().await;
        let sink = sink_guard.as_mut().ok_or(SocketError::SocketClosed)?;

        let data_len = data.len();
        if data_len >= FRAME_MAX_SIZE {
            return Err(SocketError::FrameTooLarge {
                max: FRAME_MAX_SIZE,
                got: data_len,
            });
        }

        let mut frame_header = self.header.lock().await.take().unwrap_or_default();
        let mut whole_frame = Vec::with_capacity(frame_header.len() + FRAME_LENGTH_SIZE + data_len);

        whole_frame.append(&mut frame_header);
        whole_frame.extend_from_slice(&u32::to_be_bytes(data_len as u32)[1..]);
        whole_frame.extend_from_slice(data);

        debug!(
            "--> Sending frame: payload {} bytes, total {} bytes",
            data_len,
            whole_frame.len()
        );
        sink.send(Message::Binary(bytes::Bytes::from(whole_frame)))
            .await?;
        Ok(())
    }

    async fn read_pump(
        mut stream: WsStream,
        frames_tx: mpsc::Sender<bytes::Bytes>,
        is_connected: Arc<Mutex<bool>>,
        on_disconnect: Arc<Mutex<Option<OnDisconnectCallback>>>,
    ) {
        let mut buffer = BytesMut::new();

        loop {
            match stream.next().await {
                Some(Ok(msg)) => {
                    if let Message::Binary(data) = msg {
                        debug!("<-- Received WebSocket message: {} bytes", data.len());
                        buffer.extend_from_slice(&data);

                        while buffer.len() >= FRAME_LENGTH_SIZE {
                            let frame_len = ((buffer[0] as usize) << 16)
                                | ((buffer[1] as usize) << 8)
                                | (buffer[2] as usize);

                            if buffer.len() >= FRAME_LENGTH_SIZE + frame_len {
                                buffer.advance(FRAME_LENGTH_SIZE);
                                let frame_data = buffer.split_to(frame_len).freeze();
                                debug!("<-- Assembled frame: {} bytes", frame_data.len());
                                if frames_tx.send(frame_data).await.is_err() {
                                    warn!("Frame receiver dropped, closing read pump");
                                    break;
                                }
                            } else {
                                break;
                            }
                        }
                    } else if let Message::Close(_) = msg {
                        debug!("Received close frame");
                        break;
                    }
                }
                Some(Err(e)) => {
                    error!("Error reading from websocket: {e}");
                    break;
                }
                None => {
                    debug!("Websocket stream ended");
                    break;
                }
            }
        }

        *is_connected.lock().await = false;
        if let Some(cb) = on_disconnect.lock().await.as_ref() {
            (cb)(true); // remote disconnect
        }
    }

    pub async fn close(&self) {
        let mut is_connected = self.is_connected.lock().await;
        if *is_connected {
            *is_connected = false;
            // The read_pump will naturally exit when the connection is closed.
            // Dropping the sink will initiate the close handshake.
            *self.ws_sink.lock().await = None;
            if let Some(cb) = self.on_disconnect.lock().await.as_ref() {
                (cb)(false); // local disconnect
            }
        }
    }
}
