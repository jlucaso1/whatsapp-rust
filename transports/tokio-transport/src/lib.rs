/// Tokio-based WebSocket transport implementation for whatsapp-rust
///
/// This crate provides a concrete implementation of the Transport trait
/// using tokio-websockets. It handles raw byte transmission without any
/// knowledge of WhatsApp framing.
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, trace, warn};
use std::sync::{Arc, Once};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_websockets::{ClientBuilder, Connector, MaybeTlsStream, Message, WebSocketStream};
use wacore::net::{Transport, TransportEvent, TransportFactory, WHATSAPP_WEB_WS_URL};

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
    async fn send(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        let mut sink_guard = self.ws_sink.lock().await;
        let sink = sink_guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Socket is closed"))?;

        debug!("--> Sending {} bytes", data.len());
        sink.send(Message::binary(data))
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
pub struct TokioWebSocketTransportFactory {
    url: String,
}

impl TokioWebSocketTransportFactory {
    /// Create a new factory instance
    pub fn new() -> Self {
        Self {
            url: WHATSAPP_WEB_WS_URL.to_string(),
        }
    }

    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into();
        self
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

        let url = self.url.as_str();
        debug!("Dialing {url}");
        let uri: http::Uri = url
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
                    let payload = msg.into_payload();
                    debug!("<-- Received WebSocket data: {} bytes", payload.len());
                    if event_tx
                        .send(TransportEvent::DataReceived(Bytes::from(payload)))
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
