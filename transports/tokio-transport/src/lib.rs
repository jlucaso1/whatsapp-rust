//! Tokio WebSocket transport for whatsapp-rust.
//!
//! For custom connections, use [`from_websocket`].

use async_trait::async_trait;
use bytes::Bytes;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use log::{debug, error, trace, warn};
use std::sync::{Arc, Once};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;
use tokio_websockets::{ClientBuilder, Connector, Message, WebSocketStream};
use wacore::net::{Transport, TransportEvent, TransportFactory, WHATSAPP_WEB_WS_URL};

const EVENT_CHANNEL_CAPACITY: usize = 10_000;

static CRYPTO_PROVIDER_INIT: Once = Once::new();

fn create_tls_connector() -> Connector {
    CRYPTO_PROVIDER_INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });

    #[cfg(feature = "danger-skip-tls-verify")]
    {
        use std::sync::Arc as StdArc;
        use tokio_rustls::TlsConnector;

        warn!("TLS certificate verification is DISABLED");

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

        Connector::Rustls(TlsConnector::from(StdArc::new(config)))
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

        Connector::Rustls(TlsConnector::from(StdArc::new(config)))
    }
}

type Sink<S> = SplitSink<WebSocketStream<S>, Message>;

struct WsTransport<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> {
    sink: Arc<Mutex<Option<Sink<S>>>>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> WsTransport<S> {
    fn new(sink: Sink<S>, shutdown_tx: tokio::sync::watch::Sender<bool>) -> Self {
        Self {
            sink: Arc::new(Mutex::new(Some(sink))),
            shutdown_tx,
        }
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> Transport for WsTransport<S> {
    async fn send(&self, data: Vec<u8>) -> Result<(), anyhow::Error> {
        let mut guard = self.sink.lock().await;
        let sink = guard
            .as_mut()
            .ok_or_else(|| anyhow::anyhow!("Socket is closed"))?;
        debug!("--> Sending {} bytes", data.len());
        sink.send(Message::binary(data))
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket send error: {e}"))?;
        Ok(())
    }

    async fn disconnect(&self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(mut sink) = self.sink.lock().await.take() {
            let _ = sink
                .send(Message::close(
                    Some(tokio_websockets::CloseCode::NORMAL_CLOSURE),
                    "",
                ))
                .await;
        }
    }
}

async fn read_pump<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    mut stream: SplitStream<WebSocketStream<S>>,
    tx: async_channel::Sender<TransportEvent>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            next = stream.next() => match next {
                Some(Ok(msg)) if msg.is_binary() => {
                    let payload = msg.into_payload();
                    debug!("<-- Received WebSocket data: {} bytes", payload.len());
                    tokio::select! {
                        biased;
                        _ = shutdown.changed() => break,
                        r = tx.send(TransportEvent::DataReceived(Bytes::from(payload))) => {
                            if r.is_err() {
                                warn!("Event receiver dropped");
                                break;
                            }
                        }
                    }
                }
                Some(Ok(msg)) if msg.is_close() => {
                    trace!("Received close frame");
                    break;
                }
                Some(Ok(_)) => {} // ping/pong/text handled by tokio-websockets
                Some(Err(e)) => {
                    error!("WebSocket read error: {e}");
                    break;
                }
                None => {
                    trace!("WebSocket stream ended");
                    break;
                }
            },
        }
    }

    let _ = tx.send(TransportEvent::Disconnected).await;
}

/// Wraps an already-upgraded [`WebSocketStream`] into a [`Transport`] + event channel.
///
/// Useful for custom connection strategies (e.g. IPv4 preference, TCP keepalive).
pub fn from_websocket<S>(
    ws: WebSocketStream<S>,
) -> (Arc<dyn Transport>, async_channel::Receiver<TransportEvent>)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (sink, stream) = ws.split();
    let (event_tx, event_rx) = async_channel::bounded(EVENT_CHANNEL_CAPACITY);
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let transport = Arc::new(WsTransport::new(sink, shutdown_tx));

    // Enqueue Connected before spawning so it precedes any DataReceived.
    let _ = event_tx.try_send(TransportEvent::Connected);

    tokio::task::spawn(read_pump(stream, event_tx, shutdown_rx));

    (transport, event_rx)
}

/// Default [`TransportFactory`] using system DNS, TCP, and TLS.
///
/// For custom connection logic, use [`from_websocket`] directly.
pub struct TokioWebSocketTransportFactory {
    url: String,
}

impl TokioWebSocketTransportFactory {
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
        let uri: http::Uri = self
            .url
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse URL: {e}"))?;

        debug!("Dialing {}", self.url);
        let (ws, _) = ClientBuilder::from_uri(uri)
            .connector(&connector)
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("WebSocket connect failed: {e}"))?;

        Ok(from_websocket(ws))
    }
}
