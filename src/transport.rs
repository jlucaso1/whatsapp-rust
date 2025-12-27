// Re-export transport types from wacore
pub use wacore::net::{Transport, TransportEvent, TransportFactory};

#[cfg(feature = "tokio-transport")]
pub use whatsapp_rust_tokio_transport::{TokioWebSocketTransport, TokioWebSocketTransportFactory};

#[cfg(feature = "ureq-client")]
pub use whatsapp_rust_ureq_http_client::UreqHttpClient;

#[cfg(test)]
pub mod mock {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;

    /// A mock transport that does nothing, for testing purposes
    pub struct MockTransport;

    #[async_trait]
    impl Transport for MockTransport {
        async fn send(&self, _data: Vec<u8>) -> Result<(), anyhow::Error> {
            Ok(())
        }

        async fn disconnect(&self) {}
    }

    /// A mock transport factory for testing
    #[derive(Default)]
    pub struct MockTransportFactory;

    impl MockTransportFactory {
        pub fn new() -> Self {
            Self
        }
    }

    #[async_trait]
    impl TransportFactory for MockTransportFactory {
        async fn create_transport(
            &self,
        ) -> Result<(Arc<dyn Transport>, async_channel::Receiver<TransportEvent>), anyhow::Error>
        {
            let (_tx, rx) = async_channel::bounded(1);
            Ok((Arc::new(MockTransport), rx))
        }
    }
}
