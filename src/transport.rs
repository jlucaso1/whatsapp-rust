pub use whatsapp_rust_tokio_transport::{
    TokioWebSocketTransportFactory, Transport, TransportEvent, TransportFactory,
};

#[cfg(test)]
pub mod mock {
    use super::*;
    use async_trait::async_trait;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    /// A mock transport that does nothing, for testing purposes
    pub struct MockTransport;

    #[async_trait]
    impl Transport for MockTransport {
        async fn send(&self, _data: &[u8]) -> Result<(), anyhow::Error> {
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
        ) -> Result<(Arc<dyn Transport>, mpsc::Receiver<TransportEvent>), anyhow::Error> {
            let (_tx, rx) = mpsc::channel(1);
            Ok((Arc::new(MockTransport), rx))
        }
    }
}
