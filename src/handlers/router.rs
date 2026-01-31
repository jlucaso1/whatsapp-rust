use super::traits::StanzaHandler;
use crate::client::Client;
use std::collections::HashMap;
use std::sync::Arc;
use wacore_binary::node::Node;

/// Central router for dispatching XML stanzas to their appropriate handlers.
///
/// The router maintains a registry of handlers keyed by XML tag and efficiently
/// dispatches incoming nodes to the correct handler based on the node's tag.
pub struct StanzaRouter {
    /// Map of XML tag -> handler for fast lookups
    handlers: HashMap<&'static str, Arc<dyn StanzaHandler>>,
}

impl StanzaRouter {
    /// Create a new empty router.
    pub fn new() -> Self {
        Self {
            handlers: HashMap::new(),
        }
    }

    /// Register a handler for a specific XML tag.
    ///
    /// # Arguments
    /// * `handler` - The handler implementation to register
    ///
    /// # Panics
    /// Panics if a handler is already registered for the same tag to prevent
    /// accidental overwrites during initialization.
    pub fn register(&mut self, handler: Arc<dyn StanzaHandler>) {
        let tag = handler.tag();
        if self.handlers.insert(tag, handler).is_some() {
            panic!("Handler for tag '{}' already registered", tag);
        }
    }

    /// Dispatch a node to its appropriate handler.
    ///
    /// # Arguments
    /// * `client` - Arc reference to the client instance
    /// * `node` - Arc-wrapped owned Node (avoids cloning)
    ///
    /// # Returns
    /// Returns `true` if a handler was found and successfully processed the node,
    /// `false` if no handler was registered for the node's tag or the handler
    /// indicated it couldn't process the node.
    pub async fn dispatch(
        &self,
        client: Arc<Client>,
        node: Arc<Node>,
        cancelled: &mut bool,
    ) -> bool {
        if let Some(handler) = self.handlers.get(node.tag.as_str()) {
            handler.handle(client, node, cancelled).await
        } else {
            false
        }
    }

    /// Get the number of registered handlers (useful for testing).
    pub fn handler_count(&self) -> usize {
        self.handlers.len()
    }
}

impl Default for StanzaRouter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::MockHttpClient;
    use std::sync::Arc;
    use wacore_binary::node::{Attrs, Node, NodeContent};

    #[derive(Debug)]
    struct MockHandler {
        tag: &'static str,
        handled: std::sync::atomic::AtomicBool,
    }

    impl MockHandler {
        fn new(tag: &'static str) -> Self {
            Self {
                tag,
                handled: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn was_handled(&self) -> bool {
            self.handled.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl StanzaHandler for MockHandler {
        fn tag(&self) -> &'static str {
            self.tag
        }

        async fn handle(
            &self,
            _client: Arc<crate::client::Client>,
            _node: Arc<Node>,
            _cancelled: &mut bool,
        ) -> bool {
            self.handled
                .store(true, std::sync::atomic::Ordering::SeqCst);
            true
        }
    }

    #[test]
    fn test_router_registration() {
        let mut router = StanzaRouter::new();
        let handler = Arc::new(MockHandler::new("test"));

        router.register(handler);
        assert_eq!(router.handler_count(), 1);
    }

    #[test]
    #[should_panic(expected = "Handler for tag 'test' already registered")]
    fn test_router_double_registration_panics() {
        let mut router = StanzaRouter::new();
        let handler1 = Arc::new(MockHandler::new("test"));
        let handler2 = Arc::new(MockHandler::new("test"));

        router.register(handler1);
        router.register(handler2); // Should panic
    }

    #[tokio::test]
    async fn test_router_dispatch_found() {
        let mut router = StanzaRouter::new();
        let handler = Arc::new(MockHandler::new("test"));
        let handler_ref = handler.clone();

        router.register(handler);

        // Create owned Node wrapped in Arc
        let mut attrs = Attrs::new();
        attrs.insert("id".to_string(), "test-id".to_string());
        let node = Arc::new(Node::new(
            "test",
            attrs,
            Some(NodeContent::String("test".to_string())),
        ));

        // Create a minimal client for testing with an in-memory database
        use crate::store::persistence_manager::PersistenceManager;

        let backend = crate::test_utils::create_test_backend().await;
        let pm = PersistenceManager::new(backend)
            .await
            .expect("persistence manager should initialize");
        let transport = Arc::new(crate::transport::mock::MockTransportFactory::new());
        let http_client = Arc::new(MockHttpClient);
        let (client, _rx) =
            crate::client::Client::new(Arc::new(pm), transport, http_client, None).await;

        let mut cancelled = false;
        let result = router.dispatch(client, node, &mut cancelled).await;

        assert!(result);
        assert!(handler_ref.was_handled());
    }

    #[tokio::test]
    async fn test_router_dispatch_not_found() {
        let router = StanzaRouter::new();

        // Create owned Node wrapped in Arc
        let mut attrs = Attrs::new();
        attrs.insert("id".to_string(), "test-id".to_string());
        let node = Arc::new(Node::new(
            "unknown",
            attrs,
            Some(NodeContent::String("test".to_string())),
        ));

        // Create a minimal client for testing with an in-memory database
        use crate::store::persistence_manager::PersistenceManager;

        let backend = crate::test_utils::create_test_backend().await;
        let pm = PersistenceManager::new(backend)
            .await
            .expect("persistence manager should initialize");
        let transport = Arc::new(crate::transport::mock::MockTransportFactory::new());
        let http_client = Arc::new(MockHttpClient);
        let (client, _rx) =
            crate::client::Client::new(Arc::new(pm), transport, http_client, None).await;

        let mut cancelled = false;
        let result = router.dispatch(client, node, &mut cancelled).await;

        assert!(!result);
    }
}
