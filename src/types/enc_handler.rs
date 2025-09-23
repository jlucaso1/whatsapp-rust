use crate::client::Client;
use crate::types::message::MessageInfo;
use anyhow::Result;
use std::sync::Arc;
use wacore_binary::node::Node;

/// Trait for handling custom encrypted message types
#[async_trait::async_trait]
pub trait EncHandler: Send + Sync {
    /// Handle an encrypted node of a specific type
    ///
    /// # Arguments
    /// * `client` - The client instance
    /// * `enc_node` - The encrypted node to handle
    /// * `info` - The message info context
    ///
    /// # Returns
    /// * `Ok(())` if the message was handled successfully
    /// * `Err(anyhow::Error)` if handling failed
    async fn handle(&self, client: Arc<Client>, enc_node: &Node, info: &MessageInfo) -> Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::message::MessageInfo;
    use anyhow::Result;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use wacore_binary::node::Node;

    /// Mock handler for testing custom enc types
    #[derive(Debug)]
    struct MockEncHandler {
        pub calls: Arc<Mutex<Vec<String>>>,
    }

    impl MockEncHandler {
        fn new() -> Self {
            Self {
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }
    }

    #[async_trait::async_trait]
    impl EncHandler for MockEncHandler {
        async fn handle(
            &self,
            _client: Arc<crate::client::Client>,
            enc_node: &Node,
            _info: &MessageInfo,
        ) -> Result<()> {
            let enc_type = enc_node.attrs().string("type");
            self.calls.lock().await.push(enc_type);
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_custom_enc_handler_registration() {
        use crate::bot::Bot;

        // Create a mock handler
        let mock_handler = MockEncHandler::new();

        // Build bot with custom handler and unique DB
        let db_path = format!("/tmp/test_enc_handler_{}.db", rand::random::<u64>());
        let backend = Arc::new(
            crate::store::sqlite_store::SqliteStore::new(&db_path)
                .await
                .expect("Failed to create SQLite backend"),
        );

        let bot = Bot::builder()
            .with_backend(backend)
            .with_enc_handler("frskmsg", mock_handler)
            .build()
            .await
            .expect("Failed to build bot");

        // Verify handler was registered
        assert!(bot.client().custom_enc_handlers.contains_key("frskmsg"));
    }

    #[tokio::test]
    async fn test_multiple_custom_handlers() {
        use crate::bot::Bot;

        let handler1 = MockEncHandler::new();
        let handler2 = MockEncHandler::new();

        // Build bot with unique DB
        let db_path = format!("/tmp/test_enc_multiple_{}.db", rand::random::<u64>());
        let backend = Arc::new(
            crate::store::sqlite_store::SqliteStore::new(&db_path)
                .await
                .expect("Failed to create SQLite backend"),
        );

        let bot = Bot::builder()
            .with_backend(backend)
            .with_enc_handler("frskmsg", handler1)
            .with_enc_handler("customtype", handler2)
            .build()
            .await
            .expect("Failed to build bot");

        // Verify both handlers were registered
        assert!(bot.client().custom_enc_handlers.contains_key("frskmsg"));
        assert!(bot.client().custom_enc_handlers.contains_key("customtype"));
        assert_eq!(bot.client().custom_enc_handlers.len(), 2);
    }

    #[tokio::test]
    async fn test_builtin_handlers_still_work() {
        use crate::bot::Bot;

        // Build bot without custom handlers but with unique DB
        let db_path = format!("/tmp/test_enc_builtin_{}.db", rand::random::<u64>());
        let backend = Arc::new(
            crate::store::sqlite_store::SqliteStore::new(&db_path)
                .await
                .expect("Failed to create SQLite backend"),
        );

        let bot = Bot::builder()
            .with_backend(backend)
            .build()
            .await
            .expect("Failed to build bot");

        // Verify no custom handlers are registered
        assert_eq!(bot.client().custom_enc_handlers.len(), 0);
    }
}
