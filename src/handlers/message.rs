use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use std::sync::Arc;
use wacore_binary::node::Node;

/// Handler for `<message>` stanzas.
///
/// Processes incoming WhatsApp messages, including:
/// - Text messages
/// - Media messages (images, videos, documents, etc.)
/// - System messages
/// - Group messages
#[derive(Default)]
pub struct MessageHandler;

impl MessageHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for MessageHandler {
    fn tag(&self) -> &'static str {
        "message"
    }

    async fn handle(&self, client: Arc<Client>, node: &Node, _cancelled: &mut bool) -> bool {
        let client_clone = client.clone();
        let node_arc = Arc::new(node.clone());

        // Process messages in parallel without per-chat locking
        // The Signal protocol store has internal locking to prevent race conditions
        // This allows new messages (like "ping") to be processed immediately
        // even if there are many queued undecryptable messages from the same chat
        tokio::spawn(async move {
            client_clone.handle_encrypted_message(node_arc).await;
        });

        true
    }
}
