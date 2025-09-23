use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use log::warn;
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

    async fn handle(&self, client: Arc<Client>, node: &Node) -> bool {
        let client_clone = client.clone();
        let node_arc = Arc::new(node.clone());

        tokio::spawn(async move {
            let info = match client_clone.parse_message_info(&node_arc).await {
                Ok(info) => info,
                Err(e) => {
                    warn!(
                        "Could not parse message info to acquire lock; dropping message. Error: {e:?}"
                    );
                    return;
                }
            };
            let chat_jid = info.source.chat;

            let mutex_arc = client_clone
                .chat_locks
                .entry(chat_jid)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone();

            let _lock_guard = mutex_arc.lock().await;

            client_clone.handle_encrypted_message(node_arc).await;
        });

        true
    }
}
