use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use log::debug;
use std::sync::Arc;
use wacore_binary::node::Node;

/// Handler for `<chatstate>` stanzas (typing indicators).
///
/// Currently we just log them at DEBUG level to avoid log noise,
/// as we don't need to take any action on them yet.
pub struct ChatStateHandler;

#[async_trait]
impl StanzaHandler for ChatStateHandler {
    fn tag(&self) -> &'static str {
        "chatstate"
    }

    async fn handle(&self, _client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        let from = node
            .attrs
            .get("from")
            .and_then(|s| s.as_str())
            .unwrap_or("unknown");
        debug!(target: "Client", "Received chatstate from {}: {:?}", from, node);
        true
    }
}
