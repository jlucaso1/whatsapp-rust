use crate::client::Client;
use async_trait::async_trait;
use std::sync::Arc;
use wacore_binary::node::Node;

/// Trait for handling specific types of XML stanzas received from the WhatsApp server.
///
/// Each handler is responsible for processing a specific top-level XML tag (e.g., "message", "iq", "receipt").
/// This pattern allows for better separation of concerns and makes it easier to add new stanza types
/// without modifying the core client dispatch logic.
#[async_trait]
pub trait StanzaHandler: Send + Sync {
    /// Returns the XML tag this handler is responsible for (e.g., "message", "iq").
    fn tag(&self) -> &'static str;

    /// Asynchronously handle the incoming node.
    ///
    /// # Arguments
    /// * `client` - Arc reference to the client instance
    /// * `node` - Arc-wrapped owned Node (avoids cloning - handlers can share or store cheaply)
    /// * `cancelled` - If set to `true`, prevents the deferred ack from being sent
    ///
    /// # Returns
    /// Returns `true` if the node was successfully handled, `false` if it should be
    /// processed by other handlers or logged as unhandled.
    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, cancelled: &mut bool) -> bool;
}
