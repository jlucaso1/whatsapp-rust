use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use std::sync::Arc;
use wacore_binary::node::Node;

/// Handler for stanza types that are not yet fully implemented.
///
/// This handler provides a placeholder for stanza types like:
/// - `<call>` - Voice/video call signaling
/// - `<presence>` - User presence updates
/// - `<chatstate>` - Typing indicators
///
/// These will be logged and handled minimally until full implementations are added.
pub struct UnimplementedHandler {
    tags: Vec<&'static str>,
}

impl UnimplementedHandler {
    pub fn new(tags: Vec<&'static str>) -> Self {
        Self { tags }
    }

    pub fn for_call() -> Self {
        Self::new(vec!["call"])
    }

    pub fn for_presence() -> Self {
        Self::new(vec!["presence"])
    }
}

#[async_trait]
impl StanzaHandler for UnimplementedHandler {
    fn tag(&self) -> &'static str {
        // For multi-tag handlers, we'll register multiple instances
        // This method should only be called after registration
        if self.tags.len() == 1 {
            self.tags[0]
        } else {
            panic!("UnimplementedHandler with multiple tags should be registered individually")
        }
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        client.handle_unimplemented(&node.tag).await;
        true
    }
}
