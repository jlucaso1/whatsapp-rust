use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use std::sync::Arc;
use wacore_binary::node::Node;

/// Handler for `<success>` stanzas.
///
/// Processes successful authentication/connection events.
#[derive(Default)]
pub struct SuccessHandler;

#[async_trait]
impl StanzaHandler for SuccessHandler {
    fn tag(&self) -> &'static str {
        "success"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        client.handle_success(&node).await;
        true
    }
}

/// Handler for `<failure>` stanzas.
///
/// Processes connection or authentication failures.
#[derive(Default)]
pub struct FailureHandler;

#[async_trait]
impl StanzaHandler for FailureHandler {
    fn tag(&self) -> &'static str {
        "failure"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        client.handle_connect_failure(&node).await;
        true
    }
}

/// Handler for `<stream:error>` stanzas.
///
/// Processes stream-level errors that may require connection reset.
#[derive(Default)]
pub struct StreamErrorHandler;

#[async_trait]
impl StanzaHandler for StreamErrorHandler {
    fn tag(&self) -> &'static str {
        "stream:error"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        client.handle_stream_error(&node).await;
        true
    }
}

/// Handler for `<ack>` stanzas.
///
/// Processes acknowledgment messages.
#[derive(Default)]
pub struct AckHandler;

#[async_trait]
impl StanzaHandler for AckHandler {
    fn tag(&self) -> &'static str {
        "ack"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        // Delegate to the client to check if any task is waiting for this ack.
        // The client will resolve pending response waiters if the ID matches.
        // Try to unwrap Arc or clone Node if there are other references
        let owned_node = Arc::try_unwrap(node).unwrap_or_else(|arc| (*arc).clone());
        client.handle_ack_response(owned_node).await;
        // We return `true` because this handler's purpose is to consume all <ack> stanzas.
        true
    }
}
