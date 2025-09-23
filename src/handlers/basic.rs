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

impl SuccessHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for SuccessHandler {
    fn tag(&self) -> &'static str {
        "success"
    }

    async fn handle(&self, client: Arc<Client>, node: &Node) -> bool {
        client.handle_success(node).await;
        true
    }
}

/// Handler for `<failure>` stanzas.
///
/// Processes connection or authentication failures.
#[derive(Default)]
pub struct FailureHandler;

impl FailureHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for FailureHandler {
    fn tag(&self) -> &'static str {
        "failure"
    }

    async fn handle(&self, client: Arc<Client>, node: &Node) -> bool {
        client.handle_connect_failure(node).await;
        true
    }
}

/// Handler for `<stream:error>` stanzas.
///
/// Processes stream-level errors that may require connection reset.
#[derive(Default)]
pub struct StreamErrorHandler;

impl StreamErrorHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for StreamErrorHandler {
    fn tag(&self) -> &'static str {
        "stream:error"
    }

    async fn handle(&self, client: Arc<Client>, node: &Node) -> bool {
        client.handle_stream_error(node).await;
        true
    }
}

/// Handler for `<ack>` stanzas.
///
/// Processes acknowledgment messages.
#[derive(Default)]
pub struct AckHandler;

impl AckHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for AckHandler {
    fn tag(&self) -> &'static str {
        "ack"
    }

    async fn handle(&self, _client: Arc<Client>, node: &Node) -> bool {
        use log::info;
        use wacore::xml::DisplayableNode;

        info!(target: "Client/Recv", "Received ACK node: {}", DisplayableNode(node));
        true
    }
}
