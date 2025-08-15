use async_trait::async_trait;
use wacore_binary::node::Node;

/// Trait for sending data over the network.
/// The driver implementation will handle the actual I/O operations.
#[async_trait]
pub trait NetworkTransport: Send + Sync {
    /// Send a node over the network
    async fn send_node(&self, node: Node) -> Result<(), anyhow::Error>;

    /// Wait for a response to an IQ with the given ID
    async fn wait_for_response(
        &self,
        id: &str,
        timeout: std::time::Duration,
    ) -> Result<Node, anyhow::Error>;
}

/// Result type for core processing operations
#[derive(Debug)]
pub struct ProcessResult {
    pub nodes_to_send: Vec<Node>,
}

impl ProcessResult {
    pub fn new() -> Self {
        Self {
            nodes_to_send: Vec::new(),
        }
    }

    pub fn with_node(mut self, node: Node) -> Self {
        self.nodes_to_send.push(node);
        self
    }

    pub fn with_nodes(mut self, nodes: Vec<Node>) -> Self {
        self.nodes_to_send.extend(nodes);
        self
    }
}

impl Default for ProcessResult {
    fn default() -> Self {
        Self::new()
    }
}
