use crate::binary::node::Node;
use async_trait::async_trait;

/// Trait for sending data over the network.
/// The driver implementation will handle the actual I/O operations.
#[async_trait]
pub trait NetworkTransport: Send + Sync {
    /// Send a node over the network
    async fn send_node(&self, node: Node) -> Result<(), anyhow::Error>;
    
    /// Wait for a response to an IQ with the given ID
    async fn wait_for_response(&self, id: &str, timeout: std::time::Duration) -> Result<Node, anyhow::Error>;
}

/// Trait for dispatching events to the outside world.
/// The driver implementation will handle event distribution.
#[async_trait]
pub trait EventDispatch: Send + Sync {
    /// Dispatch an event to event handlers
    async fn dispatch(&self, event: crate::types::events::Event);
}

/// Result type for core processing operations
#[derive(Debug)]
pub struct ProcessResult {
    /// Nodes that should be sent over the network
    pub nodes_to_send: Vec<Node>,
    /// Events that should be dispatched
    pub events_to_dispatch: Vec<crate::types::events::Event>,
}

impl ProcessResult {
    pub fn new() -> Self {
        Self {
            nodes_to_send: Vec::new(),
            events_to_dispatch: Vec::new(),
        }
    }
    
    pub fn with_node(mut self, node: Node) -> Self {
        self.nodes_to_send.push(node);
        self
    }
    
    pub fn with_event(mut self, event: crate::types::events::Event) -> Self {
        self.events_to_dispatch.push(event);
        self
    }
    
    pub fn with_nodes(mut self, nodes: Vec<Node>) -> Self {
        self.nodes_to_send.extend(nodes);
        self
    }
    
    pub fn with_events(mut self, events: Vec<crate::types::events::Event>) -> Self {
        self.events_to_dispatch.extend(events);
        self
    }
}

impl Default for ProcessResult {
    fn default() -> Self {
        Self::new()
    }
}