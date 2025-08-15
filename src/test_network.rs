use std::sync::Arc;
use tokio::sync::mpsc;
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

/// Message sent over the test network bus
#[derive(Debug, Clone)]
pub struct TestMessage {
    /// The node being sent
    pub node: Node,
    /// The sender's JID
    pub from: Jid,
    /// Optional target recipient JID (for direct messages)
    pub to: Option<Jid>,
}

/// Network bus for routing messages between test clients
#[derive(Debug)]
pub struct TestNetworkBus {
    /// Channel for sending messages through the test network
    sender: mpsc::UnboundedSender<TestMessage>,
    /// Channel for receiving messages from the test network
    receiver: Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<TestMessage>>>,
}

impl TestNetworkBus {
    /// Creates a new test network bus
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            sender,
            receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
        }
    }

    /// Gets a sender handle for sending messages to the network
    pub fn get_sender(&self) -> mpsc::UnboundedSender<TestMessage> {
        self.sender.clone()
    }

    /// Gets the receiver (should only be used by the test harness)
    pub fn get_receiver(&self) -> Arc<tokio::sync::Mutex<mpsc::UnboundedReceiver<TestMessage>>> {
        self.receiver.clone()
    }
}

impl Default for TestNetworkBus {
    fn default() -> Self {
        Self::new()
    }
}
