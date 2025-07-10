use crate::binary::node::Node;
use crate::store::persistence_manager::PersistenceManager;
use crate::types::events::ConnectFailureReason;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::oneshot;

// --- Messages for ConnectionManager ---
#[derive(Debug)]
pub enum ConnectionManagerCommand {
    Connect {
        persistence_manager: Arc<PersistenceManager>, // Handshake needs store access
    },
    Disconnect,
    SendFrame(Bytes), // Encrypted frame
}

#[derive(Debug)]
pub enum ConnectionManagerEvent {
    Connected,
    ConnectionFailed(ConnectFailureReason), // Or a more detailed error type
    Disconnected(bool),                     // bool indicates if it was expected
    FrameReceived(Bytes),                   // Decrypted frame
}

// --- Messages for NodeProcessor ---
#[derive(Debug)]
pub enum NodeProcessorCommand {
    ProcessDecryptedNode {
        node: Node,
        response_tx: Option<oneshot::Sender<Node>>, // For IQ responses
    },
    SendNode(Node), // Node to be sent (will be given to ConnectionManager to encrypt and send)
    // Add other commands like ProcessAppstateSync, HandleReceipt, etc.
    // Or more generic commands like:
    ProcessIncomingNode(Node),
    SendOutgoingNode {
        node: Node,
        response_tx: Option<oneshot::Sender<Result<Node, anyhow::Error>>>, // For IQs
    },
    Shutdown,
}

// NodeProcessor might send events back to the Client facade or dispatch them directly.
// If sending back to Client facade to dispatch:
#[derive(Debug, Clone)]
pub enum NodeProcessorEvent {
    // Using existing crate::types::events::Event for now
    // Or define specific ones if needed
    Event(Arc<crate::types::events::Event>),
    // Specific events for internal state if Client facade needs them
    LoggedIn,
    LoggedOut,
}

// --- Messages for the Client Facade (from Actors) ---
// This could be a unified enum or specific ones from each actor if preferred.
#[derive(Debug)]
pub enum ActorEvent {
    ConnectionEvent(ConnectionManagerEvent),
    NodeEvent(NodeProcessorEvent),
    // Can also include direct events like:
    // Disconnected(bool),
    // LoggedIn,
    // Event(Arc<crate::types::events::Event>),
}

// --- General command for the Client facade to send to appropriate actor ---
// This helps in routing commands from the public API of the Client facade.
#[derive(Debug)]
pub enum ClientActorCommand {
    Connect,
    Disconnect,
    SendNode(Node),
    SendIq {
        node: Node,
        response_tx: oneshot::Sender<Result<Node, anyhow::Error>>,
    },
    // Add more client actions here
}
