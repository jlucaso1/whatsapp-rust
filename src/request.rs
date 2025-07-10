use crate::binary::node::{Node, NodeContent}; // Keep Node, NodeContent
use crate::types::jid::Jid; // Keep Jid
                            // Remove: use crate::client::Client;
                            // Remove: use crate::socket::error::SocketError; // IqError::Socket will take String
                            // Remove: use log::warn;
use std::time::Duration; // Keep Duration for InfoQuery
use thiserror::Error;
// Remove: use tokio::time::timeout; // Not used in this file anymore

/// Represents the type of an IQ stanza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoQueryType {
    Set,
    Get,
}

impl InfoQueryType {
    // This method might be used by code that constructs InfoQuery, keep for now
    #[allow(dead_code)] // If not used elsewhere after Client::send_iq removal
    fn as_str(&self) -> &'static str {
        match self {
            InfoQueryType::Set => "set",
            InfoQueryType::Get => "get",
        }
    }
}

/// Defines an IQ request to be sent. (Used by SessionManager to construct IQs)
/// Note: The sending logic (Client::send_iq) is moved to StanzaProcessor.
#[derive(Debug, Clone)]
pub struct InfoQuery<'a> {
    pub namespace: &'a str,
    pub query_type: InfoQueryType,
    pub to: Jid,
    pub target: Option<Jid>,
    pub id: Option<String>, // StanzaProcessor.send_request_iq will generate if None
    pub content: Option<NodeContent>,
    pub timeout: Option<Duration>, // StanzaProcessor.send_request_iq will use its default if None
}

/// Custom error types for IQ operations.
#[derive(Debug, Error)]
pub enum IqError {
    #[error("IQ request timed out")]
    Timeout,
    #[error("Socket error during IQ send/recv: {0}")]
    Socket(String),
    // Disconnected variant might be less relevant here, as StanzaProcessor won't be waiting on an IQ if disconnected.
    // ConnectionManager's read_loop would terminate.
    // #[error("Received disconnect while waiting for IQ response: {0:?}")]
    // Disconnected(Node),
    #[error("IQ server error response: code={code}, text='{text}'")]
    ServerError { code: u16, text: String },
    #[error("Response channel closed prematurely / request dropped")]
    RequestDropped,
    #[error("Bad IQ request: {0}")]
    BadRequest(String),
    #[error("IQ operation failed: {0}")]
    Other(String),
}

// The `impl Client` block containing `send_iq` and `handle_iq_response` is removed
// as this functionality is now part of StanzaProcessor.
// Helper functions to *construct* specific IQ Nodes might still live here,
// but not the sending/response handling logic tied to the old Client.
