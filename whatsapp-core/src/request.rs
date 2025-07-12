use crate::binary::node::{Attrs, Node, NodeContent};
use crate::types::jid::Jid;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

/// Represents the type of an IQ stanza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoQueryType {
    Set,
    Get,
}

impl InfoQueryType {
    pub fn as_str(&self) -> &'static str {
        match self {
            InfoQueryType::Set => "set",
            InfoQueryType::Get => "get",
        }
    }
}

/// Defines an IQ request to be sent to the server.
#[derive(Debug, Clone)]
pub struct InfoQuery<'a> {
    pub namespace: &'a str,
    pub query_type: InfoQueryType,
    pub to: Jid,
    pub target: Option<Jid>,
    pub id: Option<String>,
    pub content: Option<NodeContent>,
    pub timeout: Option<Duration>,
}

/// Custom error types for IQ operations.
#[derive(Debug, Error)]
pub enum IqError {
    #[error("IQ request timed out")]
    Timeout,
    #[error("Client is not connected")]
    NotConnected,
    #[error("Received disconnect node during IQ wait: {0:?}")]
    Disconnected(Node),
    #[error("Received a server error response: code={code}, text='{text}'")]
    ServerError { code: u16, text: String },
    #[error("Internal channel closed unexpectedly")]
    InternalChannelClosed,
    #[error("Network error: {0}")]
    Network(String),
}

/// Core request utilities that are platform-independent
pub struct RequestUtils {
    unique_id: String,
    id_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl RequestUtils {
    pub fn new(unique_id: String) -> Self {
        Self {
            unique_id,
            id_counter: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn with_counter(
        unique_id: String,
        id_counter: std::sync::Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            unique_id,
            id_counter,
        }
    }

    /// Generates a new unique request ID string.
    pub fn generate_request_id(&self) -> String {
        let count = self
            .id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!(
            "{unique_id}-{count}",
            unique_id = self.unique_id,
            count = count
        )
    }

    /// Generates a proper WhatsApp message ID in the format expected by the protocol.
    /// Message IDs are used for chat messages and must follow the 3EB0... format
    /// to ensure proper synchronization across devices and support for features
    /// like receipts, replies, reactions, and message revokes.
    pub fn generate_message_id(&self, user_jid: Option<&Jid>) -> String {
        let mut data = Vec::with_capacity(8 + 20 + 16);

        // 1. Add current unix timestamp (8 bytes)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        data.extend_from_slice(&timestamp.to_be_bytes());

        // 2. Add own JID if available (best effort)
        if let Some(jid) = user_jid {
            data.extend_from_slice(jid.user.as_bytes());
            data.extend_from_slice(b"@c.us"); // whatsmeow uses legacy server here
        }

        // 3. Add random bytes (16 bytes)
        let mut random_bytes = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut random_bytes);
        data.extend_from_slice(&random_bytes);

        // 4. Hash, truncate, and format with 3EB0 prefix
        let hash = Sha256::digest(&data);
        let truncated_hash = &hash[..9]; // Use first 9 bytes for 18 hex chars

        format!(
            "3EB0{hash}",
            hash = hex::encode(truncated_hash).to_uppercase()
        )
    }

    /// Builds an IQ node from the given InfoQuery
    pub fn build_iq_node(&self, query: &InfoQuery<'_>, req_id: Option<String>) -> Node {
        let id = req_id.unwrap_or_else(|| self.generate_request_id());

        let mut attrs = Attrs::new();
        attrs.insert("id".into(), id);
        attrs.insert("xmlns".into(), query.namespace.into());
        attrs.insert("type".into(), query.query_type.as_str().into());
        attrs.insert("to".into(), query.to.to_string());

        if let Some(target) = &query.target {
            if !target.is_empty() {
                attrs.insert("target".into(), target.to_string());
            }
        }

        Node {
            tag: "iq".into(),
            attrs,
            content: query.content.clone(),
        }
    }

    /// Parses an IQ response to check for errors
    pub fn parse_iq_response(&self, response_node: &Node) -> Result<(), IqError> {
        if response_node.tag == "stream:error" || response_node.tag == "xmlstreamend" {
            return Err(IqError::Disconnected(response_node.clone()));
        }

        if let Some(res_type) = response_node.attrs.get("type")
            && res_type == "error"
        {
            let error_child = response_node.get_optional_child_by_tag(&["error"]);
            if let Some(error_node) = error_child {
                let mut parser = crate::binary::attrs::AttrParser::new(error_node);
                let code = parser.optional_u64("code").unwrap_or(0) as u16;
                let text = parser.optional_string("text").unwrap_or("").to_string();
                return Err(IqError::ServerError { code, text });
            }
            // Fallback for a malformed error response with no child
            return Err(IqError::ServerError {
                code: 0,
                text: "Malformed error response".to_string(),
            });
        }

        Ok(())
    }
}
