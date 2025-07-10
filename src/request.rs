use crate::binary::node::{Attrs, Node, NodeContent};
use crate::client::Client;
use crate::socket::error::SocketError;
use crate::types::jid::Jid;
use log::warn;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

// Additional imports for message ID generation
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore;

/// Represents the type of an IQ stanza.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InfoQueryType {
    Set,
    Get,
}

impl InfoQueryType {
    fn as_str(&self) -> &'static str {
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
    #[error("Socket error: {0}")]
    Socket(#[from] SocketError),
    #[error("Received disconnect node during IQ wait: {0:?}")]
    Disconnected(Node),
    #[error("Received a server error response: code={code}, text='{text}'")]
    ServerError { code: u16, text: String },
    #[error("Internal channel closed unexpectedly")]
    InternalChannelClosed,
}

impl Client {
    /// Generates a new unique request ID string.
    pub fn generate_request_id(&self) -> String {
        let count = self
            .id_counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!("{}-{}", self.unique_id, count)
    }

    /// Generates a proper WhatsApp message ID in the format expected by the protocol.
    /// Message IDs are used for chat messages and must follow the 3EB0... format
    /// to ensure proper synchronization across devices and support for features
    /// like receipts, replies, reactions, and message revokes.
    pub async fn generate_message_id(&self) -> String {
        let mut data = Vec::with_capacity(8 + 20 + 16);

        // 1. Add current unix timestamp (8 bytes)
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        data.extend_from_slice(&timestamp.to_be_bytes());

        // 2. Add own JID if available (best effort)
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        if let Some(jid) = &device_snapshot.id {
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

        format!("3EB0{}", hex::encode(truncated_hash).to_uppercase())
    }

    /// Sends an IQ (Info/Query) stanza and asynchronously waits for a response.
    pub async fn send_iq(&self, query: InfoQuery<'_>) -> Result<Node, IqError> {
        let req_id = query
            .id
            .clone()
            .unwrap_or_else(|| self.generate_request_id());
        let default_timeout = Duration::from_secs(75);

        let (tx, rx) = tokio::sync::oneshot::channel();
        self.response_waiters
            .lock()
            .await
            .insert(req_id.clone(), tx);

        let mut attrs = Attrs::new();
        attrs.insert("id".into(), req_id.clone());
        attrs.insert("xmlns".into(), query.namespace.into());
        attrs.insert("type".into(), query.query_type.as_str().into());
        attrs.insert("to".into(), query.to.to_string());
        if let Some(target) = query.target {
            if !target.is_empty() {
                attrs.insert("target".into(), target.to_string());
            }
        }

        let node = Node {
            tag: "iq".into(),
            attrs,
            content: query.content,
        };

        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
            Some(s) => s,
            None => return Err(IqError::NotConnected),
        };
        if let Err(e) = noise_socket.send_node(&node).await {
            self.response_waiters.lock().await.remove(&req_id);
            return Err(IqError::Socket(e));
        }

        match timeout(query.timeout.unwrap_or(default_timeout), rx).await {
            Ok(Ok(response_node)) => {
                if response_node.tag == "stream:error" || response_node.tag == "xmlstreamend" {
                    return Err(IqError::Disconnected(response_node));
                }

                if let Some(res_type) = response_node.attrs.get("type") {
                    if res_type == "error" {
                        let error_child = response_node.get_optional_child_by_tag(&["error"]);
                        if let Some(error_node) = error_child {
                            let mut parser = crate::binary::attrs::AttrParser::new(error_node);
                            let code = parser.optional_u64("code").unwrap_or(0) as u16;
                            let text = parser.optional_string("text").unwrap_or("").to_string();
                            if !parser.ok() {
                                warn!(
                                    target: "Client/IQ",
                                    "Attribute parsing errors in IQ error response: {:?}",
                                    parser.errors
                                );
                            }
                            return Err(IqError::ServerError { code, text });
                        }
                        // Fallback for a malformed error response with no child
                        return Err(IqError::ServerError {
                            code: 0,
                            text: "Malformed error response".to_string(),
                        });
                    }
                }
                Ok(response_node)
            }
            Ok(Err(_)) => Err(IqError::InternalChannelClosed),
            Err(_) => {
                self.response_waiters.lock().await.remove(&req_id);
                Err(IqError::Timeout)
            }
        }
    }

    /// Handles an incoming IQ response by forwarding it to the waiting task.
    pub async fn handle_iq_response(&self, node: Node) -> bool {
        let id_opt = node.attrs.get("id").cloned();
        if let Some(id) = id_opt {
            if let Some(waiter) = self.response_waiters.lock().await.remove(&id) {
                if waiter.send(node).is_err() {
                    warn!(target: "Client/IQ", "Failed to send IQ response to waiter for ID {id}. Receiver was likely dropped.");
                }
                return true;
            }
        }
        false
    }
}
