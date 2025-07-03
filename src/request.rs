use crate::binary::node::{Attrs, Node, NodeContent};
use crate::client::Client;
use crate::socket::error::SocketError;
use crate::types::jid::Jid;
use log::warn;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

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
        attrs.insert("id".into(), req_id.clone().into());
        attrs.insert("xmlns".into(), query.namespace.into());
        attrs.insert("type".into(), query.query_type.as_str().into());
        attrs.insert("to".into(), query.to.to_string().into());
        if let Some(target) = query.target {
            if !target.is_empty() {
                attrs.insert("target".into(), target.to_string().into());
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
                    warn!(target: "Client/IQ", "Failed to send IQ response to waiter for ID {}. Receiver was likely dropped.", id);
                }
                return true;
            }
        }
        false
    }
}
