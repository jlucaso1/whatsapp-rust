use crate::binary::node::Node;
use crate::client::Client;
use crate::socket::error::SocketError;
use log::warn;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;

// Re-export core types
pub use whatsapp_core::request::{InfoQuery, InfoQueryType, RequestUtils};

/// Platform-specific IQ error that includes socket errors
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

impl From<whatsapp_core::request::IqError> for IqError {
    fn from(err: whatsapp_core::request::IqError) -> Self {
        match err {
            whatsapp_core::request::IqError::Timeout => Self::Timeout,
            whatsapp_core::request::IqError::NotConnected => Self::NotConnected,
            whatsapp_core::request::IqError::Disconnected(node) => Self::Disconnected(node),
            whatsapp_core::request::IqError::ServerError { code, text } => Self::ServerError { code, text },
            whatsapp_core::request::IqError::InternalChannelClosed => Self::InternalChannelClosed,
            whatsapp_core::request::IqError::Network(msg) => Self::Socket(SocketError::Crypto(msg)),
        }
    }
}

impl Client {
    /// Generates a new unique request ID string.
    pub fn generate_request_id(&self) -> String {
        self.get_request_utils().generate_request_id()
    }

    /// Generates a proper WhatsApp message ID in the format expected by the protocol.
    pub async fn generate_message_id(&self) -> String {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        self.get_request_utils().generate_message_id(device_snapshot.id.as_ref())
    }

    /// Gets the request utilities instance
    fn get_request_utils(&self) -> RequestUtils {
        RequestUtils::with_counter(self.unique_id.clone(), self.id_counter.clone())
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

        let request_utils = self.get_request_utils();
        let node = request_utils.build_iq_node(&query, Some(req_id.clone()));

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
                // Use core logic to parse the response
                request_utils.parse_iq_response(&response_node)?;
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
        if let Some(id) = id_opt
            && let Some(waiter) = self.response_waiters.lock().await.remove(&id)
        {
            if waiter.send(node).is_err() {
                warn!(target: "Client/IQ", "Failed to send IQ response to waiter for ID {id}. Receiver was likely dropped.");
            }
            return true;
        }
        false
    }
}
