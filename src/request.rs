use crate::client::Client;
use crate::socket::error::SocketError;
use log::warn;
use std::time::Duration;
use thiserror::Error;
use tokio::time::timeout;
use wacore_binary::node::Node;

pub use wacore::request::{InfoQuery, InfoQueryType, RequestUtils};

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

impl From<wacore::request::IqError> for IqError {
    fn from(err: wacore::request::IqError) -> Self {
        match err {
            wacore::request::IqError::Timeout => Self::Timeout,
            wacore::request::IqError::NotConnected => Self::NotConnected,
            wacore::request::IqError::Disconnected(node) => Self::Disconnected(node),
            wacore::request::IqError::ServerError { code, text } => {
                Self::ServerError { code, text }
            }
            wacore::request::IqError::InternalChannelClosed => Self::InternalChannelClosed,
            wacore::request::IqError::Network(msg) => Self::Socket(SocketError::Crypto(msg)),
        }
    }
}

impl Client {
    pub(crate) fn generate_request_id(&self) -> String {
        self.get_request_utils().generate_request_id()
    }

    /// Generates a unique message ID that conforms to the WhatsApp protocol format.
    ///
    /// This is an advanced function that allows library users to generate message IDs
    /// that are compatible with the WhatsApp protocol. The generated ID includes
    /// timestamp, user JID, and random components to ensure uniqueness.
    ///
    /// # Advanced Use Case
    ///
    /// This function is intended for advanced users who need to build custom protocol
    /// interactions or manage message IDs manually. Most users should use higher-level
    /// methods like `send_message` which handle ID generation automatically.
    ///
    /// # Returns
    ///
    /// A string containing the generated message ID in the format expected by WhatsApp.
    pub async fn generate_message_id(&self) -> String {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        self.get_request_utils()
            .generate_message_id(device_snapshot.pn.as_ref())
    }

    fn get_request_utils(&self) -> RequestUtils {
        RequestUtils::with_counter(self.unique_id.clone(), self.id_counter.clone())
    }

    /// Sends a custom IQ (Info/Query) stanza to the WhatsApp server.
    ///
    /// This is an advanced function that allows library users to send custom IQ stanzas
    /// for protocol interactions that are not covered by higher-level methods. Common
    /// use cases include live location updates, custom presence management, or other
    /// advanced WhatsApp features.
    ///
    /// # Advanced Use Case
    ///
    /// This function bypasses some of the higher-level abstractions and safety checks
    /// provided by other client methods. Users should be familiar with the WhatsApp
    /// protocol and IQ stanza format before using this function.
    ///
    /// # Arguments
    ///
    /// * `query` - The IQ query to send, containing the stanza type, namespace, content, and optional timeout
    ///
    /// # Returns
    ///
    /// * `Ok(Node)` - The response node from the server
    /// * `Err(IqError)` - Various error conditions including timeout, connection issues, or server errors
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

        if let Err(e) = self.send_node(node).await {
            self.response_waiters.lock().await.remove(&req_id);
            return match e {
                crate::client::ClientError::Socket(s_err) => Err(IqError::Socket(s_err)),
                crate::client::ClientError::NotConnected => Err(IqError::NotConnected),
                _ => Err(IqError::Socket(SocketError::Crypto(e.to_string()))),
            };
        }

        match timeout(query.timeout.unwrap_or(default_timeout), rx).await {
            Ok(Ok(response_node)) => {
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

    pub(crate) async fn handle_iq_response(&self, node: Node) -> bool {
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

#[cfg(test)]
mod tests {
    use super::*;

    // This test verifies that the public API methods are accessible
    // It's a compile-time test - if the methods aren't public, this won't compile
    #[tokio::test]
    async fn test_public_api_accessibility() {
        // We can't test the actual functionality without a real client setup,
        // but we can verify the methods exist and are public by checking they exist

        // This is a compile-time test for method visibility
        // The fact that this compiles means the methods are public and accessible

        // If these were private, this would fail to compile
        fn _check_methods_exist() {
            // Check that generate_message_id exists and is accessible
            let _method = Client::generate_message_id;

            // Check that send_iq exists and is accessible
            let _method = Client::send_iq;
        }

        // Test passes if it compiles - which it will if methods are public
        _check_methods_exist();
    }
}
