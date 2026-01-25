use crate::client::Client;
use crate::socket::error::SocketError;
use log::warn;
use std::sync::Arc;
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
    #[error("Failed to parse IQ response: {0}")]
    ParseError(#[from] anyhow::Error),
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
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use wacore::request::{InfoQuery, InfoQueryType};
    /// use wacore_binary::builder::NodeBuilder;
    /// use wacore_binary::node::NodeContent;
    /// use wacore_binary::jid::{Jid, SERVER_JID};
    ///
    /// // This is a simplified example - real usage requires proper setup
    /// # async fn example(client: &whatsapp_rust::Client) -> Result<(), Box<dyn std::error::Error>> {
    /// let query_node = NodeBuilder::new("presence")
    ///     .attr("type", "available")
    ///     .build();
    ///
    /// let server_jid = Jid::new("", SERVER_JID);
    ///
    /// let query = InfoQuery {
    ///     query_type: InfoQueryType::Set,
    ///     namespace: "presence",
    ///     to: server_jid,
    ///     target: None,
    ///     content: Some(NodeContent::Nodes(vec![query_node])),
    ///     id: None,
    ///     timeout: None,
    /// };
    ///
    /// let response = client.send_iq(query).await?;
    /// # Ok(())
    /// # }
    /// ```
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
            Ok(Ok(response_node)) => match *request_utils.parse_iq_response(&response_node) {
                Ok(()) => Ok(response_node),
                Err(e) => Err(e.into()),
            },
            Ok(Err(_)) => Err(IqError::InternalChannelClosed),
            Err(_) => {
                self.response_waiters.lock().await.remove(&req_id);
                Err(IqError::Timeout)
            }
        }
    }

    /// Executes an IQ specification and returns the typed response.
    ///
    /// This is a convenience method that combines building the IQ request,
    /// sending it, and parsing the response into a single operation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use wacore::iq::groups::GroupQueryIq;
    ///
    /// let group_info = client.execute(GroupQueryIq::new(&group_jid)).await?;
    /// println!("Group subject: {}", group_info.subject);
    /// ```
    pub async fn execute<S>(&self, spec: S) -> Result<S::Response, IqError>
    where
        S: wacore::iq::spec::IqSpec,
    {
        let iq = spec.build_iq();
        let response = self.send_iq(iq).await?;
        spec.parse_response(&response).map_err(IqError::ParseError)
    }

    /// Handles an IQ response by checking if there's a waiter for this response ID.
    ///
    /// This method accepts an `Arc<Node>` - if there's a waiter, we clone the Arc (cheap)
    /// and unwrap it if we're the only holder, otherwise clone the inner Node.
    pub(crate) async fn handle_iq_response(&self, node: Arc<Node>) -> bool {
        let id_opt = node.attrs.get("id").map(|v| v.to_string_value());
        if let Some(id) = id_opt {
            // First check if there's a waiter (without cloning)
            let waiter = self.response_waiters.lock().await.remove(&id);
            if let Some(waiter) = waiter {
                // Try to unwrap the Arc, or clone if there are other references
                let owned_node = Arc::try_unwrap(node).unwrap_or_else(|arc| (*arc).clone());
                if waiter.send(owned_node).is_err() {
                    warn!(target: "Client/IQ", "Failed to send IQ response to waiter for ID {id}. Receiver was likely dropped.");
                }
                return true;
            }
        }
        false
    }
}
