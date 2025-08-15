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
    pub fn generate_request_id(&self) -> String {
        self.get_request_utils().generate_request_id()
    }

    pub async fn generate_message_id(&self) -> String {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        self.get_request_utils()
            .generate_message_id(device_snapshot.id.as_ref())
    }

    fn get_request_utils(&self) -> RequestUtils {
        RequestUtils::with_counter(self.unique_id.clone(), self.id_counter.clone())
    }

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
