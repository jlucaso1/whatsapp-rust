use rand_core::{OsRng, TryRngCore};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{self, Jid, JidExt};
use wacore_binary::node::{Node, NodeContent};

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

    pub fn generate_message_id(&self, user_jid: Option<&Jid>) -> String {
        let mut data = Vec::with_capacity(8 + 20 + 16);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        data.extend_from_slice(&timestamp.to_be_bytes());

        if let Some(jid) = user_jid {
            data.extend_from_slice(jid.user.as_bytes());
            data.extend_from_slice(b"@");
            data.extend_from_slice(jid::LEGACY_USER_SERVER.as_bytes());
        }

        let mut random_bytes = [0u8; 16];
        OsRng
            .try_fill_bytes(&mut random_bytes)
            .expect("failed to fill random bytes for message id");
        data.extend_from_slice(&random_bytes);

        let hash = Sha256::digest(&data);
        let truncated_hash = &hash[..9];

        format!(
            "3EB0{hash}",
            hash = hex::encode(truncated_hash).to_uppercase()
        )
    }

    pub fn build_iq_node(&self, query: &InfoQuery<'_>, req_id: Option<String>) -> Node {
        let id = req_id.unwrap_or_else(|| self.generate_request_id());

        let mut builder = NodeBuilder::new("iq")
            .attr("id", id)
            .attr("xmlns", query.namespace)
            .attr("type", query.query_type.as_str())
            .attr("to", query.to.to_string());

        if let Some(target) = &query.target
            && !target.is_empty()
        {
            builder = builder.attr("target", target.to_string());
        }

        if let Some(content) = &query.content {
            match content {
                NodeContent::Bytes(b) => builder = builder.bytes(b.clone()),
                NodeContent::String(s) => builder = builder.string_content(s.clone()),
                NodeContent::Nodes(n) => builder = builder.children(n.clone()),
            }
        }

        builder.build()
    }

    pub fn parse_iq_response(&self, response_node: &Node) -> Result<(), IqError> {
        if response_node.tag == "stream:error" || response_node.tag == "xmlstreamend" {
            return Err(IqError::Disconnected(response_node.clone()));
        }

        if let Some(res_type) = response_node.attrs.get("type")
            && res_type == "error"
        {
            let error_child = response_node.get_optional_child_by_tag(&["error"]);
            if let Some(error_node) = error_child {
                let mut parser = wacore_binary::attrs::AttrParser::new(error_node);
                let code = parser.optional_u64("code").unwrap_or(0) as u16;
                let text = parser.optional_string("text").unwrap_or("").to_string();
                return Err(IqError::ServerError { code, text });
            }
            return Err(IqError::ServerError {
                code: 0,
                text: "Malformed error response".to_string(),
            });
        }

        Ok(())
    }
}
