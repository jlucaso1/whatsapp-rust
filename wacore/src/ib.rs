//! IB stanza types for unified session telemetry.
//!
//! Wire format: `<ib><unified_session id="..."/></ib>`

use crate::protocol::ProtocolNode;
use anyhow::Result;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::node::Node;

/// Unified session telemetry node.
///
/// Session ID formula: `(now_ms + server_offset_ms + 3_DAYS_MS) % 7_DAYS_MS`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnifiedSession {
    pub id: String,
}

impl UnifiedSession {
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    /// Calculate session ID from server time offset.
    pub fn calculate_id(server_time_offset_ms: i64) -> String {
        const DAY_MS: i64 = 24 * 60 * 60 * 1000;
        const WEEK_MS: i64 = 7 * DAY_MS;
        const OFFSET_MS: i64 = 3 * DAY_MS;

        let now = chrono::Utc::now().timestamp_millis();
        let adjusted_now = now + server_time_offset_ms;
        let id = (adjusted_now + OFFSET_MS) % WEEK_MS;
        id.to_string()
    }

    pub fn from_offset(server_time_offset_ms: i64) -> Self {
        Self::new(Self::calculate_id(server_time_offset_ms))
    }
}

impl ProtocolNode for UnifiedSession {
    fn tag(&self) -> &'static str {
        "unified_session"
    }

    fn into_node(self) -> Node {
        NodeBuilder::new("unified_session")
            .attr("id", self.id)
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "unified_session" {
            return Err(anyhow::anyhow!(
                "expected <unified_session>, got <{}>",
                node.tag
            ));
        }
        let id = node
            .attrs
            .get("id")
            .map(|v| v.to_string_value())
            .unwrap_or_default();
        Ok(Self { id })
    }
}

/// IB stanza content types.
#[derive(Debug, Clone)]
pub enum IbContent {
    UnifiedSession(UnifiedSession),
}

impl IbContent {
    pub fn into_node(self) -> Node {
        match self {
            IbContent::UnifiedSession(us) => us.into_node(),
        }
    }
}

/// IB (Information Broadcast) stanza container.
#[derive(Debug, Clone)]
pub struct IbStanza {
    pub content: IbContent,
}

impl IbStanza {
    pub fn unified_session(session: UnifiedSession) -> Self {
        Self {
            content: IbContent::UnifiedSession(session),
        }
    }
}

impl ProtocolNode for IbStanza {
    fn tag(&self) -> &'static str {
        "ib"
    }

    fn into_node(self) -> Node {
        NodeBuilder::new("ib")
            .children([self.content.into_node()])
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "ib" {
            return Err(anyhow::anyhow!("expected <ib>, got <{}>", node.tag));
        }

        if let Some(children) = node.children() {
            for child in children {
                if child.tag == "unified_session" {
                    return Ok(Self::unified_session(UnifiedSession::try_from_node(child)?));
                }
            }
        }

        Err(anyhow::anyhow!("unknown or missing <ib> content"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_session_into_node() {
        let session = UnifiedSession::new("123456789");
        let node = session.into_node();

        assert_eq!(node.tag, "unified_session");
        assert_eq!(
            node.attrs.get("id").and_then(|v| v.as_str()),
            Some("123456789")
        );
    }

    #[test]
    fn test_unified_session_try_from_node() {
        let node = NodeBuilder::new("unified_session")
            .attr("id", "123456789")
            .build();

        let session = UnifiedSession::try_from_node(&node).unwrap();
        assert_eq!(session.id, "123456789");
    }

    #[test]
    fn test_ib_stanza_into_node() {
        let stanza = IbStanza::unified_session(UnifiedSession::new("123456789"));
        let node = stanza.into_node();

        assert_eq!(node.tag, "ib");
        let children = node.children().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "unified_session");
        assert_eq!(
            children[0].attrs.get("id").and_then(|v| v.as_str()),
            Some("123456789")
        );
    }

    #[test]
    fn test_unified_session_calculate_id() {
        const WEEK_MS: i64 = 7 * 24 * 60 * 60 * 1000;

        let id = UnifiedSession::calculate_id(0);
        let id_num: i64 = id.parse().unwrap();
        assert!(id_num >= 0);
        assert!(id_num < WEEK_MS);

        let id_positive = UnifiedSession::calculate_id(5000);
        let id_positive_num: i64 = id_positive.parse().unwrap();
        assert!(id_positive_num >= 0);
        assert!(id_positive_num < WEEK_MS);

        let id_negative = UnifiedSession::calculate_id(-5000);
        let id_negative_num: i64 = id_negative.parse().unwrap();
        assert!(id_negative_num >= 0);
        assert!(id_negative_num < WEEK_MS);
    }

    #[test]
    fn test_unified_session_from_offset() {
        let session = UnifiedSession::from_offset(1000);
        assert!(!session.id.is_empty());
    }
}
