use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// IQ namespace for dirty bits.
pub const DIRTY_NAMESPACE: &str = "urn:xmpp:whatsapp:dirty";

/// Known dirty bit types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirtyType {
    AccountSync,
    Groups,
    Other(String),
}

impl DirtyType {
    pub fn as_str(&self) -> &str {
        match self {
            DirtyType::AccountSync => "account_sync",
            DirtyType::Groups => "groups",
            DirtyType::Other(s) => s.as_str(),
        }
    }
}

impl From<&str> for DirtyType {
    fn from(s: &str) -> Self {
        match s {
            "account_sync" => DirtyType::AccountSync,
            "groups" => DirtyType::Groups,
            other => DirtyType::Other(other.to_string()),
        }
    }
}

/// A dirty bit to clean.
#[derive(Debug, Clone)]
pub struct DirtyBit {
    pub dirty_type: DirtyType,
    pub timestamp: Option<u64>,
}

impl DirtyBit {
    pub fn new(dirty_type: impl Into<DirtyType>) -> Self {
        Self {
            dirty_type: dirty_type.into(),
            timestamp: None,
        }
    }

    pub fn with_timestamp(dirty_type: impl Into<DirtyType>, timestamp: u64) -> Self {
        Self {
            dirty_type: dirty_type.into(),
            timestamp: Some(timestamp),
        }
    }
}

/// Clears dirty bits on the server.
#[derive(Debug, Clone)]
pub struct CleanDirtyBitsSpec {
    pub bits: Vec<DirtyBit>,
}

impl CleanDirtyBitsSpec {
    /// Returns error if `timestamp` cannot be parsed as `u64`.
    pub fn single(dirty_type: &str, timestamp: Option<&str>) -> Result<Self, anyhow::Error> {
        let bit = if let Some(ts) = timestamp {
            let ts_num: u64 = ts
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid timestamp '{}': {}", ts, e))?;
            DirtyBit::with_timestamp(DirtyType::from(dirty_type), ts_num)
        } else {
            DirtyBit::new(DirtyType::from(dirty_type))
        };
        Ok(Self { bits: vec![bit] })
    }

    pub fn multiple(bits: Vec<DirtyBit>) -> Self {
        Self { bits }
    }
}

impl IqSpec for CleanDirtyBitsSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let children: Vec<Node> = self
            .bits
            .iter()
            .map(|bit| {
                let mut builder =
                    NodeBuilder::new("clean").attr("type", bit.dirty_type.as_str().to_string());
                if let Some(ts) = bit.timestamp {
                    builder = builder.attr("timestamp", ts.to_string());
                }
                builder.build()
            })
            .collect();

        InfoQuery::set(
            DIRTY_NAMESPACE,
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(children)),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response, anyhow::Error> {
        // Clean dirty bits just needs a successful response
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_dirty_bits_spec_single() {
        let spec = CleanDirtyBitsSpec::single("account_sync", None).unwrap();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, DIRTY_NAMESPACE);
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "clean");
            assert_eq!(
                nodes[0].attrs.get("type").and_then(|v| v.as_str()),
                Some("account_sync")
            );
            assert!(nodes[0].attrs.get("timestamp").is_none());
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_clean_dirty_bits_spec_with_timestamp() {
        let spec = CleanDirtyBitsSpec::single("groups", Some("1234567890")).unwrap();
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(
                nodes[0].attrs.get("type").and_then(|v| v.as_str()),
                Some("groups")
            );
            assert_eq!(
                nodes[0].attrs.get("timestamp").and_then(|v| v.as_str()),
                Some("1234567890")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_clean_dirty_bits_spec_invalid_timestamp() {
        let result = CleanDirtyBitsSpec::single("account_sync", Some("not_a_number"));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid timestamp"),
            "Error should mention invalid timestamp: {}",
            err_msg
        );
    }

    #[test]
    fn test_clean_dirty_bits_spec_multiple() {
        let bits = vec![
            DirtyBit::new(DirtyType::AccountSync),
            DirtyBit::with_timestamp(DirtyType::Groups, 9876543210),
        ];
        let spec = CleanDirtyBitsSpec::multiple(bits);
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 2);
            assert_eq!(
                nodes[0].attrs.get("type").and_then(|v| v.as_str()),
                Some("account_sync")
            );
            assert!(nodes[0].attrs.get("timestamp").is_none());
            assert_eq!(
                nodes[1].attrs.get("type").and_then(|v| v.as_str()),
                Some("groups")
            );
            assert_eq!(
                nodes[1].attrs.get("timestamp").and_then(|v| v.as_str()),
                Some("9876543210")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_clean_dirty_bits_spec_parse_response() {
        let spec = CleanDirtyBitsSpec::single("account_sync", None).unwrap();
        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response);
        assert!(result.is_ok());
    }

    #[test]
    fn test_dirty_type_from_str() {
        assert_eq!(DirtyType::from("account_sync"), DirtyType::AccountSync);
        assert_eq!(DirtyType::from("groups"), DirtyType::Groups);
        assert_eq!(
            DirtyType::from("other"),
            DirtyType::Other("other".to_string())
        );
    }
}
