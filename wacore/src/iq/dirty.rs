use crate::WireEnum;
use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, Server};
use wacore_binary::{Node, NodeContent, NodeRef};

pub const DIRTY_NAMESPACE: &str = "urn:xmpp:whatsapp:dirty";

#[derive(Debug, Clone, PartialEq, Eq, WireEnum)]
pub enum DirtyType {
    #[wire = "account_sync"]
    AccountSync,
    #[wire = "groups"]
    Groups,
    #[wire = "syncd_app_state"]
    SyncdAppState,
    #[wire = "newsletter_metadata"]
    NewsletterMetadata,
    #[wire_fallback]
    Other(String),
}

#[derive(Debug, thiserror::Error)]
pub enum DirtyBitParseError {
    #[error("invalid timestamp '{value}': {source}")]
    InvalidTimestamp {
        value: String,
        source: std::num::ParseIntError,
    },
}

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

    /// Parse from raw protocol node attributes.
    pub fn from_raw(dirty_type: &str, timestamp: Option<&str>) -> Result<Self, DirtyBitParseError> {
        let ts = timestamp
            .map(|s| {
                s.parse::<u64>()
                    .map_err(|e| DirtyBitParseError::InvalidTimestamp {
                        value: s.to_string(),
                        source: e,
                    })
            })
            .transpose()?;
        Ok(Self {
            dirty_type: DirtyType::from(dirty_type),
            timestamp: ts,
        })
    }
}

/// Clears dirty bits on the server.
#[derive(Debug, Clone)]
pub struct CleanDirtyBitsSpec {
    pub bits: Vec<DirtyBit>,
}

impl CleanDirtyBitsSpec {
    pub fn single(bit: DirtyBit) -> Self {
        Self { bits: vec![bit] }
    }

    /// Parse from raw string attributes. Delegates to `DirtyBit::from_raw`.
    pub fn from_raw(dirty_type: &str, timestamp: Option<&str>) -> Result<Self, DirtyBitParseError> {
        Ok(Self {
            bits: vec![DirtyBit::from_raw(dirty_type, timestamp)?],
        })
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
                let mut builder = NodeBuilder::new("clean").attr("type", bit.dirty_type.as_str());
                if let Some(ts) = bit.timestamp {
                    builder = builder.attr("timestamp", ts);
                }
                builder.build()
            })
            .collect();

        InfoQuery::set(
            DIRTY_NAMESPACE,
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(children)),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {
        // Clean dirty bits just needs a successful response
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_dirty_bits_spec_single() {
        let spec = CleanDirtyBitsSpec::single(DirtyBit::new(DirtyType::AccountSync));
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, DIRTY_NAMESPACE);
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "clean");
            assert!(
                nodes[0]
                    .attrs
                    .get("type")
                    .is_some_and(|v| v == "account_sync")
            );
            assert!(nodes[0].attrs.get("timestamp").is_none());
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_clean_dirty_bits_spec_with_timestamp() {
        let spec =
            CleanDirtyBitsSpec::single(DirtyBit::with_timestamp(DirtyType::Groups, 1234567890));
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert!(nodes[0].attrs.get("type").is_some_and(|v| v == "groups"));
            assert!(
                nodes[0]
                    .attrs
                    .get("timestamp")
                    .is_some_and(|v| v == "1234567890")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_clean_dirty_bits_from_raw_invalid_timestamp() {
        let result = CleanDirtyBitsSpec::from_raw("account_sync", Some("not_a_number"));
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid timestamp"),
            "Error should mention invalid timestamp: {}",
            err_msg
        );
    }

    #[test]
    fn test_clean_dirty_bits_from_raw() {
        let spec = CleanDirtyBitsSpec::from_raw("groups", Some("1234567890")).unwrap();
        assert_eq!(spec.bits.len(), 1);
        assert_eq!(spec.bits[0].dirty_type, DirtyType::Groups);
        assert_eq!(spec.bits[0].timestamp, Some(1234567890));

        let spec = CleanDirtyBitsSpec::from_raw("account_sync", None).unwrap();
        assert_eq!(spec.bits[0].dirty_type, DirtyType::AccountSync);
        assert_eq!(spec.bits[0].timestamp, None);
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
            assert!(
                nodes[0]
                    .attrs
                    .get("type")
                    .is_some_and(|v| v == "account_sync")
            );
            assert!(nodes[0].attrs.get("timestamp").is_none());
            assert!(nodes[1].attrs.get("type").is_some_and(|v| v == "groups"));
            assert!(
                nodes[1]
                    .attrs
                    .get("timestamp")
                    .is_some_and(|v| v == "9876543210")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_clean_dirty_bits_spec_parse_response() {
        let spec = CleanDirtyBitsSpec::single(DirtyBit::new(DirtyType::AccountSync));
        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response.as_node_ref());
        assert!(result.is_ok());
    }

    #[test]
    fn test_dirty_type_from_str() {
        assert_eq!(DirtyType::from("account_sync"), DirtyType::AccountSync);
        assert_eq!(DirtyType::from("groups"), DirtyType::Groups);
        assert_eq!(DirtyType::from("syncd_app_state"), DirtyType::SyncdAppState);
        assert_eq!(
            DirtyType::from("newsletter_metadata"),
            DirtyType::NewsletterMetadata
        );
        assert_eq!(
            DirtyType::from("other"),
            DirtyType::Other("other".to_string())
        );
    }
}
