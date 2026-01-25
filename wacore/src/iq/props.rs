//! A/B Props (experiment config) IQ specification.
//!
//! Fetches server-side A/B testing properties and experiment configurations.
//!
//! ## Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="abt" type="get" to="s.whatsapp.net" id="...">
//!   <props protocol="1" hash="..." refresh_id="..."/>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <props protocol="1" ab_key="..." hash="..." refresh="..." refresh_id="...">
//!     <prop config_code="123" config_value="value"/>
//!     <prop config_code="456" config_value="other"/>
//!     ...
//!   </props>
//! </iq>
//! ```
//!
//! Verified against WhatsApp Web JS (WASmaxOutAbPropsGetExperimentConfigRequest).

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// IQ namespace for A/B props.
pub const PROPS_NAMESPACE: &str = "abt";

/// Protocol version for props requests.
pub const PROPS_PROTOCOL_VERSION: &str = "1";

/// A/B property returned from the server.
#[derive(Debug, Clone)]
pub struct AbProp {
    /// The config code (property identifier).
    pub config_code: u32,
    /// The config value.
    pub config_value: String,
    /// Optional experiment exposure key.
    pub config_expo_key: Option<u32>,
}

/// Response from props query.
#[derive(Debug, Clone, Default)]
pub struct PropsResponse {
    /// A/B key for this configuration set.
    pub ab_key: Option<String>,
    /// Hash of the current configuration.
    pub hash: Option<String>,
    /// Refresh interval in seconds.
    pub refresh: Option<u32>,
    /// Refresh ID for delta updates.
    pub refresh_id: Option<u32>,
    /// Whether this is a delta update.
    pub delta_update: bool,
    /// The properties.
    pub props: Vec<AbProp>,
}

/// Fetches A/B testing properties from the server.
#[derive(Debug, Clone, Default)]
pub struct PropsSpec {
    /// Optional hash from previous props fetch (for delta updates).
    pub hash: Option<String>,
    /// Optional refresh ID (for emergency push updates).
    pub refresh_id: Option<u32>,
}

impl PropsSpec {
    /// Create a new props spec without hash or refresh_id.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a props spec with a hash for delta updates.
    pub fn with_hash(hash: impl Into<String>) -> Self {
        Self {
            hash: Some(hash.into()),
            refresh_id: None,
        }
    }

    /// Create a props spec with a refresh_id for emergency push responses.
    pub fn with_refresh_id(refresh_id: u32) -> Self {
        Self {
            hash: None,
            refresh_id: Some(refresh_id),
        }
    }
}

impl IqSpec for PropsSpec {
    type Response = PropsResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let mut builder = NodeBuilder::new("props").attr("protocol", PROPS_PROTOCOL_VERSION);

        if let Some(ref hash) = self.hash {
            builder = builder.attr("hash", hash.as_str());
        }

        if let Some(refresh_id) = self.refresh_id {
            builder = builder.attr("refresh_id", refresh_id.to_string());
        }

        InfoQuery::get(
            PROPS_NAMESPACE,
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![builder.build()])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        use crate::iq::node::{optional_attr, required_child};

        // Find the props child node
        let props_node = required_child(response, "props")?;

        let ab_key = optional_attr(props_node, "ab_key").map(str::to_string);
        let hash = optional_attr(props_node, "hash").map(str::to_string);
        let refresh = optional_attr(props_node, "refresh").and_then(|s| s.parse().ok());
        let refresh_id = optional_attr(props_node, "refresh_id").and_then(|s| s.parse().ok());
        let delta_update = optional_attr(props_node, "delta_update")
            .map(|s| s == "true")
            .unwrap_or(false);

        // Parse individual prop children
        let mut props = Vec::new();
        for child in props_node.get_children_by_tag("prop") {
            let config_code: u32 = optional_attr(child, "config_code")
                .ok_or_else(|| anyhow::anyhow!("missing config_code in prop"))?
                .parse()?;
            let config_value = optional_attr(child, "config_value")
                .ok_or_else(|| anyhow::anyhow!("missing config_value in prop"))?
                .to_string();
            let config_expo_key =
                optional_attr(child, "config_expo_key").and_then(|s| s.parse().ok());

            props.push(AbProp {
                config_code,
                config_value,
                config_expo_key,
            });
        }

        Ok(PropsResponse {
            ab_key,
            hash,
            refresh,
            refresh_id,
            delta_update,
            props,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_props_spec_build_iq_no_params() {
        let spec = PropsSpec::new();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, PROPS_NAMESPACE);
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "props");
            assert_eq!(
                nodes[0].attrs.get("protocol").and_then(|v| v.as_str()),
                Some("1")
            );
            assert!(nodes[0].attrs.get("hash").is_none());
            assert!(nodes[0].attrs.get("refresh_id").is_none());
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_props_spec_build_iq_with_hash() {
        let spec = PropsSpec::with_hash("abc123");
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(
                nodes[0].attrs.get("hash").and_then(|v| v.as_str()),
                Some("abc123")
            );
            assert!(nodes[0].attrs.get("refresh_id").is_none());
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_props_spec_build_iq_with_refresh_id() {
        let spec = PropsSpec::with_refresh_id(42);
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert!(nodes[0].attrs.get("hash").is_none());
            assert_eq!(
                nodes[0].attrs.get("refresh_id").and_then(|v| v.as_str()),
                Some("42")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_props_spec_parse_response() {
        let spec = PropsSpec::new();
        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("props")
                .attr("protocol", "1")
                .attr("ab_key", "test_key")
                .attr("hash", "abcdef")
                .attr("refresh", "3600")
                .attr("refresh_id", "123")
                .children([
                    NodeBuilder::new("prop")
                        .attr("config_code", "100")
                        .attr("config_value", "enabled")
                        .build(),
                    NodeBuilder::new("prop")
                        .attr("config_code", "200")
                        .attr("config_value", "disabled")
                        .attr("config_expo_key", "5")
                        .build(),
                ])
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.ab_key, Some("test_key".to_string()));
        assert_eq!(result.hash, Some("abcdef".to_string()));
        assert_eq!(result.refresh, Some(3600));
        assert_eq!(result.refresh_id, Some(123));
        assert!(!result.delta_update);
        assert_eq!(result.props.len(), 2);
        assert_eq!(result.props[0].config_code, 100);
        assert_eq!(result.props[0].config_value, "enabled");
        assert!(result.props[0].config_expo_key.is_none());
        assert_eq!(result.props[1].config_code, 200);
        assert_eq!(result.props[1].config_value, "disabled");
        assert_eq!(result.props[1].config_expo_key, Some(5));
    }

    #[test]
    fn test_props_spec_parse_response_delta_update() {
        let spec = PropsSpec::new();
        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("props")
                .attr("protocol", "1")
                .attr("delta_update", "true")
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert!(result.delta_update);
    }
}
