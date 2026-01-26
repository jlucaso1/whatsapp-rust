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
//!     <prop event_code="5138" sampling_weight="-1"/>
//!     <prop config_code="456" config_value="other"/>
//!     ...
//!   </props>
//! </iq>
//! ```
//!
//! Verified against WhatsApp Web JS (WASmaxOutAbPropsGetExperimentConfigRequest,
//! WASmaxInAbPropsConfigs).

use crate::iq::spec::IqSpec;
use crate::protocol::ProtocolNode;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// IQ namespace for A/B props.
pub const PROPS_NAMESPACE: &str = "abt";

/// Protocol version for props requests.
pub const PROPS_PROTOCOL_VERSION: &str = "1";

/// A/B experiment property returned from the server.
#[derive(Debug, Clone)]
pub struct AbProp {
    /// The config code (property identifier).
    pub config_code: u32,
    /// The config value.
    pub config_value: String,
    /// Optional experiment exposure key.
    pub config_expo_key: Option<u32>,
}

impl crate::protocol::ProtocolNode for AbProp {
    fn tag(&self) -> &'static str {
        "prop"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("prop")
            .attr("config_code", self.config_code.to_string())
            .attr("config_value", &self.config_value);

        if let Some(expo_key) = self.config_expo_key {
            builder = builder.attr("config_expo_key", expo_key.to_string());
        }

        builder.build()
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        use crate::iq::node::optional_attr;

        if node.tag != "prop" {
            return Err(anyhow::anyhow!("expected <prop>, got <{}>", node.tag));
        }

        let config_code: u32 = optional_attr(node, "config_code")
            .ok_or_else(|| anyhow::anyhow!("missing config_code in prop"))?
            .parse()?;
        if config_code == 0 {
            return Err(anyhow::anyhow!("config_code must be >= 1"));
        }
        let config_value = optional_attr(node, "config_value")
            .ok_or_else(|| anyhow::anyhow!("missing config_value in prop"))?
            .to_string();
        let config_expo_key = optional_attr(node, "config_expo_key").and_then(|s| s.parse().ok());

        Ok(Self {
            config_code,
            config_value,
            config_expo_key,
        })
    }
}

/// A/B sampling property returned from the server.
#[derive(Debug, Clone)]
pub struct SamplingProp {
    /// The event code (sampling identifier).
    pub event_code: u32,
    /// The sampling weight (typically -10000..=10000).
    pub sampling_weight: i32,
}

impl crate::protocol::ProtocolNode for SamplingProp {
    fn tag(&self) -> &'static str {
        "prop"
    }

    fn into_node(self) -> Node {
        NodeBuilder::new("prop")
            .attr("event_code", self.event_code.to_string())
            .attr("sampling_weight", self.sampling_weight.to_string())
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        use crate::iq::node::optional_attr;

        if node.tag != "prop" {
            return Err(anyhow::anyhow!("expected <prop>, got <{}>", node.tag));
        }

        let event_code: u32 = optional_attr(node, "event_code")
            .ok_or_else(|| anyhow::anyhow!("missing event_code in prop"))?
            .parse()?;
        if event_code == 0 {
            return Err(anyhow::anyhow!("event_code must be >= 1"));
        }

        let sampling_weight: i32 = optional_attr(node, "sampling_weight")
            .ok_or_else(|| anyhow::anyhow!("missing sampling_weight in prop"))?
            .parse()?;
        if !(-10000..=10000).contains(&sampling_weight) {
            return Err(anyhow::anyhow!(
                "sampling_weight out of range (-10000..=10000): {}",
                sampling_weight
            ));
        }

        Ok(Self {
            event_code,
            sampling_weight,
        })
    }
}

/// A/B config entry, which can be an experiment or sampling config.
#[derive(Debug, Clone)]
pub enum AbPropConfig {
    Experiment(AbProp),
    Sampling(SamplingProp),
}

impl crate::protocol::ProtocolNode for AbPropConfig {
    fn tag(&self) -> &'static str {
        "prop"
    }

    fn into_node(self) -> Node {
        match self {
            Self::Experiment(prop) => prop.into_node(),
            Self::Sampling(prop) => prop.into_node(),
        }
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        if node.tag != "prop" {
            return Err(anyhow::anyhow!("expected <prop>, got <{}>", node.tag));
        }

        let experiment = AbProp::try_from_node(node);
        if let Ok(prop) = experiment {
            return Ok(Self::Experiment(prop));
        }

        let sampling = SamplingProp::try_from_node(node);
        if let Ok(prop) = sampling {
            return Ok(Self::Sampling(prop));
        }

        let experiment_err = experiment
            .err()
            .unwrap_or_else(|| anyhow::anyhow!("unknown error"));
        let sampling_err = sampling
            .err()
            .unwrap_or_else(|| anyhow::anyhow!("unknown error"));
        Err(anyhow::anyhow!(
            "prop did not match experiment or sampling config: experiment_err={}; sampling_err={}",
            experiment_err,
            sampling_err
        ))
    }
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
    /// The properties (experiment or sampling configs).
    pub props: Vec<AbPropConfig>,
}

impl crate::protocol::ProtocolNode for PropsResponse {
    fn tag(&self) -> &'static str {
        "props"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("props").attr("protocol", PROPS_PROTOCOL_VERSION);

        if let Some(ref ab_key) = self.ab_key {
            builder = builder.attr("ab_key", ab_key);
        }
        if let Some(ref hash) = self.hash {
            builder = builder.attr("hash", hash);
        }
        if let Some(refresh) = self.refresh {
            builder = builder.attr("refresh", refresh.to_string());
        }
        if let Some(refresh_id) = self.refresh_id {
            builder = builder.attr("refresh_id", refresh_id.to_string());
        }
        builder = builder.attr("delta_update", self.delta_update.to_string());

        let prop_nodes: Vec<Node> = self.props.into_iter().map(|p| p.into_node()).collect();
        builder = builder.children(prop_nodes);

        builder.build()
    }

    fn try_from_node(node: &Node) -> Result<Self, anyhow::Error> {
        use crate::iq::node::optional_attr;

        if node.tag != "props" {
            return Err(anyhow::anyhow!("expected <props>, got <{}>", node.tag));
        }

        let ab_key = optional_attr(node, "ab_key").map(str::to_string);
        let hash = optional_attr(node, "hash").map(str::to_string);
        let refresh = optional_attr(node, "refresh").and_then(|s| s.parse().ok());
        let refresh_id = optional_attr(node, "refresh_id").and_then(|s| s.parse().ok());
        let delta_update = optional_attr(node, "delta_update")
            .map(|s| s == "true")
            .unwrap_or(false);

        let mut props = Vec::new();
        for child in node.get_children_by_tag("prop") {
            props.push(AbPropConfig::try_from_node(child)?);
        }

        Ok(Self {
            ab_key,
            hash,
            refresh,
            refresh_id,
            delta_update,
            props,
        })
    }
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
        use crate::iq::node::required_child;

        // Find the props child node and parse it using ProtocolNode
        let props_node = required_child(response, "props")?;
        PropsResponse::try_from_node(props_node)
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
                        .attr("event_code", "5138")
                        .attr("sampling_weight", "-1")
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
        assert_eq!(result.props.len(), 3);
        match &result.props[0] {
            AbPropConfig::Experiment(prop) => {
                assert_eq!(prop.config_code, 100);
                assert_eq!(prop.config_value, "enabled");
                assert!(prop.config_expo_key.is_none());
            }
            _ => panic!("Expected Experiment prop"),
        }
        match &result.props[1] {
            AbPropConfig::Sampling(prop) => {
                assert_eq!(prop.event_code, 5138);
                assert_eq!(prop.sampling_weight, -1);
            }
            _ => panic!("Expected Sampling prop"),
        }
        match &result.props[2] {
            AbPropConfig::Experiment(prop) => {
                assert_eq!(prop.config_code, 200);
                assert_eq!(prop.config_value, "disabled");
                assert_eq!(prop.config_expo_key, Some(5));
            }
            _ => panic!("Expected Experiment prop"),
        }
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

    #[test]
    fn test_ab_prop_protocol_node_round_trip() {
        let prop = AbProp {
            config_code: 123,
            config_value: "test_value".to_string(),
            config_expo_key: Some(456),
        };

        let node = prop.clone().into_node();
        let parsed = AbProp::try_from_node(&node).unwrap();

        assert_eq!(parsed.config_code, prop.config_code);
        assert_eq!(parsed.config_value, prop.config_value);
        assert_eq!(parsed.config_expo_key, prop.config_expo_key);
    }

    #[test]
    fn test_ab_prop_protocol_node_no_expo_key() {
        let prop = AbProp {
            config_code: 789,
            config_value: "another_value".to_string(),
            config_expo_key: None,
        };

        let node = prop.clone().into_node();
        let parsed = AbProp::try_from_node(&node).unwrap();

        assert_eq!(parsed.config_code, prop.config_code);
        assert_eq!(parsed.config_value, prop.config_value);
        assert_eq!(parsed.config_expo_key, None);
    }

    #[test]
    fn test_props_response_protocol_node_round_trip() {
        let response = PropsResponse {
            ab_key: Some("test_ab_key".to_string()),
            hash: Some("hash123".to_string()),
            refresh: Some(7200),
            refresh_id: Some(42),
            delta_update: true,
            props: vec![
                AbPropConfig::Experiment(AbProp {
                    config_code: 100,
                    config_value: "value1".to_string(),
                    config_expo_key: None,
                }),
                AbPropConfig::Sampling(SamplingProp {
                    event_code: 9001,
                    sampling_weight: -5,
                }),
                AbPropConfig::Experiment(AbProp {
                    config_code: 200,
                    config_value: "value2".to_string(),
                    config_expo_key: Some(99),
                }),
            ],
        };

        let node = response.clone().into_node();
        let parsed = PropsResponse::try_from_node(&node).unwrap();

        assert_eq!(parsed.ab_key, response.ab_key);
        assert_eq!(parsed.hash, response.hash);
        assert_eq!(parsed.refresh, response.refresh);
        assert_eq!(parsed.refresh_id, response.refresh_id);
        assert_eq!(parsed.delta_update, response.delta_update);
        assert_eq!(parsed.props.len(), response.props.len());
        match &parsed.props[0] {
            AbPropConfig::Experiment(prop) => assert_eq!(prop.config_code, 100),
            _ => panic!("Expected Experiment prop"),
        }
        match &parsed.props[1] {
            AbPropConfig::Sampling(prop) => assert_eq!(prop.event_code, 9001),
            _ => panic!("Expected Sampling prop"),
        }
        match &parsed.props[2] {
            AbPropConfig::Experiment(prop) => assert_eq!(prop.config_expo_key, Some(99)),
            _ => panic!("Expected Experiment prop"),
        }
    }

    #[test]
    fn test_props_response_protocol_node_minimal() {
        let response = PropsResponse {
            ab_key: None,
            hash: None,
            refresh: None,
            refresh_id: None,
            delta_update: false,
            props: vec![],
        };

        let node = response.clone().into_node();
        let parsed = PropsResponse::try_from_node(&node).unwrap();

        assert_eq!(parsed.ab_key, None);
        assert_eq!(parsed.hash, None);
        assert_eq!(parsed.refresh, None);
        assert_eq!(parsed.refresh_id, None);
        assert!(!parsed.delta_update);
        assert_eq!(parsed.props.len(), 0);
    }

    #[test]
    fn test_sampling_prop_protocol_node_round_trip() {
        let prop = SamplingProp {
            event_code: 5138,
            sampling_weight: -1,
        };

        let node = prop.clone().into_node();
        let parsed = SamplingProp::try_from_node(&node).unwrap();

        assert_eq!(parsed.event_code, prop.event_code);
        assert_eq!(parsed.sampling_weight, prop.sampling_weight);
    }
}
