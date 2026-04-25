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
use wacore_binary::CompactString;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, Server};
use wacore_binary::{Node, NodeContent, NodeRef};

/// IQ namespace for A/B props.
pub const PROPS_NAMESPACE: &str = "abt";

/// Well-known AB prop config codes from WhatsApp Web's ABPropConfigs.
pub mod config_codes {
    // --- Privacy token gating ---
    pub const PRIVACY_TOKEN_ON_ALL_1_ON_1_MESSAGES: u32 = 10_518;
    pub const PRIVACY_TOKEN_ON_GROUP_CREATE: u32 = 11_261;
    pub const PRIVACY_TOKEN_ON_GROUP_PARTICIPANT_ADD: u32 = 11_262;
    pub const PRIVACY_TOKEN_ONLY_CHECK_LID: u32 = 15_491;
    /// Gates tctoken inclusion in profile picture IQ requests.
    pub const PROFILE_PIC_PRIVACY_TOKEN: u32 = 9_666;
    /// When true, issue privacy tokens to LID JIDs instead of PN JIDs.
    pub const LID_TRUSTED_TOKEN_ISSUE_TO_LID: u32 = 14_303;

    // --- tctoken timing (int props, not booleans) ---
    /// Receiver-side bucket duration in seconds (default 604800 = 7 days).
    pub const TCTOKEN_DURATION: u32 = 865;
    /// Sender-side bucket duration in seconds (default 604800 = 7 days).
    pub const TCTOKEN_DURATION_SENDER: u32 = 996;
    /// Receiver-side number of buckets in the rolling window (default 4).
    pub const TCTOKEN_NUM_BUCKETS: u32 = 909;
    /// Sender-side number of buckets (default 4).
    pub const TCTOKEN_NUM_BUCKETS_SENDER: u32 = 997;

    // --- NCT / cstoken ---
    /// Gates cstoken (HMAC fallback) inclusion in outgoing messages.
    pub const NCT_TOKEN_SEND_ENABLED: u32 = 24_941;

    /// All production config codes. Must match DEFAULT_INTEREST in ab_props.rs.
    /// When adding a new code above, add it here too.
    pub const ALL: &[u32] = &[
        PRIVACY_TOKEN_ON_ALL_1_ON_1_MESSAGES,
        PRIVACY_TOKEN_ON_GROUP_CREATE,
        PRIVACY_TOKEN_ON_GROUP_PARTICIPANT_ADD,
        PRIVACY_TOKEN_ONLY_CHECK_LID,
        PROFILE_PIC_PRIVACY_TOKEN,
        LID_TRUSTED_TOKEN_ISSUE_TO_LID,
        TCTOKEN_DURATION,
        TCTOKEN_DURATION_SENDER,
        TCTOKEN_NUM_BUCKETS,
        TCTOKEN_NUM_BUCKETS_SENDER,
        NCT_TOKEN_SEND_ENABLED,
    ];
}

/// Protocol version for props requests.
pub const PROPS_PROTOCOL_VERSION: &str = "1";

/// A/B experiment property returned from the server.
#[derive(Debug, Clone)]
pub struct AbProp {
    /// The config code (property identifier).
    pub config_code: u32,
    /// The config value. CompactString inlines values <=24 bytes (covers most props).
    pub config_value: CompactString,
    /// Optional experiment exposure key.
    pub config_expo_key: Option<u32>,
}

impl crate::protocol::ProtocolNode for AbProp {
    fn tag(&self) -> &'static str {
        "prop"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("prop")
            .attr("config_code", self.config_code)
            .attr("config_value", &*self.config_value);

        if let Some(expo_key) = self.config_expo_key {
            builder = builder.attr("config_expo_key", expo_key);
        }

        builder.build()
    }

    fn try_from_node_ref(node: &NodeRef<'_>) -> Result<Self, anyhow::Error> {
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
            .ok_or_else(|| anyhow::anyhow!("missing config_value in prop"))?;
        let config_value = CompactString::from(config_value.as_ref());
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
            .attr("event_code", self.event_code)
            .attr("sampling_weight", self.sampling_weight)
            .build()
    }

    fn try_from_node_ref(node: &NodeRef<'_>) -> Result<Self, anyhow::Error> {
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

    fn try_from_node_ref(node: &NodeRef<'_>) -> Result<Self, anyhow::Error> {
        use crate::iq::node::optional_attr;

        if node.tag != "prop" {
            return Err(anyhow::anyhow!("expected <prop>, got <{}>", node.tag));
        }

        // Check discriminating attribute to avoid double-parse allocations
        let has_config = optional_attr(node, "config_code").is_some();
        let has_event = optional_attr(node, "event_code").is_some();

        if has_config && has_event {
            Err(anyhow::anyhow!(
                "prop has both config_code and event_code (attrs: {:?})",
                node.attrs
            ))
        } else if has_config {
            Ok(Self::Experiment(AbProp::try_from_node_ref(node)?))
        } else if has_event {
            Ok(Self::Sampling(SamplingProp::try_from_node_ref(node)?))
        } else {
            Err(anyhow::anyhow!(
                "prop has neither config_code nor event_code (attrs: {:?})",
                node.attrs
            ))
        }
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
    /// Experiment prop code-value pairs (lightweight, no enum wrapper).
    /// Sampling props are skipped during parsing.
    pub experiment_props: Vec<(u32, CompactString)>,
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
            builder = builder.attr("refresh", refresh);
        }
        if let Some(refresh_id) = self.refresh_id {
            builder = builder.attr("refresh_id", refresh_id);
        }
        builder = builder.attr("delta_update", self.delta_update);

        // Round-trip with try_from_node_ref. config_expo_key is dropped on
        // both sides; extend the tuple type before adding it back.
        let prop_nodes: Vec<Node> = self
            .experiment_props
            .into_iter()
            .map(|(code, value)| {
                NodeBuilder::new("prop")
                    .attr("config_code", code)
                    .attr("config_value", &*value)
                    .build()
            })
            .collect();

        builder.children(prop_nodes).build()
    }

    fn try_from_node_ref(node: &NodeRef<'_>) -> Result<Self, anyhow::Error> {
        use crate::iq::node::optional_attr;

        if node.tag != "props" {
            return Err(anyhow::anyhow!("expected <props>, got <{}>", node.tag));
        }

        let ab_key = optional_attr(node, "ab_key").map(|s| s.into_owned());
        let hash = optional_attr(node, "hash").map(|s| s.into_owned());
        let refresh = optional_attr(node, "refresh").and_then(|s| s.parse().ok());
        let refresh_id = optional_attr(node, "refresh_id").and_then(|s| s.parse().ok());
        let delta_update = optional_attr(node, "delta_update")
            .map(|s| s == "true")
            .unwrap_or(false);

        // Parse experiment props as lightweight (code, value) tuples.
        // Sampling props (missing config_code or config_value) are skipped.
        let mut experiment_props = Vec::new();
        for child in node.get_children_by_tag("prop") {
            if let Some(code_str) = optional_attr(child, "config_code")
                && let Ok(code) = code_str.parse::<u32>()
                && code > 0
                && let Some(value) = optional_attr(child, "config_value")
            {
                experiment_props.push((code, CompactString::from(value.as_ref())));
            }
        }

        Ok(Self {
            ab_key,
            hash,
            refresh,
            refresh_id,
            delta_update,
            experiment_props,
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
            builder = builder.attr("refresh_id", refresh_id);
        }

        InfoQuery::get(
            PROPS_NAMESPACE,
            Jid::new("", Server::Pn),
            Some(NodeContent::Nodes(vec![builder.build()])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response, anyhow::Error> {
        use crate::iq::node::required_child;

        let props_node = required_child(response, "props")?;
        PropsResponse::try_from_node_ref(props_node)
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
            assert!(nodes[0].attrs.get("protocol").is_some_and(|v| v == "1"));
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
            assert!(nodes[0].attrs.get("hash").is_some_and(|v| v == "abc123"));
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
            assert!(nodes[0].attrs.get("refresh_id").is_some_and(|v| v == "42"));
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

        let result = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(result.ab_key, Some("test_key".to_string()));
        assert_eq!(result.hash, Some("abcdef".to_string()));
        assert_eq!(result.refresh, Some(3600));
        assert_eq!(result.refresh_id, Some(123));
        assert!(!result.delta_update);
        // 2 of 3 props are experiments (sampling props are skipped)
        assert_eq!(result.experiment_props.len(), 2);
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

        let result = spec.parse_response(&response.as_node_ref()).unwrap();
        assert!(result.delta_update);
    }

    #[test]
    fn test_ab_prop_protocol_node_round_trip() {
        let prop = AbProp {
            config_code: 123,
            config_value: "test_value".into(),
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
            config_value: "another_value".into(),
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
            experiment_props: vec![
                (100, CompactString::from("value1")),
                (200, CompactString::from("value2")),
            ],
        };

        let node = response.clone().into_node();
        let parsed = PropsResponse::try_from_node(&node).unwrap();

        assert_eq!(parsed.ab_key, response.ab_key);
        assert_eq!(parsed.hash, response.hash);
        assert_eq!(parsed.refresh, response.refresh);
        assert_eq!(parsed.refresh_id, response.refresh_id);
        assert_eq!(parsed.delta_update, response.delta_update);
        assert_eq!(parsed.experiment_props, response.experiment_props);
    }

    /// `<props>` must carry one `<prop config_code config_value/>` per
    /// experiment, matching `WASmaxInAbPropsExperimentConfigMixin`.
    #[test]
    fn test_props_response_into_node_emits_wa_web_compliant_prop_children() {
        let response = PropsResponse {
            ab_key: None,
            hash: None,
            refresh: None,
            refresh_id: None,
            delta_update: false,
            experiment_props: vec![
                (11_262, CompactString::from("1")),
                (11_103, CompactString::from("0")),
            ],
        };

        let node = response.into_node();

        let children = match node.content {
            Some(NodeContent::Nodes(c)) => c,
            other => panic!("<props> must have Node children, got {other:?}"),
        };
        assert_eq!(
            children.len(),
            2,
            "expected one <prop> per experiment_props entry"
        );

        for child in &children {
            assert_eq!(child.tag, "prop");
            assert!(
                child.attrs.contains_key("config_code"),
                "missing config_code"
            );
            assert!(
                child.attrs.contains_key("config_value"),
                "missing config_value"
            );
        }

        let codes: Vec<String> = children
            .iter()
            .map(|n| {
                n.attrs
                    .get("config_code")
                    .map(|v| v.to_string())
                    .unwrap_or_default()
            })
            .collect();
        assert!(codes.iter().any(|c| c == "11262"));
        assert!(codes.iter().any(|c| c == "11103"));
    }

    #[test]
    fn test_props_response_protocol_node_minimal() {
        let response = PropsResponse {
            ab_key: None,
            hash: None,
            refresh: None,
            refresh_id: None,
            delta_update: false,
            experiment_props: vec![],
        };

        let node = response.clone().into_node();
        let parsed = PropsResponse::try_from_node(&node).unwrap();

        assert_eq!(parsed.ab_key, None);
        assert_eq!(parsed.hash, None);
        assert!(!parsed.delta_update);
        assert_eq!(parsed.experiment_props.len(), 0);
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
