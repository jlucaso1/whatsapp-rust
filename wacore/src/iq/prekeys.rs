//! Pre-key IQ specifications.
//!
//! ## Fetch Pre-Keys Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="encrypt" type="get" to="s.whatsapp.net" id="...">
//!   <key>
//!     <user jid="1234567890:0@s.whatsapp.net"/>
//!     <user jid="0987654321:0@s.whatsapp.net"/>
//!   </key>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <list>
//!     <user jid="1234567890:0@s.whatsapp.net">
//!       <registration>...</registration>
//!       <type>...</type>
//!       <identity>...</identity>
//!       <key><id>...</id><value>...</value></key>
//!       <skey><id>...</id><value>...</value><signature>...</signature></skey>
//!     </user>
//!   </list>
//! </iq>
//! ```
//!
//! ## Pre-Key Count Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="encrypt" type="get" to="s.whatsapp.net" id="...">
//!   <count/>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <count value="42"/>
//! </iq>
//! ```

use crate::iq::spec::IqSpec;
use crate::prekeys::PreKeyUtils;
use crate::request::InfoQuery;
use anyhow::anyhow;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

// Re-export PreKeyBundle for convenience
pub use crate::libsignal::protocol::PreKeyBundle;

/// Pre-key count response.
#[derive(Debug, Clone)]
pub struct PreKeyCountResponse {
    pub count: usize,
}

/// Queries the server for how many pre-keys are currently stored.
#[derive(Debug, Clone, Default)]
pub struct PreKeyCountSpec;

impl PreKeyCountSpec {
    pub fn new() -> Self {
        Self
    }
}

impl IqSpec for PreKeyCountSpec {
    type Response = PreKeyCountResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let count_node = NodeBuilder::new("count").build();

        InfoQuery::get(
            "encrypt",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![count_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        let count_node = response
            .get_optional_child("count")
            .ok_or_else(|| anyhow!("Missing <count> node in response"))?;

        // Server may return <count/> without value attribute when count is 0,
        // or return an unparseable value. Default to 0 in these cases.
        let count_str = count_node.attrs().optional_string("value").unwrap_or("0");
        let count = count_str.parse::<usize>().unwrap_or(0);

        Ok(PreKeyCountResponse { count })
    }
}

/// Fetches pre-key bundles for a list of JIDs.
#[derive(Debug, Clone)]
pub struct PreKeyFetchSpec {
    pub jids: Vec<Jid>,
    pub reason: Option<String>,
}

impl PreKeyFetchSpec {
    pub fn new(jids: Vec<Jid>) -> Self {
        Self { jids, reason: None }
    }

    pub fn with_reason(jids: Vec<Jid>, reason: impl Into<String>) -> Self {
        Self {
            jids,
            reason: Some(reason.into()),
        }
    }
}

impl IqSpec for PreKeyFetchSpec {
    type Response = std::collections::HashMap<Jid, PreKeyBundle>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let content = PreKeyUtils::build_fetch_prekeys_request(&self.jids, self.reason.as_deref());

        InfoQuery::get(
            "encrypt",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![content])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        PreKeyUtils::parse_prekeys_response(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prekey_count_spec_build_iq() {
        let spec = PreKeyCountSpec::new();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "encrypt");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "count");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_prekey_count_spec_parse_response() {
        let spec = PreKeyCountSpec::new();

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("count").attr("value", "42").build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.count, 42);
    }

    #[test]
    fn test_prekey_count_spec_parse_response_missing_value() {
        let spec = PreKeyCountSpec::new();

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("count").build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.count, 0); // Default to 0 if missing
    }

    #[test]
    fn test_prekey_fetch_spec_build_iq() {
        let jids = vec![
            "1234567890:0@s.whatsapp.net".parse().unwrap(),
            "0987654321:0@s.whatsapp.net".parse().unwrap(),
        ];
        let spec = PreKeyFetchSpec::new(jids);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "encrypt");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "key");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_prekey_fetch_spec_with_reason() {
        let jids = vec!["1234567890:0@s.whatsapp.net".parse().unwrap()];
        let spec = PreKeyFetchSpec::with_reason(jids, "retry");

        assert_eq!(spec.reason, Some("retry".to_string()));
    }
}
