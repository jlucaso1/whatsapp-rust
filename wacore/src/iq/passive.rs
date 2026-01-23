//! Passive mode IQ specification.
//!
//! Passive mode tells the server whether the client is actively receiving
//! notifications or is in a background/passive state.
//!
//! ## Wire Format
//! ```xml
//! <!-- Set Active (foreground) -->
//! <iq xmlns="passive" type="set" to="s.whatsapp.net" id="...">
//!   <active/>
//! </iq>
//!
//! <!-- Set Passive (background) -->
//! <iq xmlns="passive" type="set" to="s.whatsapp.net" id="...">
//!   <passive/>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result"/>
//! ```

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// IQ namespace for passive mode.
pub const PASSIVE_NAMESPACE: &str = "passive";

/// Sets the client's passive/active mode.
#[derive(Debug, Clone)]
pub struct PassiveModeSpec {
    /// Whether to set passive mode (true) or active mode (false).
    pub passive: bool,
}

impl PassiveModeSpec {
    /// Create a spec to set passive mode (background).
    pub fn passive() -> Self {
        Self { passive: true }
    }

    /// Create a spec to set active mode (foreground).
    pub fn active() -> Self {
        Self { passive: false }
    }

    /// Create a spec from a boolean (true = passive, false = active).
    pub fn new(passive: bool) -> Self {
        Self { passive }
    }
}

impl IqSpec for PassiveModeSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let tag = if self.passive { "passive" } else { "active" };
        let child_node = NodeBuilder::new(tag).build();

        InfoQuery::set(
            PASSIVE_NAMESPACE,
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![child_node])),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response, anyhow::Error> {
        // Passive mode just needs a successful response
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passive_mode_spec_passive() {
        let spec = PassiveModeSpec::passive();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, PASSIVE_NAMESPACE);
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "passive");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_passive_mode_spec_active() {
        let spec = PassiveModeSpec::active();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, PASSIVE_NAMESPACE);
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "active");
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_passive_mode_spec_parse_response() {
        let spec = PassiveModeSpec::passive();
        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response);
        assert!(result.is_ok());
    }
}
