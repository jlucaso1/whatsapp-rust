//! Keepalive IQ specification.
//!
//! Wire format:
//! ```xml
//! <!-- Request -->
//! <iq xmlns="w:p" type="get" to="s.whatsapp.net" id="..."/>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result"/>
//! ```

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::Node;

/// Keepalive ping to keep the connection alive.
#[derive(Debug, Clone, Default)]
pub struct KeepaliveSpec;

impl KeepaliveSpec {
    pub fn new() -> Self {
        Self
    }
}

impl IqSpec for KeepaliveSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get("w:p", Jid::new("", SERVER_JID), None)
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response, anyhow::Error> {
        // Keepalive just needs a successful response, no parsing needed
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;

    #[test]
    fn test_keepalive_spec_build_iq() {
        let spec = KeepaliveSpec::new();
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "w:p");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Get);
        assert!(iq.content.is_none());
    }

    #[test]
    fn test_keepalive_spec_parse_response() {
        let spec = KeepaliveSpec::new();
        let response = NodeBuilder::new("iq").build();

        let result = spec.parse_response(&response);
        assert!(result.is_ok());
    }
}
