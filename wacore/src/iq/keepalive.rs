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
use std::time::Duration;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::Node;

/// Keepalive ping to keep the connection alive.
#[derive(Debug, Clone, Default)]
pub struct KeepaliveSpec {
    /// Optional timeout for the keepalive response.
    pub timeout: Option<Duration>,
}

impl KeepaliveSpec {
    pub fn new() -> Self {
        Self { timeout: None }
    }

    /// Create a keepalive spec with a custom timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout: Some(timeout),
        }
    }
}

impl IqSpec for KeepaliveSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let mut iq = InfoQuery::get("w:p", Jid::new("", SERVER_JID), None);
        if let Some(timeout) = self.timeout {
            iq = iq.with_timeout(timeout);
        }
        iq
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
        assert!(iq.timeout.is_none());
    }

    #[test]
    fn test_keepalive_spec_with_timeout() {
        let spec = KeepaliveSpec::with_timeout(Duration::from_secs(20));
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "w:p");
        assert_eq!(iq.timeout, Some(Duration::from_secs(20)));
    }

    #[test]
    fn test_keepalive_spec_parse_response() {
        let spec = KeepaliveSpec::new();
        let response = NodeBuilder::new("iq").build();

        let result = spec.parse_response(&response);
        assert!(result.is_ok());
    }
}
