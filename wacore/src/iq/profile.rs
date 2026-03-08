//! Profile IQ types for setting own status text.
//!
//! ## Wire Format
//!
//! ### Set Status Text
//! ```xml
//! <iq xmlns="status" type="set" to="s.whatsapp.net" id="...">
//!   <status>Hello world!</status>
//! </iq>
//! ```
//! Response: `<iq type="result" .../>`

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::jid::DEFAULT_USER_SERVER;
use wacore_binary::node::{Node, NodeContent};

/// IQ spec for setting the user's own status text (about).
pub struct SetStatusTextSpec {
    text: String,
}

impl SetStatusTextSpec {
    pub fn new(text: impl Into<String>) -> Self {
        Self { text: text.into() }
    }
}

impl IqSpec for SetStatusTextSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set(
            "status",
            DEFAULT_USER_SERVER.parse().expect("valid server JID"),
            Some(NodeContent::Nodes(vec![Node {
                tag: "status".to_string(),
                attrs: Default::default(),
                content: Some(NodeContent::String(self.text.clone())),
            }])),
        )
    }

    fn parse_response(&self, _response: &Node) -> anyhow::Result<Self::Response> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_status_text_iq() {
        let spec = SetStatusTextSpec::new("Hello world!");
        let iq = spec.build_iq();
        assert_eq!(iq.namespace, "status");
        assert_eq!(iq.query_type.as_str(), "set");
    }
}
