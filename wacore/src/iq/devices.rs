//! Device management IQ specs.

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

/// Deregister this companion device from the WhatsApp account.
pub struct RemoveCompanionDeviceSpec {
    jid: Jid,
}

impl RemoveCompanionDeviceSpec {
    pub fn new(jid: Jid) -> Self {
        Self { jid }
    }
}

impl IqSpec for RemoveCompanionDeviceSpec {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let child = NodeBuilder::new("remove-companion-device")
            .attr("jid", self.jid.clone())
            .attr("reason", "user_initiated")
            .build();

        InfoQuery::set(
            "md",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![child])),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response, anyhow::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iq_structure() {
        let jid: Jid = "551199887766:87@s.whatsapp.net".parse().unwrap();
        let spec = RemoveCompanionDeviceSpec::new(jid);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "md");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        let children = match &iq.content {
            Some(NodeContent::Nodes(c)) => c,
            _ => panic!("expected Nodes content"),
        };
        assert_eq!(children[0].tag, "remove-companion-device");

        let mut attrs = children[0].attrs();
        assert_eq!(
            attrs.optional_string("reason").unwrap().as_ref(),
            "user_initiated"
        );
    }
}
