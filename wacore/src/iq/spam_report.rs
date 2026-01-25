//! Spam report IQ specification.
//!
//! ## Wire Format
//! ```xml
//! <!-- Request -->
//! <iq xmlns="spam" type="set" to="s.whatsapp.net" id="...">
//!   <spam_list spam_flow="MessageMenu">
//!     <message id="MSG_ID" t="1234567890" from="1234567890@s.whatsapp.net">
//!       <raw v="3" mediatype="image">...</raw>
//!     </message>
//!   </spam_list>
//! </iq>
//!
//! <!-- Response -->
//! <iq from="s.whatsapp.net" id="..." type="result">
//!   <report_id>REPORT_123</report_id>
//! </iq>
//! ```

use crate::iq::spec::IqSpec;
use crate::request::InfoQuery;
use crate::types::spam_report::{SpamReportRequest, SpamReportResult, build_spam_list_node};
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};

// Re-export types for convenience
pub use crate::types::spam_report::{
    SpamFlow, SpamReportRequest as Request, SpamReportResult as Response,
};

/// Sends a spam report for one or more messages to WhatsApp.
#[derive(Debug, Clone)]
pub struct SpamReportSpec {
    pub request: SpamReportRequest,
}

impl SpamReportSpec {
    pub fn new(request: SpamReportRequest) -> Self {
        Self { request }
    }
}

impl IqSpec for SpamReportSpec {
    type Response = SpamReportResult;

    fn build_iq(&self) -> InfoQuery<'static> {
        let spam_list_node = build_spam_list_node(&self.request);

        InfoQuery::set(
            "spam",
            Jid::new("", SERVER_JID),
            Some(NodeContent::Nodes(vec![spam_list_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response, anyhow::Error> {
        // Extract report_id from response if present
        let report_id = response
            .get_optional_child_by_tag(&["report_id"])
            .and_then(|n| match &n.content {
                Some(NodeContent::String(s)) => Some(s.clone()),
                _ => None,
            });

        Ok(SpamReportResult { report_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::spam_report::SpamFlow;
    use wacore_binary::builder::NodeBuilder;

    #[test]
    fn test_spam_report_spec_build_iq() {
        let request = SpamReportRequest {
            message_id: "TEST123".to_string(),
            message_timestamp: 1234567890,
            spam_flow: SpamFlow::MessageMenu,
            ..Default::default()
        };

        let spec = SpamReportSpec::new(request);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, "spam");
        assert_eq!(iq.query_type, crate::request::InfoQueryType::Set);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes.len(), 1);
            assert_eq!(nodes[0].tag, "spam_list");
            assert_eq!(
                nodes[0].attrs.get("spam_flow").and_then(|s| s.as_str()),
                Some("MessageMenu")
            );
        } else {
            panic!("Expected NodeContent::Nodes");
        }
    }

    #[test]
    fn test_spam_report_spec_parse_response_with_report_id() {
        let request = SpamReportRequest {
            message_id: "TEST123".to_string(),
            message_timestamp: 1234567890,
            spam_flow: SpamFlow::MessageMenu,
            ..Default::default()
        };

        let spec = SpamReportSpec::new(request);

        let response = NodeBuilder::new("iq")
            .attr("type", "result")
            .children([NodeBuilder::new("report_id")
                .string_content("REPORT_ABC123")
                .build()])
            .build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.report_id, Some("REPORT_ABC123".to_string()));
    }

    #[test]
    fn test_spam_report_spec_parse_response_without_report_id() {
        let request = SpamReportRequest {
            message_id: "TEST123".to_string(),
            message_timestamp: 1234567890,
            spam_flow: SpamFlow::MessageMenu,
            ..Default::default()
        };

        let spec = SpamReportSpec::new(request);

        let response = NodeBuilder::new("iq").attr("type", "result").build();

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result.report_id, None);
    }
}
