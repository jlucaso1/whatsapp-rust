use crate::client::Client;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::NodeContent;

pub use wacore::types::{SpamFlow, SpamReportRequest, SpamReportResult, build_spam_list_node};

impl Client {
    /// Send a spam report to WhatsApp.
    ///
    /// This sends a `spam_list` IQ stanza to report one or more messages as spam.
    ///
    /// # Arguments
    /// * `request` - The spam report request containing message details
    ///
    /// # Returns
    /// * `Ok(SpamReportResult)` - If the report was successfully submitted
    /// * `Err` - If there was an error sending or processing the report
    ///
    /// # Example
    /// ```rust,ignore
    /// let result = client.send_spam_report(SpamReportRequest {
    ///     message_id: "MSG_ID".to_string(),
    ///     message_timestamp: 1234567890,
    ///     from_jid: Some(sender_jid),
    ///     spam_flow: SpamFlow::MessageMenu,
    ///     ..Default::default()
    /// }).await?;
    /// ```
    pub async fn send_spam_report(
        &self,
        request: SpamReportRequest,
    ) -> Result<SpamReportResult, IqError> {
        let spam_list_node = build_spam_list_node(&request);

        let server_jid = Jid::new("", SERVER_JID);

        let query = InfoQuery {
            query_type: InfoQueryType::Set,
            namespace: "spam",
            to: server_jid,
            target: None,
            content: Some(NodeContent::Nodes(vec![spam_list_node])),
            id: None,
            timeout: None,
        };

        let response = self.send_iq(query).await?;

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
    use wacore_binary::jid::Jid;

    #[test]
    fn test_spam_flow_as_str() {
        assert_eq!(SpamFlow::MessageMenu.as_str(), "MessageMenu");
        assert_eq!(
            SpamFlow::GroupSpamBannerReport.as_str(),
            "GroupSpamBannerReport"
        );
        assert_eq!(SpamFlow::ContactInfo.as_str(), "ContactInfo");
    }

    #[test]
    fn test_build_spam_list_node_basic() {
        let request = SpamReportRequest {
            message_id: "TEST123".to_string(),
            message_timestamp: 1234567890,
            spam_flow: SpamFlow::MessageMenu,
            ..Default::default()
        };

        let node = build_spam_list_node(&request);

        assert_eq!(node.tag, "spam_list");
        assert_eq!(node.attrs().string("spam_flow"), "MessageMenu");

        let message = node
            .get_optional_child_by_tag(&["message"])
            .expect("spam_list node should have message child");
        assert_eq!(message.attrs().string("id"), "TEST123");
        assert_eq!(message.attrs().string("t"), "1234567890");
    }

    #[test]
    fn test_build_spam_list_node_with_raw_message() {
        let request = SpamReportRequest {
            message_id: "TEST456".to_string(),
            message_timestamp: 1234567890,
            from_jid: Some(Jid {
                user: "5511999887766".to_string(),
                server: "s.whatsapp.net".to_string(),
                device: 0,
                agent: 0,
                integrator: 0,
            }),
            spam_flow: SpamFlow::MessageMenu,
            raw_message: Some(vec![0x01, 0x02, 0x03]),
            media_type: Some("image".to_string()),
            ..Default::default()
        };

        let node = build_spam_list_node(&request);
        let message = node
            .get_optional_child_by_tag(&["message"])
            .expect("spam_list node should have message child");
        let raw = message
            .get_optional_child_by_tag(&["raw"])
            .expect("message node should have raw child");

        assert_eq!(raw.attrs().string("v"), "3");
        assert_eq!(raw.attrs().string("mediatype"), "image");
    }

    #[test]
    fn test_build_spam_list_node_group() {
        let request = SpamReportRequest {
            message_id: "TEST789".to_string(),
            message_timestamp: 1234567890,
            group_jid: Some(Jid {
                user: "120363025918861132".to_string(),
                server: "g.us".to_string(),
                device: 0,
                agent: 0,
                integrator: 0,
            }),
            group_subject: Some("Test Group".to_string()),
            participant_jid: Some(Jid {
                user: "5511999887766".to_string(),
                server: "s.whatsapp.net".to_string(),
                device: 0,
                agent: 0,
                integrator: 0,
            }),
            spam_flow: SpamFlow::GroupInfoReport,
            ..Default::default()
        };

        let node = build_spam_list_node(&request);

        assert_eq!(node.attrs().string("spam_flow"), "GroupInfoReport");
        assert_eq!(node.attrs().string("jid"), "120363025918861132@g.us");
        assert_eq!(node.attrs().string("subject"), "Test Group");
    }
}
