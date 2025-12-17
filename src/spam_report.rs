//! Spam Report Implementation
//!
//! This module provides functionality for reporting spam/abuse messages to WhatsApp.
//! Spam reports are sent as `spam_list` IQ stanzas to the server.
//!
//! ## Usage
//!
//! ```rust,ignore
//! // Report a spam message
//! let report_id = client.send_spam_report(SpamReportRequest {
//!     message_id: "3EB0E0E5F2D4F618589C0B".to_string(),
//!     message_timestamp: 1765491957,
//!     from_jid: Some(Jid::parse("5511999887766@s.whatsapp.net").unwrap()),
//!     spam_flow: SpamFlow::MessageMenu,
//!     raw_message: Some(raw_bytes),
//!     ..Default::default()
//! }).await?;
//! ```

use crate::client::Client;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::NodeContent;

/// The type of spam flow indicating the source of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SpamFlow {
    /// Report triggered from group spam banner
    GroupSpamBannerReport,
    /// Report triggered from group info screen
    GroupInfoReport,
    /// Report triggered from message context menu
    #[default]
    MessageMenu,
    /// Report triggered from contact info screen
    ContactInfo,
    /// Report triggered from status view
    StatusReport,
}

impl SpamFlow {
    fn as_str(&self) -> &'static str {
        match self {
            SpamFlow::GroupSpamBannerReport => "GroupSpamBannerReport",
            SpamFlow::GroupInfoReport => "GroupInfoReport",
            SpamFlow::MessageMenu => "MessageMenu",
            SpamFlow::ContactInfo => "ContactInfo",
            SpamFlow::StatusReport => "StatusReport",
        }
    }
}

/// A request to report a message as spam.
#[derive(Debug, Clone, Default)]
pub struct SpamReportRequest {
    /// The message ID being reported
    pub message_id: String,
    /// The timestamp of the message
    pub message_timestamp: u64,
    /// The JID the message was from (sender)
    pub from_jid: Option<Jid>,
    /// For group messages, the participant JID
    pub participant_jid: Option<Jid>,
    /// For group reports, the group JID
    pub group_jid: Option<Jid>,
    /// For group reports, the group subject/name
    pub group_subject: Option<String>,
    /// The type of spam flow
    pub spam_flow: SpamFlow,
    /// Raw message bytes (protobuf encoded)
    pub raw_message: Option<Vec<u8>>,
    /// Media type of the message (if applicable)
    pub media_type: Option<String>,
    /// Local message type
    pub local_message_type: Option<String>,
}

/// The result of a spam report.
#[derive(Debug, Clone)]
pub struct SpamReportResult {
    /// The report ID returned by the server
    pub report_id: Option<String>,
}

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

/// Build the spam_list node for a spam report.
fn build_spam_list_node(request: &SpamReportRequest) -> wacore_binary::node::Node {
    // Build the message node with attributes
    let mut message_attrs = vec![
        ("id", request.message_id.clone()),
        ("t", request.message_timestamp.to_string()),
    ];

    if let Some(ref from) = request.from_jid {
        message_attrs.push(("from", from.to_string()));
    }

    if let Some(ref participant) = request.participant_jid {
        message_attrs.push(("participant", participant.to_string()));
    }

    let mut message_children = Vec::new();

    // Add raw message node if provided
    if let Some(ref raw) = request.raw_message {
        let mut raw_attrs = vec![("v", "3".to_string())];

        if let Some(ref media_type) = request.media_type {
            raw_attrs.push(("mediatype", media_type.clone()));
        }

        if let Some(ref local_type) = request.local_message_type {
            raw_attrs.push(("local_message_type", local_type.clone()));
        }

        let raw_node = NodeBuilder::new("raw")
            .attrs(raw_attrs)
            .bytes(raw.clone())
            .build();

        message_children.push(raw_node);
    }

    let message_node = NodeBuilder::new("message")
        .attrs(message_attrs)
        .children(message_children)
        .build();

    // Build spam_list node
    let mut spam_list_attrs = vec![("spam_flow", request.spam_flow.as_str().to_string())];

    if let Some(ref group_jid) = request.group_jid {
        spam_list_attrs.push(("jid", group_jid.to_string()));
    }

    if let Some(ref subject) = request.group_subject {
        spam_list_attrs.push(("subject", subject.clone()));
    }

    NodeBuilder::new("spam_list")
        .attrs(spam_list_attrs)
        .children([message_node])
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let message = node.get_optional_child_by_tag(&["message"]).unwrap();
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
        let message = node.get_optional_child_by_tag(&["message"]).unwrap();
        let raw = message.get_optional_child_by_tag(&["raw"]).unwrap();

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
