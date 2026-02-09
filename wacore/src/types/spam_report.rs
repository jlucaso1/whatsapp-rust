//! Spam report types and node building.

use crate::StringEnum;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

/// The type of spam flow indicating the source of the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum SpamFlow {
    /// Report triggered from group spam banner
    #[str = "GroupSpamBannerReport"]
    GroupSpamBannerReport,
    /// Report triggered from group info screen
    #[str = "GroupInfoReport"]
    GroupInfoReport,
    /// Report triggered from message context menu
    #[string_default]
    #[str = "MessageMenu"]
    MessageMenu,
    /// Report triggered from contact info screen
    #[str = "ContactInfo"]
    ContactInfo,
    /// Report triggered from status view
    #[str = "StatusReport"]
    StatusReport,
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

/// Build the spam_list node for a spam report.
///
/// This constructs the XML/binary node structure required by WhatsApp's spam reporting API.
///
/// # Arguments
/// * `request` - The spam report request containing message details
///
/// # Returns
/// A `Node` representing the spam_list element
pub fn build_spam_list_node(request: &SpamReportRequest) -> Node {
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
#[allow(deprecated)]
mod tests {
    use super::*;

    #[test]
    fn test_spam_flow_string_enum() {
        assert_eq!(SpamFlow::MessageMenu.as_str(), "MessageMenu");
        assert_eq!(
            SpamFlow::GroupSpamBannerReport.to_string(),
            "GroupSpamBannerReport"
        );
        assert_eq!(SpamFlow::default(), SpamFlow::MessageMenu);
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
            .expect("test node child should exist");
        assert_eq!(message.attrs().string("id"), "TEST123");
        assert_eq!(message.attrs().string("t"), "1234567890");
    }

    #[test]
    fn test_build_spam_list_node_with_raw_message() {
        let request = SpamReportRequest {
            message_id: "TEST456".to_string(),
            message_timestamp: 1234567890,
            from_jid: Some(Jid::pn("5511999887766")),
            spam_flow: SpamFlow::MessageMenu,
            raw_message: Some(vec![0x01, 0x02, 0x03]),
            media_type: Some("image".to_string()),
            ..Default::default()
        };

        let node = build_spam_list_node(&request);
        let message = node
            .get_optional_child_by_tag(&["message"])
            .expect("test node child should exist");
        let raw = message
            .get_optional_child_by_tag(&["raw"])
            .expect("test node child should exist");

        assert_eq!(raw.attrs().string("v"), "3");
        assert_eq!(raw.attrs().string("mediatype"), "image");
    }

    #[test]
    fn test_build_spam_list_node_group() {
        let request = SpamReportRequest {
            message_id: "TEST789".to_string(),
            message_timestamp: 1234567890,
            group_jid: Some(Jid::group("120363025918861132")),
            group_subject: Some("Test Group".to_string()),
            participant_jid: Some(Jid::pn("5511999887766")),
            spam_flow: SpamFlow::GroupInfoReport,
            ..Default::default()
        };

        let node = build_spam_list_node(&request);

        assert_eq!(node.attrs().string("spam_flow"), "GroupInfoReport");
        assert_eq!(node.attrs().string("jid"), "120363025918861132@g.us");
        assert_eq!(node.attrs().string("subject"), "Test Group");
    }
}
