//! Group notification stanza types.
//!
//! Parses `<notification type="w:gp2">` stanzas for group updates.
//!
//! Reference: WhatsApp Web `WAWebHandleGroupNotification` (Ri7Gf1BxhsX.js:12556-12962)
//! Tag names: `WAWebHandleGroupNotificationConst.GROUP_NOTIFICATION_TAG` (hE1cdfp8vOc.js:2460-2506)
//!
//! Key behaviors:
//! - A single notification can contain MULTIPLE child actions (mapChildren pattern)
//! - Root `participant` attribute identifies the admin/author who triggered the change
//! - Participant lists are nested `<participant jid="..." />` children

use serde::Serialize;
use wacore_binary::Jid;
use wacore_binary::{Node, NodeRef};

/// Parsed group notification containing one or more actions.
#[derive(Debug, Clone)]
pub struct GroupNotification {
    /// Group JID (from `from` attribute)
    pub group_jid: Jid,
    /// Admin/user who triggered the notification (from `participant` attribute)
    pub participant: Option<Jid>,
    /// Phone number JID of the participant (from `participant_pn` attribute, for LID groups)
    pub participant_pn: Option<Jid>,
    /// Timestamp (from `t` attribute, unix seconds)
    pub timestamp: u64,
    /// Whether the group uses LID addressing mode (from `addressing_mode="lid"`)
    pub is_lid_addressing_mode: bool,
    /// One or more actions in this notification
    pub actions: Vec<GroupNotificationAction>,
}

/// Participant info extracted from `<participant>` child elements.
///
/// Wire format:
/// ```xml
/// <participant jid="1234567890@s.whatsapp.net" phone_number="1234567890@s.whatsapp.net"/>
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct GroupParticipantInfo {
    pub jid: Jid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<Jid>,
}

/// All possible group notification action types.
///
/// Maps 1:1 to `GROUP_NOTIFICATION_TAG` child element tags from WhatsApp Web.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum GroupNotificationAction {
    // -- Participant management --
    /// `<add>` — Members added to group
    Add {
        participants: Vec<GroupParticipantInfo>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// `<remove>` — Members removed from group
    Remove {
        participants: Vec<GroupParticipantInfo>,
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },
    /// `<promote>` — Members promoted to admin
    Promote {
        participants: Vec<GroupParticipantInfo>,
    },
    /// `<demote>` — Members demoted from admin
    Demote {
        participants: Vec<GroupParticipantInfo>,
    },
    /// `<modify>` — Member changed phone number
    Modify {
        participants: Vec<GroupParticipantInfo>,
    },

    // -- Metadata --
    /// `<subject subject="..." s_o="..." s_t="..."/>` — Group name changed
    Subject {
        subject: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject_owner: Option<Jid>,
        #[serde(skip_serializing_if = "Option::is_none")]
        subject_time: Option<u64>,
    },
    /// `<description id="..."><body>text</body></description>` or `<description id="..."><delete/></description>`
    Description {
        id: String,
        /// `Some(text)` = added/updated, `None` = deleted
        #[serde(skip_serializing_if = "Option::is_none")]
        description: Option<String>,
    },

    // -- Settings --
    /// `<locked threshold="..."/>` — Only admins can edit group info
    Locked {
        #[serde(skip_serializing_if = "Option::is_none")]
        threshold: Option<String>,
    },
    /// `<unlocked/>` — All members can edit group info
    Unlocked,
    /// `<announcement/>` — Only admins can send messages
    Announce,
    /// `<not_announcement/>` — All members can send messages
    NotAnnounce,
    /// `<ephemeral expiration="..." trigger="..."/>` or `<not_ephemeral/>` (expiration=0)
    Ephemeral {
        expiration: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        trigger: Option<u32>,
    },
    /// `<membership_approval_mode><group_join state="on|off"/></membership_approval_mode>`
    MembershipApprovalMode { enabled: bool },
    /// `<member_add_mode>admin_add|all_member_add</member_add_mode>`
    MemberAddMode { mode: String },
    /// `<no_frequently_forwarded/>` — Forwarding restricted
    NoFrequentlyForwarded,
    /// `<frequently_forwarded_ok/>` — Forwarding allowed
    FrequentlyForwardedOk,

    // -- Invites --
    /// `<invite code="..."/>` — Joined via invite link
    Invite { code: String },
    /// `<revoke>` — Invite link revoked
    RevokeInvite,
    /// `<growth_locked expiration="..." type="..."/>` — Invite links unavailable
    GrowthLocked { expiration: u32, lock_type: String },
    /// `<growth_unlocked/>` — Invite links available again
    GrowthUnlocked,

    // -- Group lifecycle --
    /// `<create>` — Group created (complex structure, raw node preserved)
    Create {
        #[serde(skip)]
        raw: Node,
    },
    /// `<delete>` — Group deleted
    Delete {
        #[serde(skip_serializing_if = "Option::is_none")]
        reason: Option<String>,
    },

    // -- Community linking --
    /// `<link link_type="...">` — Subgroup linked
    Link {
        link_type: String,
        #[serde(skip)]
        raw: Node,
    },
    /// `<unlink unlink_type="..." unlink_reason="...">` — Subgroup unlinked
    Unlink {
        unlink_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        unlink_reason: Option<String>,
        #[serde(skip)]
        raw: Node,
    },

    // -- Catch-all --
    /// Unknown child tag — preserved for forward compatibility
    Unknown { tag: String },
}

impl GroupNotificationAction {
    /// Returns the wire tag name for this action, matching `GROUP_NOTIFICATION_TAG` values.
    pub fn tag_name(&self) -> &str {
        match self {
            Self::Add { .. } => "add",
            Self::Remove { .. } => "remove",
            Self::Promote { .. } => "promote",
            Self::Demote { .. } => "demote",
            Self::Modify { .. } => "modify",
            Self::Subject { .. } => "subject",
            Self::Description { .. } => "description",
            Self::Locked { .. } => "locked",
            Self::Unlocked => "unlocked",
            Self::Announce => "announcement",
            Self::NotAnnounce => "not_announcement",
            Self::Ephemeral { .. } => "ephemeral",
            Self::MembershipApprovalMode { .. } => "membership_approval_mode",
            Self::MemberAddMode { .. } => "member_add_mode",
            Self::NoFrequentlyForwarded => "no_frequently_forwarded",
            Self::FrequentlyForwardedOk => "frequently_forwarded_ok",
            Self::Invite { .. } => "invite",
            Self::RevokeInvite => "revoke",
            Self::GrowthLocked { .. } => "growth_locked",
            Self::GrowthUnlocked => "growth_unlocked",
            Self::Create { .. } => "create",
            Self::Delete { .. } => "delete",
            Self::Link { .. } => "link",
            Self::Unlink { .. } => "unlink",
            Self::Unknown { tag } => tag.as_str(),
        }
    }
}

impl GroupNotification {
    /// Parse from a `NodeRef`.
    ///
    /// Most fields are parsed zero-copy. Only `Create`/`Link`/`Unlink` actions
    /// call `.to_owned()` on their specific child node (structurally required to store `raw: Node`).
    pub fn try_from_node_ref(node: &NodeRef<'_>) -> Option<Self> {
        let mut attrs = node.attrs();
        let group_jid = attrs.optional_jid("from")?;
        let participant = attrs.optional_jid("participant");
        let participant_pn = attrs.optional_jid("participant_pn");
        let timestamp = attrs.optional_u64("t").unwrap_or(0);
        let is_lid_addressing_mode = node
            .get_attr("addressing_mode")
            .map(|v| v.as_str())
            .is_some_and(|s| s == "lid");

        let actions = node
            .children()
            .map(|children| children.iter().filter_map(parse_action).collect())
            .unwrap_or_default();

        Some(Self {
            group_jid,
            participant,
            participant_pn,
            timestamp,
            is_lid_addressing_mode,
            actions,
        })
    }
}

/// Parse a single child element into a GroupNotificationAction.
///
/// Only `Create`/`Link`/`Unlink` call `.to_owned()` because those variants store `raw: Node`.
fn parse_action(node: &NodeRef<'_>) -> Option<GroupNotificationAction> {
    use wacore_binary::NodeContentRef;
    let action = match node.tag.as_ref() {
        "add" => GroupNotificationAction::Add {
            participants: parse_participants(node),
            reason: node
                .attrs()
                .optional_string("reason")
                .map(|s| s.into_owned()),
        },
        "remove" => GroupNotificationAction::Remove {
            participants: parse_participants(node),
            reason: node
                .attrs()
                .optional_string("reason")
                .map(|s| s.into_owned()),
        },
        "promote" => GroupNotificationAction::Promote {
            participants: parse_participants(node),
        },
        "demote" => GroupNotificationAction::Demote {
            participants: parse_participants(node),
        },
        "modify" => GroupNotificationAction::Modify {
            participants: parse_participants(node),
        },
        "subject" => GroupNotificationAction::Subject {
            subject: node
                .attrs()
                .optional_string("subject")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            subject_owner: node.attrs().optional_jid("s_o"),
            subject_time: node.attrs().optional_u64("s_t"),
        },
        "description" => {
            let id = node
                .attrs()
                .optional_string("id")
                .as_deref()
                .unwrap_or_default()
                .to_string();
            let description = if node.get_optional_child("delete").is_some() {
                None
            } else {
                node.get_optional_child("body")
                    .and_then(|body| body.content_as_string())
                    .map(|s| s.to_string())
            };
            GroupNotificationAction::Description { id, description }
        }
        "locked" => GroupNotificationAction::Locked {
            threshold: node
                .attrs()
                .optional_string("threshold")
                .map(|s| s.into_owned()),
        },
        "unlocked" => GroupNotificationAction::Unlocked,
        "announcement" => GroupNotificationAction::Announce,
        "not_announcement" => GroupNotificationAction::NotAnnounce,
        "ephemeral" => GroupNotificationAction::Ephemeral {
            expiration: node.attrs().optional_u64("expiration").unwrap_or(0) as u32,
            trigger: node.attrs().optional_u64("trigger").map(|t| t as u32),
        },
        "not_ephemeral" => GroupNotificationAction::Ephemeral {
            expiration: 0,
            trigger: None,
        },
        "membership_approval_mode" => {
            let enabled = node
                .get_optional_child("group_join")
                .and_then(|gj| gj.attrs().optional_string("state"))
                .is_some_and(|s| s == "on");
            GroupNotificationAction::MembershipApprovalMode { enabled }
        }
        "member_add_mode" => {
            let mode = match node.content.as_deref() {
                Some(NodeContentRef::String(s)) => s.to_string(),
                Some(NodeContentRef::Bytes(b)) => String::from_utf8_lossy(b.as_ref()).into_owned(),
                _ => String::new(),
            };
            GroupNotificationAction::MemberAddMode { mode }
        }
        "no_frequently_forwarded" => GroupNotificationAction::NoFrequentlyForwarded,
        "frequently_forwarded_ok" => GroupNotificationAction::FrequentlyForwardedOk,
        "invite" => GroupNotificationAction::Invite {
            code: node
                .attrs()
                .optional_string("code")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
        },
        "revoke" => GroupNotificationAction::RevokeInvite,
        "growth_locked" => GroupNotificationAction::GrowthLocked {
            expiration: node.attrs().optional_u64("expiration").unwrap_or(0) as u32,
            lock_type: node
                .attrs()
                .optional_string("type")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
        },
        "growth_unlocked" => GroupNotificationAction::GrowthUnlocked,
        // These three variants store owned Node — only convert what's needed.
        "create" => GroupNotificationAction::Create {
            raw: node.to_owned(),
        },
        "delete" => GroupNotificationAction::Delete {
            reason: node
                .attrs()
                .optional_string("reason")
                .map(|s| s.into_owned()),
        },
        "link" => GroupNotificationAction::Link {
            link_type: node
                .attrs()
                .optional_string("link_type")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            raw: node.to_owned(),
        },
        "unlink" => GroupNotificationAction::Unlink {
            unlink_type: node
                .attrs()
                .optional_string("unlink_type")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            unlink_reason: node
                .attrs()
                .optional_string("unlink_reason")
                .map(|s| s.into_owned()),
            raw: node.to_owned(),
        },
        "missing_participant_identification" => return None,
        other => GroupNotificationAction::Unknown {
            tag: other.to_string(),
        },
    };
    Some(action)
}

fn parse_participants(node: &NodeRef<'_>) -> Vec<GroupParticipantInfo> {
    node.children()
        .map(|children| {
            children
                .iter()
                .filter(|c| c.tag == "participant")
                .filter_map(|c| {
                    let jid = c.attrs().optional_jid("jid")?;
                    let phone_number = c.attrs().optional_jid("phone_number");
                    Some(GroupParticipantInfo { jid, phone_number })
                })
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::Jid;
    use wacore_binary::builder::NodeBuilder;

    fn group_jid() -> Jid {
        "120363012345678901@g.us".parse().unwrap()
    }

    fn user_jid() -> Jid {
        "5511999999999@s.whatsapp.net".parse().unwrap()
    }

    fn admin_jid() -> Jid {
        "5511888888888@s.whatsapp.net".parse().unwrap()
    }

    fn make_notification(children: Vec<Node>) -> Node {
        NodeBuilder::new("notification")
            .attr("type", "w:gp2")
            .attr("from", group_jid())
            .attr("participant", admin_jid())
            .attr("t", "1704067200")
            .children(children)
            .build()
    }

    #[test]
    fn test_parse_add_notification() {
        let node = make_notification(vec![
            NodeBuilder::new("add")
                .children(vec![
                    NodeBuilder::new("participant")
                        .attr("jid", user_jid())
                        .build(),
                ])
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        assert_eq!(notif.group_jid, group_jid());
        assert_eq!(notif.participant, Some(admin_jid()));
        assert_eq!(notif.timestamp, 1704067200);
        assert_eq!(notif.actions.len(), 1);

        match &notif.actions[0] {
            GroupNotificationAction::Add {
                participants,
                reason,
            } => {
                assert_eq!(participants.len(), 1);
                assert_eq!(participants[0].jid, user_jid());
                assert!(reason.is_none());
            }
            other => panic!("expected Add, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_subject_notification() {
        let node = make_notification(vec![
            NodeBuilder::new("subject")
                .attr("subject", "New Group Name")
                .attr("s_o", admin_jid())
                .attr("s_t", "1704067200")
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        assert_eq!(notif.actions.len(), 1);

        match &notif.actions[0] {
            GroupNotificationAction::Subject {
                subject,
                subject_owner,
                subject_time,
            } => {
                assert_eq!(subject, "New Group Name");
                assert_eq!(*subject_owner, Some(admin_jid()));
                assert_eq!(*subject_time, Some(1704067200));
            }
            other => panic!("expected Subject, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_description_add() {
        let node = make_notification(vec![
            NodeBuilder::new("description")
                .attr("id", "desc123")
                .children(vec![
                    NodeBuilder::new("body")
                        .string_content("Group description text")
                        .build(),
                ])
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        match &notif.actions[0] {
            GroupNotificationAction::Description { id, description } => {
                assert_eq!(id, "desc123");
                assert_eq!(description.as_deref(), Some("Group description text"));
            }
            other => panic!("expected Description, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_description_delete() {
        let node = make_notification(vec![
            NodeBuilder::new("description")
                .attr("id", "desc123")
                .children(vec![NodeBuilder::new("delete").build()])
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        match &notif.actions[0] {
            GroupNotificationAction::Description { id, description } => {
                assert_eq!(id, "desc123");
                assert!(description.is_none());
            }
            other => panic!("expected Description, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_settings_notifications() {
        // Test multiple actions in one notification
        let node = make_notification(vec![
            NodeBuilder::new("locked").attr("threshold", "100").build(),
            NodeBuilder::new("announcement").build(),
            NodeBuilder::new("ephemeral")
                .attr("expiration", "604800")
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        assert_eq!(notif.actions.len(), 3);

        match &notif.actions[0] {
            GroupNotificationAction::Locked { threshold } => {
                assert_eq!(threshold.as_deref(), Some("100"));
            }
            other => panic!("expected Locked, got {:?}", other),
        }
        assert!(matches!(
            notif.actions[1],
            GroupNotificationAction::Announce
        ));
        match &notif.actions[2] {
            GroupNotificationAction::Ephemeral {
                expiration,
                trigger,
            } => {
                assert_eq!(*expiration, 604800);
                assert!(trigger.is_none());
            }
            other => panic!("expected Ephemeral, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_not_ephemeral() {
        let node = make_notification(vec![NodeBuilder::new("not_ephemeral").build()]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        match &notif.actions[0] {
            GroupNotificationAction::Ephemeral {
                expiration,
                trigger,
            } => {
                assert_eq!(*expiration, 0);
                assert!(trigger.is_none());
            }
            other => panic!("expected Ephemeral, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_membership_approval_mode() {
        let node = make_notification(vec![
            NodeBuilder::new("membership_approval_mode")
                .children(vec![
                    NodeBuilder::new("group_join").attr("state", "on").build(),
                ])
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        match &notif.actions[0] {
            GroupNotificationAction::MembershipApprovalMode { enabled } => {
                assert!(*enabled);
            }
            other => panic!("expected MembershipApprovalMode, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_unknown_tag() {
        let node = make_notification(vec![NodeBuilder::new("some_future_feature").build()]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        match &notif.actions[0] {
            GroupNotificationAction::Unknown { tag } => {
                assert_eq!(tag, "some_future_feature");
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn test_missing_from_returns_none() {
        let node = NodeBuilder::new("notification")
            .attr("type", "w:gp2")
            .attr("t", "1704067200")
            .build();

        assert!(GroupNotification::try_from_node_ref(&node.as_node_ref()).is_none());
    }
}
