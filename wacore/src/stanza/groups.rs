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

use crate::WireEnum;
use serde::Serialize;
use wacore_binary::Jid;
use wacore_binary::{Node, NodeRef};

/// How a membership request was initiated.
///
/// Maps to `WAWebRequestMethodType` in WhatsApp Web JS.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MembershipRequestMethod {
    InviteLink,
    LinkedGroupJoin,
    NonAdminAdd,
}

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
///
/// The `#[wire = "..."]` attribute is the SINGLE source of truth for each
/// variant's wire tag: the JSON discriminator (via the auto-derived
/// `Serialize`), the parser dispatch (via the auto-generated sibling
/// `GroupNotificationActionTag` enum), and `wire_tag()` / `tag_name()` all
/// read from the same table.
#[derive(Debug, Clone, WireEnum)]
#[wire(tag = "type")]
pub enum GroupNotificationAction {
    // -- Participant management --
    /// `<add>` — Members added to group
    #[wire = "add"]
    Add {
        participants: Vec<GroupParticipantInfo>,
        reason: Option<String>,
    },
    /// `<remove>` — Members removed from group
    #[wire = "remove"]
    Remove {
        participants: Vec<GroupParticipantInfo>,
        reason: Option<String>,
    },
    /// `<promote>` — Members promoted to admin
    #[wire = "promote"]
    Promote {
        participants: Vec<GroupParticipantInfo>,
    },
    /// `<demote>` — Members demoted from admin
    #[wire = "demote"]
    Demote {
        participants: Vec<GroupParticipantInfo>,
    },
    /// `<modify>` — Member changed phone number
    #[wire = "modify"]
    Modify {
        participants: Vec<GroupParticipantInfo>,
    },

    // -- Metadata --
    /// `<subject subject="..." s_o="..." s_t="..."/>` — Group name changed
    #[wire = "subject"]
    Subject {
        subject: String,
        subject_owner: Option<Jid>,
        subject_time: Option<u64>,
    },
    /// `<description id="..."><body>text</body></description>` or `<description id="..."><delete/></description>`
    #[wire = "description"]
    Description {
        id: String,
        /// `Some(text)` = added/updated, `None` = deleted
        description: Option<String>,
    },

    // -- Settings --
    /// `<locked threshold="..."/>` — Only admins can edit group info
    #[wire = "locked"]
    Locked { threshold: Option<String> },
    /// `<unlocked/>` — All members can edit group info
    #[wire = "unlocked"]
    Unlocked,
    /// `<announcement/>` — Only admins can send messages
    #[wire = "announcement"]
    Announce,
    /// `<not_announcement/>` — All members can send messages
    #[wire = "not_announcement"]
    NotAnnounce,
    /// `<ephemeral expiration="..." trigger="..."/>` — and the alias
    /// `<not_ephemeral/>` which parses into `Ephemeral { expiration: 0 }`,
    /// matching WA Web's collapsing of the two tags into one action type.
    #[wire = "ephemeral"]
    #[wire_alias = "not_ephemeral"]
    Ephemeral {
        expiration: u32,
        trigger: Option<u32>,
    },
    /// `<membership_approval_mode><group_join state="on|off"/></membership_approval_mode>`
    #[wire = "membership_approval_mode"]
    MembershipApprovalMode { enabled: bool },
    /// `<membership_approval_request request_method="..." parent_group_jid="..."/>`
    /// A user requested to join. Requester is on parent [`GroupNotification::participant`].
    #[wire = "membership_approval_request"]
    MembershipApprovalRequest {
        request_method: MembershipRequestMethod,
        parent_group_jid: Option<Jid>,
    },
    /// `<created_membership_requests request_method="..." parent_group_jid="...">` —
    /// admin-side notification: new join requests appeared.
    #[wire = "created_membership_requests"]
    CreatedMembershipRequests {
        request_method: MembershipRequestMethod,
        parent_group_jid: Option<Jid>,
        /// `<requested_user>` children (not `<participant>`).
        requests: Vec<GroupParticipantInfo>,
    },
    /// `<revoked_membership_requests>` — requests rejected by admin or cancelled by requester.
    #[wire = "revoked_membership_requests"]
    RevokedMembershipRequests { participants: Vec<Jid> },
    /// `<member_add_mode>admin_add|all_member_add</member_add_mode>`
    #[wire = "member_add_mode"]
    MemberAddMode { mode: String },
    /// `<no_frequently_forwarded/>` — Forwarding restricted
    #[wire = "no_frequently_forwarded"]
    NoFrequentlyForwarded,
    /// `<frequently_forwarded_ok/>` — Forwarding allowed
    #[wire = "frequently_forwarded_ok"]
    FrequentlyForwardedOk,

    // -- Invites --
    /// `<invite code="..."/>` — Joined via invite link
    #[wire = "invite"]
    Invite { code: String },
    /// `<revoke>` — Invite link revoked
    #[wire = "revoke"]
    RevokeInvite,
    /// `<growth_locked expiration="..." type="..."/>` — Invite links unavailable
    #[wire = "growth_locked"]
    GrowthLocked { expiration: u32, lock_type: String },
    /// `<growth_unlocked/>` — Invite links available again
    #[wire = "growth_unlocked"]
    GrowthUnlocked,

    // -- Group lifecycle --
    /// `<create>` — Group created (complex structure, raw node preserved)
    #[wire = "create"]
    Create {
        #[wire(skip)]
        raw: Node,
    },
    /// `<delete>` — Group deleted
    #[wire = "delete"]
    Delete { reason: Option<String> },

    // -- Community linking --
    /// `<link link_type="...">` — Subgroup linked
    #[wire = "link"]
    Link {
        link_type: String,
        #[wire(skip)]
        raw: Node,
    },
    /// `<unlink unlink_type="..." unlink_reason="...">` — Subgroup unlinked
    #[wire = "unlink"]
    Unlink {
        unlink_type: String,
        unlink_reason: Option<String>,
        #[wire(skip)]
        raw: Node,
    },

    // -- Catch-all --
    /// Unknown child tag — preserved for forward compatibility. The `tag`
    /// field is what `wire_tag()` returns, so roundtrips stay intact.
    #[wire_fallback]
    Unknown { tag: String },
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
/// Dispatches via [`GroupNotificationActionTag`] (auto-generated by
/// `#[derive(WireEnum)]`) — no wire-tag string literal appears in this
/// function. If the `#[wire = "..."]` attribute on a variant changes, both
/// the serializer and this dispatcher track it automatically.
///
/// Only `Create`/`Link`/`Unlink` call `.to_owned()` because those variants store `raw: Node`.
fn parse_action(node: &NodeRef<'_>) -> Option<GroupNotificationAction> {
    use GroupNotificationActionTag as T;
    use wacore_binary::NodeContentRef;

    // WA Web drops this child entirely; mirror that behavior.
    if node.tag.as_ref() == "missing_participant_identification" {
        return None;
    }

    let tag = T::from(node.tag.as_ref());

    let action = match tag {
        T::Add => GroupNotificationAction::Add {
            participants: parse_participants(node),
            reason: node
                .attrs()
                .optional_string("reason")
                .map(|s| s.into_owned()),
        },
        T::Remove => GroupNotificationAction::Remove {
            participants: parse_participants(node),
            reason: node
                .attrs()
                .optional_string("reason")
                .map(|s| s.into_owned()),
        },
        T::Promote => GroupNotificationAction::Promote {
            participants: parse_participants(node),
        },
        T::Demote => GroupNotificationAction::Demote {
            participants: parse_participants(node),
        },
        T::Modify => GroupNotificationAction::Modify {
            participants: parse_participants(node),
        },
        T::Subject => GroupNotificationAction::Subject {
            subject: node
                .attrs()
                .optional_string("subject")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            subject_owner: node.attrs().optional_jid("s_o"),
            subject_time: node.attrs().optional_u64("s_t"),
        },
        T::Description => {
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
        T::Locked => GroupNotificationAction::Locked {
            threshold: node
                .attrs()
                .optional_string("threshold")
                .map(|s| s.into_owned()),
        },
        T::Unlocked => GroupNotificationAction::Unlocked,
        T::Announce => GroupNotificationAction::Announce,
        T::NotAnnounce => GroupNotificationAction::NotAnnounce,
        T::Ephemeral => GroupNotificationAction::Ephemeral {
            expiration: node.attrs().optional_u64("expiration").unwrap_or(0) as u32,
            trigger: node.attrs().optional_u64("trigger").map(|t| t as u32),
        },
        // Alias auto-generated from #[wire_alias = "not_ephemeral"]. WA Web
        // collapses it into Ephemeral with duration=0.
        T::Ephemeral__Alias0 => GroupNotificationAction::Ephemeral {
            expiration: 0,
            trigger: None,
        },
        T::MembershipApprovalMode => {
            let enabled = node
                .get_optional_child("group_join")
                .and_then(|gj| gj.attrs().optional_string("state"))
                .is_some_and(|s| s == "on");
            GroupNotificationAction::MembershipApprovalMode { enabled }
        }
        T::MembershipApprovalRequest => {
            let request_method = parse_request_method(node);
            let parent_group_jid = node.attrs().optional_jid("parent_group_jid");
            GroupNotificationAction::MembershipApprovalRequest {
                request_method,
                parent_group_jid,
            }
        }
        T::CreatedMembershipRequests => {
            let request_method = parse_request_method(node);
            let parent_group_jid = node.attrs().optional_jid("parent_group_jid");
            let requests = parse_requested_users(node);
            GroupNotificationAction::CreatedMembershipRequests {
                request_method,
                parent_group_jid,
                requests,
            }
        }
        T::RevokedMembershipRequests => {
            let participants = parse_participant_jids(node);
            GroupNotificationAction::RevokedMembershipRequests { participants }
        }
        T::MemberAddMode => {
            let mode = match node.content.as_deref() {
                Some(NodeContentRef::String(s)) => s.to_string(),
                Some(NodeContentRef::Bytes(b)) => String::from_utf8_lossy(b.as_ref()).into_owned(),
                _ => String::new(),
            };
            GroupNotificationAction::MemberAddMode { mode }
        }
        T::NoFrequentlyForwarded => GroupNotificationAction::NoFrequentlyForwarded,
        T::FrequentlyForwardedOk => GroupNotificationAction::FrequentlyForwardedOk,
        T::Invite => GroupNotificationAction::Invite {
            code: node
                .attrs()
                .optional_string("code")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
        },
        T::RevokeInvite => GroupNotificationAction::RevokeInvite,
        T::GrowthLocked => GroupNotificationAction::GrowthLocked {
            expiration: node.attrs().optional_u64("expiration").unwrap_or(0) as u32,
            lock_type: node
                .attrs()
                .optional_string("type")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
        },
        T::GrowthUnlocked => GroupNotificationAction::GrowthUnlocked,
        T::Create => GroupNotificationAction::Create {
            raw: node.to_owned(),
        },
        T::Delete => GroupNotificationAction::Delete {
            reason: node
                .attrs()
                .optional_string("reason")
                .map(|s| s.into_owned()),
        },
        T::Link => GroupNotificationAction::Link {
            link_type: node
                .attrs()
                .optional_string("link_type")
                .as_deref()
                .unwrap_or_default()
                .to_string(),
            raw: node.to_owned(),
        },
        T::Unlink => GroupNotificationAction::Unlink {
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
        T::Unknown(_) => GroupNotificationAction::Unknown {
            tag: node.tag.to_string(),
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

/// Parses `<requested_user>` children from `<created_membership_requests>`.
fn parse_requested_users(node: &NodeRef<'_>) -> Vec<GroupParticipantInfo> {
    node.children()
        .map(|children| {
            children
                .iter()
                .filter(|c| c.tag == "requested_user")
                .filter_map(|c| {
                    let jid = c.attrs().optional_jid("jid")?;
                    let phone_number = c.attrs().optional_jid("phone_number");
                    Some(GroupParticipantInfo { jid, phone_number })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Parses `<participant jid="..."/>` children into plain JIDs.
fn parse_participant_jids(node: &NodeRef<'_>) -> Vec<Jid> {
    node.children()
        .map(|children| {
            children
                .iter()
                .filter(|c| c.tag == "participant")
                .filter_map(|c| c.attrs().optional_jid("jid"))
                .collect()
        })
        .unwrap_or_default()
}

/// Maps the `request_method` attribute to [`MembershipRequestMethod`].
/// Defaults to `InviteLink` when absent or unknown — matches WA Web's fallback.
fn parse_request_method(node: &NodeRef<'_>) -> MembershipRequestMethod {
    match node.attrs().optional_string("request_method").as_deref() {
        Some("linked_group_join") => MembershipRequestMethod::LinkedGroupJoin,
        Some("non_admin_add") => MembershipRequestMethod::NonAdminAdd,
        _ => MembershipRequestMethod::InviteLink,
    }
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
    fn test_parse_membership_approval_request() {
        // User requested to join — flat node with attrs only, actor is the requester.
        let node = make_notification(vec![
            NodeBuilder::new("membership_approval_request")
                .attr("request_method", "invite_link")
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        assert_eq!(notif.participant, Some(admin_jid()));
        match &notif.actions[0] {
            GroupNotificationAction::MembershipApprovalRequest {
                request_method,
                parent_group_jid,
            } => {
                assert_eq!(*request_method, MembershipRequestMethod::InviteLink);
                assert!(parent_group_jid.is_none());
            }
            other => panic!("expected MembershipApprovalRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_created_membership_requests() {
        // Admin-side: new requests appeared — uses <requested_user> children.
        let node = make_notification(vec![
            NodeBuilder::new("created_membership_requests")
                .attr("request_method", "non_admin_add")
                .children(vec![
                    NodeBuilder::new("requested_user")
                        .attr("jid", user_jid())
                        .build(),
                ])
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        assert_eq!(notif.participant, Some(admin_jid()));
        match &notif.actions[0] {
            GroupNotificationAction::CreatedMembershipRequests {
                request_method,
                parent_group_jid,
                requests,
            } => {
                assert_eq!(*request_method, MembershipRequestMethod::NonAdminAdd);
                assert!(parent_group_jid.is_none());
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].jid, user_jid());
            }
            other => panic!("expected CreatedMembershipRequests, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_revoked_membership_requests() {
        // Requests rejected by admin — uses <participant jid="..."/> children.
        let node = make_notification(vec![
            NodeBuilder::new("revoked_membership_requests")
                .children(vec![
                    NodeBuilder::new("participant")
                        .attr("jid", user_jid())
                        .build(),
                ])
                .build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        assert_eq!(notif.participant, Some(admin_jid()));
        match &notif.actions[0] {
            GroupNotificationAction::RevokedMembershipRequests { participants } => {
                assert_eq!(participants.len(), 1);
                assert_eq!(participants[0], user_jid());
            }
            other => panic!("expected RevokedMembershipRequests, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_membership_approval_request_default_method() {
        // No request_method attr → defaults to InviteLink (matches WA Web fallback).
        let node = make_notification(vec![
            NodeBuilder::new("membership_approval_request").build(),
        ]);

        let notif = GroupNotification::try_from_node_ref(&node.as_node_ref()).unwrap();
        assert_eq!(notif.participant, Some(admin_jid()));
        match &notif.actions[0] {
            GroupNotificationAction::MembershipApprovalRequest {
                request_method,
                parent_group_jid,
            } => {
                assert_eq!(*request_method, MembershipRequestMethod::InviteLink);
                assert!(parent_group_jid.is_none());
            }
            other => panic!("expected MembershipApprovalRequest, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_membership_request_with_parent_group_jid() {
        // Community-linked join — both variants carry parent_group_jid.
        let parent_jid: Jid = "999999999999999999@g.us".parse().unwrap();

        let approval_node = make_notification(vec![
            NodeBuilder::new("membership_approval_request")
                .attr("request_method", "linked_group_join")
                .attr("parent_group_jid", parent_jid.clone())
                .build(),
        ]);
        let notif = GroupNotification::try_from_node_ref(&approval_node.as_node_ref()).unwrap();
        match &notif.actions[0] {
            GroupNotificationAction::MembershipApprovalRequest {
                request_method,
                parent_group_jid,
            } => {
                assert_eq!(*request_method, MembershipRequestMethod::LinkedGroupJoin);
                assert_eq!(*parent_group_jid, Some(parent_jid.clone()));
            }
            other => panic!("expected MembershipApprovalRequest, got {:?}", other),
        }

        let created_node = make_notification(vec![
            NodeBuilder::new("created_membership_requests")
                .attr("request_method", "linked_group_join")
                .attr("parent_group_jid", parent_jid.clone())
                .children(vec![
                    NodeBuilder::new("requested_user")
                        .attr("jid", user_jid())
                        .build(),
                ])
                .build(),
        ]);
        let notif2 = GroupNotification::try_from_node_ref(&created_node.as_node_ref()).unwrap();
        match &notif2.actions[0] {
            GroupNotificationAction::CreatedMembershipRequests {
                request_method,
                parent_group_jid,
                requests,
            } => {
                assert_eq!(*request_method, MembershipRequestMethod::LinkedGroupJoin);
                assert_eq!(*parent_group_jid, Some(parent_jid));
                assert_eq!(requests.len(), 1);
                assert_eq!(requests[0].jid, user_jid());
            }
            other => panic!("expected CreatedMembershipRequests, got {:?}", other),
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

    /// Every variant serializes its JSON `"type"` discriminator using the
    /// exact wire tag the parser dispatches on. This is the regression guard
    /// for the PascalCase discriminator leak that used to ship
    /// `{"type":"Demote", ...}` instead of `{"type":"demote", ...}`.
    #[test]
    fn serialize_discriminator_matches_wire_tag() {
        let dummy_node = NodeBuilder::new("placeholder").build();
        let samples: Vec<GroupNotificationAction> = vec![
            GroupNotificationAction::Add {
                participants: vec![],
                reason: None,
            },
            GroupNotificationAction::Remove {
                participants: vec![],
                reason: Some("r".into()),
            },
            GroupNotificationAction::Promote {
                participants: vec![],
            },
            GroupNotificationAction::Demote {
                participants: vec![],
            },
            GroupNotificationAction::Modify {
                participants: vec![],
            },
            GroupNotificationAction::Subject {
                subject: "s".into(),
                subject_owner: None,
                subject_time: None,
            },
            GroupNotificationAction::Description {
                id: "i".into(),
                description: None,
            },
            GroupNotificationAction::Locked { threshold: None },
            GroupNotificationAction::Unlocked,
            GroupNotificationAction::Announce,
            GroupNotificationAction::NotAnnounce,
            GroupNotificationAction::Ephemeral {
                expiration: 0,
                trigger: None,
            },
            GroupNotificationAction::MembershipApprovalMode { enabled: true },
            GroupNotificationAction::MembershipApprovalRequest {
                request_method: MembershipRequestMethod::InviteLink,
                parent_group_jid: None,
            },
            GroupNotificationAction::CreatedMembershipRequests {
                request_method: MembershipRequestMethod::InviteLink,
                parent_group_jid: None,
                requests: vec![],
            },
            GroupNotificationAction::RevokedMembershipRequests {
                participants: vec![],
            },
            GroupNotificationAction::MemberAddMode { mode: "x".into() },
            GroupNotificationAction::NoFrequentlyForwarded,
            GroupNotificationAction::FrequentlyForwardedOk,
            GroupNotificationAction::Invite { code: "c".into() },
            GroupNotificationAction::RevokeInvite,
            GroupNotificationAction::GrowthLocked {
                expiration: 0,
                lock_type: "x".into(),
            },
            GroupNotificationAction::GrowthUnlocked,
            GroupNotificationAction::Create {
                raw: dummy_node.clone(),
            },
            GroupNotificationAction::Delete { reason: None },
            GroupNotificationAction::Link {
                link_type: "x".into(),
                raw: dummy_node.clone(),
            },
            GroupNotificationAction::Unlink {
                unlink_type: "x".into(),
                unlink_reason: None,
                raw: dummy_node,
            },
            GroupNotificationAction::Unknown {
                tag: "future_tag".into(),
            },
        ];

        for action in &samples {
            let value = serde_json::to_value(action).expect("serialize");
            let ty = value
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| panic!("missing type in {value}"));
            assert_eq!(
                ty,
                action.tag_name(),
                "serialized discriminator diverged from wire tag for {action:?}"
            );
        }
    }

    /// Lowercase wire strings round-trip through the parser, matching the
    /// exact JSON discriminators we now emit. If someone renames a variant
    /// and forgets to keep `tag_name()` aligned with the parser's dispatch
    /// table, this test fails.
    #[test]
    fn wire_tags_round_trip_through_parser() {
        type Check = fn(&GroupNotificationAction) -> bool;
        let cases: &[(&str, Check)] = &[
            ("add", |a| matches!(a, GroupNotificationAction::Add { .. })),
            ("demote", |a| {
                matches!(a, GroupNotificationAction::Demote { .. })
            }),
            ("promote", |a| {
                matches!(a, GroupNotificationAction::Promote { .. })
            }),
            ("revoke", |a| {
                matches!(a, GroupNotificationAction::RevokeInvite)
            }),
            ("not_announcement", |a| {
                matches!(a, GroupNotificationAction::NotAnnounce)
            }),
            ("announcement", |a| {
                matches!(a, GroupNotificationAction::Announce)
            }),
        ];

        for (tag, check) in cases {
            let node = make_notification(vec![NodeBuilder::new(tag).build()]);
            let notif = GroupNotification::try_from_node_ref(&node.as_node_ref())
                .unwrap_or_else(|| panic!("parse failed for <{tag}>"));
            let action = &notif.actions[0];
            assert!(
                check(action),
                "tag <{tag}> did not produce expected variant (got {action:?})"
            );
            assert_eq!(action.tag_name(), *tag);
        }
    }
}
