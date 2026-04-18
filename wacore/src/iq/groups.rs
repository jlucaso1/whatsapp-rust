use crate::StringEnum;
use crate::iq::node::{collect_children, required_attr, required_child};
use crate::iq::spec::IqSpec;
use crate::protocol::ProtocolNode;
use crate::request::InfoQuery;
use anyhow::{Result, anyhow};
use std::num::NonZeroU32;
use typed_builder::TypedBuilder;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, Server};
use wacore_binary::{Node, NodeContent, NodeRef};

// Re-export AddressingMode from types::message for convenience
pub use crate::types::message::AddressingMode;

/// MEX (GraphQL) document IDs for group operations.
pub mod mex_docs {
    /// Update a group property (xwa2_group_update_property mutation).
    pub const UPDATE_GROUP_PROPERTY: &str = "9418211574894172";
}

/// IQ namespace for group operations.
pub const GROUP_IQ_NAMESPACE: &str = "w:g2";

/// Maximum length for a WhatsApp group subject (from `group_max_subject` A/B prop).
pub const GROUP_SUBJECT_MAX_LENGTH: usize = 100;

/// Maximum length for a WhatsApp group description (from `group_description_length` A/B prop).
pub const GROUP_DESCRIPTION_MAX_LENGTH: usize = 2048;

/// Maximum number of participants in a group (from `group_size_limit` A/B prop).
pub const GROUP_SIZE_LIMIT: usize = 257;

/// Maximum number of groups in a batch info query.
pub const BATCH_GROUP_INFO_LIMIT: usize = 10_000;

/// Maximum number of pictures in a batch profile picture query.
pub const BATCH_PROFILE_PICTURES_LIMIT: usize = 1_000;

/// Member link mode for group invite links.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum MemberLinkMode {
    #[str = "admin_link"]
    AdminLink,
    #[str = "all_member_link"]
    AllMemberLink,
}

/// Member add mode for who can add participants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum MemberAddMode {
    #[str = "admin_add"]
    AdminAdd,
    #[str = "all_member_add"]
    AllMemberAdd,
}

/// Membership approval mode for join requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum MembershipApprovalMode {
    #[string_default]
    #[str = "off"]
    Off,
    #[str = "on"]
    On,
}

/// Who can share message history with new members.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum MemberShareHistoryMode {
    #[string_default]
    #[str = "admin_share"]
    AdminShare,
    #[str = "all_member_share"]
    AllMemberShare,
}

/// Growth lock info (system-managed, read-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrowthLockInfo {
    pub lock_type: String,
    pub expiration: u64,
}

/// Generates a typed error-code enum with `from_code`, `code`, and `Display`.
macro_rules! define_error_code_enum {
    (
        $(#[$meta:meta])*
        $name:ident { $( $variant:ident = $code:literal : $desc:literal ),+ $(,)? }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum $name {
            $( $variant, )+
            Unknown(u16),
        }

        impl $name {
            pub fn from_code(code: u16) -> Self {
                match code {
                    $( $code => Self::$variant, )+
                    _ => Self::Unknown(code),
                }
            }

            pub fn code(&self) -> u16 {
                match self {
                    $( Self::$variant => $code, )+
                    Self::Unknown(c) => *c,
                }
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $( Self::$variant => write!(f, concat!($desc, " (", stringify!($code), ")")), )+
                    Self::Unknown(c) => write!(f, "unknown error ({c})"),
                }
            }
        }
    };
}

define_error_code_enum! {
    /// Error codes returned when querying invite group info.
    InviteInfoError {
        BadRequest          = 400: "bad request",
        NotAuthorized       = 401: "not authorized",
        NotFound            = 404: "group not found",
        NotAcceptable       = 406: "not acceptable",
        Gone                = 410: "invite link was reset",
        ParentGroupSuspended = 416: "parent group suspended",
        Locked              = 423: "group locked",
        GrowthLocked        = 436: "invite link unavailable",
    }
}

define_error_code_enum! {
    /// Error codes returned when joining a group via invite.
    GroupJoinError {
        AlreadyMember  = 304: "already a member",
        BadRequest     = 400: "bad request",
        Forbidden      = 403: "forbidden",
        NotFound       = 404: "group not found",
        NotAllowed     = 405: "removed from group",
        Conflict       = 409: "conflict",
        Gone           = 410: "invite link was reset",
        CommunityFull  = 412: "community is full",
        GroupFull      = 419: "group is full",
        Locked         = 423: "group locked",
    }
}

/// Query request type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum GroupQueryRequestType {
    #[string_default]
    #[str = "interactive"]
    Interactive,
}

/// Participant type (admin level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, StringEnum)]
pub enum ParticipantType {
    #[string_default]
    #[str = "member"]
    Member,
    #[str = "admin"]
    Admin,
    #[str = "superadmin"]
    SuperAdmin,
}

impl ParticipantType {
    pub fn is_admin(&self) -> bool {
        matches!(self, ParticipantType::Admin | ParticipantType::SuperAdmin)
    }
}

impl TryFrom<Option<&str>> for ParticipantType {
    type Error = anyhow::Error;

    fn try_from(value: Option<&str>) -> Result<Self> {
        match value {
            Some("admin") => Ok(ParticipantType::Admin),
            Some("superadmin") => Ok(ParticipantType::SuperAdmin),
            Some("member") | None => Ok(ParticipantType::Member),
            Some(other) => Err(anyhow!("unknown participant type: {other}")),
        }
    }
}
crate::define_validated_string! {
    /// A validated group subject string.
    ///
    /// WhatsApp limits group subjects to [`GROUP_SUBJECT_MAX_LENGTH`] characters.
    pub struct GroupSubject(max_len = GROUP_SUBJECT_MAX_LENGTH, name = "Group subject")
}

crate::define_validated_string! {
    /// A validated group description string.
    ///
    /// WhatsApp limits group descriptions to [`GROUP_DESCRIPTION_MAX_LENGTH`] characters.
    pub struct GroupDescription(max_len = GROUP_DESCRIPTION_MAX_LENGTH, name = "Group description")
}
/// Options for a participant when creating a group.
#[derive(Debug, Clone, TypedBuilder)]
#[builder(build_method(into))]
pub struct GroupParticipantOptions {
    pub jid: Jid,
    #[builder(default, setter(strip_option))]
    pub phone_number: Option<Jid>,
    #[builder(default, setter(strip_option))]
    pub privacy: Option<Vec<u8>>,
}

impl GroupParticipantOptions {
    pub fn new(jid: Jid) -> Self {
        Self {
            jid,
            phone_number: None,
            privacy: None,
        }
    }

    pub fn from_phone(phone_number: Jid) -> Self {
        Self::new(phone_number)
    }

    pub fn from_lid_and_phone(lid: Jid, phone_number: Jid) -> Self {
        Self::new(lid).with_phone_number(phone_number)
    }

    pub fn with_phone_number(mut self, phone_number: Jid) -> Self {
        self.phone_number = Some(phone_number);
        self
    }

    pub fn with_privacy(mut self, privacy: Vec<u8>) -> Self {
        self.privacy = Some(privacy);
        self
    }
}

/// Options for creating a new group.
#[derive(Debug, Clone, TypedBuilder)]
#[builder(build_method(into))]
pub struct GroupCreateOptions {
    #[builder(setter(into))]
    pub subject: String,
    #[builder(default)]
    pub participants: Vec<GroupParticipantOptions>,
    #[builder(default = Some(MemberLinkMode::AdminLink), setter(strip_option))]
    pub member_link_mode: Option<MemberLinkMode>,
    #[builder(default = Some(MemberAddMode::AllMemberAdd), setter(strip_option))]
    pub member_add_mode: Option<MemberAddMode>,
    #[builder(default = Some(MembershipApprovalMode::Off), setter(strip_option))]
    pub membership_approval_mode: Option<MembershipApprovalMode>,
    #[builder(default = Some(0), setter(strip_option))]
    pub ephemeral_expiration: Option<u32>,
    /// Create as a community (parent group). Emits `<parent/>` in the create stanza.
    #[builder(default)]
    pub is_parent: bool,
    /// Whether the community is closed (requires approval to join).
    /// Only used when `is_parent` is true.
    #[builder(default)]
    pub closed: bool,
    /// Allow non-admin members to create subgroups.
    /// Only used when `is_parent` is true.
    #[builder(default)]
    pub allow_non_admin_sub_group_creation: bool,
    /// Create a general chat subgroup alongside the community.
    /// Only used when `is_parent` is true.
    #[builder(default)]
    pub create_general_chat: bool,
}

impl GroupCreateOptions {
    /// Create new options with just a subject (for backwards compatibility).
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            ..Default::default()
        }
    }

    pub fn with_participant(mut self, participant: GroupParticipantOptions) -> Self {
        self.participants.push(participant);
        self
    }

    pub fn with_participants(mut self, participants: Vec<GroupParticipantOptions>) -> Self {
        self.participants = participants;
        self
    }

    pub fn with_member_link_mode(mut self, mode: MemberLinkMode) -> Self {
        self.member_link_mode = Some(mode);
        self
    }

    pub fn with_member_add_mode(mut self, mode: MemberAddMode) -> Self {
        self.member_add_mode = Some(mode);
        self
    }

    pub fn with_membership_approval_mode(mut self, mode: MembershipApprovalMode) -> Self {
        self.membership_approval_mode = Some(mode);
        self
    }

    pub fn with_ephemeral_expiration(mut self, expiration: u32) -> Self {
        self.ephemeral_expiration = Some(expiration);
        self
    }
}

impl Default for GroupCreateOptions {
    fn default() -> Self {
        Self {
            subject: String::new(),
            participants: Vec::new(),
            member_link_mode: Some(MemberLinkMode::AdminLink),
            member_add_mode: Some(MemberAddMode::AllMemberAdd),
            membership_approval_mode: Some(MembershipApprovalMode::Off),
            ephemeral_expiration: Some(0),
            is_parent: false,
            closed: false,
            allow_non_admin_sub_group_creation: false,
            create_general_chat: false,
        }
    }
}

/// Normalize participants: drop phone_number for non-LID JIDs.
pub fn normalize_participants(
    participants: &[GroupParticipantOptions],
) -> Vec<GroupParticipantOptions> {
    participants
        .iter()
        .cloned()
        .map(|p| {
            if !p.jid.is_lid() && p.phone_number.is_some() {
                GroupParticipantOptions {
                    phone_number: None,
                    ..p
                }
            } else {
                p
            }
        })
        .collect()
}

/// Build the `<create>` node for group creation.
pub fn build_create_group_node(options: &GroupCreateOptions) -> Node {
    let mut children = Vec::new();

    if let Some(link_mode) = &options.member_link_mode {
        children.push(
            NodeBuilder::new("member_link_mode")
                .string_content(link_mode.as_str())
                .build(),
        );
    }

    if let Some(add_mode) = &options.member_add_mode {
        children.push(
            NodeBuilder::new("member_add_mode")
                .string_content(add_mode.as_str())
                .build(),
        );
    }

    // Normalize participants to avoid sending phone_number for non-LID JIDs
    let participants = normalize_participants(&options.participants);

    for participant in &participants {
        let mut attrs = vec![("jid", participant.jid.to_string())];
        if let Some(pn) = &participant.phone_number {
            attrs.push(("phone_number", pn.to_string()));
        }

        let participant_node = if let Some(privacy_bytes) = &participant.privacy {
            NodeBuilder::new("participant")
                .attrs(attrs)
                .children([NodeBuilder::new("privacy")
                    .string_content(hex::encode(privacy_bytes))
                    .build()])
                .build()
        } else {
            NodeBuilder::new("participant").attrs(attrs).build()
        };
        children.push(participant_node);
    }

    if let Some(expiration) = &options.ephemeral_expiration {
        children.push(
            NodeBuilder::new("ephemeral")
                .attr("expiration", expiration.to_string())
                .build(),
        );
    }

    if let Some(approval_mode) = &options.membership_approval_mode {
        children.push(
            NodeBuilder::new("membership_approval_mode")
                .children([NodeBuilder::new("group_join")
                    .attr("state", approval_mode.as_str())
                    .build()])
                .build(),
        );
    }

    // Community (parent group) fields
    if options.is_parent {
        let mut parent_builder = NodeBuilder::new("parent");
        if options.closed {
            parent_builder =
                parent_builder.attr("default_membership_approval_mode", "request_required");
        }
        children.push(parent_builder.build());

        if options.allow_non_admin_sub_group_creation {
            children.push(NodeBuilder::new("allow_non_admin_sub_group_creation").build());
        }
        if options.create_general_chat {
            children.push(NodeBuilder::new("create_general_chat").build());
        }
    }

    NodeBuilder::new("create")
        .attr("subject", &options.subject)
        .children(children)
        .build()
}
/// Request to query group information.
///
/// Wire format: `<query request="interactive"/>`
#[derive(Debug, Clone, crate::ProtocolNode)]
#[protocol(tag = "query")]
pub struct GroupQueryRequest {
    #[attr(name = "request", string_enum)]
    pub request: GroupQueryRequestType,
}

/// A participant in a group response.
#[derive(Debug, Clone)]
pub struct GroupParticipantResponse {
    pub jid: Jid,
    pub phone_number: Option<Jid>,
    pub participant_type: ParticipantType,
}

impl ProtocolNode for GroupParticipantResponse {
    fn tag(&self) -> &'static str {
        "participant"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("participant").attr("jid", self.jid);
        if let Some(pn) = self.phone_number {
            builder = builder.attr("phone_number", pn);
        }
        if self.participant_type != ParticipantType::Member {
            builder = builder.attr("type", self.participant_type.as_str());
        }
        builder.build()
    }

    fn try_from_node_ref(node: &NodeRef<'_>) -> Result<Self> {
        if node.tag != "participant" {
            return Err(anyhow!("expected <participant>, got <{}>", node.tag));
        }
        let mut attrs = node.attrs();
        let jid = attrs
            .optional_jid("jid")
            .ok_or_else(|| anyhow!("participant missing required 'jid' attribute"))?;
        let phone_number = attrs.optional_jid("phone_number");
        let participant_type = attrs
            .optional_string("type")
            .and_then(|s| ParticipantType::try_from(s.as_ref()).ok())
            .unwrap_or(ParticipantType::Member);

        Ok(Self {
            jid,
            phone_number,
            participant_type,
        })
    }
}

/// Response from a group info query.
#[derive(Debug, Clone)]
pub struct GroupInfoResponse {
    pub id: Jid,
    pub subject: GroupSubject,
    pub addressing_mode: AddressingMode,
    pub participants: Vec<GroupParticipantResponse>,
    /// Group creator JID (from `creator` attribute).
    pub creator: Option<Jid>,
    /// Group creation timestamp (from `creation` attribute).
    pub creation_time: Option<u64>,
    /// Subject modification timestamp (from `s_t` attribute).
    pub subject_time: Option<u64>,
    /// Subject owner JID (from `s_o` attribute).
    pub subject_owner: Option<Jid>,
    /// Group description body text.
    pub description: Option<String>,
    /// Description ID (for conflict detection when updating).
    pub description_id: Option<String>,
    /// JID of the participant who set the description.
    pub description_owner: Option<Jid>,
    /// Timestamp when the description was set.
    pub description_time: Option<u64>,
    /// Whether the group is locked (only admins can edit group info).
    pub is_locked: bool,
    /// Whether announcement mode is enabled (only admins can send messages).
    pub is_announcement: bool,
    /// Ephemeral message expiration in seconds (0 = disabled).
    pub ephemeral_expiration: u32,
    /// Disappearing mode trigger (0-20 range, from `trigger` attribute on `<ephemeral>`).
    pub ephemeral_trigger: Option<u32>,
    /// Whether membership approval is required to join.
    pub membership_approval: bool,
    /// Who can add members to the group.
    pub member_add_mode: Option<MemberAddMode>,
    /// Who can use invite links.
    pub member_link_mode: Option<MemberLinkMode>,
    /// Total participant count (from `size` attribute, useful for large groups).
    pub size: Option<u32>,
    /// Whether this group is a community parent group (has `<parent>` child).
    pub is_parent_group: bool,
    /// JID of the parent community (for subgroups, from `<linked_parent jid="..."/>`).
    pub parent_group_jid: Option<Jid>,
    /// Whether this is the default announcement subgroup of a community.
    pub is_default_sub_group: bool,
    /// Whether this is the general chat subgroup of a community.
    pub is_general_chat: bool,
    /// Whether non-admin community members can create subgroups.
    pub allow_non_admin_sub_group_creation: bool,
    /// Whether frequently-forwarded messages are restricted.
    pub no_frequently_forwarded: bool,
    /// Who can share message history with new members.
    pub member_share_history_mode: Option<MemberShareHistoryMode>,
    /// Growth lock status (invite links temporarily disabled).
    pub growth_locked: Option<GrowthLockInfo>,
    /// Whether the group is suspended.
    pub is_suspended: bool,
    /// Whether admin reports are allowed.
    pub allow_admin_reports: bool,
    /// Whether the group is hidden.
    pub is_hidden_group: bool,
    /// Whether incognito mode is enabled.
    pub is_incognito: bool,
    /// Whether group history is enabled.
    pub has_group_history: bool,
    /// Whether limit sharing is enabled.
    pub is_limit_sharing_enabled: bool,
}

impl ProtocolNode for GroupInfoResponse {
    fn tag(&self) -> &'static str {
        "group"
    }

    fn into_node(self) -> Node {
        let mut children: Vec<Node> = self
            .participants
            .into_iter()
            .map(|p| p.into_node())
            .collect();

        if self.is_locked {
            children.push(NodeBuilder::new("locked").build());
        }
        if self.is_announcement {
            children.push(NodeBuilder::new("announcement").build());
        }
        if self.ephemeral_expiration > 0 || self.ephemeral_trigger.is_some() {
            let mut eph = NodeBuilder::new("ephemeral")
                .attr("expiration", self.ephemeral_expiration.to_string());
            if let Some(trigger) = self.ephemeral_trigger {
                eph = eph.attr("trigger", trigger.to_string());
            }
            children.push(eph.build());
        }
        if self.membership_approval {
            children.push(
                NodeBuilder::new("membership_approval_mode")
                    .children(vec![
                        NodeBuilder::new("group_join").attr("state", "on").build(),
                    ])
                    .build(),
            );
        }
        if let Some(ref add_mode) = self.member_add_mode {
            children.push(
                NodeBuilder::new("member_add_mode")
                    .string_content(add_mode.as_str())
                    .build(),
            );
        }
        if let Some(ref link_mode) = self.member_link_mode {
            children.push(
                NodeBuilder::new("member_link_mode")
                    .string_content(link_mode.as_str())
                    .build(),
            );
        }
        if self.description.is_some()
            || self.description_id.is_some()
            || self.description_owner.is_some()
            || self.description_time.is_some()
        {
            let mut desc_builder = NodeBuilder::new("description");
            if let Some(ref desc_id) = self.description_id {
                desc_builder = desc_builder.attr("id", desc_id.as_str());
            }
            if let Some(ref owner) = self.description_owner {
                desc_builder = desc_builder.attr("participant", owner);
            }
            if let Some(t) = self.description_time {
                desc_builder = desc_builder.attr("t", t.to_string());
            }
            if let Some(ref desc) = self.description {
                desc_builder = desc_builder.children([NodeBuilder::new("body")
                    .string_content(desc.as_str())
                    .build()]);
            }
            children.push(desc_builder.build());
        }

        // Community fields
        if self.is_parent_group {
            children.push(NodeBuilder::new("parent").build());
        }
        if let Some(ref parent_jid) = self.parent_group_jid {
            children.push(
                NodeBuilder::new("linked_parent")
                    .attr("jid", parent_jid)
                    .build(),
            );
        }
        if self.is_default_sub_group {
            children.push(NodeBuilder::new("default_sub_group").build());
        }
        if self.is_general_chat {
            children.push(NodeBuilder::new("general_chat").build());
        }
        if self.allow_non_admin_sub_group_creation {
            children.push(NodeBuilder::new("allow_non_admin_sub_group_creation").build());
        }
        if self.no_frequently_forwarded {
            children.push(NodeBuilder::new("no_frequently_forwarded").build());
        }
        if let Some(ref mode) = self.member_share_history_mode {
            children.push(
                NodeBuilder::new("member_share_group_history_mode")
                    .string_content(mode.as_str())
                    .build(),
            );
        }
        if let Some(ref gl) = self.growth_locked {
            children.push(
                NodeBuilder::new("growth_locked")
                    .attr("type", &gl.lock_type)
                    .attr("expiration", gl.expiration.to_string())
                    .build(),
            );
        }
        if self.is_suspended {
            children.push(NodeBuilder::new("suspended").build());
        }
        if self.allow_admin_reports {
            children.push(NodeBuilder::new("allow_admin_reports").build());
        }
        if self.is_hidden_group {
            children.push(NodeBuilder::new("hidden_group").build());
        }
        if self.is_incognito {
            children.push(NodeBuilder::new("incognito").build());
        }
        if self.has_group_history {
            children.push(NodeBuilder::new("group_history").build());
        }
        if self.is_limit_sharing_enabled {
            children.push(NodeBuilder::new("limit_sharing_enabled").build());
        }

        let mut builder = NodeBuilder::new("group")
            .attr("id", self.id)
            .attr("subject", self.subject.as_str())
            .attr("addressing_mode", self.addressing_mode.as_str());

        if let Some(creator) = self.creator {
            builder = builder.attr("creator", creator);
        }
        if let Some(creation_time) = self.creation_time {
            builder = builder.attr("creation", creation_time.to_string());
        }
        if let Some(subject_time) = self.subject_time {
            builder = builder.attr("s_t", subject_time.to_string());
        }
        if let Some(subject_owner) = self.subject_owner {
            builder = builder.attr("s_o", subject_owner);
        }
        if let Some(size) = self.size {
            builder = builder.attr("size", size.to_string());
        }

        builder.children(children).build()
    }

    fn try_from_node_ref(node: &NodeRef<'_>) -> Result<Self> {
        use wacore_binary::NodeContentRef;
        if node.tag != "group" {
            return Err(anyhow!("expected <group>, got <{}>", node.tag));
        }

        let mut attrs = node.attrs();
        let id_str = attrs
            .optional_string("id")
            .ok_or_else(|| anyhow!("missing required attribute id"))?;
        let id = if id_str.contains('@') {
            id_str.parse()?
        } else {
            Jid::group(id_str.as_ref())
        };

        let subject = GroupSubject::new_unchecked(
            attrs
                .optional_string("subject")
                .as_deref()
                .unwrap_or_default(),
        );

        let addressing_mode = AddressingMode::try_from(
            attrs
                .optional_string("addressing_mode")
                .as_deref()
                .unwrap_or("pn"),
        )?;

        let creator = attrs.optional_jid("creator");
        let creation_time = attrs.optional_u64("creation");
        let subject_time = attrs.optional_u64("s_t");
        let subject_owner = attrs.optional_jid("s_o");
        let size = attrs
            .optional_string("size")
            .and_then(|s| s.parse::<u32>().ok());

        let participants = collect_children::<GroupParticipantResponse>(node, "participant")?;

        let is_locked = node.get_optional_child_by_tag(&["locked"]).is_some();
        let is_announcement = node.get_optional_child_by_tag(&["announcement"]).is_some();

        let ephemeral_node = node.get_optional_child_by_tag(&["ephemeral"]);
        let ephemeral_expiration = ephemeral_node
            .and_then(|n| n.attrs().optional_string("expiration"))
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0);
        let ephemeral_trigger = ephemeral_node
            .and_then(|n| n.attrs().optional_string("trigger"))
            .and_then(|s| s.parse::<u32>().ok());

        let membership_approval = node
            .get_optional_child_by_tag(&["membership_approval_mode", "group_join"])
            .and_then(|n| n.attrs().optional_string("state"))
            .is_some_and(|s| s == "on");

        let member_add_mode = node
            .get_optional_child_by_tag(&["member_add_mode"])
            .and_then(|n| match n.content.as_deref() {
                Some(NodeContentRef::String(s)) => MemberAddMode::try_from(s.as_ref()).ok(),
                _ => None,
            });

        let member_link_mode = node
            .get_optional_child_by_tag(&["member_link_mode"])
            .and_then(|n| match n.content.as_deref() {
                Some(NodeContentRef::String(s)) => MemberLinkMode::try_from(s.as_ref()).ok(),
                _ => None,
            });

        let description_node = node.get_optional_child_by_tag(&["description"]);
        let description = description_node
            .and_then(|n| n.get_optional_child("body"))
            .and_then(|body| body.content_as_string())
            .map(|s| s.to_string());
        let description_id = description_node
            .and_then(|n| n.attrs().optional_string("id"))
            .map(|s| s.to_string());
        let description_owner =
            description_node.and_then(|n| n.attrs().optional_jid("participant"));
        let description_time = description_node
            .and_then(|n| n.attrs().optional_string("t"))
            .and_then(|s| s.parse::<u64>().ok());

        let is_parent_group = node.get_optional_child_by_tag(&["parent"]).is_some();
        let parent_group_jid = node
            .get_optional_child_by_tag(&["linked_parent"])
            .and_then(|n| n.attrs().optional_jid("jid"));
        let is_default_sub_group = node
            .get_optional_child_by_tag(&["default_sub_group"])
            .is_some();
        let is_general_chat = node.get_optional_child_by_tag(&["general_chat"]).is_some();
        let allow_non_admin_sub_group_creation = node
            .get_optional_child_by_tag(&["allow_non_admin_sub_group_creation"])
            .is_some();

        let no_frequently_forwarded = node
            .get_optional_child_by_tag(&["no_frequently_forwarded"])
            .is_some();

        let member_share_history_mode = node
            .get_optional_child_by_tag(&["member_share_group_history_mode"])
            .and_then(|n| match n.content.as_deref() {
                Some(NodeContentRef::String(s)) => {
                    MemberShareHistoryMode::try_from(s.as_ref()).ok()
                }
                _ => None,
            });

        let growth_locked = node.get_optional_child_by_tag(&["growth_locked"]).map(|n| {
            let mut attrs = n.attrs();
            GrowthLockInfo {
                lock_type: attrs
                    .optional_string("type")
                    .unwrap_or_default()
                    .to_string(),
                expiration: attrs
                    .optional_string("expiration")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
            }
        });

        let is_suspended = node.get_optional_child_by_tag(&["suspended"]).is_some();
        let allow_admin_reports = node
            .get_optional_child_by_tag(&["allow_admin_reports"])
            .is_some();
        let is_hidden_group = node.get_optional_child_by_tag(&["hidden_group"]).is_some();
        let is_incognito = node.get_optional_child_by_tag(&["incognito"]).is_some();
        let has_group_history = node.get_optional_child_by_tag(&["group_history"]).is_some();
        let is_limit_sharing_enabled = node
            .get_optional_child_by_tag(&["limit_sharing_enabled"])
            .is_some();

        Ok(Self {
            id,
            subject,
            addressing_mode,
            participants,
            creator,
            creation_time,
            subject_time,
            subject_owner,
            description,
            description_id,
            description_owner,
            description_time,
            is_locked,
            is_announcement,
            ephemeral_expiration,
            ephemeral_trigger,
            membership_approval,
            member_add_mode,
            member_link_mode,
            size,
            is_parent_group,
            parent_group_jid,
            is_default_sub_group,
            is_general_chat,
            allow_non_admin_sub_group_creation,
            no_frequently_forwarded,
            member_share_history_mode,
            growth_locked,
            is_suspended,
            allow_admin_reports,
            is_hidden_group,
            is_incognito,
            has_group_history,
            is_limit_sharing_enabled,
        })
    }
}
/// Request to get all groups the user is participating in.
#[derive(Debug, Clone)]
pub struct GroupParticipatingRequest {
    pub include_participants: bool,
    pub include_description: bool,
}

impl GroupParticipatingRequest {
    pub fn new() -> Self {
        Self {
            include_participants: true,
            include_description: true,
        }
    }
}

impl Default for GroupParticipatingRequest {
    fn default() -> Self {
        Self::new()
    }
}

impl ProtocolNode for GroupParticipatingRequest {
    fn tag(&self) -> &'static str {
        "participating"
    }

    fn into_node(self) -> Node {
        let mut children = Vec::new();
        if self.include_participants {
            children.push(NodeBuilder::new("participants").build());
        }
        if self.include_description {
            children.push(NodeBuilder::new("description").build());
        }
        NodeBuilder::new("participating").children(children).build()
    }

    fn try_from_node_ref(node: &NodeRef<'_>) -> Result<Self> {
        if node.tag != "participating" {
            return Err(anyhow!("expected <participating>, got <{}>", node.tag));
        }
        Ok(Self {
            include_participants: node.get_optional_child("participants").is_some(),
            include_description: node.get_optional_child("description").is_some(),
        })
    }
}

/// Response containing all groups the user is participating in.
#[derive(Debug, Clone, Default)]
pub struct GroupParticipatingResponse {
    pub groups: Vec<GroupInfoResponse>,
}

impl ProtocolNode for GroupParticipatingResponse {
    fn tag(&self) -> &'static str {
        "groups"
    }

    fn into_node(self) -> Node {
        let children: Vec<Node> = self.groups.into_iter().map(|g| g.into_node()).collect();
        NodeBuilder::new("groups").children(children).build()
    }

    fn try_from_node_ref(node: &NodeRef<'_>) -> Result<Self> {
        if node.tag != "groups" {
            return Err(anyhow!("expected <groups>, got <{}>", node.tag));
        }

        let groups = collect_children::<GroupInfoResponse>(node, "group")?;

        Ok(Self { groups })
    }
}
/// IQ specification for querying a specific group's info.
#[derive(Debug, Clone)]
pub struct GroupQueryIq {
    pub group_jid: Jid,
}

impl GroupQueryIq {
    pub fn new(group_jid: &Jid) -> Self {
        Self {
            group_jid: group_jid.clone(),
        }
    }
}

impl IqSpec for GroupQueryIq {
    type Response = GroupInfoResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![
                GroupQueryRequest::default().into_node(),
            ])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let group_node = required_child(response, "group")?;
        GroupInfoResponse::try_from_node_ref(group_node)
    }
}

/// IQ specification for getting all groups the user is participating in.
#[derive(Debug, Clone, Default)]
pub struct GroupParticipatingIq;

impl GroupParticipatingIq {
    pub fn new() -> Self {
        Self
    }
}

impl IqSpec for GroupParticipatingIq {
    type Response = GroupParticipatingResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get(
            GROUP_IQ_NAMESPACE,
            Jid::new("", Server::Group),
            Some(NodeContent::Nodes(vec![
                GroupParticipatingRequest::new().into_node(),
            ])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let groups_node = required_child(response, "groups")?;
        GroupParticipatingResponse::try_from_node_ref(groups_node)
    }
}

/// IQ specification for creating a new group.
#[derive(Debug, Clone)]
pub struct GroupCreateIq {
    pub options: GroupCreateOptions,
}

impl GroupCreateIq {
    pub fn new(options: GroupCreateOptions) -> Self {
        Self { options }
    }
}

impl IqSpec for GroupCreateIq {
    type Response = Jid;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set(
            GROUP_IQ_NAMESPACE,
            Jid::new("", Server::Group),
            Some(NodeContent::Nodes(vec![build_create_group_node(
                &self.options,
            )])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let group_node = required_child(response, "group")?;
        let group_id_str = required_attr(group_node, "id")?;

        if group_id_str.contains('@') {
            group_id_str.parse().map_err(Into::into)
        } else {
            Ok(Jid::group(group_id_str))
        }
    }
}

// ---------------------------------------------------------------------------
// Group Management IQ Specs
// ---------------------------------------------------------------------------

/// Response for participant change operations.
///
/// Success is signaled by absent `error`; `type` is often omitted by the server.
#[derive(Debug, Clone, crate::ProtocolNode)]
#[protocol(tag = "participant")]
pub struct ParticipantChangeResponse {
    #[attr(name = "jid", jid)]
    pub jid: Jid,
    #[attr(name = "type")]
    pub status: Option<String>,
    #[attr(name = "error")]
    pub error: Option<String>,
    #[attr(name = "phone_number", jid)]
    pub phone_number: Option<Jid>,
    #[attr(name = "username")]
    pub username: Option<String>,
}

impl ParticipantChangeResponse {
    pub fn is_ok(&self) -> bool {
        self.error.is_none()
    }
}

/// IQ specification for setting a group's subject.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <subject>{text}</subject>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct SetGroupSubjectIq {
    pub group_jid: Jid,
    pub subject: GroupSubject,
}

impl SetGroupSubjectIq {
    pub fn new(group_jid: &Jid, subject: GroupSubject) -> Self {
        Self {
            group_jid: group_jid.clone(),
            subject,
        }
    }
}

impl IqSpec for SetGroupSubjectIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("subject")
                    .string_content(self.subject.as_str())
                    .build(),
            ])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

/// IQ specification for setting a group's description.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <description id="{new_id}" prev="{prev_id}"><body>{text}</body></description>
/// </iq>
/// ```
///
/// - `id`: random 8-char hex, generated automatically.
/// - `prev`: the current description ID (from group metadata), used for conflict detection.
/// - To delete the description, pass `None` as the description.
#[derive(Debug, Clone)]
pub struct SetGroupDescriptionIq {
    pub group_jid: Jid,
    pub description: Option<GroupDescription>,
    /// New description ID (random 8-char hex).
    pub id: String,
    /// Previous description ID from group metadata, for conflict detection.
    pub prev: Option<String>,
}

impl SetGroupDescriptionIq {
    pub fn new(
        group_jid: &Jid,
        description: Option<GroupDescription>,
        prev: Option<String>,
    ) -> Self {
        use rand::RngExt;
        let id = format!(
            "{:08X}",
            rand::make_rng::<rand::rngs::StdRng>().random::<u32>()
        );
        Self {
            group_jid: group_jid.clone(),
            description,
            id,
            prev,
        }
    }
}

impl IqSpec for SetGroupDescriptionIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let desc_node = if let Some(ref desc) = self.description {
            let mut builder = NodeBuilder::new("description").attr("id", &self.id);
            if let Some(ref prev) = self.prev {
                builder = builder.attr("prev", prev);
            }
            builder
                .children([NodeBuilder::new("body")
                    .string_content(desc.as_str())
                    .build()])
                .build()
        } else {
            let mut builder = NodeBuilder::new("description")
                .attr("id", &self.id)
                .attr("delete", "true");
            if let Some(ref prev) = self.prev {
                builder = builder.attr("prev", prev);
            }
            builder.build()
        };

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![desc_node])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

/// IQ specification for leaving a group.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="g.us">
///   <leave><group id="{group_jid}"/></leave>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct LeaveGroupIq {
    pub group_jid: Jid,
}

impl LeaveGroupIq {
    pub fn new(group_jid: &Jid) -> Self {
        Self {
            group_jid: group_jid.clone(),
        }
    }
}

impl IqSpec for LeaveGroupIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let group_node = NodeBuilder::new("group")
            .attr("id", &self.group_jid)
            .build();
        let leave_node = NodeBuilder::new("leave").children([group_node]).build();

        InfoQuery::set(
            GROUP_IQ_NAMESPACE,
            Jid::new("", Server::Group),
            Some(NodeContent::Nodes(vec![leave_node])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

/// Macro to generate group participant IQ specs that share the same structure:
/// a `set` IQ to `{group_jid}` with `<{action}><participant jid="..."/>...</{action}>`.
macro_rules! define_group_participant_iq {
    (
        $(#[$meta:meta])*
        $name:ident, action = $action:literal, response = Vec<ParticipantChangeResponse>
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name {
            pub group_jid: Jid,
            pub participants: Vec<Jid>,
        }

        impl $name {
            pub fn new(group_jid: &Jid, participants: &[Jid]) -> Self {
                Self {
                    group_jid: group_jid.clone(),
                    participants: participants.to_vec(),
                }
            }
        }

        impl IqSpec for $name {
            type Response = Vec<ParticipantChangeResponse>;

            fn build_iq(&self) -> InfoQuery<'static> {
                let children: Vec<Node> = self
                    .participants
                    .iter()
                    .map(|jid| {
                        NodeBuilder::new("participant")
                            .attr("jid", jid)
                            .build()
                    })
                    .collect();

                let action_node = NodeBuilder::new($action).children(children).build();

                InfoQuery::set_ref(
                    GROUP_IQ_NAMESPACE,
                    &self.group_jid,
                    Some(NodeContent::Nodes(vec![action_node])),
                )
            }

            fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
                let action_node = required_child(response, $action)?;
                collect_children::<ParticipantChangeResponse>(action_node, "participant")
            }
        }
    };
    (
        $(#[$meta:meta])*
        $name:ident, action = $action:literal, response = ()
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name {
            pub group_jid: Jid,
            pub participants: Vec<Jid>,
        }

        impl $name {
            pub fn new(group_jid: &Jid, participants: &[Jid]) -> Self {
                Self {
                    group_jid: group_jid.clone(),
                    participants: participants.to_vec(),
                }
            }
        }

        impl IqSpec for $name {
            type Response = ();

            fn build_iq(&self) -> InfoQuery<'static> {
                let children: Vec<Node> = self
                    .participants
                    .iter()
                    .map(|jid| {
                        NodeBuilder::new("participant")
                            .attr("jid", jid)
                            .build()
                    })
                    .collect();

                let action_node = NodeBuilder::new($action).children(children).build();

                InfoQuery::set_ref(
                    GROUP_IQ_NAMESPACE,
                    &self.group_jid,
                    Some(NodeContent::Nodes(vec![action_node])),
                )
            }

            fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
                Ok(())
            }
        }
    };
}

/// IQ specification for adding participants to a group, with optional
/// per-participant privacy tokens.
#[derive(Debug, Clone)]
pub struct AddParticipantsIq {
    pub group_jid: Jid,
    pub participants: Vec<GroupParticipantOptions>,
}

impl AddParticipantsIq {
    /// Create from plain JIDs (no privacy tokens). Backwards compatible.
    pub fn new(group_jid: &Jid, participants: &[Jid]) -> Self {
        Self {
            group_jid: group_jid.clone(),
            participants: participants
                .iter()
                .map(|jid| GroupParticipantOptions::new(jid.clone()))
                .collect(),
        }
    }

    /// Create with full participant options (JID + optional phone_number + optional privacy token).
    pub fn with_options(group_jid: &Jid, participants: Vec<GroupParticipantOptions>) -> Self {
        Self {
            group_jid: group_jid.clone(),
            participants,
        }
    }
}

impl IqSpec for AddParticipantsIq {
    type Response = Vec<ParticipantChangeResponse>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let children: Vec<Node> = self
            .participants
            .iter()
            .map(|p| {
                let mut attrs = vec![("jid", p.jid.to_string())];
                // phone_number is only meaningful for LID JIDs
                if p.jid.is_lid()
                    && let Some(pn) = &p.phone_number
                {
                    attrs.push(("phone_number", pn.to_string()));
                }
                if let Some(privacy_bytes) = &p.privacy {
                    NodeBuilder::new("participant")
                        .attrs(attrs)
                        .children([NodeBuilder::new("privacy")
                            .string_content(hex::encode(privacy_bytes))
                            .build()])
                        .build()
                } else {
                    NodeBuilder::new("participant").attrs(attrs).build()
                }
            })
            .collect();

        let action_node = NodeBuilder::new("add").children(children).build();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![action_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let action_node = required_child(response, "add")?;
        collect_children::<ParticipantChangeResponse>(action_node, "participant")
    }
}

define_group_participant_iq!(
    /// IQ specification for removing participants from a group.
    ///
    /// Wire format:
    /// ```xml
    /// <iq type="set" xmlns="w:g2" to="{group_jid}">
    ///   <remove><participant jid="{user_jid}"/></remove>
    /// </iq>
    /// ```
    RemoveParticipantsIq, action = "remove", response = Vec<ParticipantChangeResponse>
);

define_group_participant_iq!(
    /// IQ specification for promoting participants to admin.
    ///
    /// Wire format:
    /// ```xml
    /// <iq type="set" xmlns="w:g2" to="{group_jid}">
    ///   <promote><participant jid="{user_jid}"/></promote>
    /// </iq>
    /// ```
    PromoteParticipantsIq, action = "promote", response = ()
);

define_group_participant_iq!(
    /// IQ specification for demoting participants from admin.
    ///
    /// Wire format:
    /// ```xml
    /// <iq type="set" xmlns="w:g2" to="{group_jid}">
    ///   <demote><participant jid="{user_jid}"/></demote>
    /// </iq>
    /// ```
    DemoteParticipantsIq, action = "demote", response = ()
);

/// IQ specification for getting (or resetting) a group's invite link.
///
/// - `reset: false` (GET) fetches the existing link.
/// - `reset: true` (SET) revokes the old link and generates a new one.
///
/// Response: `<invite code="XXXX"/>`
#[derive(Debug, Clone)]
pub struct GetGroupInviteLinkIq {
    pub group_jid: Jid,
    pub reset: bool,
}

impl GetGroupInviteLinkIq {
    pub fn new(group_jid: &Jid, reset: bool) -> Self {
        Self {
            group_jid: group_jid.clone(),
            reset,
        }
    }
}

impl IqSpec for GetGroupInviteLinkIq {
    type Response = String;

    fn build_iq(&self) -> InfoQuery<'static> {
        let content = Some(NodeContent::Nodes(vec![NodeBuilder::new("invite").build()]));
        if self.reset {
            InfoQuery::set_ref(GROUP_IQ_NAMESPACE, &self.group_jid, content)
        } else {
            InfoQuery::get_ref(GROUP_IQ_NAMESPACE, &self.group_jid, content)
        }
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let invite_node = required_child(response, "invite")?;
        let code = required_attr(invite_node, "code")?;
        Ok(format!("https://chat.whatsapp.com/{code}"))
    }
}

// ---------------------------------------------------------------------------
// Group property setters (SetProperty RPC)
// ---------------------------------------------------------------------------

/// IQ specification for locking or unlocking a group (only admins can change group info).
///
/// Wire format:
///  - Lock group:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <locked/>
/// </iq>
/// ```
///  - Unlock group:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <unlocked/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct SetGroupLockedIq {
    pub group_jid: Jid,
    pub locked: bool,
}

impl SetGroupLockedIq {
    pub fn lock(group_jid: &Jid) -> Self {
        Self {
            group_jid: group_jid.clone(),
            locked: true,
        }
    }

    pub fn unlock(group_jid: &Jid) -> Self {
        Self {
            group_jid: group_jid.clone(),
            locked: false,
        }
    }
}

impl IqSpec for SetGroupLockedIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let tag = if self.locked { "locked" } else { "unlocked" };
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![NodeBuilder::new(tag).build()])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

/// IQ specification for setting announcement mode (only admins can send messages).
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <announcement/>
///   <!-- or -->
///   <not_announcement/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct SetGroupAnnouncementIq {
    pub group_jid: Jid,
    pub announce: bool,
}

impl SetGroupAnnouncementIq {
    pub fn announce(group_jid: &Jid) -> Self {
        Self {
            group_jid: group_jid.clone(),
            announce: true,
        }
    }

    pub fn unannounce(group_jid: &Jid) -> Self {
        Self {
            group_jid: group_jid.clone(),
            announce: false,
        }
    }
}

impl IqSpec for SetGroupAnnouncementIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let tag = if self.announce {
            "announcement"
        } else {
            "not_announcement"
        };
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![NodeBuilder::new(tag).build()])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

/// IQ specification for setting ephemeral (disappearing) messages on a group.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <ephemeral expiration="86400"/>
///   <!-- or to disable: -->
///   <not_ephemeral/>
/// </iq>
/// ```
///
/// Common expiration values (seconds):
/// - 86400 (24 hours)
/// - 604800 (7 days)
/// - 7776000 (90 days)
/// - 0 or `not_ephemeral` to disable
#[derive(Debug, Clone)]
pub struct SetGroupEphemeralIq {
    pub group_jid: Jid,
    /// Expiration in seconds. `None` means disable.
    pub expiration: Option<NonZeroU32>,
}

impl SetGroupEphemeralIq {
    /// Enable ephemeral messages with the given expiration in seconds.
    pub fn enable(group_jid: &Jid, expiration: NonZeroU32) -> Self {
        Self {
            group_jid: group_jid.clone(),
            expiration: Some(expiration),
        }
    }

    /// Disable ephemeral messages.
    pub fn disable(group_jid: &Jid) -> Self {
        Self {
            group_jid: group_jid.clone(),
            expiration: None,
        }
    }
}

impl IqSpec for SetGroupEphemeralIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let node = match self.expiration {
            Some(exp) => NodeBuilder::new("ephemeral")
                .attr("expiration", exp.to_string())
                .build(),
            None => NodeBuilder::new("not_ephemeral").build(),
        };
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![node])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

/// IQ specification for setting the membership approval mode on a group.
///
/// When enabled, new members must be approved by an admin before joining.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <membership_approval_mode>
///     <group_join state="on"/>
///   </membership_approval_mode>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct SetGroupMembershipApprovalIq {
    pub group_jid: Jid,
    pub mode: MembershipApprovalMode,
}

impl SetGroupMembershipApprovalIq {
    pub fn new(group_jid: &Jid, mode: MembershipApprovalMode) -> Self {
        Self {
            group_jid: group_jid.clone(),
            mode,
        }
    }
}

impl IqSpec for SetGroupMembershipApprovalIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let node = NodeBuilder::new("membership_approval_mode")
            .children([NodeBuilder::new("group_join")
                .attr("state", self.mode.as_str())
                .build()])
            .build();
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![node])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

/// Macro for boolean group property toggle IQs (on_tag / off_tag pattern).
macro_rules! define_group_property_toggle_iq {
    (
        $(#[$meta:meta])*
        $name:ident, on_tag = $on:literal, off_tag = $off:literal
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone)]
        pub struct $name {
            pub group_jid: Jid,
            pub enabled: bool,
        }

        impl $name {
            pub fn new(group_jid: &Jid, enabled: bool) -> Self {
                Self {
                    group_jid: group_jid.clone(),
                    enabled,
                }
            }
        }

        impl IqSpec for $name {
            type Response = ();

            fn build_iq(&self) -> InfoQuery<'static> {
                let tag = if self.enabled { $on } else { $off };
                InfoQuery::set_ref(
                    GROUP_IQ_NAMESPACE,
                    &self.group_jid,
                    Some(NodeContent::Nodes(vec![NodeBuilder::new(tag).build()])),
                )
            }

            fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
                Ok(())
            }
        }
    };
}

define_group_property_toggle_iq!(
    /// Set whether frequently-forwarded messages are restricted in the group.
    SetNoFrequentlyForwardedIq,
    on_tag = "no_frequently_forwarded",
    off_tag = "frequently_forwarded_ok"
);

define_group_property_toggle_iq!(
    /// Set whether admin reports are allowed in the group.
    SetAllowAdminReportsIq,
    on_tag = "allow_admin_reports",
    off_tag = "not_allow_admin_reports"
);

define_group_property_toggle_iq!(
    /// Enable or disable group history sharing.
    SetGroupHistoryIq,
    on_tag = "group_history",
    off_tag = "no_group_history"
);

// ---------------------------------------------------------------------------
// Community IQ Specs
// ---------------------------------------------------------------------------

/// Response for a single group in a link/unlink operation.
#[derive(Debug, Clone)]
pub struct LinkedGroupResult {
    pub jid: Jid,
    /// Error code if the operation failed for this group (e.g. 406 = community full).
    pub error: Option<u32>,
}

/// Response from linking subgroups to a community.
#[derive(Debug, Clone)]
pub struct LinkSubgroupsResponse {
    pub groups: Vec<LinkedGroupResult>,
}

/// Response from unlinking subgroups from a community.
#[derive(Debug, Clone)]
pub struct UnlinkSubgroupsResponse {
    pub groups: Vec<LinkedGroupResult>,
}

/// IQ specification for linking subgroups to a community parent group.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{parent_jid}">
///   <links>
///     <link link_type="sub_group">
///       <group jid="{subgroup_jid}"/>
///     </link>
///   </links>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct LinkSubgroupsIq {
    pub parent_jid: Jid,
    pub subgroup_jids: Vec<Jid>,
}

impl LinkSubgroupsIq {
    pub fn new(parent_jid: &Jid, subgroup_jids: &[Jid]) -> Self {
        Self {
            parent_jid: parent_jid.clone(),
            subgroup_jids: subgroup_jids.to_vec(),
        }
    }
}

impl IqSpec for LinkSubgroupsIq {
    type Response = LinkSubgroupsResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let group_nodes: Vec<Node> = self
            .subgroup_jids
            .iter()
            .map(|jid| NodeBuilder::new("group").attr("jid", jid).build())
            .collect();

        let link_node = NodeBuilder::new("link")
            .attr("link_type", "sub_group")
            .children(group_nodes)
            .build();

        let links_node = NodeBuilder::new("links").children([link_node]).build();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.parent_jid,
            Some(NodeContent::Nodes(vec![links_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let links_node = required_child(response, "links")?;
        let link_node = required_child(links_node, "link")?;

        let mut groups = Vec::new();
        for child in link_node.get_children_by_tag("group") {
            let jid_str = required_attr(child, "jid")?;
            let jid: Jid = jid_str.parse()?;
            let error = child
                .attrs()
                .optional_string("error")
                .and_then(|s| s.parse::<u32>().ok());
            groups.push(LinkedGroupResult { jid, error });
        }

        Ok(LinkSubgroupsResponse { groups })
    }
}

/// IQ specification for unlinking subgroups from a community parent group.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{parent_jid}">
///   <unlink unlink_type="sub_group">
///     <group jid="{subgroup_jid}"/>
///   </unlink>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct UnlinkSubgroupsIq {
    pub parent_jid: Jid,
    pub subgroup_jids: Vec<Jid>,
    pub remove_orphan_members: bool,
}

impl UnlinkSubgroupsIq {
    pub fn new(parent_jid: &Jid, subgroup_jids: &[Jid], remove_orphan_members: bool) -> Self {
        Self {
            parent_jid: parent_jid.clone(),
            subgroup_jids: subgroup_jids.to_vec(),
            remove_orphan_members,
        }
    }
}

impl IqSpec for UnlinkSubgroupsIq {
    type Response = UnlinkSubgroupsResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let group_nodes: Vec<Node> = self
            .subgroup_jids
            .iter()
            .map(|jid| {
                let mut builder = NodeBuilder::new("group").attr("jid", jid);
                if self.remove_orphan_members {
                    builder = builder.attr("remove_orphaned_members", "true");
                }
                builder.build()
            })
            .collect();

        let unlink_node = NodeBuilder::new("unlink")
            .attr("unlink_type", "sub_group")
            .children(group_nodes)
            .build();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.parent_jid,
            Some(NodeContent::Nodes(vec![unlink_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let unlink_node = required_child(response, "unlink")?;

        let mut groups = Vec::new();
        for child in unlink_node.get_children_by_tag("group") {
            let jid_str = required_attr(child, "jid")?;
            let jid: Jid = jid_str.parse()?;
            let error = child
                .attrs()
                .optional_string("error")
                .and_then(|s| s.parse::<u32>().ok());
            groups.push(LinkedGroupResult { jid, error });
        }

        Ok(UnlinkSubgroupsResponse { groups })
    }
}

/// IQ specification for deleting (deactivating) a community.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{parent_jid}">
///   <delete_parent/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct DeleteCommunityIq {
    pub parent_jid: Jid,
}

impl DeleteCommunityIq {
    pub fn new(parent_jid: &Jid) -> Self {
        Self {
            parent_jid: parent_jid.clone(),
        }
    }
}

impl IqSpec for DeleteCommunityIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.parent_jid,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("delete_parent").build(),
            ])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

/// IQ specification for querying a linked subgroup's info from the parent community.
///
/// Wire format:
/// ```xml
/// <iq type="get" xmlns="w:g2" to="{parent_jid}">
///   <query_linked type="sub_group" jid="{subgroup_jid}"/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct QueryLinkedGroupIq {
    pub parent_jid: Jid,
    pub subgroup_jid: Jid,
}

impl QueryLinkedGroupIq {
    pub fn new(parent_jid: &Jid, subgroup_jid: &Jid) -> Self {
        Self {
            parent_jid: parent_jid.clone(),
            subgroup_jid: subgroup_jid.clone(),
        }
    }
}

impl IqSpec for QueryLinkedGroupIq {
    type Response = GroupInfoResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let query_node = NodeBuilder::new("query_linked")
            .attr("type", "sub_group")
            .attr("jid", &self.subgroup_jid)
            .build();

        InfoQuery::get_ref(
            GROUP_IQ_NAMESPACE,
            &self.parent_jid,
            Some(NodeContent::Nodes(vec![query_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let linked_node = required_child(response, "linked_group")?;
        let group_node = required_child(linked_node, "group")?;
        GroupInfoResponse::try_from_node_ref(group_node)
    }
}

/// IQ specification for joining a linked subgroup via the parent community.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{parent_jid}">
///   <join_linked_group jid="{subgroup_jid}"/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct JoinLinkedGroupIq {
    pub parent_jid: Jid,
    pub subgroup_jid: Jid,
}

impl JoinLinkedGroupIq {
    pub fn new(parent_jid: &Jid, subgroup_jid: &Jid) -> Self {
        Self {
            parent_jid: parent_jid.clone(),
            subgroup_jid: subgroup_jid.clone(),
        }
    }
}

impl IqSpec for JoinLinkedGroupIq {
    type Response = GroupInfoResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let node = NodeBuilder::new("join_linked_group")
            .attr("jid", &self.subgroup_jid)
            .build();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.parent_jid,
            Some(NodeContent::Nodes(vec![node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let linked_node = required_child(response, "linked_group")?;
        let group_node = required_child(linked_node, "group")?;
        GroupInfoResponse::try_from_node_ref(group_node)
    }
}

/// IQ specification for getting all participants across linked groups.
///
/// Wire format:
/// ```xml
/// <iq type="get" xmlns="w:g2" to="{parent_jid}">
///   <linked_groups_participants/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct GetLinkedGroupsParticipantsIq {
    pub parent_jid: Jid,
}

impl GetLinkedGroupsParticipantsIq {
    pub fn new(parent_jid: &Jid) -> Self {
        Self {
            parent_jid: parent_jid.clone(),
        }
    }
}

impl IqSpec for GetLinkedGroupsParticipantsIq {
    type Response = Vec<GroupParticipantResponse>;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get_ref(
            GROUP_IQ_NAMESPACE,
            &self.parent_jid,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("linked_groups_participants").build(),
            ])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let container = required_child(response, "linked_groups_participants")?;

        // Participants may be direct children or nested inside <group> nodes.
        let direct = collect_children::<GroupParticipantResponse>(container, "participant")?;
        if !direct.is_empty() {
            return Ok(direct);
        }

        // Nested: <linked_groups_participants><group><participant/></group></linked_groups_participants>
        let mut all = Vec::new();
        for group_node in container.get_children_by_tag("group") {
            let participants =
                collect_children::<GroupParticipantResponse>(group_node, "participant")?;
            all.extend(participants);
        }
        Ok(all)
    }
}

// ---------------------------------------------------------------------------
// Accept group invite (join via code)
// ---------------------------------------------------------------------------

/// Result of joining a group via invite code.
#[derive(Debug, Clone, PartialEq)]
pub enum JoinGroupResult {
    Joined(Jid),
    PendingApproval(Jid),
}

impl JoinGroupResult {
    pub fn group_jid(&self) -> &Jid {
        match self {
            JoinGroupResult::Joined(jid) | JoinGroupResult::PendingApproval(jid) => jid,
        }
    }
}

fn parse_group_id(id_str: &str) -> Result<Jid> {
    if id_str.contains('@') {
        id_str.parse().map_err(Into::into)
    } else {
        Ok(Jid::group(id_str))
    }
}

/// Shared response parser for group join IQs (both code-based and V4 invite).
fn parse_join_group_response(response: &NodeRef<'_>) -> Result<JoinGroupResult> {
    if let Some(group_node) = response.get_optional_child("group") {
        let jid_str = required_attr(group_node, "jid")?;
        let jid: Jid = jid_str
            .parse()
            .map_err(|e| anyhow!("invalid group jid: {e}"))?;
        return Ok(JoinGroupResult::Joined(jid));
    }
    if let Some(approval_node) = response.get_optional_child("membership_approval_request") {
        let jid_str = required_attr(approval_node, "jid")?;
        let jid: Jid = jid_str
            .parse()
            .map_err(|e| anyhow!("invalid group jid: {e}"))?;
        return Ok(JoinGroupResult::PendingApproval(jid));
    }
    Err(anyhow!(
        "expected <group> or <membership_approval_request> in join response"
    ))
}

/// ```xml
/// <iq type="set" xmlns="w:g2" to="@g.us">
///   <invite code="{code}"/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct AcceptGroupInviteIq {
    pub code: String,
}

impl AcceptGroupInviteIq {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

impl IqSpec for AcceptGroupInviteIq {
    type Response = JoinGroupResult;

    fn build_iq(&self) -> InfoQuery<'static> {
        let to = Jid::new("", Server::Group);
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &to,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("invite").attr("code", &self.code).build(),
            ])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        parse_join_group_response(response)
    }
}

// ---------------------------------------------------------------------------
// Accept group invite V4 (via invite message)
// ---------------------------------------------------------------------------

/// Accepts a V4 invite (sent as a GroupInviteMessage, not a link).
/// Sends `<accept>` to the group JID with code, expiration, and admin.
pub struct AcceptGroupInviteV4Iq {
    pub group_jid: Jid,
    pub code: String,
    pub expiration: i64,
    pub admin_jid: Jid,
}

impl AcceptGroupInviteV4Iq {
    pub fn new(group_jid: Jid, code: String, expiration: i64, admin_jid: Jid) -> Self {
        Self {
            group_jid,
            code,
            expiration,
            admin_jid,
        }
    }
}

impl IqSpec for AcceptGroupInviteV4Iq {
    type Response = JoinGroupResult;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("accept")
                    .attr("code", &self.code)
                    .attr("expiration", self.expiration.to_string())
                    .attr("admin", self.admin_jid.to_string())
                    .build(),
            ])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        parse_join_group_response(response)
    }
}

// ---------------------------------------------------------------------------
// Get group info by invite code
// ---------------------------------------------------------------------------

/// Get group metadata from an invite code without joining.
///
/// ```xml
/// <iq type="get" xmlns="w:g2" to="@g.us">
///   <invite code="{code}"/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct GetGroupInviteInfoIq {
    pub code: String,
}

impl GetGroupInviteInfoIq {
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

impl IqSpec for GetGroupInviteInfoIq {
    type Response = GroupInfoResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        let to = Jid::new("", Server::Group);
        InfoQuery::get_ref(
            GROUP_IQ_NAMESPACE,
            &to,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("invite").attr("code", &self.code).build(),
            ])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let group_node = required_child(response, "group")?;
        GroupInfoResponse::try_from_node_ref(group_node)
    }
}

// ---------------------------------------------------------------------------
// Membership approval requests
// ---------------------------------------------------------------------------

/// Get pending membership approval requests for a group.
///
/// ```xml
/// <iq type="get" xmlns="w:g2" to="{group_jid}">
///   <membership_approval_requests/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct GetMembershipRequestsIq {
    pub group_jid: Jid,
}

impl GetMembershipRequestsIq {
    pub fn new(jid: &Jid) -> Self {
        Self {
            group_jid: jid.clone(),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MembershipRequest {
    pub jid: Jid,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_time: Option<u64>,
}

impl IqSpec for GetMembershipRequestsIq {
    type Response = Vec<MembershipRequest>;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("membership_approval_requests").build(),
            ])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let requests_node = response
            .get_optional_child("membership_approval_requests")
            .ok_or_else(|| anyhow!("missing membership_approval_requests"))?;

        let mut requests = Vec::new();
        for child in requests_node.get_children_by_tag("membership_approval_request") {
            let jid_str = required_attr(child, "jid")?;
            let jid: Jid = jid_str
                .parse()
                .map_err(|e| anyhow!("invalid jid in membership request: {e}"))?;
            let request_time = child
                .attrs()
                .optional_string("request_time")
                .and_then(|s| s.parse::<u64>().ok());
            requests.push(MembershipRequest { jid, request_time });
        }
        Ok(requests)
    }
}

/// Approve or reject pending membership requests.
///
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <membership_requests_action>
///     <approve> or <reject>
///       <participant jid="{jid}"/>
///     </approve>
///   </membership_requests_action>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct MembershipRequestActionIq {
    pub group_jid: Jid,
    pub participants: Vec<Jid>,
    pub approve: bool,
}

impl MembershipRequestActionIq {
    pub fn approve(group_jid: &Jid, participants: &[Jid]) -> Self {
        Self {
            group_jid: group_jid.clone(),
            participants: participants.to_vec(),
            approve: true,
        }
    }

    pub fn reject(group_jid: &Jid, participants: &[Jid]) -> Self {
        Self {
            group_jid: group_jid.clone(),
            participants: participants.to_vec(),
            approve: false,
        }
    }
}

impl IqSpec for MembershipRequestActionIq {
    type Response = Vec<ParticipantChangeResponse>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let action_tag = if self.approve { "approve" } else { "reject" };
        let participant_nodes: Vec<Node> = self
            .participants
            .iter()
            .map(|jid| NodeBuilder::new("participant").attr("jid", jid).build())
            .collect();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("membership_requests_action")
                    .children(vec![
                        NodeBuilder::new(action_tag)
                            .children(participant_nodes)
                            .build(),
                    ])
                    .build(),
            ])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let action_node = required_child(response, "membership_requests_action")?;
        let action_tag = if self.approve { "approve" } else { "reject" };
        let inner = required_child(action_node, action_tag)?;
        collect_children::<ParticipantChangeResponse>(inner, "participant")
    }
}

// ---------------------------------------------------------------------------
// Member add mode
// ---------------------------------------------------------------------------

/// Set who can add members to the group.
///
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <member_add_mode>admin_add|all_member_add</member_add_mode>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct SetMemberAddModeIq {
    pub group_jid: Jid,
    pub mode: MemberAddMode,
}

impl SetMemberAddModeIq {
    pub fn new(jid: &Jid, mode: MemberAddMode) -> Self {
        Self {
            group_jid: jid.clone(),
            mode,
        }
    }
}

impl IqSpec for SetMemberAddModeIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![
                NodeBuilder::new("member_add_mode")
                    .string_content(self.mode.as_str())
                    .build(),
            ])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Cancel membership requests (user cancels own pending request)
// ---------------------------------------------------------------------------

define_group_participant_iq!(
    /// Cancel pending membership requests (from the requesting user's side).
    ///
    /// ```xml
    /// <iq type="set" xmlns="w:g2" to="{group_jid}">
    ///   <cancel_membership_requests>
    ///     <participant jid="{user_jid}"/>
    ///   </cancel_membership_requests>
    /// </iq>
    /// ```
    CancelMembershipRequestsIq,
    action = "cancel_membership_requests",
    response = Vec<ParticipantChangeResponse>
);

// ---------------------------------------------------------------------------
// Revoke request codes from participants (admin operation)
// ---------------------------------------------------------------------------

define_group_participant_iq!(
    /// Revoke invitation codes from specific participants.
    ///
    /// ```xml
    /// <iq type="set" xmlns="w:g2" to="{group_jid}">
    ///   <revoke><participant jid="{user_jid}"/></revoke>
    /// </iq>
    /// ```
    RevokeRequestCodeIq,
    action = "revoke",
    response = Vec<ParticipantChangeResponse>
);

// ---------------------------------------------------------------------------
// Acknowledge group
// ---------------------------------------------------------------------------

/// Acknowledge a group (used for group notification acknowledgement).
///
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <ack/>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct AcknowledgeGroupIq {
    pub group_jid: Jid,
}

impl AcknowledgeGroupIq {
    pub fn new(group_jid: &Jid) -> Self {
        Self {
            group_jid: group_jid.clone(),
        }
    }
}

impl IqSpec for AcknowledgeGroupIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![NodeBuilder::new("ack").build()])),
        )
    }

    fn parse_response(&self, _response: &NodeRef<'_>) -> Result<Self::Response> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Batch get group info
// ---------------------------------------------------------------------------

/// Result for a single group in a batch query.
#[derive(Debug, Clone)]
pub enum BatchGroupInfoResult {
    Full(Box<GroupInfoResponse>),
    /// Truncated response (only id and size available).
    Truncated {
        id: Jid,
        size: Option<u32>,
    },
    Forbidden(Jid),
    NotFound(Jid),
}

/// Batch query group info for up to 10,000 groups.
///
/// ```xml
/// <iq type="get" xmlns="w:g2" to="@g.us">
///   <query>
///     <group jid="{jid1}"/>
///     <group jid="{jid2}"/>
///   </query>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct BatchGetGroupInfoIq {
    pub group_jids: Vec<Jid>,
}

impl BatchGetGroupInfoIq {
    pub fn new(group_jids: Vec<Jid>) -> Self {
        Self { group_jids }
    }
}

impl IqSpec for BatchGetGroupInfoIq {
    type Response = Vec<BatchGroupInfoResult>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let children: Vec<Node> = self
            .group_jids
            .iter()
            .map(|jid| NodeBuilder::new("group").attr("jid", jid).build())
            .collect();

        let query_node = NodeBuilder::new("query").children(children).build();

        InfoQuery::get(
            GROUP_IQ_NAMESPACE,
            Jid::new("", Server::Group),
            Some(NodeContent::Nodes(vec![query_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let groups_node = required_child(response, "groups")?;
        let mut results = Vec::new();

        for group_node in groups_node.get_children_by_tag("group") {
            let mut attrs = group_node.attrs();

            // Check error attribute first (403=forbidden, 404=not found)
            if let Some(error_code) = attrs.optional_string("error") {
                let id_str = required_attr(group_node, "id")?;
                let id = parse_group_id(&id_str)?;
                match error_code.as_ref() {
                    "403" => results.push(BatchGroupInfoResult::Forbidden(id)),
                    _ => results.push(BatchGroupInfoResult::NotFound(id)),
                };
                continue;
            }

            let is_truncated = attrs
                .optional_string("truncated")
                .is_some_and(|s| s == "true");

            if is_truncated {
                let id_str = required_attr(group_node, "id")?;
                let id = parse_group_id(&id_str)?;
                let size = attrs.optional_string("size").and_then(|s| s.parse().ok());
                results.push(BatchGroupInfoResult::Truncated { id, size });
            } else {
                let info = GroupInfoResponse::try_from_node_ref(group_node)?;
                results.push(BatchGroupInfoResult::Full(Box::new(info)));
            }
        }

        Ok(results)
    }
}

// ---------------------------------------------------------------------------
// Get group profile pictures (batch)
// ---------------------------------------------------------------------------

/// A single group profile picture result.
#[derive(Debug, Clone)]
pub struct GroupProfilePicture {
    pub group_jid: Jid,
    /// Direct URL to the picture.
    pub url: Option<String>,
    /// Direct path for the picture.
    pub direct_path: Option<String>,
    /// Photo ID / version tag.
    pub photo_id: Option<String>,
}

/// Profile picture query type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PictureType {
    Preview,
    Image,
}

/// Batch fetch group profile pictures.
///
/// ```xml
/// <iq type="get" xmlns="w:g2" to="@g.us">
///   <pictures>
///     <picture jid="{group_jid}" type="preview"/>
///   </pictures>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct GetGroupProfilePicturesIq {
    pub groups: Vec<(Jid, PictureType)>,
}

impl GetGroupProfilePicturesIq {
    pub fn new(group_jids: Vec<Jid>) -> Self {
        Self {
            groups: group_jids
                .into_iter()
                .map(|jid| (jid, PictureType::Preview))
                .collect(),
        }
    }

    pub fn with_type(groups: Vec<(Jid, PictureType)>) -> Self {
        Self { groups }
    }
}

impl IqSpec for GetGroupProfilePicturesIq {
    type Response = Vec<GroupProfilePicture>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let children: Vec<Node> = self
            .groups
            .iter()
            .map(|(jid, pic_type)| {
                let type_str = match pic_type {
                    PictureType::Preview => "preview",
                    PictureType::Image => "image",
                };
                NodeBuilder::new("picture")
                    .attr("jid", jid)
                    .attr("type", type_str)
                    .build()
            })
            .collect();

        let pictures_node = NodeBuilder::new("pictures").children(children).build();

        InfoQuery::get(
            GROUP_IQ_NAMESPACE,
            Jid::new("", Server::Group),
            Some(NodeContent::Nodes(vec![pictures_node])),
        )
    }

    fn parse_response(&self, response: &NodeRef<'_>) -> Result<Self::Response> {
        let pictures_node = required_child(response, "pictures")?;
        let mut results = Vec::new();

        for pic_node in pictures_node.get_children_by_tag("picture") {
            let mut attrs = pic_node.attrs();
            if let Some(jid_str) = attrs.optional_string("jid") {
                let jid = parse_group_id(&jid_str)?;
                results.push(GroupProfilePicture {
                    group_jid: jid,
                    url: attrs.optional_string("url").map(|s| s.to_string()),
                    direct_path: attrs.optional_string("direct_path").map(|s| s.to_string()),
                    photo_id: attrs.optional_string("id").map(|s| s.to_string()),
                });
            }
        }

        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::request::InfoQueryType;

    #[test]
    fn test_group_subject_validation() {
        let subject = GroupSubject::new("Test Group").unwrap();
        assert_eq!(subject.as_str(), "Test Group");

        let at_limit = "a".repeat(GROUP_SUBJECT_MAX_LENGTH);
        assert!(GroupSubject::new(&at_limit).is_ok());

        let over_limit = "a".repeat(GROUP_SUBJECT_MAX_LENGTH + 1);
        assert!(GroupSubject::new(&over_limit).is_err());
    }

    #[test]
    fn test_group_description_validation() {
        let desc = GroupDescription::new("Test Description").unwrap();
        assert_eq!(desc.as_str(), "Test Description");

        let at_limit = "a".repeat(GROUP_DESCRIPTION_MAX_LENGTH);
        assert!(GroupDescription::new(&at_limit).is_ok());

        let over_limit = "a".repeat(GROUP_DESCRIPTION_MAX_LENGTH + 1);
        assert!(GroupDescription::new(&over_limit).is_err());
    }

    #[test]
    fn test_string_enum_member_add_mode() {
        assert_eq!(MemberAddMode::AdminAdd.as_str(), "admin_add");
        assert_eq!(MemberAddMode::AllMemberAdd.as_str(), "all_member_add");
        assert_eq!(
            MemberAddMode::try_from("admin_add").unwrap(),
            MemberAddMode::AdminAdd
        );
        assert!(MemberAddMode::try_from("invalid").is_err());
    }

    #[test]
    fn test_string_enum_member_link_mode() {
        assert_eq!(MemberLinkMode::AdminLink.as_str(), "admin_link");
        assert_eq!(MemberLinkMode::AllMemberLink.as_str(), "all_member_link");
        assert_eq!(
            MemberLinkMode::try_from("admin_link").unwrap(),
            MemberLinkMode::AdminLink
        );
    }

    #[test]
    fn test_participant_type_is_admin() {
        assert!(!ParticipantType::Member.is_admin());
        assert!(ParticipantType::Admin.is_admin());
        assert!(ParticipantType::SuperAdmin.is_admin());
    }

    #[test]
    fn test_normalize_participants_drops_phone_for_pn() {
        let pn_jid: Jid = "15551234567@s.whatsapp.net".parse().unwrap();
        let lid_jid: Jid = "100000000000001@lid".parse().unwrap();
        let phone_jid: Jid = "15550000001@s.whatsapp.net".parse().unwrap();

        let participants = vec![
            GroupParticipantOptions::new(pn_jid.clone()).with_phone_number(phone_jid.clone()),
            GroupParticipantOptions::new(lid_jid.clone()).with_phone_number(phone_jid.clone()),
        ];

        let normalized = normalize_participants(&participants);
        assert!(normalized[0].phone_number.is_none());
        assert_eq!(normalized[0].jid, pn_jid);
        assert_eq!(normalized[1].phone_number.as_ref(), Some(&phone_jid));
    }

    #[test]
    fn test_build_create_group_node() {
        let pn_jid: Jid = "15551234567@s.whatsapp.net".parse().unwrap();
        let options = GroupCreateOptions::new("Test Subject")
            .with_participant(GroupParticipantOptions::from_phone(pn_jid))
            .with_member_link_mode(MemberLinkMode::AllMemberLink)
            .with_member_add_mode(MemberAddMode::AdminAdd);

        let node = build_create_group_node(&options);
        assert_eq!(node.tag, "create");
        assert_eq!(
            node.attrs().optional_string("subject").as_deref(),
            Some("Test Subject")
        );

        let link_mode = node.get_children_by_tag("member_link_mode").next().unwrap();
        assert_eq!(
            link_mode.content.as_ref().and_then(|c| match c {
                NodeContent::String(s) => Some(s.as_str()),
                _ => None,
            }),
            Some("all_member_link")
        );
    }

    #[test]
    fn test_typed_builder() {
        let options: GroupCreateOptions = GroupCreateOptions::builder()
            .subject("My Group")
            .member_add_mode(MemberAddMode::AdminAdd)
            .build();

        assert_eq!(options.subject, "My Group");
        assert_eq!(options.member_add_mode, Some(MemberAddMode::AdminAdd));
    }

    #[test]
    fn test_set_group_description_with_id_and_prev() {
        let jid: Jid = "120363000000000001@g.us".parse().unwrap();
        let desc = GroupDescription::new("New description").unwrap();
        let spec = SetGroupDescriptionIq::new(&jid, Some(desc), Some("AABBCCDD".to_string()));
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let desc_node = &nodes[0];
            assert_eq!(desc_node.tag, "description");
            // id is random hex, just check it exists and is 8 chars
            let id = desc_node.attrs().optional_string("id").unwrap();
            assert_eq!(id.len(), 8);
            assert_eq!(
                desc_node.attrs().optional_string("prev").as_deref(),
                Some("AABBCCDD")
            );
            // Should have a <body> child
            assert!(desc_node.get_children_by_tag("body").next().is_some());
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_set_group_description_delete() {
        let jid: Jid = "120363000000000001@g.us".parse().unwrap();
        let spec = SetGroupDescriptionIq::new(&jid, None, Some("PREV1234".to_string()));
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let desc_node = &nodes[0];
            assert_eq!(desc_node.tag, "description");
            assert_eq!(
                desc_node.attrs().optional_string("delete").as_deref(),
                Some("true")
            );
            assert_eq!(
                desc_node.attrs().optional_string("prev").as_deref(),
                Some("PREV1234")
            );
            // id should still be present
            assert!(desc_node.attrs().optional_string("id").is_some());
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_leave_group_iq() {
        let jid: Jid = "120363000000000001@g.us".parse().unwrap();
        let spec = LeaveGroupIq::new(&jid);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, GROUP_IQ_NAMESPACE);
        assert_eq!(iq.query_type, InfoQueryType::Set);
        // Leave goes to g.us, not the group JID
        assert_eq!(iq.to.server, Server::Group);
    }

    #[test]
    fn test_add_participants_iq() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();
        let p1: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let p2: Jid = "9876543210@s.whatsapp.net".parse().unwrap();
        let spec = AddParticipantsIq::new(&group, &[p1, p2]);
        let iq = spec.build_iq();

        assert_eq!(iq.namespace, GROUP_IQ_NAMESPACE);
        assert_eq!(iq.to, group);

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let add_node = &nodes[0];
            assert_eq!(add_node.tag, "add");
            let participants: Vec<_> = add_node.get_children_by_tag("participant").collect();
            assert_eq!(participants.len(), 2);
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_add_participants_with_options_privacy() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();
        let p1 = GroupParticipantOptions {
            jid: "1234567890@s.whatsapp.net".parse().unwrap(),
            phone_number: None,
            privacy: Some(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };
        let spec = AddParticipantsIq::with_options(&group, vec![p1]);
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let add_node = &nodes[0];
            assert_eq!(add_node.tag, "add");

            let participants: Vec<_> = add_node.get_children_by_tag("participant").collect();
            assert_eq!(participants.len(), 1);

            let privacy_children: Vec<_> = participants[0].get_children_by_tag("privacy").collect();
            assert_eq!(privacy_children.len(), 1, "expected a <privacy> child node");

            match &privacy_children[0].content {
                Some(NodeContent::String(s)) => assert_eq!(s, "deadbeef"),
                other => panic!("expected String content in <privacy>, got: {:?}", other),
            }
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_add_participants_with_options_no_privacy() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();
        let p1 = GroupParticipantOptions {
            jid: "1234567890@s.whatsapp.net".parse().unwrap(),
            phone_number: None,
            privacy: None,
        };
        let spec = AddParticipantsIq::with_options(&group, vec![p1]);
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let add_node = &nodes[0];
            assert_eq!(add_node.tag, "add");

            let participants: Vec<_> = add_node.get_children_by_tag("participant").collect();
            assert_eq!(participants.len(), 1);

            let privacy_children: Vec<_> = participants[0].get_children_by_tag("privacy").collect();
            assert!(
                privacy_children.is_empty(),
                "expected no <privacy> child when privacy is None"
            );
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_add_participants_strips_phone_number_for_pn_jid() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();
        let pn_jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        // PN JID with phone_number set: build_iq should strip it
        let p1 = GroupParticipantOptions::new(pn_jid.clone())
            .with_phone_number("9876543210@s.whatsapp.net".parse().unwrap());
        let spec = AddParticipantsIq::with_options(&group, vec![p1]);
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let add_node = &nodes[0];
            let participants: Vec<_> = add_node.get_children_by_tag("participant").collect();
            assert_eq!(participants.len(), 1);
            assert!(
                participants[0]
                    .attrs()
                    .optional_string("phone_number")
                    .is_none(),
                "phone_number should be stripped for non-LID JIDs"
            );
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_promote_demote_iq() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();
        let p1: Jid = "1234567890@s.whatsapp.net".parse().unwrap();

        let promote = PromoteParticipantsIq::new(&group, std::slice::from_ref(&p1));
        let iq = promote.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "promote");
        } else {
            panic!("expected nodes content");
        }

        let demote = DemoteParticipantsIq::new(&group, &[p1]);
        let iq = demote.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "demote");
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_get_group_invite_link_iq() {
        let jid: Jid = "120363000000000001@g.us".parse().unwrap();
        let spec = GetGroupInviteLinkIq::new(&jid, false);
        let iq = spec.build_iq();

        assert_eq!(iq.query_type, InfoQueryType::Get);
        assert_eq!(iq.to, jid);

        // With reset=true it should be a SET
        let reset_spec = GetGroupInviteLinkIq::new(&jid, true);
        assert_eq!(reset_spec.build_iq().query_type, InfoQueryType::Set);
    }

    #[test]
    fn test_get_group_invite_link_parse_response() {
        let jid: Jid = "120363000000000001@g.us".parse().unwrap();
        let spec = GetGroupInviteLinkIq::new(&jid, false);

        let response = NodeBuilder::new("response")
            .children([NodeBuilder::new("invite")
                .attr("code", "AbCdEfGhIjKl")
                .build()])
            .build();

        let result = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(result, "https://chat.whatsapp.com/AbCdEfGhIjKl");
    }

    #[test]
    fn test_participant_change_response_parse_with_type() {
        let node = NodeBuilder::new("participant")
            .attr("jid", "1234567890@s.whatsapp.net")
            .attr("type", "200")
            .build();

        let result = ParticipantChangeResponse::try_from_node(&node).unwrap();
        assert_eq!(result.jid.user, "1234567890");
        assert_eq!(result.status, Some("200".to_string()));
        assert!(result.is_ok());
    }

    #[test]
    fn test_participant_change_response_parse_without_type() {
        let node = NodeBuilder::new("participant")
            .attr("jid", "1234567890@s.whatsapp.net")
            .build();

        let result = ParticipantChangeResponse::try_from_node(&node).unwrap();
        assert_eq!(result.status, None);
        assert_eq!(result.error, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_participant_change_response_parse_error() {
        let node = NodeBuilder::new("participant")
            .attr("jid", "1234567890@s.whatsapp.net")
            .attr("error", "403")
            .build();

        let result = ParticipantChangeResponse::try_from_node(&node).unwrap();
        assert_eq!(result.error.as_deref(), Some("403"));
        assert!(!result.is_ok());
    }

    #[test]
    fn test_participant_change_response_parse_mixins() {
        let node = NodeBuilder::new("participant")
            .attr("jid", "100000000000001@lid")
            .attr("phone_number", "15555550100@s.whatsapp.net")
            .attr("username", "example_user")
            .build();

        let result = ParticipantChangeResponse::try_from_node(&node).unwrap();
        assert!(result.is_ok());
        assert_eq!(
            result.phone_number.as_ref().map(|j| j.user.as_str()),
            Some("15555550100")
        );
        assert_eq!(result.username.as_deref(), Some("example_user"));
    }

    #[test]
    fn test_set_group_locked_iq() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();

        let lock = SetGroupLockedIq::lock(&group);
        let iq = lock.build_iq();
        assert_eq!(iq.query_type, InfoQueryType::Set);
        assert_eq!(iq.to, group);
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "locked");
        } else {
            panic!("expected nodes content");
        }

        let unlock = SetGroupLockedIq::unlock(&group);
        let iq = unlock.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "unlocked");
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_set_group_announcement_iq() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();

        let announce = SetGroupAnnouncementIq::announce(&group);
        let iq = announce.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "announcement");
        } else {
            panic!("expected nodes content");
        }

        let not_announce = SetGroupAnnouncementIq::unannounce(&group);
        let iq = not_announce.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "not_announcement");
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_set_group_ephemeral_iq() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();

        let enable = SetGroupEphemeralIq::enable(&group, NonZeroU32::new(86400).unwrap());
        let iq = enable.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "ephemeral");
            assert_eq!(
                nodes[0].attrs().optional_string("expiration").as_deref(),
                Some("86400")
            );
        } else {
            panic!("expected nodes content");
        }

        let disable = SetGroupEphemeralIq::disable(&group);
        let iq = disable.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "not_ephemeral");
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_set_group_membership_approval_iq() {
        let group: Jid = "120363000000000001@g.us".parse().unwrap();

        let spec = SetGroupMembershipApprovalIq::new(&group, MembershipApprovalMode::On);
        let iq = spec.build_iq();
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "membership_approval_mode");
            let join = nodes[0].get_children_by_tag("group_join").next().unwrap();
            assert!(join.attrs.get("state").is_some_and(|v| v == "on"));
        } else {
            panic!("expected nodes content");
        }
    }

    // -----------------------------------------------------------------------
    // Community IQ spec tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_create_community_node() {
        let options = GroupCreateOptions {
            subject: "My Community".to_string(),
            is_parent: true,
            closed: true,
            allow_non_admin_sub_group_creation: true,
            create_general_chat: true,
            ..Default::default()
        };

        let node = build_create_group_node(&options);
        assert_eq!(node.tag, "create");

        // Should have <parent default_membership_approval_mode="request_required"/>
        let parent = node.get_children_by_tag("parent").next().unwrap();
        assert_eq!(
            parent
                .attrs()
                .optional_string("default_membership_approval_mode")
                .as_deref(),
            Some("request_required")
        );

        assert!(
            node.get_children_by_tag("allow_non_admin_sub_group_creation")
                .next()
                .is_some()
        );
        assert!(
            node.get_children_by_tag("create_general_chat")
                .next()
                .is_some()
        );
    }

    #[test]
    fn test_build_create_non_community_omits_parent() {
        let options = GroupCreateOptions {
            subject: "Regular Group".to_string(),
            is_parent: false,
            ..Default::default()
        };

        let node = build_create_group_node(&options);
        assert!(
            node.get_children_by_tag("parent").next().is_none(),
            "non-community group should not have <parent>"
        );
    }

    #[test]
    fn test_link_subgroups_iq_build() {
        let parent: Jid = "120363000000000001@g.us".parse().unwrap();
        let sub: Jid = "120363000000000002@g.us".parse().unwrap();

        let spec = LinkSubgroupsIq::new(&parent, std::slice::from_ref(&sub));
        let iq = spec.build_iq();

        assert_eq!(iq.to, parent);
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let links = &nodes[0];
            assert_eq!(links.tag, "links");
            let link = links.get_children_by_tag("link").next().unwrap();
            assert_eq!(
                link.attrs().optional_string("link_type").as_deref(),
                Some("sub_group")
            );
            let group = link.get_children_by_tag("group").next().unwrap();
            assert_eq!(group.attrs().optional_jid("jid"), Some(sub));
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_link_subgroups_iq_parse_response() {
        let parent: Jid = "120363000000000001@g.us".parse().unwrap();
        let sub: Jid = "120363000000000002@g.us".parse().unwrap();

        let response = NodeBuilder::new("iq")
            .children([NodeBuilder::new("links")
                .children([NodeBuilder::new("link")
                    .attr("link_type", "sub_group")
                    .children([NodeBuilder::new("group")
                        .attr("jid", sub.to_string())
                        .build()])
                    .build()])
                .build()])
            .build();

        let spec = LinkSubgroupsIq::new(&parent, std::slice::from_ref(&sub));
        let result = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.groups[0].jid, sub);
        assert!(result.groups[0].error.is_none());
    }

    #[test]
    fn test_unlink_subgroups_iq_build() {
        let parent: Jid = "120363000000000001@g.us".parse().unwrap();
        let sub: Jid = "120363000000000002@g.us".parse().unwrap();

        let spec = UnlinkSubgroupsIq::new(&parent, std::slice::from_ref(&sub), true);
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let unlink = &nodes[0];
            assert_eq!(unlink.tag, "unlink");
            assert_eq!(
                unlink.attrs().optional_string("unlink_type").as_deref(),
                Some("sub_group")
            );
            let group = unlink.get_children_by_tag("group").next().unwrap();
            assert_eq!(group.attrs().optional_jid("jid"), Some(sub));
            assert_eq!(
                group
                    .attrs()
                    .optional_string("remove_orphaned_members")
                    .as_deref(),
                Some("true")
            );
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_unlink_subgroups_iq_parse_response_with_error() {
        let parent: Jid = "120363000000000001@g.us".parse().unwrap();
        let sub: Jid = "120363000000000002@g.us".parse().unwrap();

        let response = NodeBuilder::new("iq")
            .children([NodeBuilder::new("unlink")
                .attr("unlink_type", "sub_group")
                .children([NodeBuilder::new("group")
                    .attr("jid", sub.to_string())
                    .attr("error", "406")
                    .build()])
                .build()])
            .build();

        let spec = UnlinkSubgroupsIq::new(&parent, std::slice::from_ref(&sub), false);
        let result = spec.parse_response(&response.as_node_ref()).unwrap();
        assert_eq!(result.groups.len(), 1);
        assert_eq!(result.groups[0].jid, sub);
        assert_eq!(result.groups[0].error, Some(406));
    }

    #[test]
    fn test_delete_community_iq_build() {
        let parent: Jid = "120363000000000001@g.us".parse().unwrap();
        let spec = DeleteCommunityIq::new(&parent);
        let iq = spec.build_iq();

        assert_eq!(iq.to, parent);
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "delete_parent");
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_query_linked_group_iq_build() {
        let parent: Jid = "120363000000000001@g.us".parse().unwrap();
        let sub: Jid = "120363000000000002@g.us".parse().unwrap();

        let spec = QueryLinkedGroupIq::new(&parent, &sub);
        let iq = spec.build_iq();

        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let query = &nodes[0];
            assert_eq!(query.tag, "query_linked");
            assert_eq!(
                query.attrs().optional_string("type").as_deref(),
                Some("sub_group")
            );
            assert_eq!(query.attrs().optional_jid("jid"), Some(sub));
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_join_linked_group_iq_build() {
        let parent: Jid = "120363000000000001@g.us".parse().unwrap();
        let sub: Jid = "120363000000000002@g.us".parse().unwrap();

        let spec = JoinLinkedGroupIq::new(&parent, &sub);
        let iq = spec.build_iq();

        assert_eq!(iq.to, parent);
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            let join = &nodes[0];
            assert_eq!(join.tag, "join_linked_group");
            assert_eq!(join.attrs().optional_jid("jid"), Some(sub));
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_get_linked_groups_participants_iq_build() {
        let parent: Jid = "120363000000000001@g.us".parse().unwrap();
        let spec = GetLinkedGroupsParticipantsIq::new(&parent);
        let iq = spec.build_iq();

        assert_eq!(iq.to, parent);
        if let Some(NodeContent::Nodes(nodes)) = &iq.content {
            assert_eq!(nodes[0].tag, "linked_groups_participants");
        } else {
            panic!("expected nodes content");
        }
    }

    #[test]
    fn test_group_info_response_parses_community_fields() {
        let node = NodeBuilder::new("group")
            .attr("id", "120363000000000001@g.us")
            .attr("subject", "My Community")
            .children([
                NodeBuilder::new("parent").build(),
                NodeBuilder::new("allow_non_admin_sub_group_creation").build(),
            ])
            .build();

        let response = GroupInfoResponse::try_from_node(&node).unwrap();
        assert!(response.is_parent_group);
        assert!(response.allow_non_admin_sub_group_creation);
        assert!(response.parent_group_jid.is_none());
        assert!(!response.is_default_sub_group);
        assert!(!response.is_general_chat);
    }

    #[test]
    fn test_group_info_response_parses_subgroup_fields() {
        let parent_jid = "120363000000000001@g.us";
        let node = NodeBuilder::new("group")
            .attr("id", "120363000000000002@g.us")
            .attr("subject", "Sub Group")
            .children([
                NodeBuilder::new("linked_parent")
                    .attr("jid", parent_jid)
                    .build(),
                NodeBuilder::new("default_sub_group").build(),
            ])
            .build();

        let response = GroupInfoResponse::try_from_node(&node).unwrap();
        assert!(!response.is_parent_group);
        assert!(response.is_default_sub_group);
        assert_eq!(response.parent_group_jid, Some(parent_jid.parse().unwrap()));
    }

    #[test]
    fn test_group_info_response_parses_description_from_body() {
        let node = NodeBuilder::new("group")
            .attr("id", "120363000000000001@g.us")
            .attr("subject", "Test Group")
            .children([NodeBuilder::new("description")
                .attr("id", "desc123")
                .attr("participant", "5511999999999@s.whatsapp.net")
                .attr("t", "1700000000")
                .children([NodeBuilder::new("body")
                    .apply_content(Some(NodeContent::String("Hello world".into())))
                    .build()])
                .build()])
            .build();

        let response = GroupInfoResponse::try_from_node(&node).unwrap();
        assert_eq!(response.description.as_deref(), Some("Hello world"));
        assert_eq!(response.description_id.as_deref(), Some("desc123"));
        assert_eq!(
            response.description_owner,
            Some("5511999999999@s.whatsapp.net".parse().unwrap())
        );
        assert_eq!(response.description_time, Some(1700000000));
    }

    #[test]
    fn test_group_info_response_no_description() {
        let node = NodeBuilder::new("group")
            .attr("id", "120363000000000001@g.us")
            .attr("subject", "Test Group")
            .build();

        let response = GroupInfoResponse::try_from_node(&node).unwrap();
        assert!(response.description.is_none());
        assert!(response.description_id.is_none());
        assert!(response.description_owner.is_none());
        assert!(response.description_time.is_none());
    }
}
