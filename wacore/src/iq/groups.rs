use crate::StringEnum;
use crate::iq::node::{optional_attr, required_attr, required_child};
use crate::iq::spec::IqSpec;
use crate::protocol::ProtocolNode;
use crate::request::InfoQuery;
use anyhow::{Result, anyhow};
use typed_builder::TypedBuilder;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{GROUP_SERVER, Jid};
use wacore_binary::node::{Node, NodeContent};

// Re-export AddressingMode from types::message for convenience
pub use crate::types::message::AddressingMode;
/// IQ namespace for group operations.
pub const GROUP_IQ_NAMESPACE: &str = "w:g2";

/// Maximum length for a WhatsApp group subject (from `group_max_subject` A/B prop).
pub const GROUP_SUBJECT_MAX_LENGTH: usize = 100;

/// Maximum length for a WhatsApp group description (from `group_description_length` A/B prop).
pub const GROUP_DESCRIPTION_MAX_LENGTH: usize = 512;

/// Maximum number of participants in a group (from `group_size_limit` A/B prop).
pub const GROUP_SIZE_LIMIT: usize = 257;
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
/// A validated group subject string.
///
/// WhatsApp limits group subjects to [`GROUP_SUBJECT_MAX_LENGTH`] characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupSubject(String);

impl GroupSubject {
    /// Create a new validated group subject.
    pub fn new(subject: impl Into<String>) -> Result<Self> {
        let s = subject.into();
        if s.chars().count() > GROUP_SUBJECT_MAX_LENGTH {
            return Err(anyhow!(
                "Group subject exceeds {} characters",
                GROUP_SUBJECT_MAX_LENGTH
            ));
        }
        Ok(Self(s))
    }

    /// Create a group subject without validation (for parsing responses).
    pub fn new_unchecked(subject: impl Into<String>) -> Self {
        Self(subject.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

/// A validated group description string.
///
/// WhatsApp limits group descriptions to [`GROUP_DESCRIPTION_MAX_LENGTH`] characters.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GroupDescription(String);

impl GroupDescription {
    /// Create a new validated group description.
    pub fn new(description: impl Into<String>) -> Result<Self> {
        let s = description.into();
        if s.chars().count() > GROUP_DESCRIPTION_MAX_LENGTH {
            return Err(anyhow!(
                "Group description exceeds {} characters",
                GROUP_DESCRIPTION_MAX_LENGTH
            ));
        }
        Ok(Self(s))
    }

    /// Create a group description without validation (for parsing responses).
    pub fn new_unchecked(description: impl Into<String>) -> Self {
        Self(description.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
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

    NodeBuilder::new("create")
        .attr("subject", &options.subject)
        .children(children)
        .build()
}
/// Request to query group information.
#[derive(Debug, Clone, Default)]
pub struct GroupQueryRequest {
    pub request: GroupQueryRequestType,
}

impl ProtocolNode for GroupQueryRequest {
    fn tag(&self) -> &'static str {
        "query"
    }

    fn into_node(self) -> Node {
        NodeBuilder::new("query")
            .attr("request", self.request.as_str())
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "query" {
            return Err(anyhow!("expected <query>, got <{}>", node.tag));
        }
        Ok(Self::default())
    }
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
        let mut builder = NodeBuilder::new("participant").attr("jid", self.jid.to_string());
        if let Some(pn) = &self.phone_number {
            builder = builder.attr("phone_number", pn.to_string());
        }
        if self.participant_type != ParticipantType::Member {
            builder = builder.attr("type", self.participant_type.as_str());
        }
        builder.build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "participant" {
            return Err(anyhow!("expected <participant>, got <{}>", node.tag));
        }
        let jid = node
            .attrs()
            .optional_jid("jid")
            .ok_or_else(|| anyhow!("participant missing required 'jid' attribute"))?;
        let phone_number = node.attrs().optional_jid("phone_number");
        // Default to Member for unknown participant types to avoid failing the whole group parse
        let participant_type = ParticipantType::try_from(node.attrs().optional_string("type"))
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
}

impl ProtocolNode for GroupInfoResponse {
    fn tag(&self) -> &'static str {
        "group"
    }

    fn into_node(self) -> Node {
        let children: Vec<Node> = self
            .participants
            .into_iter()
            .map(|p| p.into_node())
            .collect();
        NodeBuilder::new("group")
            .attr("id", self.id.to_string())
            .attr("subject", self.subject.as_str())
            .attr("addressing_mode", self.addressing_mode.as_str())
            .children(children)
            .build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "group" {
            return Err(anyhow!("expected <group>, got <{}>", node.tag));
        }

        let id_str = required_attr(node, "id")?;
        let id = if id_str.contains('@') {
            id_str.parse()?
        } else {
            Jid::group(id_str)
        };

        let subject =
            GroupSubject::new_unchecked(optional_attr(node, "subject").unwrap_or_default());

        let addressing_mode =
            AddressingMode::try_from(optional_attr(node, "addressing_mode").unwrap_or("pn"))?;

        let participants = node
            .get_children_by_tag("participant")
            .iter()
            .map(|child| GroupParticipantResponse::try_from_node(child))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            id,
            subject,
            addressing_mode,
            participants,
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

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "participating" {
            return Err(anyhow!("expected <participating>, got <{}>", node.tag));
        }
        Ok(Self::default())
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

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "groups" {
            return Err(anyhow!("expected <groups>, got <{}>", node.tag));
        }

        let groups = node
            .get_children_by_tag("group")
            .iter()
            .map(|child| GroupInfoResponse::try_from_node(child))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self { groups })
    }
}
/// IQ specification for querying a specific group's info.
#[derive(Debug, Clone)]
pub struct GroupQueryIq {
    pub group_jid: Jid,
}

impl GroupQueryIq {
    pub fn new(group_jid: Jid) -> Self {
        Self { group_jid }
    }
}

impl IqSpec for GroupQueryIq {
    type Response = GroupInfoResponse;

    fn build_iq(&self) -> InfoQuery<'static> {
        InfoQuery::get(
            GROUP_IQ_NAMESPACE,
            self.group_jid.clone(),
            Some(NodeContent::Nodes(vec![
                GroupQueryRequest::default().into_node(),
            ])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response> {
        let group_node = required_child(response, "group")?;
        GroupInfoResponse::try_from_node(group_node)
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
            Jid::new("", GROUP_SERVER),
            Some(NodeContent::Nodes(vec![
                GroupParticipatingRequest::new().into_node(),
            ])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response> {
        let groups_node = required_child(response, "groups")?;
        GroupParticipatingResponse::try_from_node(groups_node)
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
            Jid::new("", GROUP_SERVER),
            Some(NodeContent::Nodes(vec![build_create_group_node(
                &self.options,
            )])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response> {
        let group_node = required_child(response, "group")?;
        let group_id_str = required_attr(group_node, "id")?;

        if group_id_str.contains('@') {
            group_id_str.parse().map_err(Into::into)
        } else {
            Ok(Jid::group(group_id_str))
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

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
            node.attrs().optional_string("subject"),
            Some("Test Subject")
        );

        let link_mode = node.get_children_by_tag("member_link_mode")[0];
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
}
