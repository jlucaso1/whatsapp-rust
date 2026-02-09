use crate::StringEnum;
use crate::iq::node::{collect_children, optional_attr, required_attr, required_child};
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
pub const GROUP_DESCRIPTION_MAX_LENGTH: usize = 2048;

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

        let participants = collect_children::<GroupParticipantResponse>(node, "participant")?;

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

// ---------------------------------------------------------------------------
// Group Management IQ Specs
// ---------------------------------------------------------------------------

/// Response for participant change operations (add/remove/promote/demote).
#[derive(Debug, Clone)]
pub struct ParticipantChangeResponse {
    pub jid: Jid,
    /// HTTP-like status code (e.g. 200, 403, 409).
    pub status: Option<String>,
    pub error: Option<String>,
}

impl ProtocolNode for ParticipantChangeResponse {
    fn tag(&self) -> &'static str {
        "participant"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("participant").attr("jid", self.jid.to_string());
        if let Some(ref status) = self.status {
            builder = builder.attr("type", status);
        }
        if let Some(ref error) = self.error {
            builder = builder.attr("error", error);
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
        let status = optional_attr(node, "type").map(String::from);
        let error = optional_attr(node, "error").map(String::from);
        Ok(Self { jid, status, error })
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

    fn parse_response(&self, _response: &Node) -> Result<Self::Response> {
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
        use rand::Rng;
        let id = format!("{:08X}", rand::rng().random::<u32>());
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

    fn parse_response(&self, _response: &Node) -> Result<Self::Response> {
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
            .attr("id", self.group_jid.to_string())
            .build();
        let leave_node = NodeBuilder::new("leave").children([group_node]).build();

        InfoQuery::set(
            GROUP_IQ_NAMESPACE,
            Jid::new("", GROUP_SERVER),
            Some(NodeContent::Nodes(vec![leave_node])),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response> {
        Ok(())
    }
}

/// IQ specification for adding participants to a group.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <add>
///     <participant jid="{user_jid}"/>
///   </add>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct AddParticipantsIq {
    pub group_jid: Jid,
    pub participants: Vec<Jid>,
}

impl AddParticipantsIq {
    pub fn new(group_jid: &Jid, participants: &[Jid]) -> Self {
        Self {
            group_jid: group_jid.clone(),
            participants: participants.to_vec(),
        }
    }
}

impl IqSpec for AddParticipantsIq {
    type Response = Vec<ParticipantChangeResponse>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let children: Vec<Node> = self
            .participants
            .iter()
            .map(|jid| {
                NodeBuilder::new("participant")
                    .attr("jid", jid.to_string())
                    .build()
            })
            .collect();

        let add_node = NodeBuilder::new("add").children(children).build();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![add_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response> {
        let add_node = required_child(response, "add")?;
        collect_children::<ParticipantChangeResponse>(add_node, "participant")
    }
}

/// IQ specification for removing participants from a group.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <remove>
///     <participant jid="{user_jid}"/>
///   </remove>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct RemoveParticipantsIq {
    pub group_jid: Jid,
    pub participants: Vec<Jid>,
}

impl RemoveParticipantsIq {
    pub fn new(group_jid: &Jid, participants: &[Jid]) -> Self {
        Self {
            group_jid: group_jid.clone(),
            participants: participants.to_vec(),
        }
    }
}

impl IqSpec for RemoveParticipantsIq {
    type Response = Vec<ParticipantChangeResponse>;

    fn build_iq(&self) -> InfoQuery<'static> {
        let children: Vec<Node> = self
            .participants
            .iter()
            .map(|jid| {
                NodeBuilder::new("participant")
                    .attr("jid", jid.to_string())
                    .build()
            })
            .collect();

        let remove_node = NodeBuilder::new("remove").children(children).build();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![remove_node])),
        )
    }

    fn parse_response(&self, response: &Node) -> Result<Self::Response> {
        let remove_node = required_child(response, "remove")?;
        collect_children::<ParticipantChangeResponse>(remove_node, "participant")
    }
}

/// IQ specification for promoting participants to admin.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <promote>
///     <participant jid="{user_jid}"/>
///   </promote>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct PromoteParticipantsIq {
    pub group_jid: Jid,
    pub participants: Vec<Jid>,
}

impl PromoteParticipantsIq {
    pub fn new(group_jid: &Jid, participants: &[Jid]) -> Self {
        Self {
            group_jid: group_jid.clone(),
            participants: participants.to_vec(),
        }
    }
}

impl IqSpec for PromoteParticipantsIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let children: Vec<Node> = self
            .participants
            .iter()
            .map(|jid| {
                NodeBuilder::new("participant")
                    .attr("jid", jid.to_string())
                    .build()
            })
            .collect();

        let promote_node = NodeBuilder::new("promote").children(children).build();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![promote_node])),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response> {
        Ok(())
    }
}

/// IQ specification for demoting participants from admin.
///
/// Wire format:
/// ```xml
/// <iq type="set" xmlns="w:g2" to="{group_jid}">
///   <demote>
///     <participant jid="{user_jid}"/>
///   </demote>
/// </iq>
/// ```
#[derive(Debug, Clone)]
pub struct DemoteParticipantsIq {
    pub group_jid: Jid,
    pub participants: Vec<Jid>,
}

impl DemoteParticipantsIq {
    pub fn new(group_jid: &Jid, participants: &[Jid]) -> Self {
        Self {
            group_jid: group_jid.clone(),
            participants: participants.to_vec(),
        }
    }
}

impl IqSpec for DemoteParticipantsIq {
    type Response = ();

    fn build_iq(&self) -> InfoQuery<'static> {
        let children: Vec<Node> = self
            .participants
            .iter()
            .map(|jid| {
                NodeBuilder::new("participant")
                    .attr("jid", jid.to_string())
                    .build()
            })
            .collect();

        let demote_node = NodeBuilder::new("demote").children(children).build();

        InfoQuery::set_ref(
            GROUP_IQ_NAMESPACE,
            &self.group_jid,
            Some(NodeContent::Nodes(vec![demote_node])),
        )
    }

    fn parse_response(&self, _response: &Node) -> Result<Self::Response> {
        Ok(())
    }
}

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

    fn parse_response(&self, response: &Node) -> Result<Self::Response> {
        let invite_node = required_child(response, "invite")?;
        let code = required_attr(invite_node, "code")?;
        Ok(format!("https://chat.whatsapp.com/{code}"))
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
            node.attrs().optional_string("subject"),
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
            assert_eq!(desc_node.attrs().optional_string("prev"), Some("AABBCCDD"));
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
            assert_eq!(desc_node.attrs().optional_string("delete"), Some("true"));
            assert_eq!(desc_node.attrs().optional_string("prev"), Some("PREV1234"));
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
        assert_eq!(iq.to.server, GROUP_SERVER);
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

        let result = spec.parse_response(&response).unwrap();
        assert_eq!(result, "https://chat.whatsapp.com/AbCdEfGhIjKl");
    }

    #[test]
    fn test_participant_change_response_parse() {
        let node = NodeBuilder::new("participant")
            .attr("jid", "1234567890@s.whatsapp.net")
            .attr("type", "200")
            .build();

        let result = ParticipantChangeResponse::try_from_node(&node).unwrap();
        assert_eq!(result.jid.user, "1234567890");
        assert_eq!(result.status, Some("200".to_string()));
    }
}
