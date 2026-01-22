use crate::client::Client;
use crate::request::InfoQuery;
use std::collections::HashMap;
use std::sync::LazyLock;
use wacore::client::context::GroupInfo;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{GROUP_SERVER, Jid};
use wacore_binary::node::{Node, NodeContent};

static G_US_JID: LazyLock<Jid> = LazyLock::new(|| Jid::new("", GROUP_SERVER));

#[derive(Debug, Clone)]
pub struct GroupMetadata {
    pub id: Jid,
    pub subject: String,
    pub participants: Vec<GroupParticipant>,
    pub addressing_mode: crate::types::message::AddressingMode,
}

#[derive(Debug, Clone)]
pub struct GroupParticipant {
    pub jid: Jid,
    pub phone_number: Option<Jid>,
    pub is_admin: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum MemberLinkMode {
    AdminLink,
    AllMemberLink,
}

impl MemberLinkMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemberLinkMode::AdminLink => "admin_link",
            MemberLinkMode::AllMemberLink => "all_member_link",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum MemberAddMode {
    AdminAdd,
    AllMemberAdd,
}

impl MemberAddMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemberAddMode::AdminAdd => "admin_add",
            MemberAddMode::AllMemberAdd => "all_member_add",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum MembershipApprovalMode {
    #[default]
    Off,
    On,
}

impl MembershipApprovalMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            MembershipApprovalMode::Off => "off",
            MembershipApprovalMode::On => "on",
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupParticipantOptions {
    pub jid: Jid,
    pub phone_number: Option<Jid>,
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

    pub fn with_phone_number(mut self, phone_number: Jid) -> Self {
        self.phone_number = Some(phone_number);
        self
    }

    pub fn from_lid_and_phone(lid: Jid, phone_number: Jid) -> Self {
        Self::new(lid).with_phone_number(phone_number)
    }

    pub fn from_phone(phone_number: Jid) -> Self {
        Self::new(phone_number)
    }

    pub fn with_privacy(mut self, privacy: Vec<u8>) -> Self {
        self.privacy = Some(privacy);
        self
    }
}

#[derive(Debug, Clone)]
pub struct GroupCreateOptions {
    pub subject: String,
    pub participants: Vec<GroupParticipantOptions>,
    pub member_link_mode: Option<MemberLinkMode>,
    pub member_add_mode: Option<MemberAddMode>,
    pub membership_approval_mode: Option<MembershipApprovalMode>,
    pub ephemeral_expiration: Option<u32>,
}

impl GroupCreateOptions {
    pub fn new(subject: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            participants: Vec::new(),
            member_link_mode: Some(MemberLinkMode::AdminLink),
            member_add_mode: Some(MemberAddMode::AllMemberAdd),
            membership_approval_mode: Some(MembershipApprovalMode::Off),
            ephemeral_expiration: Some(0),
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
        Self::new("")
    }
}

#[derive(Debug, Clone)]
pub struct CreateGroupResult {
    pub gid: Jid,
}

fn normalize_participants(
    participants: &[GroupParticipantOptions],
) -> Vec<GroupParticipantOptions> {
    participants
        .iter()
        .cloned()
        .map(|participant| {
            if !participant.jid.is_lid() && participant.phone_number.is_some() {
                GroupParticipantOptions {
                    phone_number: None,
                    ..participant
                }
            } else {
                participant
            }
        })
        .collect()
}

fn build_create_group_node(options: &GroupCreateOptions) -> Node {
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

    for participant in &options.participants {
        let mut participant_attrs = Vec::new();
        participant_attrs.push(("jid", participant.jid.to_string()));

        if let Some(phone_number) = &participant.phone_number {
            participant_attrs.push(("phone_number", phone_number.to_string()));
        }

        let participant_node = if let Some(privacy_bytes) = &participant.privacy {
            let privacy_hex = hex::encode(privacy_bytes);
            NodeBuilder::new("participant")
                .attrs(participant_attrs)
                .children([NodeBuilder::new("privacy")
                    .string_content(&privacy_hex)
                    .build()])
                .build()
        } else {
            NodeBuilder::new("participant")
                .attrs(participant_attrs)
                .build()
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

pub struct Groups<'a> {
    client: &'a Client,
}

impl<'a> Groups<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn query_info(&self, jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
        if let Some(cached) = self.client.get_group_cache().await.get(jid).await {
            return Ok(cached);
        }

        let query_node = NodeBuilder::new("query")
            .attr("request", "interactive")
            .build();

        let iq = InfoQuery::get(
            "w:g2",
            jid.clone(),
            Some(NodeContent::Nodes(vec![query_node])),
        );

        let resp_node = self.client.send_iq(iq).await?;

        let group_node = resp_node
            .get_optional_child("group")
            .ok_or_else(|| anyhow::anyhow!("<group> not found in group info response"))?;

        let mut participants = Vec::new();
        let mut lid_to_pn_map = HashMap::new();

        let addressing_mode_str = group_node
            .attrs()
            .optional_string("addressing_mode")
            .unwrap_or("pn");
        let addressing_mode = match addressing_mode_str {
            "lid" => crate::types::message::AddressingMode::Lid,
            _ => crate::types::message::AddressingMode::Pn,
        };

        for participant_node in group_node.get_children_by_tag("participant") {
            let participant_jid = participant_node.attrs().jid("jid");
            participants.push(participant_jid.clone());

            if addressing_mode == crate::types::message::AddressingMode::Lid
                && let Some(phone_number) = participant_node.attrs().optional_jid("phone_number")
            {
                lid_to_pn_map.insert(participant_jid.user.clone(), phone_number);
            }
        }

        let mut info = GroupInfo::new(participants, addressing_mode);
        if !lid_to_pn_map.is_empty() {
            info.set_lid_to_pn_map(lid_to_pn_map);
        }

        self.client
            .get_group_cache()
            .await
            .insert(jid.clone(), info.clone())
            .await;

        Ok(info)
    }

    pub async fn get_participating(&self) -> Result<HashMap<String, GroupMetadata>, anyhow::Error> {
        let participants_node = NodeBuilder::new("participants").build();
        let description_node = NodeBuilder::new("description").build();
        let participating_node = NodeBuilder::new("participating")
            .children([participants_node, description_node])
            .build();

        let iq = InfoQuery::get(
            "w:g2",
            G_US_JID.clone(),
            Some(NodeContent::Nodes(vec![participating_node])),
        );

        let resp_node = self.client.send_iq(iq).await?;

        let mut result = HashMap::new();

        if let Some(groups_node) = resp_node.get_optional_child("groups") {
            for group_node in groups_node.get_children_by_tag("group") {
                let group_id_str = group_node.attrs().string("id");
                let group_jid: Jid = if group_id_str.contains('@') {
                    group_id_str
                        .parse()
                        .unwrap_or_else(|_| Jid::group(&group_id_str))
                } else {
                    Jid::group(&group_id_str)
                };

                let subject = group_node
                    .attrs()
                    .optional_string("subject")
                    .unwrap_or_default()
                    .to_string();

                let addressing_mode_str = group_node
                    .attrs()
                    .optional_string("addressing_mode")
                    .unwrap_or("pn");
                let addressing_mode = match addressing_mode_str {
                    "lid" => crate::types::message::AddressingMode::Lid,
                    _ => crate::types::message::AddressingMode::Pn,
                };

                let mut participants = Vec::new();
                for participant_node in group_node.get_children_by_tag("participant") {
                    let jid = participant_node.attrs().jid("jid");
                    let phone_number = participant_node.attrs().optional_jid("phone_number");
                    let admin_type = participant_node.attrs().optional_string("type");
                    let is_admin = admin_type == Some("admin") || admin_type == Some("superadmin");

                    participants.push(GroupParticipant {
                        jid,
                        phone_number,
                        is_admin,
                    });
                }

                let metadata = GroupMetadata {
                    id: group_jid.clone(),
                    subject,
                    participants,
                    addressing_mode,
                };

                result.insert(group_jid.to_string(), metadata);
            }
        }

        Ok(result)
    }

    pub async fn get_metadata(&self, jid: &Jid) -> Result<GroupMetadata, anyhow::Error> {
        let query_node = NodeBuilder::new("query")
            .attr("request", "interactive")
            .build();

        let iq = InfoQuery::get(
            "w:g2",
            jid.clone(),
            Some(NodeContent::Nodes(vec![query_node])),
        );

        let resp_node = self.client.send_iq(iq).await?;

        let group_node = resp_node
            .get_optional_child("group")
            .ok_or_else(|| anyhow::anyhow!("<group> not found in group info response"))?;

        let subject = group_node
            .attrs()
            .optional_string("subject")
            .unwrap_or_default()
            .to_string();

        let addressing_mode_str = group_node
            .attrs()
            .optional_string("addressing_mode")
            .unwrap_or("pn");
        let addressing_mode = match addressing_mode_str {
            "lid" => crate::types::message::AddressingMode::Lid,
            _ => crate::types::message::AddressingMode::Pn,
        };

        let mut participants = Vec::new();
        for participant_node in group_node.get_children_by_tag("participant") {
            let participant_jid = participant_node.attrs().jid("jid");
            let phone_number = participant_node.attrs().optional_jid("phone_number");
            let admin_type = participant_node.attrs().optional_string("type");
            let is_admin = admin_type == Some("admin") || admin_type == Some("superadmin");

            participants.push(GroupParticipant {
                jid: participant_jid,
                phone_number,
                is_admin,
            });
        }

        Ok(GroupMetadata {
            id: jid.clone(),
            subject,
            participants,
            addressing_mode,
        })
    }

    pub async fn create_group(
        &self,
        options: GroupCreateOptions,
    ) -> Result<CreateGroupResult, anyhow::Error> {
        let mut resolved_options = options;
        let mut resolved_participants = Vec::with_capacity(resolved_options.participants.len());

        for participant in resolved_options.participants.into_iter() {
            if participant.jid.is_lid() && participant.phone_number.is_none() {
                if let Some(phone_number) = self
                    .client
                    .get_phone_number_from_lid(&participant.jid.user)
                    .await
                {
                    resolved_participants
                        .push(participant.with_phone_number(Jid::pn(phone_number)));
                } else {
                    return Err(anyhow::anyhow!(
                        "Missing phone number mapping for LID {}",
                        participant.jid
                    ));
                }
            } else {
                resolved_participants.push(participant);
            }
        }

        resolved_options.participants = normalize_participants(&resolved_participants);

        let create_node = build_create_group_node(&resolved_options);

        let iq = InfoQuery::set(
            "w:g2",
            G_US_JID.clone(),
            Some(NodeContent::Nodes(vec![create_node])),
        );

        let resp_node = self.client.send_iq(iq).await?;

        let group_node = resp_node
            .get_optional_child("group")
            .ok_or_else(|| anyhow::anyhow!("<group> not found in create group response"))?;

        let group_id_str = group_node.attrs().string("id");
        let gid: Jid = if group_id_str.contains('@') {
            group_id_str.parse()?
        } else {
            Jid::group(&group_id_str)
        };

        Ok(CreateGroupResult { gid })
    }
}

impl Client {
    pub fn groups(&self) -> Groups<'_> {
        Groups::new(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_group_metadata_struct() {
        let jid: Jid = "123456789@g.us"
            .parse()
            .expect("test group JID should be valid");
        let participant_jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test participant JID should be valid");

        let metadata = GroupMetadata {
            id: jid.clone(),
            subject: "Test Group".to_string(),
            participants: vec![GroupParticipant {
                jid: participant_jid,
                phone_number: None,
                is_admin: true,
            }],
            addressing_mode: crate::types::message::AddressingMode::Pn,
        };

        assert_eq!(metadata.subject, "Test Group");
        assert_eq!(metadata.participants.len(), 1);
        assert!(metadata.participants[0].is_admin);
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
        assert_eq!(normalized[1].jid, lid_jid);
    }

    #[test]
    fn test_build_create_group_node_includes_phone_number_for_lid() {
        let lid_jid: Jid = "100000000000001@lid".parse().unwrap();
        let phone_jid: Jid = "15550000001@s.whatsapp.net".parse().unwrap();

        let options = GroupCreateOptions::new("subject").with_participants(vec![
            GroupParticipantOptions::from_lid_and_phone(lid_jid.clone(), phone_jid.clone()),
        ]);

        let create_node = build_create_group_node(&options);
        let participants = create_node.get_children_by_tag("participant");
        assert_eq!(participants.len(), 1);

        let participant = participants[0];
        let participant_jid = participant.attrs().jid("jid");
        let participant_phone = participant.attrs().optional_jid("phone_number");

        assert_eq!(participant_jid, lid_jid);
        assert_eq!(participant_phone, Some(phone_jid));
    }

    #[test]
    fn test_build_create_group_node_includes_modes_ephemeral_and_membership() {
        let pn_jid: Jid = "15551234567@s.whatsapp.net".parse().unwrap();
        let options = GroupCreateOptions::new("subject")
            .with_participant(GroupParticipantOptions::from_phone(pn_jid))
            .with_member_link_mode(MemberLinkMode::AllMemberLink)
            .with_member_add_mode(MemberAddMode::AdminAdd)
            .with_membership_approval_mode(MembershipApprovalMode::On)
            .with_ephemeral_expiration(86400);

        let create_node = build_create_group_node(&options);

        let link_mode = create_node.get_children_by_tag("member_link_mode")[0];
        let add_mode = create_node.get_children_by_tag("member_add_mode")[0];
        let ephemeral = create_node.get_children_by_tag("ephemeral")[0];
        let approval = create_node.get_children_by_tag("membership_approval_mode")[0];
        let join = approval.get_children_by_tag("group_join")[0];

        let link_mode_value = match link_mode.content.as_ref() {
            Some(NodeContent::String(value)) => value.as_str(),
            _ => "",
        };
        let add_mode_value = match add_mode.content.as_ref() {
            Some(NodeContent::String(value)) => value.as_str(),
            _ => "",
        };

        assert_eq!(link_mode_value, "all_member_link");
        assert_eq!(add_mode_value, "admin_add");
        assert_eq!(ephemeral.attrs().string("expiration"), "86400");
        assert_eq!(join.attrs().string("state"), "on");
    }

    #[test]
    fn test_build_create_group_node_includes_privacy_child() {
        let lid_jid: Jid = "100000000000001@lid".parse().unwrap();
        let phone_jid: Jid = "15550000001@s.whatsapp.net".parse().unwrap();

        let options = GroupCreateOptions::new("subject").with_participants(vec![
            GroupParticipantOptions::from_lid_and_phone(lid_jid, phone_jid)
                .with_privacy(vec![0x01, 0x02, 0x0f]),
        ]);

        let create_node = build_create_group_node(&options);
        let participant = create_node.get_children_by_tag("participant")[0];
        let privacy = participant.get_children_by_tag("privacy")[0];

        let privacy_value = match privacy.content.as_ref() {
            Some(NodeContent::String(value)) => value.as_str(),
            _ => "",
        };

        assert_eq!(privacy_value, "01020f");
    }
}
