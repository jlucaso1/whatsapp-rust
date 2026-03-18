//! Community feature.
//!
//! Communities are parent groups that contain linked subgroups.
//! Uses the `w:g2` IQ namespace for mutations and MEX (GraphQL) for metadata queries.

use crate::client::Client;
use crate::features::groups::GroupMetadata;
use crate::features::groups::GroupParticipant;
use crate::features::mex::{MexError, MexRequest};
use log::warn;
use serde_json::json;
use wacore::iq::community::mex_docs;
use wacore::iq::groups::{
    DeleteCommunityIq, GetLinkedGroupsParticipantsIq, GroupCreateIq, GroupCreateOptions,
    JoinLinkedGroupIq, LinkSubgroupsIq, QueryLinkedGroupIq, UnlinkSubgroupsIq,
};
use wacore_binary::jid::Jid;

// Types

/// Classification of a group within the community hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupType {
    /// Regular standalone group (not part of a community).
    Default,
    /// Community parent group.
    Community,
    /// A subgroup linked to a community.
    LinkedSubgroup,
    /// The default announcement subgroup of a community.
    LinkedAnnouncementGroup,
    /// The general chat subgroup of a community.
    LinkedGeneralGroup,
}

/// Options for creating a new community.
#[derive(Debug, Clone)]
pub struct CreateCommunityOptions {
    pub name: String,
    pub description: Option<String>,
    /// Whether the community is closed (requires approval to join).
    pub closed: bool,
    /// Allow non-admin members to create subgroups.
    pub allow_non_admin_sub_group_creation: bool,
    /// Create a general chat subgroup alongside the community.
    pub create_general_chat: bool,
}

impl CreateCommunityOptions {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: None,
            closed: false,
            allow_non_admin_sub_group_creation: false,
            create_general_chat: true,
        }
    }
}

/// Result of creating a community.
#[derive(Debug, Clone)]
pub struct CreateCommunityResult {
    /// JID of the created community parent group.
    pub gid: Jid,
}

/// A subgroup within a community.
#[derive(Debug, Clone)]
pub struct CommunitySubgroup {
    pub id: Jid,
    pub subject: String,
    pub participant_count: Option<u32>,
    pub is_default_sub_group: bool,
    pub is_general_chat: bool,
}

/// Result of linking subgroups to a community.
#[derive(Debug, Clone)]
pub struct LinkSubgroupsResult {
    pub linked_jids: Vec<Jid>,
    pub failed_groups: Vec<(Jid, u32)>,
}

/// Result of unlinking subgroups from a community.
#[derive(Debug, Clone)]
pub struct UnlinkSubgroupsResult {
    pub unlinked_jids: Vec<Jid>,
    pub failed_groups: Vec<(Jid, u32)>,
}

/// Determine the group type from metadata fields.
pub fn group_type(metadata: &GroupMetadata) -> GroupType {
    if metadata.is_default_sub_group {
        GroupType::LinkedAnnouncementGroup
    } else if metadata.is_general_chat {
        GroupType::LinkedGeneralGroup
    } else if metadata.parent_group_jid.is_some() {
        GroupType::LinkedSubgroup
    } else if metadata.is_parent_group {
        GroupType::Community
    } else {
        GroupType::Default
    }
}

// Feature handle

pub struct Community<'a> {
    client: &'a Client,
}

impl<'a> Community<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Create a new community.
    pub async fn create(
        &self,
        options: CreateCommunityOptions,
    ) -> Result<CreateCommunityResult, anyhow::Error> {
        let create_options = GroupCreateOptions {
            subject: options.name,
            is_parent: true,
            closed: options.closed,
            allow_non_admin_sub_group_creation: options.allow_non_admin_sub_group_creation,
            create_general_chat: options.create_general_chat,
            ..Default::default()
        };

        let gid = self
            .client
            .execute(GroupCreateIq::new(create_options))
            .await?;

        Ok(CreateCommunityResult { gid })
    }

    /// Deactivate (delete) a community. Subgroups are unlinked but not deleted.
    pub async fn deactivate(&self, community_jid: &Jid) -> Result<(), anyhow::Error> {
        self.client
            .execute(DeleteCommunityIq::new(community_jid))
            .await?;
        Ok(())
    }

    /// Link existing groups as subgroups of a community.
    pub async fn link_subgroups(
        &self,
        community_jid: &Jid,
        subgroup_jids: &[Jid],
    ) -> Result<LinkSubgroupsResult, anyhow::Error> {
        let response = self
            .client
            .execute(LinkSubgroupsIq::new(community_jid, subgroup_jids))
            .await?;

        let mut linked_jids = Vec::new();
        let mut failed_groups = Vec::new();

        for group in response.groups {
            if let Some(error) = group.error {
                failed_groups.push((group.jid, error));
            } else {
                linked_jids.push(group.jid);
            }
        }

        Ok(LinkSubgroupsResult {
            linked_jids,
            failed_groups,
        })
    }

    /// Unlink subgroups from a community.
    pub async fn unlink_subgroups(
        &self,
        community_jid: &Jid,
        subgroup_jids: &[Jid],
        remove_orphan_members: bool,
    ) -> Result<UnlinkSubgroupsResult, anyhow::Error> {
        let response = self
            .client
            .execute(UnlinkSubgroupsIq::new(
                community_jid,
                subgroup_jids,
                remove_orphan_members,
            ))
            .await?;

        let mut unlinked_jids = Vec::new();
        let mut failed_groups = Vec::new();

        for group in response.groups {
            if let Some(error) = group.error {
                failed_groups.push((group.jid, error));
            } else {
                unlinked_jids.push(group.jid);
            }
        }

        Ok(UnlinkSubgroupsResult {
            unlinked_jids,
            failed_groups,
        })
    }

    /// Fetch all subgroups of a community via MEX (GraphQL).
    pub async fn get_subgroups(
        &self,
        community_jid: &Jid,
    ) -> Result<Vec<CommunitySubgroup>, MexError> {
        let response = self
            .client
            .mex()
            .query(MexRequest {
                doc_id: mex_docs::FETCH_ALL_SUBGROUPS,
                variables: json!({
                    "group_id": community_jid.to_string()
                }),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data field".into()))?;

        let group_query = &data["xwa2_group_query_by_id"];
        let mut subgroups = Vec::new();

        // Parse default subgroup
        if let Some(default_sub) = group_query.get("default_sub_group")
            && !default_sub.is_null()
            && let Some(sg) = parse_subgroup_node(default_sub, true)
        {
            subgroups.push(sg);
        }

        // Parse regular subgroups
        if let Some(sub_groups) = group_query.get("sub_groups")
            && let Some(edges) = sub_groups.get("edges").and_then(|e| e.as_array())
        {
            for edge in edges {
                if let Some(node) = edge.get("node")
                    && let Some(sg) = parse_subgroup_node(node, false)
                {
                    subgroups.push(sg);
                }
            }
        }

        Ok(subgroups)
    }

    /// Fetch participant counts per subgroup via MEX (GraphQL).
    pub async fn get_subgroup_participant_counts(
        &self,
        community_jid: &Jid,
    ) -> Result<Vec<(Jid, u32)>, MexError> {
        let response = self
            .client
            .mex()
            .query(MexRequest {
                doc_id: mex_docs::FETCH_SUBGROUP_PARTICIPANT_COUNT,
                variables: json!({
                    "input": {
                        "group_jid": community_jid.to_string()
                    }
                }),
            })
            .await?;

        let data = response
            .data
            .ok_or_else(|| MexError::PayloadParsing("missing data field".into()))?;

        let group_query = &data["xwa2_group_query_by_id"];
        let mut counts = Vec::new();

        if let Some(sub_groups) = group_query.get("sub_groups")
            && let Some(edges) = sub_groups.get("edges").and_then(|e| e.as_array())
        {
            for edge in edges {
                if let Some(node) = edge.get("node") {
                    let id_str = node["id"].as_str().unwrap_or_default();
                    let count = node
                        .get("total_participants_count")
                        .or_else(|| node.get("participants_count"))
                        .and_then(|c| c.as_u64())
                        .unwrap_or(0) as u32;
                    match id_str.parse::<Jid>() {
                        Ok(jid) => counts.push((jid, count)),
                        Err(_) => warn!(
                            "community: skipping subgroup with unparseable id: {:?}",
                            id_str
                        ),
                    }
                }
            }
        }

        Ok(counts)
    }

    /// Query a linked subgroup's metadata from the parent community.
    pub async fn query_linked_group(
        &self,
        community_jid: &Jid,
        subgroup_jid: &Jid,
    ) -> Result<GroupMetadata, anyhow::Error> {
        let response = self
            .client
            .execute(QueryLinkedGroupIq::new(community_jid, subgroup_jid))
            .await?;
        Ok(GroupMetadata::from_response(response))
    }

    /// Join a linked subgroup via the parent community.
    pub async fn join_subgroup(
        &self,
        community_jid: &Jid,
        subgroup_jid: &Jid,
    ) -> Result<GroupMetadata, anyhow::Error> {
        let response = self
            .client
            .execute(JoinLinkedGroupIq::new(community_jid, subgroup_jid))
            .await?;
        Ok(GroupMetadata::from_response(response))
    }

    /// Get all participants across all linked groups of a community.
    pub async fn get_linked_groups_participants(
        &self,
        community_jid: &Jid,
    ) -> Result<Vec<GroupParticipant>, anyhow::Error> {
        let response = self
            .client
            .execute(GetLinkedGroupsParticipantsIq::new(community_jid))
            .await?;
        Ok(response.into_iter().map(Into::into).collect())
    }
}

fn parse_subgroup_node(node: &serde_json::Value, is_default: bool) -> Option<CommunitySubgroup> {
    let id_str = node.get("id")?.as_str()?;
    let jid: Jid = id_str.parse().ok()?;

    // Subject can be a plain string or an object {"value": "..."}
    let subject = node
        .get("subject")
        .and_then(|s| {
            s.as_str().map(|v| v.to_string()).or_else(|| {
                s.get("value")
                    .and_then(|v| v.as_str())
                    .map(|v| v.to_string())
            })
        })
        .unwrap_or_default();

    let participant_count = node
        .get("participants_count")
        .or_else(|| node.get("total_participants_count"))
        .and_then(|c| c.as_u64())
        .map(|c| c as u32);

    // Check if properties indicate general chat
    let is_general_from_props = node
        .get("properties")
        .and_then(|p| p.get("general_chat"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    Some(CommunitySubgroup {
        id: jid,
        subject,
        participant_count,
        is_default_sub_group: is_default,
        is_general_chat: is_general_from_props,
    })
}

impl Client {
    pub fn community(&self) -> Community<'_> {
        Community::new(self)
    }
}
