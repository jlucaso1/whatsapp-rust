use crate::client::Client;
use crate::features::mex::{MexError, MexRequest};
use std::collections::HashMap;
use wacore::client::context::GroupInfo;
use wacore::iq::groups::{
    AcceptGroupInviteIq, AcceptGroupInviteV4Iq, AcknowledgeGroupIq, AddParticipantsIq,
    BatchGetGroupInfoIq, CancelMembershipRequestsIq, DemoteParticipantsIq, GetGroupInviteInfoIq,
    GetGroupInviteLinkIq, GetGroupProfilePicturesIq, GetMembershipRequestsIq, GroupCreateIq,
    GroupInfoResponse, GroupParticipantResponse, GroupParticipatingIq, GroupQueryIq, LeaveGroupIq,
    MembershipRequestActionIq, PromoteParticipantsIq, RemoveParticipantsIq, RevokeRequestCodeIq,
    SetAllowAdminReportsIq, SetGroupAnnouncementIq, SetGroupDescriptionIq, SetGroupEphemeralIq,
    SetGroupHistoryIq, SetGroupLockedIq, SetGroupMembershipApprovalIq, SetGroupSubjectIq,
    SetMemberAddModeIq, SetNoFrequentlyForwardedIq, normalize_participants,
};
use wacore::types::message::AddressingMode;
use wacore_binary::Jid;

use wacore::iq::groups::BatchGroupInfoResult as RawBatchResult;
pub use wacore::iq::groups::{
    GroupCreateOptions, GroupDescription, GroupJoinError, GroupParticipantOptions,
    GroupProfilePicture, GroupSubject, GrowthLockInfo, InviteInfoError, JoinGroupResult,
    MemberAddMode, MemberLinkMode, MemberShareHistoryMode, MembershipApprovalMode,
    MembershipRequest, ParticipantChangeResponse, ParticipantType, PictureType,
};

/// Result for a single group in a batch query.
#[derive(Debug, Clone)]
pub enum BatchGroupResult {
    Full(Box<GroupMetadata>),
    /// Server returned truncated info (only id and size).
    Truncated {
        id: Jid,
        size: Option<u32>,
    },
    Forbidden(Jid),
    NotFound(Jid),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupMetadata {
    pub id: Jid,
    pub subject: String,
    pub participants: Vec<GroupParticipant>,
    pub addressing_mode: AddressingMode,
    /// Group creator JID.
    pub creator: Option<Jid>,
    /// Group creation timestamp (Unix seconds).
    pub creation_time: Option<u64>,
    /// Subject modification timestamp (Unix seconds).
    pub subject_time: Option<u64>,
    /// Subject owner JID.
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
    /// Disappearing mode trigger (from `trigger` attribute on `<ephemeral>`).
    pub ephemeral_trigger: Option<u32>,
    /// Whether membership approval is required to join.
    pub membership_approval: bool,
    /// Who can add members to the group.
    pub member_add_mode: Option<MemberAddMode>,
    /// Who can use invite links.
    pub member_link_mode: Option<MemberLinkMode>,
    /// Total participant count.
    pub size: Option<u32>,
    /// Whether this group is a community parent group.
    pub is_parent_group: bool,
    /// JID of the parent community (for subgroups).
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupParticipant {
    pub jid: Jid,
    pub phone_number: Option<Jid>,
    pub participant_type: ParticipantType,
}

impl GroupParticipant {
    pub fn is_admin(&self) -> bool {
        self.participant_type.is_admin()
    }

    pub fn is_super_admin(&self) -> bool {
        self.participant_type == ParticipantType::SuperAdmin
    }
}

impl From<GroupParticipantResponse> for GroupParticipant {
    fn from(p: GroupParticipantResponse) -> Self {
        Self {
            jid: p.jid,
            phone_number: p.phone_number,
            participant_type: p.participant_type,
        }
    }
}

impl From<GroupInfoResponse> for GroupMetadata {
    fn from(group: GroupInfoResponse) -> Self {
        Self {
            id: group.id,
            subject: group.subject.into_string(),
            participants: group.participants.into_iter().map(Into::into).collect(),
            addressing_mode: group.addressing_mode,
            creator: group.creator,
            creation_time: group.creation_time,
            subject_time: group.subject_time,
            subject_owner: group.subject_owner,
            description: group.description,
            description_id: group.description_id,
            description_owner: group.description_owner,
            description_time: group.description_time,
            is_locked: group.is_locked,
            is_announcement: group.is_announcement,
            ephemeral_expiration: group.ephemeral_expiration,
            ephemeral_trigger: group.ephemeral_trigger,
            membership_approval: group.membership_approval,
            member_add_mode: group.member_add_mode,
            member_link_mode: group.member_link_mode,
            size: group.size,
            is_parent_group: group.is_parent_group,
            parent_group_jid: group.parent_group_jid,
            is_default_sub_group: group.is_default_sub_group,
            is_general_chat: group.is_general_chat,
            allow_non_admin_sub_group_creation: group.allow_non_admin_sub_group_creation,
            no_frequently_forwarded: group.no_frequently_forwarded,
            member_share_history_mode: group.member_share_history_mode,
            growth_locked: group.growth_locked,
            is_suspended: group.is_suspended,
            allow_admin_reports: group.allow_admin_reports,
            is_hidden_group: group.is_hidden_group,
            is_incognito: group.is_incognito,
            has_group_history: group.has_group_history,
            is_limit_sharing_enabled: group.is_limit_sharing_enabled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateGroupResult {
    pub gid: Jid,
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

        let group = self.client.execute(GroupQueryIq::new(jid)).await?;

        let participants: Vec<Jid> = group.participants.iter().map(|p| p.jid.clone()).collect();

        let lid_to_pn_map: HashMap<wacore_binary::CompactString, Jid> =
            if group.addressing_mode == AddressingMode::Lid {
                group
                    .participants
                    .iter()
                    .filter_map(|p| {
                        p.phone_number
                            .as_ref()
                            .map(|pn| (p.jid.user.clone(), pn.clone()))
                    })
                    .collect()
            } else {
                HashMap::new()
            };

        let mut info = GroupInfo::new(participants, group.addressing_mode);
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
        let response = self.client.execute(GroupParticipatingIq::new()).await?;

        let result = response
            .groups
            .into_iter()
            .map(|group| {
                let key = group.id.to_string();
                let metadata = GroupMetadata::from(group);
                (key, metadata)
            })
            .collect();

        Ok(result)
    }

    pub async fn get_metadata(&self, jid: &Jid) -> Result<GroupMetadata, anyhow::Error> {
        let group = self.client.execute(GroupQueryIq::new(jid)).await?;
        Ok(GroupMetadata::from(group))
    }

    pub async fn create_group(
        &self,
        mut options: GroupCreateOptions,
    ) -> Result<CreateGroupResult, anyhow::Error> {
        // Resolve phone numbers for LID participants that don't have one
        let mut resolved_participants = Vec::with_capacity(options.participants.len());

        for participant in options.participants {
            let resolved = if participant.jid.is_lid() && participant.phone_number.is_none() {
                let entry = self
                    .client
                    .get_lid_pn_entry(&participant.jid)
                    .await
                    .ok_or_else(|| {
                        anyhow::anyhow!("Missing phone number mapping for LID {}", participant.jid)
                    })?;
                participant.with_phone_number(Jid::pn(entry.phone_number))
            } else {
                participant
            };
            resolved_participants.push(resolved);
        }

        options.participants = normalize_participants(&resolved_participants);

        if self
            .client
            .ab_props()
            .is_enabled(wacore::iq::props::config_codes::PRIVACY_TOKEN_ON_GROUP_CREATE)
            .await
        {
            self.attach_tokens_to_participants(&mut options.participants)
                .await;
        }

        let gid = self.client.execute(GroupCreateIq::new(options)).await?;

        Ok(CreateGroupResult { gid })
    }

    pub async fn set_subject(&self, jid: &Jid, subject: GroupSubject) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(SetGroupSubjectIq::new(jid, subject))
            .await?)
    }

    /// Sets or deletes a group's description.
    ///
    /// `prev` is the current description ID (from group metadata) used for
    /// conflict detection. Pass `None` if unknown.
    pub async fn set_description(
        &self,
        jid: &Jid,
        description: Option<GroupDescription>,
        prev: Option<String>,
    ) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(SetGroupDescriptionIq::new(jid, description, prev))
            .await?)
    }

    pub async fn leave(&self, jid: &Jid) -> Result<(), anyhow::Error> {
        self.client.execute(LeaveGroupIq::new(jid)).await?;
        self.client.get_group_cache().await.invalidate(jid).await;
        Ok(())
    }

    pub async fn add_participants(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<Vec<ParticipantChangeResponse>, anyhow::Error> {
        let iq = if self
            .client
            .ab_props()
            .is_enabled(wacore::iq::props::config_codes::PRIVACY_TOKEN_ON_GROUP_PARTICIPANT_ADD)
            .await
        {
            let options = self.resolve_participant_tokens(participants).await;
            AddParticipantsIq::with_options(jid, options)
        } else {
            AddParticipantsIq::new(jid, participants)
        };

        let result = self.client.execute(iq).await?;
        // Patch cache with only the participants the server accepted (status 200).
        // Note: the get→mutate→insert is not atomic; a concurrent notification
        // for the same group could race.  This is acceptable — the cache is
        // best-effort and a full refetch on next query_info() corrects it.
        let accepted: Vec<_> = result
            .iter()
            .filter(|r| r.status.as_deref() == Some("200"))
            .map(|r| (r.jid.clone(), None))
            .collect();
        if !accepted.is_empty() {
            let group_cache = self.client.get_group_cache().await;
            if let Some(mut info) = group_cache.get(jid).await {
                info.add_participants(&accepted);
                group_cache.insert(jid.clone(), info).await;
            }
        }
        Ok(result)
    }

    pub async fn remove_participants(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<Vec<ParticipantChangeResponse>, anyhow::Error> {
        let result = self
            .client
            .execute(RemoveParticipantsIq::new(jid, participants))
            .await?;
        // Patch cache with only the participants the server accepted.
        let accepted: Vec<&str> = result
            .iter()
            .filter(|r| r.status.as_deref() == Some("200"))
            .map(|r| r.jid.user.as_str())
            .collect();
        if !accepted.is_empty() {
            let group_cache = self.client.get_group_cache().await;
            if let Some(mut info) = group_cache.get(jid).await {
                info.remove_participants(&accepted);
                group_cache.insert(jid.clone(), info).await;
            }
        }
        Ok(result)
    }

    pub async fn promote_participants(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(PromoteParticipantsIq::new(jid, participants))
            .await?)
    }

    pub async fn demote_participants(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(DemoteParticipantsIq::new(jid, participants))
            .await?)
    }

    pub async fn get_invite_link(&self, jid: &Jid, reset: bool) -> Result<String, anyhow::Error> {
        Ok(self
            .client
            .execute(GetGroupInviteLinkIq::new(jid, reset))
            .await?)
    }

    /// Lock the group so only admins can change group info.
    pub async fn set_locked(&self, jid: &Jid, locked: bool) -> Result<(), anyhow::Error> {
        let spec = if locked {
            SetGroupLockedIq::lock(jid)
        } else {
            SetGroupLockedIq::unlock(jid)
        };
        Ok(self.client.execute(spec).await?)
    }

    /// Set announcement mode. When enabled, only admins can send messages.
    pub async fn set_announce(&self, jid: &Jid, announce: bool) -> Result<(), anyhow::Error> {
        let spec = if announce {
            SetGroupAnnouncementIq::announce(jid)
        } else {
            SetGroupAnnouncementIq::unannounce(jid)
        };
        Ok(self.client.execute(spec).await?)
    }

    /// Set ephemeral (disappearing) messages timer on the group.
    ///
    /// Common values: 86400 (24h), 604800 (7d), 7776000 (90d).
    /// Pass 0 to disable.
    pub async fn set_ephemeral(&self, jid: &Jid, expiration: u32) -> Result<(), anyhow::Error> {
        let spec = match std::num::NonZeroU32::new(expiration) {
            Some(exp) => SetGroupEphemeralIq::enable(jid, exp),
            None => SetGroupEphemeralIq::disable(jid),
        };
        Ok(self.client.execute(spec).await?)
    }

    /// Set membership approval mode. When on, new members must be approved by an admin.
    pub async fn set_membership_approval(
        &self,
        jid: &Jid,
        mode: MembershipApprovalMode,
    ) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(SetGroupMembershipApprovalIq::new(jid, mode))
            .await?)
    }

    /// Join a group using an invite code.
    pub async fn join_with_invite_code(
        &self,
        code: &str,
    ) -> Result<JoinGroupResult, anyhow::Error> {
        let code = extract_invite_code(code)
            .ok_or_else(|| anyhow::anyhow!("invalid or empty invite code"))?;
        Ok(self.client.execute(AcceptGroupInviteIq::new(code)).await?)
    }

    /// Accept a V4 invite (received as a GroupInviteMessage, not a link).
    pub async fn join_with_invite_v4(
        &self,
        group_jid: &Jid,
        code: &str,
        expiration: i64,
        admin_jid: &Jid,
    ) -> Result<JoinGroupResult, anyhow::Error> {
        if expiration > 0 {
            let now = wacore::time::now_millis() / 1000;
            if expiration < now {
                anyhow::bail!("V4 invite has expired (expiration={expiration}, now={now})");
            }
        }
        Ok(self
            .client
            .execute(AcceptGroupInviteV4Iq::new(
                group_jid.clone(),
                code.to_string(),
                expiration,
                admin_jid.clone(),
            ))
            .await?)
    }

    /// Get group metadata from an invite code without joining.
    pub async fn get_invite_info(&self, code: &str) -> Result<GroupMetadata, anyhow::Error> {
        let code = extract_invite_code(code)
            .ok_or_else(|| anyhow::anyhow!("invalid or empty invite code"))?;
        let group = self.client.execute(GetGroupInviteInfoIq::new(code)).await?;
        Ok(GroupMetadata::from(group))
    }

    /// Get pending membership approval requests.
    pub async fn get_membership_requests(
        &self,
        jid: &Jid,
    ) -> Result<Vec<MembershipRequest>, anyhow::Error> {
        Ok(self
            .client
            .execute(GetMembershipRequestsIq::new(jid))
            .await?)
    }

    /// Approve pending membership requests.
    pub async fn approve_membership_requests(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<Vec<ParticipantChangeResponse>, anyhow::Error> {
        Ok(self
            .client
            .execute(MembershipRequestActionIq::approve(jid, participants))
            .await?)
    }

    /// Reject pending membership requests.
    pub async fn reject_membership_requests(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<Vec<ParticipantChangeResponse>, anyhow::Error> {
        Ok(self
            .client
            .execute(MembershipRequestActionIq::reject(jid, participants))
            .await?)
    }

    /// Set who can add members to the group.
    pub async fn set_member_add_mode(
        &self,
        jid: &Jid,
        mode: MemberAddMode,
    ) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(SetMemberAddModeIq::new(jid, mode))
            .await?)
    }

    /// Restrict or allow frequently-forwarded messages in the group.
    pub async fn set_no_frequently_forwarded(
        &self,
        jid: &Jid,
        restrict: bool,
    ) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(SetNoFrequentlyForwardedIq::new(jid, restrict))
            .await?)
    }

    /// Enable or disable admin reports in the group.
    pub async fn set_allow_admin_reports(
        &self,
        jid: &Jid,
        allow: bool,
    ) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(SetAllowAdminReportsIq::new(jid, allow))
            .await?)
    }

    /// Enable or disable group history sharing.
    pub async fn set_group_history(&self, jid: &Jid, enabled: bool) -> Result<(), anyhow::Error> {
        Ok(self
            .client
            .execute(SetGroupHistoryIq::new(jid, enabled))
            .await?)
    }

    /// Set who can share invite links (via MEX).
    pub async fn set_member_link_mode(
        &self,
        jid: &Jid,
        mode: MemberLinkMode,
    ) -> Result<(), MexError> {
        let value = match mode {
            MemberLinkMode::AdminLink => "ADMIN_LINK",
            MemberLinkMode::AllMemberLink => "ALL_MEMBER_LINK",
        };
        self.mex_update_group_property(jid, serde_json::json!({ "member_link_mode": value }))
            .await
    }

    /// Set who can share message history with new members (via MEX).
    pub async fn set_member_share_history_mode(
        &self,
        jid: &Jid,
        mode: MemberShareHistoryMode,
    ) -> Result<(), MexError> {
        let value = match mode {
            MemberShareHistoryMode::AdminShare => "ADMIN_SHARE",
            MemberShareHistoryMode::AllMemberShare => "ALL_MEMBER_SHARE",
        };
        self.mex_update_group_property(
            jid,
            serde_json::json!({ "member_share_group_history_mode": value }),
        )
        .await
    }

    /// Enable or disable limit sharing in the group (via MEX).
    pub async fn set_limit_sharing(&self, jid: &Jid, enabled: bool) -> Result<(), MexError> {
        self.mex_update_group_property(
            jid,
            serde_json::json!({
                "limit_sharing": {
                    "limit_sharing_enabled": enabled,
                    "limit_sharing_trigger": "CHAT_SETTING"
                }
            }),
        )
        .await
    }

    /// Cancel pending membership requests (from the requesting user's side).
    pub async fn cancel_membership_requests(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<Vec<ParticipantChangeResponse>, anyhow::Error> {
        Ok(self
            .client
            .execute(CancelMembershipRequestsIq::new(jid, participants))
            .await?)
    }

    /// Revoke invitation codes from specific participants (admin operation).
    pub async fn revoke_request_code(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<Vec<ParticipantChangeResponse>, anyhow::Error> {
        Ok(self
            .client
            .execute(RevokeRequestCodeIq::new(jid, participants))
            .await?)
    }

    /// Acknowledge a group notification.
    pub async fn acknowledge(&self, jid: &Jid) -> Result<(), anyhow::Error> {
        Ok(self.client.execute(AcknowledgeGroupIq::new(jid)).await?)
    }

    /// Batch query group info for multiple groups at once (max 10,000).
    pub async fn batch_get_info(
        &self,
        jids: Vec<Jid>,
    ) -> Result<Vec<BatchGroupResult>, anyhow::Error> {
        anyhow::ensure!(
            jids.len() <= wacore::iq::groups::BATCH_GROUP_INFO_LIMIT,
            "batch_get_info: {} groups exceeds limit of {}",
            jids.len(),
            wacore::iq::groups::BATCH_GROUP_INFO_LIMIT,
        );
        let raw = self.client.execute(BatchGetGroupInfoIq::new(jids)).await?;
        Ok(raw
            .into_iter()
            .map(|r| match r {
                RawBatchResult::Full(info) => {
                    BatchGroupResult::Full(Box::new(GroupMetadata::from(*info)))
                }
                RawBatchResult::Truncated { id, size } => BatchGroupResult::Truncated { id, size },
                RawBatchResult::Forbidden(id) => BatchGroupResult::Forbidden(id),
                RawBatchResult::NotFound(id) => BatchGroupResult::NotFound(id),
            })
            .collect())
    }

    /// Batch fetch group profile pictures (max 1,000).
    pub async fn get_profile_pictures(
        &self,
        group_jids: Vec<Jid>,
        picture_type: PictureType,
    ) -> Result<Vec<GroupProfilePicture>, anyhow::Error> {
        anyhow::ensure!(
            group_jids.len() <= wacore::iq::groups::BATCH_PROFILE_PICTURES_LIMIT,
            "get_profile_pictures: {} groups exceeds limit of {}",
            group_jids.len(),
            wacore::iq::groups::BATCH_PROFILE_PICTURES_LIMIT,
        );
        let groups = group_jids
            .into_iter()
            .map(|jid| (jid, picture_type))
            .collect();
        Ok(self
            .client
            .execute(GetGroupProfilePicturesIq::with_type(groups))
            .await?)
    }

    async fn mex_update_group_property(
        &self,
        jid: &Jid,
        update: serde_json::Value,
    ) -> Result<(), MexError> {
        let resp = self
            .client
            .mex()
            .mutate(MexRequest {
                doc_id: wacore::iq::groups::mex_docs::UPDATE_GROUP_PROPERTY,
                variables: serde_json::json!({
                    "group_id": jid.to_string(),
                    "update": update,
                }),
            })
            .await?;

        let state = resp
            .data
            .as_ref()
            .and_then(|d| d.get("xwa2_group_update_property"))
            .and_then(|r| r.get("state"))
            .and_then(|s| s.as_str());

        if state != Some("ACTIVE") {
            return Err(MexError::PayloadParsing(format!(
                "group property update failed, state: {state:?}"
            )));
        }

        Ok(())
    }

    async fn resolve_participant_tokens(&self, jids: &[Jid]) -> Vec<GroupParticipantOptions> {
        if jids.is_empty() {
            return Vec::new();
        }
        let only_lid = self.only_check_lid().await;
        let futs = jids.iter().map(|jid| async move {
            let mut opt = GroupParticipantOptions::new(jid.clone());
            if let Some(token_key) = self.resolve_token_key(jid, only_lid).await
                && let Some(token) = self.lookup_valid_token(&token_key).await
            {
                opt = opt.with_privacy(token);
            }
            opt
        });
        futures::future::join_all(futs).await
    }

    /// Skips participants that already have a token set by the caller.
    async fn attach_tokens_to_participants(&self, participants: &mut [GroupParticipantOptions]) {
        if participants.is_empty() {
            return;
        }
        let only_lid = self.only_check_lid().await;
        let futs = participants.iter().enumerate().map(|(i, p)| async move {
            if p.privacy.is_some() {
                return (i, None);
            }
            let Some(token_key) = self.resolve_token_key(&p.jid, only_lid).await else {
                log::debug!(
                    target: "Client/Groups",
                    "No LID mapping for participant {}, skipping privacy attachment",
                    p.jid
                );
                return (i, None);
            };
            let token = self.lookup_valid_token(&token_key).await;
            if token.is_none() {
                log::debug!(
                    target: "Client/Groups",
                    "No valid tc_token for participant {} (key={}), skipping privacy attachment",
                    p.jid, token_key
                );
            }
            (i, token)
        });
        for (i, token) in futures::future::join_all(futs).await {
            if token.is_some() {
                participants[i].privacy = token;
            }
        }
    }

    async fn only_check_lid(&self) -> bool {
        self.client
            .ab_props()
            .is_enabled(wacore::iq::props::config_codes::PRIVACY_TOKEN_ONLY_CHECK_LID)
            .await
    }

    /// Resolve JID to tc_token store key. When `only_lid`, PN JIDs without a
    /// LID mapping return `None` instead of falling back to the PN user.
    async fn resolve_token_key(&self, jid: &Jid, only_lid: bool) -> Option<String> {
        if jid.is_lid() {
            Some(jid.user.to_string())
        } else {
            let lid = self.client.lid_pn_cache.get_current_lid(&jid.user).await;
            if only_lid {
                lid
            } else {
                Some(lid.unwrap_or_else(|| jid.user.to_string()))
            }
        }
    }

    /// Returns the tc_token if present and not expired.
    async fn lookup_valid_token(&self, token_key: &str) -> Option<Vec<u8>> {
        use wacore::iq::tctoken::is_tc_token_expired_with;
        let tc_config = self.client.tc_token_config().await;
        let backend = self.client.persistence_manager.backend();
        match backend.get_tc_token(token_key).await {
            Ok(Some(entry))
                if !entry.token.is_empty()
                    && !is_tc_token_expired_with(entry.token_timestamp, &tc_config) =>
            {
                Some(entry.token)
            }
            Ok(_) => None,
            Err(e) => {
                log::warn!(
                    target: "Client/Groups",
                    "Failed to get tc_token for {}: {e}",
                    token_key
                );
                None
            }
        }
    }
}

impl Client {
    pub fn groups(&self) -> Groups<'_> {
        Groups::new(self)
    }
}

/// Extract the invite code from any supported invite URL format.
///
/// Handles all WA Web patterns:
/// - `https://chat.whatsapp.com/CODE?query`
/// - `https://chat.whatsapp.com/invite/CODE?query`
/// - `https://web.whatsapp.com/.../accept/?code=CODE&...`
/// - `whatsapp://chat/?code=CODE`
/// - bare code string
fn extract_invite_code(input: &str) -> Option<&str> {
    let input = input.trim();

    // whatsapp://chat/?code=CODE or web.whatsapp.com/.../accept/?code=CODE
    if let Some(code) = extract_code_param(input) {
        return Some(code);
    }

    // https://chat.whatsapp.com/invite/CODE or https://chat.whatsapp.com/CODE
    let stripped = input
        .strip_prefix("https://chat.whatsapp.com/")
        .or_else(|| input.strip_prefix("http://chat.whatsapp.com/"));

    let code = if let Some(path) = stripped {
        let path = path.strip_prefix("invite/").unwrap_or(path);
        path.split('?').next().unwrap_or(path).trim_end_matches('/')
    } else if input.contains("://") || input.contains('?') {
        // Looks like a URL we don't recognize or one with an empty code= param
        return None;
    } else {
        input.trim_end_matches('/')
    };

    if code.is_empty() { None } else { Some(code) }
}

fn extract_code_param(input: &str) -> Option<&str> {
    let query = input.split('?').nth(1)?;
    for pair in query.split('&') {
        if let Some(val) = pair.strip_prefix("code=") {
            let val = val.trim_end_matches('/');
            if !val.is_empty() {
                return Some(val);
            }
        }
    }
    None
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
                participant_type: ParticipantType::Admin,
            }],
            ..Default::default()
        };

        assert_eq!(metadata.subject, "Test Group");
        assert_eq!(metadata.participants.len(), 1);
        assert!(metadata.participants[0].is_admin());
        assert!(!metadata.participants[0].is_super_admin());
    }

    #[test]
    fn test_extract_invite_code() {
        // Pattern 3: most common
        assert_eq!(
            extract_invite_code("https://chat.whatsapp.com/AbCdEfGh").unwrap(),
            "AbCdEfGh"
        );
        assert_eq!(
            extract_invite_code("http://chat.whatsapp.com/AbCdEfGh").unwrap(),
            "AbCdEfGh"
        );

        // With query params
        assert_eq!(
            extract_invite_code("https://chat.whatsapp.com/AbCdEfGh?fbclid=123&utm_source=x")
                .unwrap(),
            "AbCdEfGh"
        );

        // Trailing slash
        assert_eq!(
            extract_invite_code("https://chat.whatsapp.com/AbCdEfGh/").unwrap(),
            "AbCdEfGh"
        );

        // Pattern 2: /invite/ prefix
        assert_eq!(
            extract_invite_code("https://chat.whatsapp.com/invite/AbCdEfGh").unwrap(),
            "AbCdEfGh"
        );
        assert_eq!(
            extract_invite_code("https://chat.whatsapp.com/invite/AbCdEfGh?utm=test").unwrap(),
            "AbCdEfGh"
        );

        // Pattern 1: web.whatsapp.com/accept?code=
        assert_eq!(
            extract_invite_code("https://web.whatsapp.com/accept?code=AbCdEfGh").unwrap(),
            "AbCdEfGh"
        );
        assert_eq!(
            extract_invite_code("https://web.whatsapp.com/accept/?code=AbCdEfGh&other=1").unwrap(),
            "AbCdEfGh"
        );

        // Pattern 4: deep link
        assert_eq!(
            extract_invite_code("whatsapp://chat/?code=AbCdEfGh").unwrap(),
            "AbCdEfGh"
        );
        assert_eq!(
            extract_invite_code("whatsapp://chat?code=AbCdEfGh&extra=y").unwrap(),
            "AbCdEfGh"
        );

        // Bare code
        assert_eq!(extract_invite_code("AbCdEfGh").unwrap(), "AbCdEfGh");
        assert_eq!(extract_invite_code("AbCdEfGh/").unwrap(), "AbCdEfGh");

        // Whitespace
        assert_eq!(extract_invite_code("  AbCdEfGh  ").unwrap(), "AbCdEfGh");

        // Empty / malformed inputs return None
        assert!(extract_invite_code("").is_none());
        assert!(extract_invite_code("   ").is_none());
        assert!(extract_invite_code("https://chat.whatsapp.com/").is_none());
        assert!(extract_invite_code("https://chat.whatsapp.com/invite/").is_none());
        assert!(extract_invite_code("whatsapp://chat/?code=").is_none());
        assert!(extract_invite_code("whatsapp://chat/?code=&other=1").is_none());
    }

    // Protocol-level tests (node building, parsing, validation) are in wacore/src/iq/groups.rs
}
