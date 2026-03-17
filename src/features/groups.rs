use crate::client::Client;
use std::collections::HashMap;
use wacore::client::context::GroupInfo;
use wacore::iq::groups::{
    AddParticipantsIq, DemoteParticipantsIq, GetGroupInviteLinkIq, GroupCreateIq,
    GroupInfoResponse, GroupParticipantResponse, GroupParticipatingIq, GroupQueryIq, LeaveGroupIq,
    PromoteParticipantsIq, RemoveParticipantsIq, SetGroupAnnouncementIq, SetGroupDescriptionIq,
    SetGroupEphemeralIq, SetGroupLockedIq, SetGroupMembershipApprovalIq, SetGroupSubjectIq,
    normalize_participants,
};
use wacore::types::message::AddressingMode;
use wacore_binary::jid::Jid;

pub use wacore::iq::groups::{
    GroupCreateOptions, GroupDescription, GroupParticipantOptions, GroupSubject, MemberAddMode,
    MemberLinkMode, MembershipApprovalMode, ParticipantChangeResponse,
};

#[derive(Debug, Clone)]
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
    /// Whether the group is locked (only admins can edit group info).
    pub is_locked: bool,
    /// Whether announcement mode is enabled (only admins can send messages).
    pub is_announcement: bool,
    /// Ephemeral message expiration in seconds (0 = disabled).
    pub ephemeral_expiration: u32,
    /// Whether membership approval is required to join.
    pub membership_approval: bool,
    /// Who can add members to the group.
    pub member_add_mode: Option<MemberAddMode>,
    /// Who can use invite links.
    pub member_link_mode: Option<MemberLinkMode>,
    /// Total participant count.
    pub size: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct GroupParticipant {
    pub jid: Jid,
    pub phone_number: Option<Jid>,
    pub is_admin: bool,
}

impl From<GroupParticipantResponse> for GroupParticipant {
    fn from(p: GroupParticipantResponse) -> Self {
        Self {
            jid: p.jid,
            phone_number: p.phone_number,
            is_admin: p.participant_type.is_admin(),
        }
    }
}

impl GroupMetadata {
    fn from_response(group: GroupInfoResponse) -> Self {
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
            is_locked: group.is_locked,
            is_announcement: group.is_announcement,
            ephemeral_expiration: group.ephemeral_expiration,
            membership_approval: group.membership_approval,
            member_add_mode: group.member_add_mode,
            member_link_mode: group.member_link_mode,
            size: group.size,
        }
    }
}

#[derive(Debug, Clone)]
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

        let lid_to_pn_map: HashMap<String, Jid> = if group.addressing_mode == AddressingMode::Lid {
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
                let metadata = GroupMetadata::from_response(group);
                (key, metadata)
            })
            .collect();

        Ok(result)
    }

    pub async fn get_metadata(&self, jid: &Jid) -> Result<GroupMetadata, anyhow::Error> {
        let group = self.client.execute(GroupQueryIq::new(jid)).await?;
        Ok(GroupMetadata::from_response(group))
    }

    pub async fn create_group(
        &self,
        mut options: GroupCreateOptions,
    ) -> Result<CreateGroupResult, anyhow::Error> {
        // Resolve phone numbers for LID participants that don't have one
        let mut resolved_participants = Vec::with_capacity(options.participants.len());

        for participant in options.participants {
            let resolved = if participant.jid.is_lid() && participant.phone_number.is_none() {
                let phone_number = self
                    .client
                    .get_phone_number_from_lid(&participant.jid.user)
                    .await
                    .ok_or_else(|| {
                        anyhow::anyhow!("Missing phone number mapping for LID {}", participant.jid)
                    })?;
                participant.with_phone_number(Jid::pn(phone_number))
            } else {
                participant
            };
            resolved_participants.push(resolved);
        }

        options.participants = normalize_participants(&resolved_participants);

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
        let result = self
            .client
            .execute(AddParticipantsIq::new(jid, participants))
            .await?;
        // Patch cache with the participants we just added (no phone_number
        // known here — the server notification will backfill the LID map).
        // Note: the get→mutate→insert is not atomic; a concurrent notification
        // for the same group could race.  This is acceptable — the cache is
        // best-effort and a full refetch on next query_info() corrects it.
        let group_cache = self.client.get_group_cache().await;
        if let Some(mut info) = group_cache.get(jid).await {
            let new: Vec<_> = participants.iter().map(|p| (p.clone(), None)).collect();
            info.add_participants(&new);
            group_cache.insert(jid.clone(), info).await;
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
        // Patch cache by filtering out removed participants (see add_participants
        // for race-condition note — same applies here).
        let group_cache = self.client.get_group_cache().await;
        if let Some(mut info) = group_cache.get(jid).await {
            let users: Vec<&str> = participants.iter().map(|p| p.user.as_str()).collect();
            info.remove_participants(&users);
            group_cache.insert(jid.clone(), info).await;
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
            addressing_mode: AddressingMode::Pn,
            creator: None,
            creation_time: None,
            subject_time: None,
            subject_owner: None,
            description: None,
            description_id: None,
            is_locked: false,
            is_announcement: false,
            ephemeral_expiration: 0,
            membership_approval: false,
            member_add_mode: None,
            member_link_mode: None,
            size: None,
        };

        assert_eq!(metadata.subject, "Test Group");
        assert_eq!(metadata.participants.len(), 1);
        assert!(metadata.participants[0].is_admin);
    }

    // Protocol-level tests (node building, parsing, validation) are in wacore/src/iq/groups.rs
}
