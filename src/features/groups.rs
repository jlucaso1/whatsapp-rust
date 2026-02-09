use crate::client::Client;
use std::collections::HashMap;
use wacore::client::context::GroupInfo;
use wacore::iq::groups::{
    AddParticipantsIq, DemoteParticipantsIq, GetGroupInviteLinkIq, GroupCreateIq,
    GroupParticipantResponse, GroupParticipatingIq, GroupQueryIq, LeaveGroupIq,
    PromoteParticipantsIq, RemoveParticipantsIq, SetGroupDescriptionIq, SetGroupSubjectIq,
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
                let metadata = GroupMetadata {
                    id: group.id,
                    subject: group.subject.into_string(),
                    participants: group.participants.into_iter().map(Into::into).collect(),
                    addressing_mode: group.addressing_mode,
                };
                (key, metadata)
            })
            .collect();

        Ok(result)
    }

    pub async fn get_metadata(&self, jid: &Jid) -> Result<GroupMetadata, anyhow::Error> {
        let group = self.client.execute(GroupQueryIq::new(jid)).await?;

        Ok(GroupMetadata {
            id: group.id,
            subject: group.subject.into_string(),
            participants: group.participants.into_iter().map(Into::into).collect(),
            addressing_mode: group.addressing_mode,
        })
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
        Ok(self.client.execute(LeaveGroupIq::new(jid)).await?)
    }

    pub async fn add_participants(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<Vec<ParticipantChangeResponse>, anyhow::Error> {
        Ok(self
            .client
            .execute(AddParticipantsIq::new(jid, participants))
            .await?)
    }

    pub async fn remove_participants(
        &self,
        jid: &Jid,
        participants: &[Jid],
    ) -> Result<Vec<ParticipantChangeResponse>, anyhow::Error> {
        Ok(self
            .client
            .execute(RemoveParticipantsIq::new(jid, participants))
            .await?)
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
        };

        assert_eq!(metadata.subject, "Test Group");
        assert_eq!(metadata.participants.len(), 1);
        assert!(metadata.participants[0].is_admin);
    }

    // Protocol-level tests (node building, parsing, validation) are in wacore/src/iq/groups.rs
}
