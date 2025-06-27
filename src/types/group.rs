use crate::types::jid::Jid;
use crate::types::message::AddressingMode;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupMemberAddMode {
    AdminAdd,
    AllMemberAdd,
}

#[derive(Debug, Clone, Default)]
pub struct GroupInfo {
    pub jid: Jid,
    pub owner_jid: Option<Jid>,
    pub owner_pn: Option<Jid>,
    pub name: GroupName,
    pub topic: GroupTopic,
    pub locked: GroupLocked,
    pub announce: GroupAnnounce,
    pub ephemeral: GroupEphemeral,
    pub incognito: GroupIncognito,
    pub parent: GroupParent,
    pub linked_parent: GroupLinkedParent,
    pub is_default_sub: GroupIsDefaultSub,
    pub membership_approval_mode: GroupMembershipApprovalMode,
    pub addressing_mode: Option<AddressingMode>,
    pub created: Option<DateTime<Utc>>,
    pub creator_country_code: Option<String>,
    pub participant_version_id: Option<String>,
    pub participants: Vec<GroupParticipant>,
    pub member_add_mode: Option<GroupMemberAddMode>,
}

#[derive(Debug, Clone, Default)]
pub struct GroupMembershipApprovalMode {
    pub is_join_approval_required: bool,
}

#[derive(Debug, Clone, Default)]
pub struct GroupParent {
    pub is_parent: bool,
    pub default_membership_approval_mode: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GroupLinkedParent {
    pub linked_parent_jid: Option<Jid>,
}

#[derive(Debug, Clone, Default)]
pub struct GroupIsDefaultSub {
    pub is_default_sub_group: bool,
}

#[derive(Debug, Clone, Default)]
pub struct GroupName {
    pub name: Option<String>,
    pub set_at: Option<DateTime<Utc>>,
    pub set_by: Option<Jid>,
    pub set_by_pn: Option<Jid>,
}

#[derive(Debug, Clone, Default)]
pub struct GroupTopic {
    pub topic: Option<String>,
    pub id: Option<String>,
    pub set_at: Option<DateTime<Utc>>,
    pub set_by: Option<Jid>,
    pub set_by_pn: Option<Jid>,
    pub deleted: bool,
}

#[derive(Debug, Clone, Default)]
pub struct GroupLocked {
    pub is_locked: bool,
}

#[derive(Debug, Clone, Default)]
pub struct GroupAnnounce {
    pub is_announce: bool,
    pub announce_version_id: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct GroupIncognito {
    pub is_incognito: bool,
}

#[derive(Debug, Clone)]
pub struct GroupParticipant {
    pub jid: Jid,
    pub phone_number: Option<Jid>,
    pub lid: Option<Jid>,
    pub is_admin: bool,
    pub is_super_admin: bool,
    pub display_name: Option<String>,
    pub error: i32,
    pub add_request: Option<GroupParticipantAddRequest>,
}

#[derive(Debug, Clone)]
pub struct GroupParticipantAddRequest {
    pub code: String,
    pub expiration: DateTime<Utc>,
}

#[derive(Debug, Clone, Default)]
pub struct GroupEphemeral {
    pub is_ephemeral: bool,
    pub disappearing_timer: u32,
}

#[derive(Debug, Clone, Default)]
pub struct GroupDelete {
    pub deleted: bool,
    pub delete_reason: Option<String>,
}
