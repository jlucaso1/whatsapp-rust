use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

#[derive(Debug, Clone)]
pub struct VerifiedName {
    pub certificate: Box<wa::VerifiedNameCertificate>,
    pub details: Box<wa::verified_name_certificate::Details>,
}

#[derive(Debug, Clone, Default)]
pub struct LocalChatSettings {
    pub found: bool,
    pub muted_until: Option<DateTime<Utc>>,
    pub pinned: bool,
    pub archived: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySetting {
    All,
    Contacts,
    ContactBlacklist,
    MatchLastSeen,
    Known,
    None,
    #[serde(other)]
    Undefined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivacySettingType {
    GroupAdd,
    Last,
    Status,
    Profile,
    ReadReceipts,
    Online,
    CallAdd,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrivacySettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_add: Option<PrivacySetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<PrivacySetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<PrivacySetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<PrivacySetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_receipts: Option<PrivacySetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_add: Option<PrivacySetting>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<PrivacySetting>,
}

#[derive(Debug, Clone)]
pub struct BusinessHoursConfig {
    pub day_of_week: String,
    pub mode: String,
    pub open_time: String,
    pub close_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Category {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct BusinessProfile {
    pub jid: Jid,
    pub address: Option<String>,
    pub email: Option<String>,
    pub categories: Vec<Category>,
    pub profile_options: HashMap<String, String>,
    pub business_hours_time_zone: Option<String>,
    pub business_hours: Vec<BusinessHoursConfig>,
}
