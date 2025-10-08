use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wacore_binary::jid::{Jid, MessageId, MessageServerId};
use waproto::whatsapp as wa;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NewsletterVerificationState {
    Verified,
    Unverified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NewsletterPrivacy {
    Private,
    Public,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NewsletterReactionsMode {
    All,
    Basic,
    None,
    Blocklist,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NewsletterState {
    Active,
    Suspended,
    Geosuspended,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedNewsletterState {
    pub r#type: NewsletterState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NewsletterMuteState {
    On,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NewsletterRole {
    Subscriber,
    Guest,
    Admin,
    Owner,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewsletterMetadata {
    pub id: Jid,
    pub state: WrappedNewsletterState,
    pub thread_metadata: NewsletterThreadMetadata,
    pub viewer_metadata: Option<NewsletterViewerMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterViewerMetadata {
    pub mute: NewsletterMuteState,
    pub role: NewsletterRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterReactionSettings {
    pub value: NewsletterReactionsMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterSettings {
    pub reaction_codes: NewsletterReactionSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterThreadMetadata {
    #[serde(with = "chrono::serde::ts_seconds")]
    pub creation_time: DateTime<Utc>,
    #[serde(rename = "invite")]
    pub invite_code: String,
    pub name: NewsletterText,
    pub description: NewsletterText,
    #[serde(rename = "subscribers_count")]
    pub subscriber_count: i32,
    #[serde(rename = "verification")]
    pub verification_state: NewsletterVerificationState,
    pub picture_url: Option<String>,
    pub preview_url: Option<String>,
    pub settings: NewsletterSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewsletterText {
    pub text: String,
    pub id: String,
    #[serde(with = "chrono::serde::ts_microseconds")]
    pub update_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NewsletterMessage {
    pub message_server_id: MessageServerId,
    pub message_id: MessageId,
    pub r#type: String,
    pub timestamp: DateTime<Utc>,
    pub views_count: i32,
    pub reaction_counts: HashMap<String, i32>,
    pub message: Option<wa::Message>,
}
