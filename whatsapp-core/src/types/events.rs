use crate::binary::node::Node;
use crate::types::jid::{Jid, MessageId};
use crate::types::message::MessageInfo;
use crate::types::newsletter::{NewsletterMetadata, NewsletterMuteState, NewsletterRole};
use crate::types::presence::{ChatPresence, ChatPresenceMedia, ReceiptType};
use crate::types::user::PrivacySettings;
use chrono::{DateTime, Duration, Utc};
use std::fmt;
use whatsapp_proto::whatsapp as wa;

#[derive(Debug, Clone)]
pub struct SelfPushNameUpdated {
    pub from_server: bool,
    pub old_name: String,
    pub new_name: String,
}

#[derive(Debug, Clone)]
pub enum Event {
    Connected(Connected),
    Disconnected(Disconnected),
    PairSuccess(PairSuccess),
    PairError(PairError),
    LoggedOut(LoggedOut),
    Qr(Qr),
    QrScannedWithoutMultidevice(QrScannedWithoutMultidevice),
    ClientOutdated(ClientOutdated),

    Message(Box<wa::Message>, MessageInfo),
    Receipt(Receipt),
    UndecryptableMessage(UndecryptableMessage),
    Notification(Node),

    ChatPresence(ChatPresenceUpdate),
    Presence(PresenceUpdate),
    PictureUpdate(PictureUpdate),
    UserAboutUpdate(UserAboutUpdate),

    JoinedGroup(Box<wa::Conversation>),
    GroupInfoUpdate {
        jid: Jid,
        update: Box<wa::SyncActionValue>,
    },
    ContactUpdate(ContactUpdate),

    PushNameUpdate(PushNameUpdate),
    SelfPushNameUpdated(SelfPushNameUpdated),
    PinUpdate(PinUpdate),
    MuteUpdate(MuteUpdate),
    ArchiveUpdate(ArchiveUpdate),

    StreamReplaced(StreamReplaced),
    TemporaryBan(TemporaryBan),
    ConnectFailure(ConnectFailure),
    StreamError(StreamError),
}

#[derive(Debug, Clone)]
pub struct Qr {
    pub codes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PairSuccess {
    pub id: Jid,
    pub lid: Jid,
    pub business_name: String,
    pub platform: String,
}

#[derive(Debug, Clone)]
pub struct PairError {
    pub id: Jid,
    pub lid: Jid,
    pub business_name: String,
    pub platform: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct QrScannedWithoutMultidevice;

#[derive(Debug, Clone)]
pub struct ClientOutdated;

#[derive(Debug, Clone)]
pub struct Connected;

#[derive(Debug, Clone)]
pub struct KeepAliveTimeout {
    pub error_count: i32,
    pub last_success: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct KeepAliveRestored;

#[derive(Debug, Clone)]
pub struct LoggedOut {
    pub on_connect: bool,
    pub reason: ConnectFailureReason,
}

#[derive(Debug, Clone)]
pub struct StreamReplaced;

#[derive(Debug, Clone)]
pub struct ManualLoginReconnect;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TempBanReason {
    SentToTooManyPeople,
    BlockedByUsers,
    CreatedTooManyGroups,
    SentTooManySameMessage,
    BroadcastList,
    Unknown(i32),
}

impl From<i32> for TempBanReason {
    fn from(code: i32) -> Self {
        match code {
            101 => Self::SentToTooManyPeople,
            102 => Self::BlockedByUsers,
            103 => Self::CreatedTooManyGroups,
            104 => Self::SentTooManySameMessage,
            106 => Self::BroadcastList,
            _ => Self::Unknown(code),
        }
    }
}

impl TempBanReason {
    pub fn code(&self) -> i32 {
        match self {
            Self::SentToTooManyPeople => 101,
            Self::BlockedByUsers => 102,
            Self::CreatedTooManyGroups => 103,
            Self::SentTooManySameMessage => 104,
            Self::BroadcastList => 106,
            Self::Unknown(code) => *code,
        }
    }
}

impl fmt::Display for TempBanReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::SentToTooManyPeople => {
                "you sent too many messages to people who don't have you in their address books"
            }
            Self::BlockedByUsers => "too many people blocked you",
            Self::CreatedTooManyGroups => {
                "you created too many groups with people who don't have you in their address books"
            }
            Self::SentTooManySameMessage => "you sent the same message to too many people",
            Self::BroadcastList => "you sent too many messages to a broadcast list",
            Self::Unknown(_) => "you may have violated the terms of service (unknown error)",
        };
        write!(f, "{}: {}", self.code(), msg)
    }
}

#[derive(Debug, Clone)]
pub struct TemporaryBan {
    pub code: TempBanReason,
    pub expire: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ConnectFailureReason {
    Generic,
    LoggedOut,
    TempBanned,
    MainDeviceGone,
    UnknownLogout,
    ClientOutdated,
    BadUserAgent,
    CatExpired,
    CatInvalid,
    NotFound,
    ClientUnknown,
    InternalServerError,
    Experimental,
    ServiceUnavailable,
    Unknown(i32),
}

impl From<i32> for ConnectFailureReason {
    fn from(code: i32) -> Self {
        match code {
            400 => Self::Generic,
            401 => Self::LoggedOut,
            402 => Self::TempBanned,
            403 => Self::MainDeviceGone,
            406 => Self::UnknownLogout,
            405 => Self::ClientOutdated,
            409 => Self::BadUserAgent,
            413 => Self::CatExpired,
            414 => Self::CatInvalid,
            415 => Self::NotFound,
            418 => Self::ClientUnknown,
            500 => Self::InternalServerError,
            501 => Self::Experimental,
            503 => Self::ServiceUnavailable,
            _ => Self::Unknown(code),
        }
    }
}

impl ConnectFailureReason {
    pub fn code(&self) -> i32 {
        match self {
            Self::Generic => 400,
            Self::LoggedOut => 401,
            Self::TempBanned => 402,
            Self::MainDeviceGone => 403,
            Self::UnknownLogout => 406,
            Self::ClientOutdated => 405,
            Self::BadUserAgent => 409,
            Self::CatExpired => 413,
            Self::CatInvalid => 414,
            Self::NotFound => 415,
            Self::ClientUnknown => 418,
            Self::InternalServerError => 500,
            Self::Experimental => 501,
            Self::ServiceUnavailable => 503,
            Self::Unknown(code) => *code,
        }
    }

    pub fn is_logged_out(&self) -> bool {
        matches!(
            self,
            Self::LoggedOut | Self::MainDeviceGone | Self::UnknownLogout
        )
    }

    pub fn should_reconnect(&self) -> bool {
        matches!(self, Self::ServiceUnavailable | Self::InternalServerError)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectFailure {
    pub reason: ConnectFailureReason,
    pub message: String,
    pub raw: Option<Node>,
}

#[derive(Debug, Clone)]
pub struct CatRefreshError {
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct StreamError {
    pub code: String,
    pub raw: Option<Node>,
}

#[derive(Debug, Clone)]
pub struct Disconnected;

#[derive(Debug, Clone)]
pub struct HistorySync {
    pub data: Box<wa::HistorySync>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecryptFailMode {
    Show,
    Hide,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnavailableType {
    Unknown,
    ViewOnce,
}

#[derive(Debug, Clone)]
pub struct UndecryptableMessage {
    pub info: MessageInfo,
    pub is_unavailable: bool,
    pub unavailable_type: UnavailableType,
    pub decrypt_fail_mode: DecryptFailMode,
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub source: crate::types::message::MessageSource,
    pub message_ids: Vec<MessageId>,
    pub timestamp: DateTime<Utc>,
    pub r#type: ReceiptType,
    pub message_sender: Jid,
}

#[derive(Debug, Clone)]
pub struct ChatPresenceUpdate {
    pub source: crate::types::message::MessageSource,
    pub state: ChatPresence,
    pub media: ChatPresenceMedia,
}

#[derive(Debug, Clone)]
pub struct PresenceUpdate {
    pub from: Jid,
    pub unavailable: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone)]
pub struct PictureUpdate {
    pub jid: Jid,
    pub author: Jid,
    pub timestamp: DateTime<Utc>,
    pub photo_change: Option<wa::PhotoChange>,
}

#[derive(Debug, Clone)]
pub struct UserAboutUpdate {
    pub jid: Jid,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct IdentityChange {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub implicit: bool,
}

#[derive(Debug, Clone)]
pub struct PrivacySettingsUpdate {
    pub new_settings: PrivacySettings,
}

#[derive(Debug, Clone)]
pub struct ContactUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::ContactAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone)]
pub struct PushNameUpdate {
    pub jid: Jid,
    pub message: Box<MessageInfo>,
    pub old_push_name: String,
    pub new_push_name: String,
}

#[derive(Debug, Clone)]
pub struct PinUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::PinAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone)]
pub struct StarUpdate {
    pub chat_jid: Jid,
    pub sender_jid: Option<Jid>,
    pub is_from_me: bool,
    pub message_id: MessageId,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::StarAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone)]
pub struct MuteUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::MuteAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone)]
pub struct ArchiveUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::ArchiveChatAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone)]
pub struct MarkChatAsReadUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::MarkChatAsReadAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone)]
pub struct NewsletterJoin {
    pub metadata: NewsletterMetadata,
}

#[derive(Debug, Clone)]
pub struct NewsletterLeave {
    pub id: Jid,
    pub role: NewsletterRole,
}

#[derive(Debug, Clone)]
pub struct NewsletterMuteChange {
    pub id: Jid,
    pub mute: NewsletterMuteState,
}

#[derive(Debug, Clone)]
pub struct NewsletterLiveUpdate {
    pub jid: Jid,
    pub time: DateTime<Utc>,
    pub messages: Vec<crate::types::newsletter::NewsletterMessage>,
}