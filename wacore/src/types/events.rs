use crate::stanza::BusinessSubscription;
use crate::types::message::MessageInfo;
use crate::types::presence::{ChatPresence, ChatPresenceMedia, ReceiptType};
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use prost::Message;
use serde::Serialize;
use std::fmt;
use std::sync::{Arc, OnceLock, RwLock};
use wacore_binary::jid::{Jid, MessageId};
use wacore_binary::node::Node;
use waproto::whatsapp::{self as wa, HistorySync};

/// Wrapper for large event data that uses Arc for cheap cloning.
/// This avoids cloning large protobuf messages when dispatching events.
#[derive(Debug, Clone)]
pub struct SharedData<T>(pub Arc<T>);

impl<T> SharedData<T> {
    pub fn new(data: T) -> Self {
        Self(Arc::new(data))
    }
}

impl<T> std::ops::Deref for SharedData<T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: Serialize> Serialize for SharedData<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

/// A lazily-parsed conversation from history sync.
///
/// The raw protobuf bytes are stored and only parsed when accessed.
/// This allows emitting events without the cost of parsing if the
/// consumer doesn't actually need the conversation data.
///
/// Uses `bytes::Bytes` for zero-copy reference counting. Cloning is O(1)
/// and parsing only happens once on first access.
#[derive(Clone)]
pub struct LazyConversation {
    /// Raw protobuf bytes using Bytes for zero-copy cloning.
    /// Bytes is reference-counted internally, so clones share the same data.
    raw_bytes: Bytes,
    /// Cached parsed result, initialized on first access.
    parsed: Arc<OnceLock<wa::Conversation>>,
}

impl LazyConversation {
    /// Create a new lazy conversation from raw protobuf bytes.
    /// The bytes are moved into Bytes for zero-copy sharing.
    pub fn new(raw_bytes: Vec<u8>) -> Self {
        Self {
            raw_bytes: Bytes::from(raw_bytes),
            parsed: Arc::new(OnceLock::new()),
        }
    }

    /// Create from an existing Bytes instance (true zero-copy).
    pub fn from_bytes(raw_bytes: Bytes) -> Self {
        Self {
            raw_bytes,
            parsed: Arc::new(OnceLock::new()),
        }
    }

    /// Get the parsed conversation, parsing on first access.
    /// Returns None if parsing fails (empty id indicates invalid conversation).
    pub fn get(&self) -> Option<&wa::Conversation> {
        let conv = self
            .parsed
            .get_or_init(|| wa::Conversation::decode(&self.raw_bytes[..]).unwrap_or_default());
        if conv.id.is_empty() { None } else { Some(conv) }
    }

    /// Get the parsed conversation, parsing on first access.
    /// Panics if parsing fails (use `get()` for fallible access).
    pub fn conversation(&self) -> &wa::Conversation {
        self.parsed.get_or_init(|| {
            let mut conv = wa::Conversation::decode(&self.raw_bytes[..])
                .expect("Failed to decode conversation");
            // Strip heavy fields after parsing to reduce memory
            conv.messages.clear();
            conv.messages.shrink_to_fit();
            conv
        })
    }
}

impl fmt::Debug for LazyConversation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(conv) = self.parsed.get() {
            f.debug_struct("LazyConversation")
                .field("id", &conv.id)
                .field("parsed", &true)
                .finish()
        } else {
            f.debug_struct("LazyConversation")
                .field("raw_size", &self.raw_bytes.len())
                .field("parsed", &false)
                .finish()
        }
    }
}

impl Serialize for LazyConversation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Only serialize if parsed, otherwise serialize as null/empty
        if let Some(conv) = self.parsed.get() {
            conv.serialize(serializer)
        } else {
            serializer.serialize_none()
        }
    }
}

pub trait EventHandler: Send + Sync {
    fn handle_event(&self, event: &Event);
}

#[derive(Default, Clone)]
pub struct CoreEventBus {
    handlers: Arc<RwLock<Vec<Arc<dyn EventHandler>>>>,
}

impl CoreEventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_handler(&self, handler: Arc<dyn EventHandler>) {
        self.handlers
            .write()
            .expect("RwLock should not be poisoned")
            .push(handler);
    }

    /// Returns true if there are any event handlers registered.
    /// Useful for skipping expensive work when no one is listening.
    pub fn has_handlers(&self) -> bool {
        !self
            .handlers
            .read()
            .expect("RwLock should not be poisoned")
            .is_empty()
    }

    pub fn dispatch(&self, event: &Event) {
        for handler in self
            .handlers
            .read()
            .expect("RwLock should not be poisoned")
            .iter()
        {
            handler.handle_event(event);
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SelfPushNameUpdated {
    pub from_server: bool,
    pub old_name: String,
    pub new_name: String,
}

/// Type of device list update notification.
/// Matches WhatsApp Web's device notification types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DeviceListUpdateType {
    /// A device was added to the user's account
    Add,
    /// A device was removed from the user's account
    Remove,
    /// Device information was updated
    Update,
}

impl From<crate::stanza::devices::DeviceNotificationType> for DeviceListUpdateType {
    fn from(t: crate::stanza::devices::DeviceNotificationType) -> Self {
        match t {
            crate::stanza::devices::DeviceNotificationType::Add => Self::Add,
            crate::stanza::devices::DeviceNotificationType::Remove => Self::Remove,
            crate::stanza::devices::DeviceNotificationType::Update => Self::Update,
        }
    }
}

/// Device information from notification.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceNotificationInfo {
    /// Device ID (extracted from JID)
    pub device_id: u32,
    /// Optional key index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_index: Option<u32>,
}

/// Device list update notification.
/// Emitted when a user's device list changes (device added/removed/updated).
#[derive(Debug, Clone, Serialize)]
pub struct DeviceListUpdate {
    /// The user whose device list changed (from attribute)
    pub user: Jid,
    /// Optional LID user (for LID-PN mapping)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lid_user: Option<Jid>,
    /// Type of update (add/remove/update)
    pub update_type: DeviceListUpdateType,
    /// Affected devices with detailed info
    pub devices: Vec<DeviceNotificationInfo>,
    /// Key index info (for add/remove)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_index: Option<crate::stanza::devices::KeyIndexInfo>,
    /// Contact hash (for update - used for contact lookup)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_hash: Option<String>,
}

/// Type of business status update.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum BusinessUpdateType {
    RemovedAsBusiness,
    VerifiedNameChanged,
    ProfileUpdated,
    ProductsUpdated,
    CollectionsUpdated,
    SubscriptionsUpdated,
    Unknown,
}

impl From<crate::stanza::business::BusinessNotificationType> for BusinessUpdateType {
    fn from(t: crate::stanza::business::BusinessNotificationType) -> Self {
        match t {
            crate::stanza::business::BusinessNotificationType::RemoveJid
            | crate::stanza::business::BusinessNotificationType::RemoveHash => {
                Self::RemovedAsBusiness
            }
            crate::stanza::business::BusinessNotificationType::VerifiedNameJid
            | crate::stanza::business::BusinessNotificationType::VerifiedNameHash => {
                Self::VerifiedNameChanged
            }
            crate::stanza::business::BusinessNotificationType::Profile
            | crate::stanza::business::BusinessNotificationType::ProfileHash => {
                Self::ProfileUpdated
            }
            crate::stanza::business::BusinessNotificationType::Product => Self::ProductsUpdated,
            crate::stanza::business::BusinessNotificationType::Collection => {
                Self::CollectionsUpdated
            }
            crate::stanza::business::BusinessNotificationType::Subscriptions => {
                Self::SubscriptionsUpdated
            }
            crate::stanza::business::BusinessNotificationType::Unknown => Self::Unknown,
        }
    }
}

/// Business status update notification.
#[derive(Debug, Clone, Serialize)]
pub struct BusinessStatusUpdate {
    pub jid: Jid,
    pub update_type: BusinessUpdateType,
    pub timestamp: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_jid: Option<Jid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub product_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub collection_ids: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subscriptions: Vec<BusinessSubscription>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Event {
    Connected(Connected),
    Disconnected(Disconnected),
    PairSuccess(PairSuccess),
    PairError(PairError),
    LoggedOut(LoggedOut),
    PairingQrCode {
        code: String,
        timeout: std::time::Duration,
    },
    /// Generated pair code for phone number linking.
    /// User should enter this code on their phone in WhatsApp > Linked Devices.
    PairingCode {
        /// The 8-character pairing code to display.
        code: String,
        /// Approximate validity duration (~180 seconds).
        timeout: std::time::Duration,
    },
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

    JoinedGroup(LazyConversation),
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
    MarkChatAsReadUpdate(MarkChatAsReadUpdate),

    HistorySync(HistorySync),
    OfflineSyncPreview(OfflineSyncPreview),
    OfflineSyncCompleted(OfflineSyncCompleted),

    /// Device list changed for a user (device added/removed/updated)
    DeviceListUpdate(DeviceListUpdate),

    /// Business account status changed (verified name, profile, conversion to personal)
    BusinessStatusUpdate(BusinessStatusUpdate),

    StreamReplaced(StreamReplaced),
    TemporaryBan(TemporaryBan),
    ConnectFailure(ConnectFailure),
    StreamError(StreamError),
}

#[derive(Debug, Clone, Serialize)]
pub struct PairSuccess {
    pub id: Jid,
    pub lid: Jid,
    pub business_name: String,
    pub platform: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairError {
    pub id: Jid,
    pub lid: Jid,
    pub business_name: String,
    pub platform: String,
    pub error: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct QrScannedWithoutMultidevice;

#[derive(Debug, Clone, Serialize)]
pub struct ClientOutdated;

#[derive(Debug, Clone, Serialize)]
pub struct Connected;

#[derive(Debug, Clone, Serialize)]
pub struct LoggedOut {
    pub on_connect: bool,
    pub reason: ConnectFailureReason,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamReplaced;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct TemporaryBan {
    pub code: TempBanReason,
    pub expire: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy, Serialize)]

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

#[derive(Debug, Clone, Serialize)]
pub struct ConnectFailure {
    pub reason: ConnectFailureReason,
    pub message: String,
    pub raw: Option<Node>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StreamError {
    pub code: String,
    pub raw: Option<Node>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Disconnected;

#[derive(Debug, Clone, Serialize)]
pub struct OfflineSyncPreview {
    pub total: i32,
    pub app_data_changes: i32,
    pub messages: i32,
    pub notifications: i32,
    pub receipts: i32,
}

#[derive(Debug, Clone, Serialize)]
pub struct OfflineSyncCompleted {
    pub count: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum DecryptFailMode {
    Show,
    Hide,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum UnavailableType {
    Unknown,
    ViewOnce,
}

#[derive(Debug, Clone, Serialize)]
pub struct UndecryptableMessage {
    pub info: MessageInfo,
    pub is_unavailable: bool,
    pub unavailable_type: UnavailableType,
    pub decrypt_fail_mode: DecryptFailMode,
}

#[derive(Debug, Clone, Serialize)]
pub struct Receipt {
    pub source: crate::types::message::MessageSource,
    pub message_ids: Vec<MessageId>,
    pub timestamp: DateTime<Utc>,
    pub r#type: ReceiptType,
    pub message_sender: Jid,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatPresenceUpdate {
    pub source: crate::types::message::MessageSource,
    pub state: ChatPresence,
    pub media: ChatPresenceMedia,
}

#[derive(Debug, Clone, Serialize)]
pub struct PresenceUpdate {
    pub from: Jid,
    pub unavailable: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PictureUpdate {
    pub jid: Jid,
    pub author: Jid,
    pub timestamp: DateTime<Utc>,
    pub photo_change: Option<wa::PhotoChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserAboutUpdate {
    pub jid: Jid,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContactUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::ContactAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushNameUpdate {
    pub jid: Jid,
    pub message: Box<MessageInfo>,
    pub old_push_name: String,
    pub new_push_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PinUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::PinAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MuteUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::MuteAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::ArchiveChatAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarkChatAsReadUpdate {
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::MarkChatAsReadAction>,
    pub from_full_sync: bool,
}
