use crate::stanza::BusinessSubscription;
use crate::types::message::MessageInfo;
use crate::types::presence::{ChatPresence, ChatPresenceMedia, ReceiptType};
use bytes::Bytes;
use chrono::{DateTime, Duration, Utc};
use prost::Message;
use serde::Serialize;
use std::fmt;
use std::sync::{Arc, OnceLock, RwLock};
use wacore_binary::Node;
use wacore_binary::OwnedNodeRef;
use wacore_binary::{Jid, MessageId};
use waproto::whatsapp as wa;

/// A lazily-parsed history sync blob.
///
/// Wraps the decompressed protobuf bytes and only decodes on first access.
/// With `Arc<Event>` dispatch, all handlers share the same `LazyHistorySync`
/// so `OnceLock` gives parse-once semantics for free.
///
/// Cheap metadata (`sync_type`, `chunk_order`, `progress`) is available
/// without decoding — useful for filtering events.
///
/// Call [`get()`](Self::get) for full access to conversations, pushnames,
/// global settings, past participants, call logs, and everything else in
/// the `wa::HistorySync` proto.
pub struct LazyHistorySync {
    raw_bytes: Bytes,
    sync_type: i32,
    chunk_order: Option<u32>,
    progress: Option<u32>,
    parsed: OnceLock<Option<Box<wa::HistorySync>>>,
}

impl Clone for LazyHistorySync {
    fn clone(&self) -> Self {
        Self {
            raw_bytes: self.raw_bytes.clone(),
            sync_type: self.sync_type,
            chunk_order: self.chunk_order,
            progress: self.progress,
            parsed: OnceLock::new(), // don't deep-copy the decoded proto
        }
    }
}

impl LazyHistorySync {
    pub fn new(
        raw_bytes: Bytes,
        sync_type: i32,
        chunk_order: Option<u32>,
        progress: Option<u32>,
    ) -> Self {
        Self {
            raw_bytes,
            sync_type,
            chunk_order,
            progress,
            parsed: OnceLock::new(),
        }
    }

    /// History sync type (e.g. InitialBootstrap, Recent, PushName).
    /// Available without decoding the proto.
    pub fn sync_type(&self) -> i32 {
        self.sync_type
    }

    /// Chunk ordering for multi-chunk transfers.
    pub fn chunk_order(&self) -> Option<u32> {
        self.chunk_order
    }

    /// Sync progress (0-100).
    pub fn progress(&self) -> Option<u32> {
        self.progress
    }

    /// Full decode of the history sync proto, cached via OnceLock.
    /// Returns `None` if decoding fails.
    ///
    /// Note: decoding materializes the full proto in memory alongside the
    /// raw bytes (~2x decompressed size). For large InitialBootstrap blobs,
    /// prefer [`raw_bytes()`](Self::raw_bytes) with partial decoding if
    /// you only need specific fields.
    pub fn get(&self) -> Option<&wa::HistorySync> {
        self.parsed
            .get_or_init(|| {
                wa::HistorySync::decode(&self.raw_bytes[..])
                    .ok()
                    .map(Box::new)
            })
            .as_deref()
    }

    /// Access the raw decompressed protobuf bytes for custom/partial decoding.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_bytes
    }
}

impl fmt::Debug for LazyHistorySync {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LazyHistorySync")
            .field("sync_type", &self.sync_type)
            .field("chunk_order", &self.chunk_order)
            .field("progress", &self.progress)
            .field("raw_size", &self.raw_bytes.len())
            .field(
                "parsed",
                &self.parsed.get().and_then(|o| o.as_ref()).is_some(),
            )
            .finish()
    }
}

impl Serialize for LazyHistorySync {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("LazyHistorySync", 3)?;
        s.serialize_field("sync_type", &self.sync_type)?;
        s.serialize_field("chunk_order", &self.chunk_order)?;
        s.serialize_field("progress", &self.progress)?;
        s.end()
    }
}

pub trait EventHandler: Send + Sync {
    fn handle_event(&self, event: Arc<Event>);
}

/// Event handler that forwards events to an async channel.
///
/// # Example
/// ```ignore
/// let (handler, rx) = ChannelEventHandler::new();
/// client.register_handler(handler);
/// while let Ok(event) = rx.recv().await {
///     if matches!(&*event, Event::Connected(_)) { break; }
/// }
/// ```
pub struct ChannelEventHandler {
    tx: async_channel::Sender<Arc<Event>>,
}

impl ChannelEventHandler {
    pub fn new() -> (Arc<Self>, async_channel::Receiver<Arc<Event>>) {
        let (tx, rx) = async_channel::unbounded();
        (Arc::new(Self { tx }), rx)
    }
}

impl EventHandler for ChannelEventHandler {
    fn handle_event(&self, event: Arc<Event>) {
        let _ = self.tx.try_send(event);
    }
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

    pub fn dispatch(&self, event: Event) {
        let handlers = self
            .handlers
            .read()
            .expect("RwLock should not be poisoned")
            .clone();
        if handlers.is_empty() {
            return;
        }
        let event = Arc::new(event);
        for handler in &handlers {
            handler.handle_event(Arc::clone(&event));
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

/// Identity key changed for a user (e.g., user reinstalled WhatsApp).
/// Emitted after device record cleanup so sessions and sender keys are cleared.
#[derive(Debug, Clone, Serialize)]
pub struct IdentityChange {
    /// The user whose identity changed
    pub user: Jid,
    /// Optional LID for the user
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lid_user: Option<Jid>,
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
    /// The business account whose status changed.
    pub jid: Jid,
    pub update_type: BusinessUpdateType,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
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

/// A contact's default disappearing messages setting changed.
///
/// Sent by the server as `<notification type="disappearing_mode">`.
/// WA Web: `WAWebHandleDisappearingModeNotification` →
/// `WAWebUpdateDisappearingModeForContact`.
#[derive(Debug, Clone, Serialize)]
pub struct DisappearingModeChanged {
    /// The contact whose setting changed.
    pub from: Jid,
    /// New duration in seconds (0 = disabled, 86400 = 24h, etc.).
    pub duration: u32,
    /// When the setting was changed.
    /// Consumers should only apply this if it's newer than their stored value.
    #[serde(with = "chrono::serde::ts_seconds")]
    pub setting_timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
#[non_exhaustive]
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

    Message(Box<wa::Message>, Arc<MessageInfo>),
    Receipt(Receipt),
    UndecryptableMessage(UndecryptableMessage),
    #[serde(skip)]
    Notification(Arc<OwnedNodeRef>),

    ChatPresence(ChatPresenceUpdate),
    Presence(PresenceUpdate),
    PictureUpdate(PictureUpdate),
    UserAboutUpdate(UserAboutUpdate),
    ContactUpdated(ContactUpdated),
    ContactNumberChanged(ContactNumberChanged),
    ContactSyncRequested(ContactSyncRequested),

    /// Group metadata/settings/participant change from w:gp2 notification.
    GroupUpdate(GroupUpdate),
    ContactUpdate(ContactUpdate),

    PushNameUpdate(PushNameUpdate),
    SelfPushNameUpdated(SelfPushNameUpdated),
    PinUpdate(PinUpdate),
    MuteUpdate(MuteUpdate),
    ArchiveUpdate(ArchiveUpdate),
    StarUpdate(StarUpdate),
    MarkChatAsReadUpdate(MarkChatAsReadUpdate),
    DeleteChatUpdate(DeleteChatUpdate),
    DeleteMessageForMeUpdate(DeleteMessageForMeUpdate),

    HistorySync(Box<LazyHistorySync>),
    OfflineSyncPreview(OfflineSyncPreview),
    OfflineSyncCompleted(OfflineSyncCompleted),

    /// Device list changed for a user (device added/removed/updated)
    DeviceListUpdate(DeviceListUpdate),

    /// Identity key changed (user reinstalled WhatsApp)
    IdentityChange(IdentityChange),

    /// Business account status changed (verified name, profile, conversion to personal)
    BusinessStatusUpdate(BusinessStatusUpdate),

    StreamReplaced(StreamReplaced),
    TemporaryBan(TemporaryBan),
    ConnectFailure(ConnectFailure),
    StreamError(StreamError),

    /// A contact changed their default disappearing messages setting.
    DisappearingModeChanged(DisappearingModeChanged),

    /// Newsletter live update (reaction counts changed, message updates, etc.).
    NewsletterLiveUpdate(NewsletterLiveUpdate),

    /// Raw decoded stanza, emitted before router dispatch.
    /// Library extension — no WA Web equivalent (WA Web has no raw stanza observer).
    /// Gated by `Client::set_raw_node_forwarding(true)` to avoid overhead when unused.
    #[serde(skip)]
    RawNode(Arc<OwnedNodeRef>),
}

impl Event {
    pub fn as_message(&self) -> Option<(&wa::Message, &MessageInfo)> {
        if let Event::Message(msg, info) = self {
            Some((msg, &**info))
        } else {
            None
        }
    }

    pub fn message_text(&self) -> Option<&str> {
        let (msg, _) = self.as_message()?;
        msg.conversation.as_deref()
    }
}

/// A newsletter live update notification, typically containing updated
/// reaction counts for one or more messages.
#[derive(Debug, Clone, Serialize)]
pub struct NewsletterLiveUpdate {
    /// The newsletter channel this update belongs to.
    pub newsletter_jid: Jid,
    pub messages: Vec<NewsletterLiveUpdateMessage>,
}

/// A single message entry in a newsletter live update.
#[derive(Debug, Clone, Serialize)]
pub struct NewsletterLiveUpdateMessage {
    pub server_id: u64,
    pub reactions: Vec<NewsletterLiveUpdateReaction>,
}

/// A reaction count in a newsletter live update.
#[derive(Debug, Clone, Serialize)]
pub struct NewsletterLiveUpdateReaction {
    pub code: String,
    pub count: u64,
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
    pub info: Arc<MessageInfo>,
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
}

#[derive(Debug, Clone, Serialize)]
pub struct ChatPresenceUpdate {
    pub source: crate::types::message::MessageSource,
    pub state: ChatPresence,
    pub media: ChatPresenceMedia,
}

#[derive(Debug, Clone, Serialize)]
pub struct PresenceUpdate {
    /// The contact whose presence changed.
    pub from: Jid,
    pub unavailable: bool,
    pub last_seen: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PictureUpdate {
    /// The JID whose picture changed (user or group).
    pub jid: Jid,
    /// The user who made the change. Present for group picture changes
    /// (the admin who changed it). `None` for personal picture updates.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<Jid>,
    pub timestamp: DateTime<Utc>,
    /// Whether the picture was removed (true) or set/updated (false).
    pub removed: bool,
    /// The server-assigned picture ID (from `<set id="..."/>`). `None` for deletions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserAboutUpdate {
    /// The contact whose about text changed.
    pub jid: Jid,
    pub status: String,
    pub timestamp: DateTime<Utc>,
}

/// A contact's profile changed (server notification).
///
/// Emitted from `<notification type="contacts"><update jid="..."/>`.
/// WA Web resets cached presence and refreshes the profile picture on this
/// event — consumers should invalidate any cached presence/profile data.
///
/// Not to be confused with [`ContactUpdate`] which comes from app-state
/// sync mutations (different source, different payload).
#[derive(Debug, Clone, Serialize)]
pub struct ContactUpdated {
    /// The contact whose profile was updated.
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
}

/// A contact changed their phone number.
///
/// Emitted from `<notification type="contacts"><modify old="..." new="..."
/// old_lid="..." new_lid="..."/>`.
///
/// WA Web creates two LID-PN mappings (`old_lid→old_jid`, `new_lid→new_jid`)
/// and generates a system notification message in both old and new chats.
#[derive(Debug, Clone, Serialize)]
pub struct ContactNumberChanged {
    /// Old phone number JID.
    pub old_jid: Jid,
    /// New phone number JID.
    pub new_jid: Jid,
    /// Old LID (if provided by server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_lid: Option<Jid>,
    /// New LID (if provided by server).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_lid: Option<Jid>,
    pub timestamp: DateTime<Utc>,
}

/// Server requests a full contact re-sync.
///
/// Emitted from `<notification type="contacts"><sync after="..."/>`.
#[derive(Debug, Clone, Serialize)]
pub struct ContactSyncRequested {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<DateTime<Utc>>,
    pub timestamp: DateTime<Utc>,
}

/// Group update notification.
///
/// Emitted for each action in a `<notification type="w:gp2">` stanza.
/// A single notification may produce multiple `GroupUpdate` events (one per action).
#[derive(Debug, Clone, Serialize)]
pub struct GroupUpdate {
    /// The group this update applies to
    pub group_jid: Jid,
    /// The admin/user who triggered the change (`participant` attribute)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant: Option<Jid>,
    /// Phone number JID of the participant (for LID-addressed groups)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub participant_pn: Option<Jid>,
    /// When the change occurred
    pub timestamp: DateTime<Utc>,
    /// Whether the group uses LID addressing mode
    pub is_lid_addressing_mode: bool,
    /// The specific action
    pub action: crate::stanza::groups::GroupNotificationAction,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContactUpdate {
    /// The chat/contact this sync action applies to.
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::ContactAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PushNameUpdate {
    /// The contact who changed their push name.
    pub jid: Jid,
    pub message: Box<MessageInfo>,
    pub old_push_name: String,
    pub new_push_name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PinUpdate {
    /// The chat being pinned or unpinned.
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::PinAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MuteUpdate {
    /// The chat being muted or unmuted.
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::MuteAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveUpdate {
    /// The chat being archived or unarchived.
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::ArchiveChatAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StarUpdate {
    /// The chat containing the starred or unstarred message.
    pub chat_jid: Jid,
    /// The participant who sent the message. `Some` for group messages from
    /// others, `None` for self-authored or 1-on-1 messages (wire value `"0"`).
    pub participant_jid: Option<Jid>,
    pub message_id: String,
    pub from_me: bool,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::StarAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MarkChatAsReadUpdate {
    /// The chat being marked as read or unread.
    pub jid: Jid,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::MarkChatAsReadAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeleteChatUpdate {
    /// The chat being deleted.
    pub jid: Jid,
    /// From the index, not the proto — DeleteChatAction only has messageRange.
    pub delete_media: bool,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::DeleteChatAction>,
    pub from_full_sync: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeleteMessageForMeUpdate {
    /// The chat containing the deleted message.
    pub chat_jid: Jid,
    pub participant_jid: Option<Jid>,
    pub message_id: String,
    pub from_me: bool,
    pub timestamp: DateTime<Utc>,
    pub action: Box<wa::sync_action_value::DeleteMessageForMeAction>,
    pub from_full_sync: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use waproto::whatsapp as wa;

    /// Build a HistorySync proto with conversations and encode it.
    fn make_history_sync_bytes(conversations: Vec<wa::Conversation>) -> Vec<u8> {
        let hs = wa::HistorySync {
            sync_type: wa::history_sync::HistorySyncType::InitialBootstrap as i32,
            conversations,
            ..Default::default()
        };
        hs.encode_to_vec()
    }

    #[test]
    fn lazy_history_sync_get_decodes() {
        let bytes = make_history_sync_bytes(vec![wa::Conversation {
            id: "chat@s.whatsapp.net".to_string(),
            ..Default::default()
        }]);
        let lazy = LazyHistorySync::new(Bytes::from(bytes), 0, None, None);

        let hs = lazy.get().expect("should decode");
        assert_eq!(hs.conversations.len(), 1);
        assert_eq!(hs.conversations[0].id, "chat@s.whatsapp.net");
    }

    #[test]
    fn lazy_history_sync_caches_decode() {
        let bytes = make_history_sync_bytes(vec![wa::Conversation {
            id: "test@g.us".to_string(),
            ..Default::default()
        }]);
        let lazy = LazyHistorySync::new(Bytes::from(bytes), 0, None, None);

        let first = lazy.get().expect("first decode");
        let second = lazy.get().expect("second decode");
        // Same reference — OnceLock cached it
        assert!(std::ptr::eq(first, second));
    }

    #[test]
    fn lazy_history_sync_cheap_metadata() {
        let bytes = make_history_sync_bytes(vec![]);
        let lazy = LazyHistorySync::new(Bytes::from(bytes), 3, Some(2), Some(50));

        assert_eq!(lazy.sync_type(), 3);
        assert_eq!(lazy.chunk_order(), Some(2));
        assert_eq!(lazy.progress(), Some(50));
    }

    #[test]
    fn lazy_history_sync_raw_bytes() {
        let bytes = make_history_sync_bytes(vec![wa::Conversation {
            id: "raw@s.whatsapp.net".to_string(),
            ..Default::default()
        }]);
        let raw = bytes.clone();
        let lazy = LazyHistorySync::new(Bytes::from(bytes), 0, None, None);

        assert_eq!(lazy.raw_bytes(), &raw[..]);

        // Consumer can partial-decode from raw_bytes
        let decoded = wa::HistorySync::decode(lazy.raw_bytes()).expect("should decode");
        assert_eq!(decoded.conversations[0].id, "raw@s.whatsapp.net");
    }

    #[test]
    fn lazy_history_sync_empty_bytes_decodes_default() {
        // Empty protobuf bytes are valid — decode to default HistorySync
        let lazy = LazyHistorySync::new(Bytes::new(), 0, None, None);
        let hs = lazy.get().expect("empty bytes decode to default");
        assert!(hs.conversations.is_empty());
    }

    #[test]
    fn lazy_history_sync_corrupt_bytes_returns_none() {
        let lazy = LazyHistorySync::new(Bytes::from_static(&[0xFF, 0xFF, 0xFF]), 0, None, None);
        assert!(lazy.get().is_none());
    }

    #[test]
    fn lazy_history_sync_preserves_messages() {
        let conv = wa::Conversation {
            id: "chat@s.whatsapp.net".to_string(),
            messages: vec![wa::HistorySyncMsg {
                message: Some(wa::WebMessageInfo {
                    key: wa::MessageKey {
                        id: Some("msg-0".to_string()),
                        ..Default::default()
                    },
                    ..Default::default()
                }),
                msg_order_id: Some(0),
            }],
            ..Default::default()
        };
        let bytes = make_history_sync_bytes(vec![conv]);
        let lazy = LazyHistorySync::new(Bytes::from(bytes), 0, None, None);

        let hs = lazy.get().expect("should decode");
        assert_eq!(hs.conversations[0].messages.len(), 1);
        assert_eq!(
            hs.conversations[0].messages[0]
                .message
                .as_ref()
                .unwrap()
                .key
                .id
                .as_deref(),
            Some("msg-0")
        );
    }
}
