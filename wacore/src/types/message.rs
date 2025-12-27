use chrono::{DateTime, Utc};
use serde::Serialize;
use wacore_binary::jid::{Jid, JidExt, MessageId, MessageServerId};
use waproto::whatsapp as wa;

/// Maximum retry attempts per message (matches WhatsApp Web's MAX_RETRY = 5).
/// After this many retries, we stop sending retry receipts and rely solely on PDO.
pub const MAX_DECRYPT_RETRIES: u8 = 5;

/// Retry count threshold for logging high retry warnings.
/// WhatsApp Web logs metrics when retry count exceeds this value.
pub const HIGH_RETRY_COUNT_THRESHOLD: u8 = 3;

/// Retry reason codes matching WhatsApp Web's RetryReason enum.
/// These are included in the retry receipt to help the sender understand
/// why the message couldn't be decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RetryReason {
    /// Unknown or unspecified error
    UnknownError = 0,
    /// No session exists with the sender (SessionNotFound)
    NoSession = 1,
    /// Invalid key in the message
    InvalidKey = 2,
    /// PreKey ID not found (InvalidPreKeyId)
    InvalidKeyId = 3,
    /// Invalid message format or content (InvalidMessage)
    InvalidMessage = 4,
    /// Invalid signature
    InvalidSignature = 5,
    /// Message from the future (timestamp issue)
    FutureMessage = 6,
    /// MAC verification failed (bad MAC)
    BadMac = 7,
    /// Invalid session state
    InvalidSession = 8,
    /// Invalid message key
    InvalidMsgKey = 9,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AddressingMode {
    Pn,
    Lid,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MessageSource {
    pub chat: Jid,
    pub sender: Jid,
    pub is_from_me: bool,
    pub is_group: bool,
    pub addressing_mode: Option<AddressingMode>,
    pub sender_alt: Option<Jid>,
    pub recipient_alt: Option<Jid>,
    pub broadcast_list_owner: Option<Jid>,
    pub recipient: Option<Jid>,
}

impl MessageSource {
    pub fn is_incoming_broadcast(&self) -> bool {
        (!self.is_from_me || self.broadcast_list_owner.is_some()) && self.chat.is_broadcast_list()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceSentMeta {
    pub destination_jid: String,
    pub phash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub enum EditAttribute {
    #[default]
    Empty,
    MessageEdit,
    PinInChat,
    AdminEdit,
    SenderRevoke,
    AdminRevoke,
    Unknown(String),
}

impl From<String> for EditAttribute {
    fn from(s: String) -> Self {
        match s.as_str() {
            "" => Self::Empty,
            "1" => Self::MessageEdit,
            "2" => Self::PinInChat,
            "3" => Self::AdminEdit,
            "7" => Self::SenderRevoke,
            "8" => Self::AdminRevoke,
            _ => Self::Unknown(s),
        }
    }
}

impl EditAttribute {
    pub fn to_string_val(&self) -> &'static str {
        match self {
            Self::Empty => "",
            Self::MessageEdit => "1",
            Self::PinInChat => "2",
            Self::AdminEdit => "3",
            Self::SenderRevoke => "7",
            Self::AdminRevoke => "8",
            Self::Unknown(_) => "",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum BotEditType {
    First,
    Inner,
    Last,
}

#[derive(Debug, Clone, Serialize)]
pub struct MsgBotInfo {
    pub edit_type: Option<BotEditType>,
    pub edit_target_id: Option<MessageId>,
    pub edit_sender_timestamp_ms: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MsgMetaInfo {
    pub target_id: Option<MessageId>,
    pub target_sender: Option<Jid>,
    pub deprecated_lid_session: Option<bool>,
    pub thread_message_id: Option<MessageId>,
    pub thread_message_sender_jid: Option<Jid>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct MessageInfo {
    pub source: MessageSource,
    pub id: MessageId,
    pub server_id: MessageServerId,
    pub r#type: String,
    pub push_name: String,
    pub timestamp: DateTime<Utc>,
    pub category: String,
    pub multicast: bool,
    pub media_type: String,
    pub edit: EditAttribute,
    pub bot_info: Option<MsgBotInfo>,
    pub meta_info: MsgMetaInfo,
    pub verified_name: Option<wa::VerifiedNameCertificate>,
    pub device_sent_meta: Option<DeviceSentMeta>,
}
