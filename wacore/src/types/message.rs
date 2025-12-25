use chrono::{DateTime, Utc};
use serde::Serialize;
use wacore_binary::jid::{Jid, JidExt, MessageId, MessageServerId};
use waproto::whatsapp as wa;

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
