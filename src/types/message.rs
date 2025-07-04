use crate::proto::whatsapp as wa;
use crate::types::jid::{Jid, MessageId, MessageServerId};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressingMode {
    Pn,
    Lid,
}

#[derive(Debug, Clone, Default)]
pub struct MessageSource {
    pub chat: Jid,
    pub sender: Jid,
    pub is_from_me: bool,
    pub is_group: bool,
    pub addressing_mode: Option<AddressingMode>,
    pub sender_alt: Option<Jid>,
    pub recipient_alt: Option<Jid>,
    pub broadcast_list_owner: Option<Jid>,
}

impl MessageSource {
    pub fn is_incoming_broadcast(&self) -> bool {
        (!self.is_from_me || self.broadcast_list_owner.is_some()) && self.chat.is_broadcast_list()
    }
}

#[derive(Debug, Clone)]
pub struct DeviceSentMeta {
    pub destination_jid: String,
    pub phash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditAttribute {
    Empty,
    MessageEdit,
    PinInChat,
    AdminEdit,
    SenderRevoke,
    AdminRevoke,
    Unknown(String),
}

impl Default for EditAttribute {
    fn default() -> Self {
        EditAttribute::Empty
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotEditType {
    First,
    Inner,
    Last,
}

#[derive(Debug, Clone)]
pub struct MsgBotInfo {
    pub edit_type: Option<BotEditType>,
    pub edit_target_id: Option<MessageId>,
    pub edit_sender_timestamp_ms: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Default)]
pub struct MsgMetaInfo {
    pub target_id: Option<MessageId>,
    pub target_sender: Option<Jid>,
    pub deprecated_lid_session: Option<bool>,
    pub thread_message_id: Option<MessageId>,
    pub thread_message_sender_jid: Option<Jid>,
}

#[derive(Debug, Clone, Default)]
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

pub fn get_base_message(mut message: &wa::Message) -> &wa::Message {
    if let Some(device_sent) = message
        .device_sent_message
        .as_ref()
        .and_then(|d| d.message.as_ref())
    {
        message = device_sent;
    }
    if let Some(ephemeral) = message
        .ephemeral_message
        .as_ref()
        .and_then(|e| e.message.as_ref())
    {
        message = ephemeral;
    }
    if let Some(view_once) = message
        .view_once_message
        .as_ref()
        .and_then(|v| v.message.as_ref())
    {
        message = view_once;
    }
    if let Some(view_once_v2) = message
        .view_once_message_v2
        .as_ref()
        .and_then(|v| v.message.as_ref())
    {
        message = view_once_v2;
    }
    message
}
