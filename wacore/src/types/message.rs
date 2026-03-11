use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde::Serialize;
use wacore_binary::jid::{Jid, JidExt, MessageId, MessageServerId};
use waproto::whatsapp as wa;

/// Unique identifier for a message stanza within a chat.
/// Used for deduplication and retry tracking.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StanzaKey {
    pub chat: Jid,
    pub id: MessageId,
}

impl StanzaKey {
    pub fn new(chat: Jid, id: MessageId) -> Self {
        Self { chat, id }
    }
}

/// Addressing mode for a group (phone number vs LID).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, crate::StringEnum)]
#[serde(rename_all = "lowercase")]
pub enum AddressingMode {
    #[string_default]
    #[str = "pn"]
    Pn,
    #[str = "lid"]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, crate::StringEnum)]
pub enum EditAttribute {
    #[string_default]
    #[str = ""]
    Empty,
    #[str = "1"]
    MessageEdit,
    #[str = "2"]
    PinInChat,
    #[str = "3"]
    AdminEdit,
    #[str = "7"]
    SenderRevoke,
    #[str = "8"]
    AdminRevoke,
    #[string_fallback]
    Unknown(String),
}

impl From<String> for EditAttribute {
    fn from(s: String) -> Self {
        Self::from(s.as_str())
    }
}

impl EditAttribute {
    /// Returns the wire-format string value for the edit attribute.
    /// Unknown values map to empty string (same as Empty).
    pub fn to_string_val(&self) -> &str {
        match self {
            Self::Unknown(_) => "",
            other => other.as_str(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_edit_attribute_parsing_and_serialization() {
        // Test all known edit attribute values
        let attrs = vec![
            ("", EditAttribute::Empty),
            ("1", EditAttribute::MessageEdit),
            ("2", EditAttribute::PinInChat),
            ("3", EditAttribute::AdminEdit),
            ("7", EditAttribute::SenderRevoke),
            ("8", EditAttribute::AdminRevoke),
        ];

        for (string_val, expected_attr) in attrs {
            let parsed = EditAttribute::from(string_val.to_string());
            assert_eq!(parsed, expected_attr);
            assert_eq!(parsed.to_string_val(), string_val);
        }

        // Unknown values should be preserved
        assert_eq!(
            EditAttribute::from("99".to_string()),
            EditAttribute::Unknown("99".to_string())
        );
        assert_eq!(
            EditAttribute::Unknown("anything".to_string()).to_string_val(),
            ""
        );
    }

    #[test]
    fn test_decrypt_fail_hide_logic_for_edits() {
        // Documents the logic used in prepare_group_stanza (wacore/src/send.rs).
        // The decrypt-fail="hide" attribute is added for edited messages to hide
        // failed decryption attempts. However, admin revokes should NOT have it
        // because WhatsApp Web doesn't include it, and the server rejects it.

        fn should_add_decrypt_fail_hide(edit: &EditAttribute) -> bool {
            *edit != EditAttribute::Empty && *edit != EditAttribute::AdminRevoke
        }

        // Should add decrypt-fail="hide"
        assert!(should_add_decrypt_fail_hide(&EditAttribute::MessageEdit));
        assert!(should_add_decrypt_fail_hide(&EditAttribute::PinInChat));
        assert!(should_add_decrypt_fail_hide(&EditAttribute::AdminEdit));
        assert!(should_add_decrypt_fail_hide(&EditAttribute::SenderRevoke));

        // Should NOT add decrypt-fail="hide"
        assert!(!should_add_decrypt_fail_hide(&EditAttribute::Empty));
        assert!(!should_add_decrypt_fail_hide(&EditAttribute::AdminRevoke));
    }
}
