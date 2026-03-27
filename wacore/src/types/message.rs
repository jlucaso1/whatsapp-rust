use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use wacore_binary::jid::{Jid, JidExt, MessageId, MessageServerId};
use waproto::whatsapp as wa;

use crate::StringEnum;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, crate::StringEnum)]
#[serde(rename_all = "lowercase")]
pub enum AddressingMode {
    #[string_default]
    #[str = "pn"]
    Pn,
    #[str = "lid"]
    Lid,
}

#[derive(Debug, Clone, PartialEq, Eq, StringEnum)]
pub enum MessageCategory {
    #[string_default]
    #[str = ""]
    Empty,
    #[str = "peer"]
    Peer,
    #[string_fallback]
    Other(String),
}

impl serde::Serialize for MessageCategory {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
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
    /// Preserves the original wire value for Unknown variants.
    pub fn to_string_val(&self) -> &str {
        self.as_str()
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
    pub category: MessageCategory,
    pub multicast: bool,
    pub media_type: String,
    pub edit: EditAttribute,
    pub bot_info: Option<MsgBotInfo>,
    pub meta_info: MsgMetaInfo,
    pub verified_name: Option<wa::VerifiedNameCertificate>,
    pub device_sent_meta: Option<DeviceSentMeta>,
    /// Ephemeral duration in seconds, extracted from `contextInfo.expiration`.
    pub ephemeral_expiration: Option<u32>,
}

impl MessageInfo {
    /// WA Web: expired status messages (>24h) are silently dropped — no retry receipts,
    /// no undecryptable events. Matches `WAWebMsgProcessingDecryptionHandler.E()`.
    pub fn is_expired_status(&self) -> bool {
        self.source.chat.is_status_broadcast()
            && (crate::time::now_utc() - self.timestamp) > chrono::Duration::hours(24)
    }
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

        // Unknown values should be preserved (round-trip the wire value)
        assert_eq!(
            EditAttribute::from("99".to_string()),
            EditAttribute::Unknown("99".to_string())
        );
        assert_eq!(
            EditAttribute::Unknown("anything".to_string()).to_string_val(),
            "anything"
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
