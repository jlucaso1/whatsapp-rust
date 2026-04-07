//! Pure helpers for receipt stanza logic.
//!
//! These functions contain no runtime dependencies (`self`, `Client`, spawn, sleep).
//! Orchestration and dispatch remain in `whatsapp-rust/src/receipt.rs`.

use crate::types::message::{MessageCategory, MessageInfo};
use wacore_binary::jid::{JidExt as _, STATUS_BROADCAST_USER};

/// Determines whether a delivery receipt should be sent for this message.
///
/// Returns `false` for:
/// - Messages with an empty ID
/// - Status broadcasts (`status@broadcast`)
/// - Newsletter messages
/// - Own outgoing messages (unless category is `"peer"`, i.e., self-synced)
///
/// WA Web sends `type="peer_msg"` delivery receipts for self-synced messages
/// (category="peer"). For all other messages, receipts are skipped for our own.
pub fn should_send_delivery_receipt(info: &MessageInfo) -> bool {
    if info.id.is_empty()
        || info.source.chat.user == STATUS_BROADCAST_USER
        || info.source.chat.is_newsletter()
    {
        return false;
    }

    // WA Web sends type="peer_msg" delivery receipts for self-synced
    // messages (category="peer").  These tell the primary phone that
    // this companion device received the message.
    // For all other messages, skip receipts for our own messages.
    info.category == MessageCategory::Peer || !info.source.is_from_me
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::message::{MessageCategory, MessageInfo, MessageSource};

    #[test]
    fn skip_empty_id() {
        let info = MessageInfo {
            id: "".to_string(),
            source: MessageSource {
                chat: "12345@s.whatsapp.net".parse().unwrap(),
                sender: "12345@s.whatsapp.net".parse().unwrap(),
                is_from_me: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!should_send_delivery_receipt(&info));
    }

    #[test]
    fn skip_status_broadcast() {
        let info = MessageInfo {
            id: "MSG1".to_string(),
            source: MessageSource {
                chat: "status@broadcast".parse().unwrap(),
                sender: "12345@s.whatsapp.net".parse().unwrap(),
                is_from_me: false,
                is_group: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!should_send_delivery_receipt(&info));
    }

    #[test]
    fn skip_newsletter() {
        let info = MessageInfo {
            id: "NL1".to_string(),
            source: MessageSource {
                chat: "120363173003902460@newsletter".parse().unwrap(),
                sender: "120363173003902460@newsletter".parse().unwrap(),
                is_from_me: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!should_send_delivery_receipt(&info));
    }

    #[test]
    fn skip_own_non_peer_messages() {
        let info = MessageInfo {
            id: "OWN1".to_string(),
            source: MessageSource {
                chat: "12345@s.whatsapp.net".parse().unwrap(),
                sender: "12345@s.whatsapp.net".parse().unwrap(),
                is_from_me: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(!should_send_delivery_receipt(&info));
    }

    #[test]
    fn allow_peer_self_synced_messages() {
        let info = MessageInfo {
            id: "PEER1".to_string(),
            source: MessageSource {
                chat: "12345@s.whatsapp.net".parse().unwrap(),
                sender: "12345@s.whatsapp.net".parse().unwrap(),
                is_from_me: true,
                ..Default::default()
            },
            category: MessageCategory::Peer,
            ..Default::default()
        };
        assert!(should_send_delivery_receipt(&info));
    }

    #[test]
    fn allow_incoming_dm() {
        let info = MessageInfo {
            id: "DM1".to_string(),
            source: MessageSource {
                chat: "12345@s.whatsapp.net".parse().unwrap(),
                sender: "12345@s.whatsapp.net".parse().unwrap(),
                is_from_me: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(should_send_delivery_receipt(&info));
    }
}
