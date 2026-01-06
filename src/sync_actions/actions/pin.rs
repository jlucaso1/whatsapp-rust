//! Pin chat action.

use crate::sync_actions::traits::SyncAction;
use crate::sync_actions::types::SyncCollection;
use chrono::Utc;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

/// Pin or unpin a chat.
///
/// Pinned chats appear at the top of the chat list.
#[derive(Debug, Clone)]
pub struct PinChatAction {
    /// The chat JID to pin/unpin.
    pub chat: Jid,
    /// Whether to pin (true) or unpin (false).
    pub pinned: bool,
}

impl PinChatAction {
    /// Create an action to pin a chat.
    pub fn pin(chat: Jid) -> Self {
        Self { chat, pinned: true }
    }

    /// Create an action to unpin a chat.
    pub fn unpin(chat: Jid) -> Self {
        Self {
            chat,
            pinned: false,
        }
    }
}

impl SyncAction for PinChatAction {
    fn collection(&self) -> SyncCollection {
        // WhatsApp Web uses REGULAR_LOW for pin action
        SyncCollection::RegularLow
    }

    fn build_index(&self) -> Vec<String> {
        vec!["pin_v1".to_string(), self.chat.to_string()]
    }

    fn build_value(&self) -> wa::SyncActionValue {
        wa::SyncActionValue {
            timestamp: Some(Utc::now().timestamp_millis()),
            pin_action: Some(wa::sync_action_value::PinAction {
                pinned: Some(self.pinned),
            }),
            ..Default::default()
        }
    }

    fn version(&self) -> i32 {
        5 // Pin action uses version 5
    }
}
