//! Mark chat as read action.

use crate::sync_actions::traits::SyncAction;
use crate::sync_actions::types::SyncCollection;
use chrono::Utc;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

/// Mark a chat as read or unread.
#[derive(Debug, Clone)]
pub struct MarkChatAsReadAction {
    /// The chat JID to mark.
    pub chat: Jid,
    /// Whether to mark as read (true) or unread (false).
    pub read: bool,
}

impl MarkChatAsReadAction {
    /// Create an action to mark a chat as read.
    pub fn mark_read(chat: Jid) -> Self {
        Self { chat, read: true }
    }

    /// Create an action to mark a chat as unread.
    pub fn mark_unread(chat: Jid) -> Self {
        Self { chat, read: false }
    }
}

impl SyncAction for MarkChatAsReadAction {
    fn collection(&self) -> SyncCollection {
        // WhatsApp Web uses REGULAR_LOW for mark chat as read action
        SyncCollection::RegularLow
    }

    fn build_index(&self) -> Vec<String> {
        vec!["markChatAsRead".to_string(), self.chat.to_string()]
    }

    fn build_value(&self) -> wa::SyncActionValue {
        wa::SyncActionValue {
            timestamp: Some(Utc::now().timestamp_millis()),
            mark_chat_as_read_action: Some(wa::sync_action_value::MarkChatAsReadAction {
                read: Some(self.read),
                message_range: None,
            }),
            ..Default::default()
        }
    }

    fn version(&self) -> i32 {
        3 // MarkChatAsRead action uses version 3
    }
}
