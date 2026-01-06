//! Archive chat action.

use crate::sync_actions::traits::SyncAction;
use crate::sync_actions::types::SyncCollection;
use chrono::Utc;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

/// Archive or unarchive a chat.
///
/// Archived chats are hidden from the main chat list.
#[derive(Debug, Clone)]
pub struct ArchiveChatAction {
    /// The chat JID to archive/unarchive.
    pub chat: Jid,
    /// Whether to archive (true) or unarchive (false).
    pub archived: bool,
}

impl ArchiveChatAction {
    /// Create an action to archive a chat.
    pub fn archive(chat: Jid) -> Self {
        Self {
            chat,
            archived: true,
        }
    }

    /// Create an action to unarchive a chat.
    pub fn unarchive(chat: Jid) -> Self {
        Self {
            chat,
            archived: false,
        }
    }
}

impl SyncAction for ArchiveChatAction {
    fn collection(&self) -> SyncCollection {
        // WhatsApp Web uses REGULAR_LOW for archive action
        SyncCollection::RegularLow
    }

    fn build_index(&self) -> Vec<String> {
        vec!["archive".to_string(), self.chat.to_string()]
    }

    fn build_value(&self) -> wa::SyncActionValue {
        wa::SyncActionValue {
            timestamp: Some(Utc::now().timestamp_millis()),
            archive_chat_action: Some(wa::sync_action_value::ArchiveChatAction {
                archived: Some(self.archived),
                message_range: None,
            }),
            ..Default::default()
        }
    }

    fn version(&self) -> i32 {
        3 // Archive action uses version 3
    }
}
