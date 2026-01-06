//! Mute chat action.

use crate::sync_actions::traits::SyncAction;
use crate::sync_actions::types::SyncCollection;
use chrono::Utc;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

/// Mute or unmute a chat.
///
/// Muted chats don't trigger notifications.
#[derive(Debug, Clone)]
pub struct MuteChatAction {
    /// The chat JID to mute/unmute.
    pub chat: Jid,
    /// When the mute expires (Unix timestamp in seconds).
    /// None means unmute.
    pub mute_end_timestamp: Option<i64>,
}

impl MuteChatAction {
    /// Create an action to mute a chat until the specified timestamp.
    pub fn mute_until(chat: Jid, until_timestamp: i64) -> Self {
        Self {
            chat,
            mute_end_timestamp: Some(until_timestamp),
        }
    }

    /// Create an action to mute a chat for a duration.
    pub fn mute_for(chat: Jid, duration: std::time::Duration) -> Self {
        let until = Utc::now().timestamp() + duration.as_secs() as i64;
        Self {
            chat,
            mute_end_timestamp: Some(until),
        }
    }

    /// Create an action to mute a chat indefinitely.
    pub fn mute_forever(chat: Jid) -> Self {
        // Use a timestamp far in the future (year 2100)
        Self {
            chat,
            mute_end_timestamp: Some(4102444800),
        }
    }

    /// Create an action to unmute a chat.
    pub fn unmute(chat: Jid) -> Self {
        Self {
            chat,
            mute_end_timestamp: None,
        }
    }
}

impl SyncAction for MuteChatAction {
    fn collection(&self) -> SyncCollection {
        // WhatsApp Web uses REGULAR_HIGH for mute action
        SyncCollection::RegularHigh
    }

    fn build_index(&self) -> Vec<String> {
        vec!["mute".to_string(), self.chat.to_string()]
    }

    fn build_value(&self) -> wa::SyncActionValue {
        wa::SyncActionValue {
            timestamp: Some(Utc::now().timestamp_millis()),
            mute_action: Some(wa::sync_action_value::MuteAction {
                muted: Some(self.mute_end_timestamp.is_some()),
                mute_end_timestamp: self.mute_end_timestamp,
                auto_muted: Some(false),
            }),
            ..Default::default()
        }
    }

    fn version(&self) -> i32 {
        2 // Mute action uses version 2
    }
}
