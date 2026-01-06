//! Delete message for me action.

use crate::sync_actions::traits::SyncAction;
use crate::sync_actions::types::SyncCollection;
use chrono::Utc;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

/// Delete a message locally (for yourself only).
///
/// This action removes a message from your device without affecting
/// other participants in the chat.
#[derive(Debug, Clone)]
pub struct DeleteMessageForMeAction {
    /// The chat JID where the message is located.
    pub chat: Jid,
    /// The message ID to delete.
    pub message_id: String,
    /// Whether the message was sent by you.
    pub from_me: bool,
    /// For group messages, the JID of the message sender.
    pub participant: Option<Jid>,
    /// Whether to also delete associated media files.
    pub delete_media: bool,
    /// Timestamp of the message being deleted (for proper ordering).
    pub message_timestamp: i64,
}

impl DeleteMessageForMeAction {
    /// Create a new delete action for a message you sent.
    ///
    /// # Arguments
    /// * `chat` - The chat JID where the message is located
    /// * `message_id` - The message ID to delete
    /// * `message_timestamp` - The original message's timestamp in milliseconds
    pub fn for_own_message(chat: Jid, message_id: String, message_timestamp: i64) -> Self {
        Self {
            chat,
            message_id,
            from_me: true,
            participant: None,
            delete_media: true,
            message_timestamp,
        }
    }

    /// Create a new delete action for a message in a DM.
    ///
    /// # Arguments
    /// * `chat` - The chat JID where the message is located
    /// * `message_id` - The message ID to delete
    /// * `from_me` - Whether the message was sent by you
    /// * `message_timestamp` - The original message's timestamp in milliseconds
    pub fn for_dm_message(
        chat: Jid,
        message_id: String,
        from_me: bool,
        message_timestamp: i64,
    ) -> Self {
        Self {
            chat,
            message_id,
            from_me,
            participant: None,
            delete_media: true,
            message_timestamp,
        }
    }

    /// Create a new delete action for a group message.
    ///
    /// # Arguments
    /// * `chat` - The chat JID where the message is located
    /// * `message_id` - The message ID to delete
    /// * `from_me` - Whether the message was sent by you
    /// * `sender` - The JID of the message sender
    /// * `message_timestamp` - The original message's timestamp in milliseconds
    pub fn for_group_message(
        chat: Jid,
        message_id: String,
        from_me: bool,
        sender: Jid,
        message_timestamp: i64,
    ) -> Self {
        Self {
            chat,
            message_id,
            from_me,
            participant: Some(sender),
            delete_media: true,
            message_timestamp,
        }
    }
}

impl SyncAction for DeleteMessageForMeAction {
    fn collection(&self) -> SyncCollection {
        // WhatsApp Web uses REGULAR_HIGH for delete message for me action
        SyncCollection::RegularHigh
    }

    fn build_index(&self) -> Vec<String> {
        vec![
            "deleteMessageForMe".to_string(),
            self.chat.to_string(),
            self.message_id.clone(),
            if self.from_me { "1" } else { "0" }.to_string(),
            self.participant
                .as_ref()
                .map(|j| j.to_string())
                .unwrap_or_else(|| "0".to_string()),
        ]
    }

    fn build_value(&self) -> wa::SyncActionValue {
        wa::SyncActionValue {
            timestamp: Some(Utc::now().timestamp_millis()),
            delete_message_for_me_action: Some(wa::sync_action_value::DeleteMessageForMeAction {
                delete_media: Some(self.delete_media),
                message_timestamp: Some(self.message_timestamp),
            }),
            ..Default::default()
        }
    }

    fn version(&self) -> i32 {
        2 // DeleteMessageForMe action uses version 2 (same as star)
    }
}
