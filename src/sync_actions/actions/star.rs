//! Star message action.

use crate::sync_actions::traits::SyncAction;
use crate::sync_actions::types::SyncCollection;
use chrono::Utc;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

/// Star or unstar a message.
///
/// Starred messages appear in a special "Starred Messages" section
/// for quick access.
#[derive(Debug, Clone)]
pub struct StarMessageAction {
    /// The chat JID where the message is located.
    pub chat: Jid,
    /// The message ID to star/unstar.
    pub message_id: String,
    /// Whether the message was sent by you.
    pub from_me: bool,
    /// For group messages, the JID of the message sender.
    pub participant: Option<Jid>,
    /// Whether to star (true) or unstar (false) the message.
    pub starred: bool,
}

impl StarMessageAction {
    /// Create a star action for a DM message.
    pub fn for_dm(chat: Jid, message_id: String, from_me: bool, starred: bool) -> Self {
        Self {
            chat,
            message_id,
            from_me,
            participant: None,
            starred,
        }
    }

    /// Create a star action for a group message.
    pub fn for_group(
        chat: Jid,
        message_id: String,
        from_me: bool,
        sender: Jid,
        starred: bool,
    ) -> Self {
        Self {
            chat,
            message_id,
            from_me,
            participant: Some(sender),
            starred,
        }
    }
}

impl SyncAction for StarMessageAction {
    fn collection(&self) -> SyncCollection {
        // WhatsApp Web uses REGULAR_HIGH for star action
        SyncCollection::RegularHigh
    }

    fn build_index(&self) -> Vec<String> {
        vec![
            "star".to_string(),
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
            star_action: Some(wa::sync_action_value::StarAction {
                starred: Some(self.starred),
            }),
            ..Default::default()
        }
    }

    fn version(&self) -> i32 {
        2 // Star action uses version 2
    }
}
