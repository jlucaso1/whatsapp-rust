use crate::types::jid::Jid;
use std::str::FromStr;
use waproto::whatsapp as wa;

/// Extension trait for wa::Message
pub trait MessageExt {
    /// Recursively unwraps ephemeral/view-once/document_with_caption/edited wrappers to get the core message.
    fn get_base_message(&self) -> &wa::Message;
    fn is_ephemeral(&self) -> bool;
    fn is_view_once(&self) -> bool;
    /// Gets the caption for media messages (Image, Video, Document).
    fn get_caption(&self) -> Option<&str>;
    /// Gets the primary text content of a message (from conversation or extendedTextMessage).
    fn text_content(&self) -> Option<&str>;
}

impl MessageExt for wa::Message {
    fn get_base_message(&self) -> &wa::Message {
        let mut current = self;
        if let Some(msg) = self
            .device_sent_message
            .as_ref()
            .and_then(|m| m.message.as_ref())
        {
            current = msg;
        }
        if let Some(msg) = current
            .ephemeral_message
            .as_ref()
            .and_then(|m| m.message.as_ref())
        {
            current = msg;
        }
        if let Some(msg) = current
            .view_once_message
            .as_ref()
            .and_then(|m| m.message.as_ref())
        {
            current = msg;
        }
        if let Some(msg) = current
            .view_once_message_v2
            .as_ref()
            .and_then(|m| m.message.as_ref())
        {
            current = msg;
        }
        if let Some(msg) = current
            .document_with_caption_message
            .as_ref()
            .and_then(|m| m.message.as_ref())
        {
            current = msg;
        }
        if let Some(msg) = current
            .edited_message
            .as_ref()
            .and_then(|m| m.message.as_ref())
        {
            current = msg;
        }
        current
    }

    fn is_ephemeral(&self) -> bool {
        self.ephemeral_message.is_some()
    }

    fn is_view_once(&self) -> bool {
        self.view_once_message.is_some() || self.view_once_message_v2.is_some()
    }

    fn get_caption(&self) -> Option<&str> {
        let base = self.get_base_message();
        if let Some(msg) = &base.image_message {
            return msg.caption.as_deref();
        }
        if let Some(msg) = &base.video_message {
            return msg.caption.as_deref();
        }
        if let Some(msg) = &base.document_message {
            return msg.caption.as_deref();
        }
        None
    }

    fn text_content(&self) -> Option<&str> {
        let base = self.get_base_message();
        if let Some(text) = &base.conversation
            && !text.is_empty()
        {
            return Some(text);
        }
        if let Some(ext_text) = &base.extended_text_message
            && let Some(text) = &ext_text.text
        {
            return Some(text);
        }
        None
    }
}

/// Extension trait for wa::Conversation
pub trait ConversationExt {
    fn subject(&self) -> Option<&str>;
    fn participant_jids(&self) -> Vec<Jid>;
    fn admin_jids(&self) -> Vec<Jid>;
    fn is_locked(&self) -> bool;
    fn is_announce_only(&self) -> bool;
}

impl ConversationExt for wa::Conversation {
    fn subject(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn participant_jids(&self) -> Vec<Jid> {
        self.participant
            .iter()
            .filter_map(|p| Jid::from_str(&p.user_jid).ok())
            .collect()
    }

    fn admin_jids(&self) -> Vec<Jid> {
        self.participant
            .iter()
            .filter(|p| {
                p.rank() == wa::group_participant::Rank::Admin
                    || p.rank() == wa::group_participant::Rank::Superadmin
            })
            .filter_map(|p| Jid::from_str(&p.user_jid).ok())
            .collect()
    }

    fn is_locked(&self) -> bool {
        // Placeholder: actual state should come from SyncActionValue in GroupInfoUpdate
        false
    }

    fn is_announce_only(&self) -> bool {
        // Placeholder: actual state should come from SyncActionValue in GroupInfoUpdate
        false
    }
}
