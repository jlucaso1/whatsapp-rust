//! Chat and message state structures

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use wacore::download::{Downloadable, MediaType as DownloadMediaType};

/// Maximum number of unique emoji reactions per message to prevent spam
const MAX_REACTIONS_PER_MESSAGE: usize = 50;

/// Type of media content
#[derive(Debug, Clone)]
pub enum MediaType {
    /// Image (JPEG, PNG, WebP)
    Image,
    /// Sticker (WebP, animated or static)
    Sticker,
    /// Video (thumbnail displayed, full video downloadable)
    Video,
    /// Audio (shown as placeholder)
    Audio,
    /// Document (shown as placeholder)
    Document,
}

impl MediaType {
    /// Get a display label for chat list preview
    pub fn display_label(&self) -> &'static str {
        match self {
            MediaType::Image => "📷 Photo",
            MediaType::Sticker => "🎭 Sticker",
            MediaType::Video => "🎥 Video",
            MediaType::Audio => "🎤 Voice message",
            MediaType::Document => "📄 Document",
        }
    }
}

/// Information needed to download encrypted media from WhatsApp servers.
/// This is stored separately from the thumbnail/preview data.
#[derive(Debug, Clone)]
pub struct DownloadableMedia {
    /// Direct path for CDN URL construction
    pub direct_path: String,
    /// Encryption key for decrypting the media
    pub media_key: Vec<u8>,
    /// SHA256 of encrypted file (used for URL token)
    pub file_enc_sha256: Vec<u8>,
    /// Expected file size in bytes
    pub file_length: u64,
    /// MIME type of the actual media (e.g., "video/mp4")
    pub mime_type: String,
    /// Duration in seconds (for video/audio)
    pub duration_secs: Option<u32>,
    /// Download media type (for key derivation)
    pub download_type: DownloadMediaType,
}

/// Implement Downloadable trait for DownloadableMedia to enable downloading
#[async_trait]
impl Downloadable for DownloadableMedia {
    fn direct_path(&self) -> Option<&str> {
        Some(&self.direct_path)
    }

    fn media_key(&self) -> Option<&[u8]> {
        Some(&self.media_key)
    }

    fn file_enc_sha256(&self) -> Option<&[u8]> {
        Some(&self.file_enc_sha256)
    }

    fn file_sha256(&self) -> Option<&[u8]> {
        None // Not required for download
    }

    fn file_length(&self) -> Option<u64> {
        Some(self.file_length)
    }

    fn app_info(&self) -> DownloadMediaType {
        self.download_type
    }
}

/// Media content attached to a message
#[derive(Debug, Clone)]
pub struct MediaContent {
    /// Type of media
    pub media_type: MediaType,
    /// Raw data for display (thumbnail for video, full data for images/stickers)
    pub data: Arc<Vec<u8>>,
    /// MIME type of the display data (may differ from downloadable media)
    pub mime_type: String,
    /// Width in pixels (if known)
    pub width: Option<u32>,
    /// Height in pixels (if known)
    pub height: Option<u32>,
    /// Caption text (if any)
    #[allow(dead_code)]
    pub caption: Option<String>,
    /// Download info for fetching full media (videos, documents)
    pub downloadable: Option<DownloadableMedia>,
    /// Whether this is an animated sticker (WebP animation)
    pub is_animated: bool,
    /// Duration in seconds (for audio/video)
    pub duration_secs: Option<u32>,
}

impl MediaContent {
    /// Check if this media has inline data available
    pub fn has_data(&self) -> bool {
        !self.data.is_empty()
    }

    /// Check if this media can be downloaded from server
    pub fn can_download(&self) -> bool {
        self.downloadable.is_some()
    }

    /// Check if this media can be played (has data or can be downloaded)
    pub fn can_play(&self) -> bool {
        self.has_data() || self.can_download()
    }
}

/// A chat message
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Unique message ID
    pub id: String,
    /// Sender identifier (JID)
    pub sender: String,
    /// Sender's display name (push name, for group chats)
    pub sender_name: Option<String>,
    /// Message text content
    pub content: String,
    /// When the message was sent/received
    pub timestamp: DateTime<Utc>,
    /// Whether this message was sent by the current user
    pub is_from_me: bool,
    /// Whether the message has been read
    pub is_read: bool,
    /// Optional media content
    pub media: Option<MediaContent>,
    /// Reactions on this message (emoji -> list of sender JIDs)
    pub reactions: HashMap<String, Vec<String>>,
}

impl ChatMessage {
    /// Create a new outgoing message
    pub fn new_outgoing(id: String, content: String) -> Self {
        Self {
            id,
            sender: "Me".to_string(),
            sender_name: None,
            content,
            timestamp: Utc::now(),
            is_from_me: true,
            is_read: false,
            media: None,
            reactions: HashMap::new(),
        }
    }

    /// Create a new outgoing message with media
    pub fn new_outgoing_with_media(id: String, content: String, media: MediaContent) -> Self {
        Self {
            id,
            sender: "Me".to_string(),
            sender_name: None,
            content,
            timestamp: Utc::now(),
            is_from_me: true,
            is_read: false,
            media: Some(media),
            reactions: HashMap::new(),
        }
    }

    /// Create a new incoming message
    #[allow(dead_code)]
    pub fn new_incoming(id: String, sender: String, content: String) -> Self {
        Self {
            id,
            sender,
            sender_name: None,
            content,
            timestamp: Utc::now(),
            is_from_me: false,
            is_read: false,
            media: None,
            reactions: HashMap::new(),
        }
    }

    /// Add or update a reaction to this message from a sender.
    /// Each sender can only have one reaction - adding a new one removes the previous.
    /// An empty emoji string removes the sender's reaction entirely.
    pub fn add_reaction(&mut self, emoji: String, sender: String) {
        // Remove any existing reaction from this sender (one reaction per person)
        self.reactions.values_mut().for_each(|senders| {
            senders.retain(|s| s != &sender);
        });
        self.reactions.retain(|_, senders| !senders.is_empty());

        // Add the new reaction if emoji is not empty (empty = remove)
        if !emoji.is_empty() {
            // Check if adding a new emoji type would exceed the limit
            if !self.reactions.contains_key(&emoji)
                && self.reactions.len() >= MAX_REACTIONS_PER_MESSAGE
            {
                // At limit, don't add new emoji types (but updating existing is fine)
                return;
            }
            self.reactions.entry(emoji).or_default().push(sender);
        }
    }

    /// Get the preview text for chat list display.
    ///
    /// Returns:
    /// - For text-only messages: the message content
    /// - For media messages: "[MediaType] caption" or just "[MediaType]"
    pub fn preview_text(&self) -> String {
        if let Some(media) = &self.media {
            let label = media.media_type.display_label();
            // Check caption first, then fall back to content
            let caption = media
                .caption
                .as_ref()
                .filter(|c| !c.is_empty())
                .or_else(|| Some(&self.content).filter(|c| !c.is_empty()));

            if let Some(text) = caption {
                format!("{} {}", label, text)
            } else {
                label.to_string()
            }
        } else {
            self.content.clone()
        }
    }

    /// Create a message with media content
    #[allow(dead_code)]
    pub fn with_media(mut self, media: MediaContent) -> Self {
        // Use caption as content if available
        if let Some(caption) = &media.caption
            && !caption.is_empty()
        {
            self.content = caption.clone();
        }
        self.media = Some(media);
        self
    }
}

/// A chat/conversation
#[derive(Debug, Clone)]
pub struct Chat {
    /// JID (Jabber ID) - unique identifier
    pub jid: String,
    /// Display name
    pub name: String,
    /// Last message preview
    pub last_message: Option<String>,
    /// Time of last message
    pub last_message_time: Option<DateTime<Utc>>,
    /// Number of unread messages
    pub unread_count: u32,
    /// Whether this is a group chat
    pub is_group: bool,
    /// Participant names in group chats (sender JID -> display name)
    pub participants: HashMap<String, String>,
    /// Messages in this chat
    pub messages: Vec<ChatMessage>,
}

impl Chat {
    /// Create a new chat from a JID
    pub fn new(jid: String) -> Self {
        let name = jid.split('@').next().unwrap_or(&jid).to_string();
        let is_group = jid.contains("@g.us");

        Self {
            jid,
            name,
            last_message: None,
            last_message_time: None,
            unread_count: 0,
            is_group,
            participants: HashMap::new(),
            messages: Vec::new(),
        }
    }

    /// Create a new chat with a custom name
    #[allow(dead_code)]
    pub fn with_name(jid: String, name: String) -> Self {
        let is_group = jid.contains("@g.us");

        Self {
            jid,
            name,
            last_message: None,
            last_message_time: None,
            unread_count: 0,
            is_group,
            participants: HashMap::new(),
            messages: Vec::new(),
        }
    }

    /// Update a participant's display name (for group chats)
    pub fn update_participant(&mut self, jid: String, name: String) {
        self.participants.insert(jid, name);
    }

    /// Get a participant's display name, with fallback to JID prefix
    #[allow(dead_code)]
    pub fn get_participant_name(&self, jid: &str) -> String {
        self.participants
            .get(jid)
            .cloned()
            .unwrap_or_else(|| jid.split('@').next().unwrap_or(jid).to_string())
    }

    /// Add a message to the chat, maintaining chronological order by timestamp
    pub fn add_message(&mut self, message: ChatMessage) {
        // Only increment unread count for incoming messages that are newer than last seen
        // (not for old history messages being synced)
        let is_newer = self
            .last_message_time
            .map(|t| message.timestamp >= t)
            .unwrap_or(true);

        if !message.is_from_me && is_newer {
            self.unread_count += 1;
        }

        // Only update last_message preview if this message is newer than current
        if is_newer {
            self.last_message = Some(message.preview_text());
            self.last_message_time = Some(message.timestamp);
        }

        // Insert message in sorted position by timestamp to maintain chronological order.
        // This handles out-of-order message decryption during history sync.
        // For equal timestamps, use message ID as secondary sort key for stable ordering.
        let pos = self
            .messages
            .binary_search_by(|m| {
                m.timestamp
                    .cmp(&message.timestamp)
                    .then_with(|| m.id.cmp(&message.id))
            })
            .unwrap_or_else(|pos| pos);
        self.messages.insert(pos, message);
    }

    /// Mark all messages as read
    pub fn mark_as_read(&mut self) {
        self.unread_count = 0;
        for msg in &mut self.messages {
            msg.is_read = true;
        }
    }

    /// Mark specific messages as read by their IDs
    ///
    /// Returns the number of messages that were actually updated.
    pub fn mark_messages_as_read(&mut self, message_ids: &[String]) -> usize {
        let mut count = 0;
        for msg in &mut self.messages {
            if message_ids.contains(&msg.id) && !msg.is_read {
                msg.is_read = true;
                count += 1;
                // Decrement unread count for incoming messages
                if !msg.is_from_me && self.unread_count > 0 {
                    self.unread_count -= 1;
                }
            }
        }
        count
    }

    /// Get the initial letter for avatar display
    #[allow(dead_code)]
    pub fn initial(&self) -> char {
        self.name.chars().next().unwrap_or('?')
    }

    /// Add a reaction to a message in this chat
    ///
    /// Returns true if the message was found and the reaction was added.
    pub fn add_reaction(&mut self, message_id: &str, emoji: String, sender: String) -> bool {
        if let Some(msg) = self.messages.iter_mut().find(|m| m.id == message_id) {
            msg.add_reaction(emoji, sender);
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn make_message(id: &str, timestamp_secs: i64) -> ChatMessage {
        ChatMessage {
            id: id.to_string(),
            sender: "test".to_string(),
            sender_name: None,
            content: format!("Message {}", id),
            timestamp: Utc.timestamp_opt(timestamp_secs, 0).unwrap(),
            is_from_me: false,
            is_read: false,
            media: None,
            reactions: HashMap::new(),
        }
    }

    #[test]
    fn test_messages_ordered_by_timestamp_when_added_in_order() {
        let mut chat = Chat::new("test@s.whatsapp.net".to_string());

        chat.add_message(make_message("1", 1000));
        chat.add_message(make_message("2", 2000));
        chat.add_message(make_message("3", 3000));

        assert_eq!(chat.messages.len(), 3);
        assert_eq!(chat.messages[0].id, "1");
        assert_eq!(chat.messages[1].id, "2");
        assert_eq!(chat.messages[2].id, "3");
    }

    #[test]
    fn test_messages_ordered_by_timestamp_when_added_out_of_order() {
        let mut chat = Chat::new("test@s.whatsapp.net".to_string());

        // Simulate history sync where messages are decrypted out of order
        chat.add_message(make_message("2", 2000)); // Middle message first
        chat.add_message(make_message("3", 3000)); // Newest message second
        chat.add_message(make_message("1", 1000)); // Oldest message last

        assert_eq!(chat.messages.len(), 3);
        // Should be sorted by timestamp, not insertion order
        assert_eq!(chat.messages[0].id, "1"); // oldest
        assert_eq!(chat.messages[1].id, "2"); // middle
        assert_eq!(chat.messages[2].id, "3"); // newest
    }

    #[test]
    fn test_messages_ordered_by_timestamp_reverse_order() {
        let mut chat = Chat::new("test@s.whatsapp.net".to_string());

        // Add messages in reverse chronological order (newest first)
        chat.add_message(make_message("3", 3000));
        chat.add_message(make_message("2", 2000));
        chat.add_message(make_message("1", 1000));

        assert_eq!(chat.messages.len(), 3);
        assert_eq!(chat.messages[0].id, "1");
        assert_eq!(chat.messages[1].id, "2");
        assert_eq!(chat.messages[2].id, "3");
    }

    #[test]
    fn test_messages_with_same_timestamp_sorted_by_id() {
        let mut chat = Chat::new("test@s.whatsapp.net".to_string());

        // Messages with same timestamp should be sorted by ID for stable ordering
        chat.add_message(make_message("c", 1000));
        chat.add_message(make_message("a", 1000));
        chat.add_message(make_message("b", 1000));

        assert_eq!(chat.messages.len(), 3);
        // Same timestamp: sorted alphabetically by ID
        assert_eq!(chat.messages[0].id, "a");
        assert_eq!(chat.messages[1].id, "b");
        assert_eq!(chat.messages[2].id, "c");
    }

    #[test]
    fn test_history_sync_batch_simulation() {
        let mut chat = Chat::new("test@s.whatsapp.net".to_string());

        // Simulate a realistic history sync batch where messages arrive
        // in random order due to parallel decryption
        let messages_in_arrival_order = vec![
            ("msg5", 5000),
            ("msg2", 2000),
            ("msg8", 8000),
            ("msg1", 1000),
            ("msg4", 4000),
            ("msg7", 7000),
            ("msg3", 3000),
            ("msg6", 6000),
        ];

        for (id, ts) in messages_in_arrival_order {
            chat.add_message(make_message(id, ts));
        }

        assert_eq!(chat.messages.len(), 8);

        // Verify messages are in chronological order
        let expected_order = [
            "msg1", "msg2", "msg3", "msg4", "msg5", "msg6", "msg7", "msg8",
        ];
        for (i, expected_id) in expected_order.iter().enumerate() {
            assert_eq!(
                chat.messages[i].id, *expected_id,
                "Message at index {} should be {} but was {}",
                i, expected_id, chat.messages[i].id
            );
        }

        // Verify timestamps are actually ascending
        for i in 1..chat.messages.len() {
            assert!(
                chat.messages[i].timestamp >= chat.messages[i - 1].timestamp,
                "Messages should be in ascending timestamp order"
            );
        }
    }

    #[test]
    fn test_new_message_inserted_at_correct_position() {
        let mut chat = Chat::new("test@s.whatsapp.net".to_string());

        // Add some historical messages
        chat.add_message(make_message("old1", 1000));
        chat.add_message(make_message("old2", 2000));
        chat.add_message(make_message("old3", 3000));

        // Now receive a new real-time message
        chat.add_message(make_message("new", 4000));

        assert_eq!(chat.messages.len(), 4);
        assert_eq!(chat.messages[3].id, "new"); // Should be at the end

        // Add a late-arriving historical message
        chat.add_message(make_message("late_history", 1500));

        assert_eq!(chat.messages.len(), 5);
        assert_eq!(chat.messages[0].id, "old1");
        assert_eq!(chat.messages[1].id, "late_history"); // Inserted in correct position
        assert_eq!(chat.messages[2].id, "old2");
        assert_eq!(chat.messages[3].id, "old3");
        assert_eq!(chat.messages[4].id, "new");
    }

    // Reaction tests

    #[test]
    fn test_add_single_reaction_to_message() {
        let mut msg = make_message("msg1", 1000);

        msg.add_reaction("👍".to_string(), "user1".to_string());

        assert_eq!(msg.reactions.len(), 1);
        assert!(msg.reactions.contains_key("👍"));
        assert_eq!(msg.reactions.get("👍").unwrap(), &vec!["user1".to_string()]);
    }

    #[test]
    fn test_add_multiple_different_reactions_to_message() {
        let mut msg = make_message("msg1", 1000);

        msg.add_reaction("👍".to_string(), "user1".to_string());
        msg.add_reaction("❤️".to_string(), "user2".to_string());
        msg.add_reaction("😂".to_string(), "user3".to_string());

        assert_eq!(msg.reactions.len(), 3);
        assert!(msg.reactions.contains_key("👍"));
        assert!(msg.reactions.contains_key("❤️"));
        assert!(msg.reactions.contains_key("😂"));
    }

    #[test]
    fn test_multiple_users_same_reaction() {
        let mut msg = make_message("msg1", 1000);

        msg.add_reaction("👍".to_string(), "user1".to_string());
        msg.add_reaction("👍".to_string(), "user2".to_string());
        msg.add_reaction("👍".to_string(), "user3".to_string());

        assert_eq!(msg.reactions.len(), 1);
        let senders = msg.reactions.get("👍").unwrap();
        assert_eq!(senders.len(), 3);
        assert!(senders.contains(&"user1".to_string()));
        assert!(senders.contains(&"user2".to_string()));
        assert!(senders.contains(&"user3".to_string()));
    }

    #[test]
    fn test_user_changes_reaction() {
        let mut msg = make_message("msg1", 1000);

        // User1 reacts with 👍
        msg.add_reaction("👍".to_string(), "user1".to_string());
        assert_eq!(msg.reactions.get("👍").unwrap().len(), 1);

        // User1 changes to ❤️
        msg.add_reaction("❤️".to_string(), "user1".to_string());

        // 👍 should be removed (empty), ❤️ should have user1
        assert!(!msg.reactions.contains_key("👍"));
        assert!(msg.reactions.contains_key("❤️"));
        assert_eq!(msg.reactions.get("❤️").unwrap(), &vec!["user1".to_string()]);
    }

    #[test]
    fn test_user_removes_reaction_with_empty_string() {
        let mut msg = make_message("msg1", 1000);

        msg.add_reaction("👍".to_string(), "user1".to_string());
        assert_eq!(msg.reactions.len(), 1);

        // Remove reaction by sending empty emoji
        msg.add_reaction("".to_string(), "user1".to_string());

        assert_eq!(msg.reactions.len(), 0);
    }

    #[test]
    fn test_chat_add_reaction() {
        let mut chat = Chat::new("test@s.whatsapp.net".to_string());
        chat.add_message(make_message("msg1", 1000));
        chat.add_message(make_message("msg2", 2000));

        // Add reaction to msg1
        let found = chat.add_reaction("msg1", "👍".to_string(), "user1".to_string());
        assert!(found);
        assert_eq!(chat.messages[0].reactions.len(), 1);

        // Add reaction to msg2
        let found = chat.add_reaction("msg2", "❤️".to_string(), "user2".to_string());
        assert!(found);
        assert_eq!(chat.messages[1].reactions.len(), 1);
    }

    #[test]
    fn test_chat_add_reaction_message_not_found() {
        let mut chat = Chat::new("test@s.whatsapp.net".to_string());
        chat.add_message(make_message("msg1", 1000));

        // Try to add reaction to non-existent message
        let found = chat.add_reaction("nonexistent", "👍".to_string(), "user1".to_string());
        assert!(!found);
    }

    #[test]
    fn test_reaction_count_multiple_emojis() {
        let mut msg = make_message("msg1", 1000);

        // 3 users react with 👍
        msg.add_reaction("👍".to_string(), "user1".to_string());
        msg.add_reaction("👍".to_string(), "user2".to_string());
        msg.add_reaction("👍".to_string(), "user3".to_string());

        // 2 users react with ❤️
        msg.add_reaction("❤️".to_string(), "user4".to_string());
        msg.add_reaction("❤️".to_string(), "user5".to_string());

        // 1 user reacts with 😂
        msg.add_reaction("😂".to_string(), "user6".to_string());

        assert_eq!(msg.reactions.len(), 3);
        assert_eq!(msg.reactions.get("👍").unwrap().len(), 3);
        assert_eq!(msg.reactions.get("❤️").unwrap().len(), 2);
        assert_eq!(msg.reactions.get("😂").unwrap().len(), 1);
    }
}
