use std::str::FromStr;
use wacore_binary::jid::{Jid, JidExt};
use waproto::whatsapp as wa;

/// Invokes a callback macro with the list of all message types that have `context_info`.
///
/// This macro ensures both `for_each_context_info_message!` and `set_context_info_on_message!`
/// use the same list of message types, making it easy to add new types in one place.
///
/// When WhatsApp adds new message types with context_info, add them here.
macro_rules! with_context_info_fields {
    ($callback:ident!($($prefix:tt)*)) => {
        $callback!($($prefix)*
            extended_text_message,
            image_message,
            video_message,
            audio_message,
            document_message,
            sticker_message,
            location_message,
            live_location_message,
            contact_message,
            contacts_array_message,
            buttons_message,
            buttons_response_message,
            list_message,
            list_response_message,
            template_message,
            template_button_reply_message,
            interactive_message,
            interactive_response_message,
            poll_creation_message,
            poll_creation_message_v2,
            poll_creation_message_v3,
            product_message,
            order_message,
            group_invite_message,
            event_message,
            sticker_pack_message,
            newsletter_admin_invite_message,
        )
    };
}

/// Applies an operation to all message types that have a `context_info` field.
///
/// Usage:
/// ```ignore
/// for_each_context_info_message!(msg, ctx, {
///     ctx.mentioned_jid.clear();
/// });
/// ```
macro_rules! for_each_context_info_message {
    ($msg:expr, $ctx:ident, $body:block) => {
        with_context_info_fields!(for_each_context_info_impl!($msg, $ctx, $body,))
    };
}

macro_rules! for_each_context_info_impl {
    ($msg:expr, $ctx:ident, $body:block, $($field:ident),+ $(,)?) => {
        $(
            if let Some(ref mut m) = $msg.$field {
                if let Some(ref mut $ctx) = m.context_info $body
            }
        )+
    };
}

/// Sets context_info on the first matching message type.
/// Returns true if context was set, false otherwise.
macro_rules! set_context_info_on_message {
    ($msg:expr, $ctx:expr) => {
        with_context_info_fields!(set_context_info_impl!($msg, $ctx,))
    };
}

macro_rules! set_context_info_impl {
    ($msg:expr, $ctx:expr, $($field:ident),+ $(,)?) => {{
        let ctx = $ctx;
        $(
            if let Some(ref mut m) = $msg.$field {
                m.context_info = Some(ctx);
                return true;
            }
        )+
        false
    }};
}

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

    /// Prepares a message for use as a quoted message by stripping nested mentions.
    ///
    /// When quoting a message, WhatsApp Web builds a fresh `ContextInfo` and does NOT
    /// carry over mentions from the original message's nested `context_info` fields.
    /// Without this, if someone quotes a message that contained mentions or was itself
    /// a reply with mentions, those mentions would be preserved and WhatsApp would
    /// tag those people in the new reply.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use wacore::proto_helpers::MessageExt;
    ///
    /// let context_info = wa::ContextInfo {
    ///     stanza_id: Some(message_id.clone()),
    ///     participant: Some(sender_jid.to_string()),
    ///     quoted_message: Some(original_message.prepare_for_quote()),
    ///     ..Default::default()
    /// };
    /// ```
    fn prepare_for_quote(&self) -> Box<wa::Message>;

    /// Sets the context_info on this message for quoting/replying.
    ///
    /// This method finds the appropriate message field (image, video, text, etc.)
    /// and sets its context_info. Returns `true` if context was set successfully,
    /// `false` if the message type doesn't support context_info.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use wacore::proto_helpers::MessageExt;
    ///
    /// let mut reply = wa::Message {
    ///     image_message: Some(Box::new(wa::message::ImageMessage {
    ///         // ... image data
    ///         ..Default::default()
    ///     })),
    ///     ..Default::default()
    /// };
    ///
    /// let context = wa::ContextInfo {
    ///     stanza_id: Some("original-msg-id".to_string()),
    ///     participant: Some("sender@s.whatsapp.net".to_string()),
    ///     quoted_message: Some(original_msg.prepare_for_quote()),
    ///     ..Default::default()
    /// };
    ///
    /// reply.set_context_info(context);
    /// ```
    fn set_context_info(&mut self, context: wa::ContextInfo) -> bool;
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

    fn prepare_for_quote(&self) -> Box<wa::Message> {
        let mut msg = self.clone();
        strip_nested_context_info(&mut msg);
        Box::new(msg)
    }

    fn set_context_info(&mut self, context: wa::ContextInfo) -> bool {
        set_context_info_on_message!(self, Box::new(context))
    }
}

/// Strips nested context_info fields from a message to match WhatsApp Web behavior.
///
/// WhatsApp Web (when `drop_inner_message_context_infos_when_sending` is enabled,
/// which is the default) clears these fields from nested context_info:
/// - `quoted_message` - Breaks the quote chain
/// - `stanza_id` - The quoted message ID
/// - `remote_jid` - The chat where the quoted message was sent
/// - `participant` - Who sent the quoted message
/// - `mentioned_jid` - Mentions in the nested message
/// - `group_mentions` - Group mentions in the nested message
///
/// This prevents:
/// 1. Infinite quote chains in deeply nested replies
/// 2. Accidental mentions from quoted messages
/// 3. Excessive message size from nested content
///
///
/// This is used internally by `MessageExt::prepare_for_quote()` but can also be called
/// directly if you need to modify a message in place.
fn strip_nested_context_info(msg: &mut wa::Message) {
    fn clear_nested_context(ctx: &mut wa::ContextInfo) {
        // Always clear mentions (prevents accidental tagging)
        ctx.mentioned_jid.clear();
        ctx.group_mentions.clear();

        // Check if participant is a bot - if so, preserve quote chain
        // WhatsApp Web (3JJWKHeu5-P.js:48737-48742) only clears quote-chain fields
        // if the participant is NOT a bot
        let is_bot = ctx
            .participant
            .as_ref()
            .and_then(|p| Jid::from_str(p).ok())
            .is_some_and(|jid| jid.is_bot());

        if !is_bot {
            // Clear quote-chain fields (matches WhatsApp Web behavior)
            // This breaks the quote chain at the first level - when you quote a reply,
            // the nested reply's quote info is stripped
            ctx.quoted_message = None;
            ctx.stanza_id = None;
            ctx.remote_jid = None;
            ctx.participant = None;
        }
    }

    for_each_context_info_message!(msg, ctx, {
        clear_nested_context(ctx);
    });

    // Handle wrapper messages that contain nested messages
    macro_rules! recurse_into_wrapper {
        ($($wrapper:ident),+ $(,)?) => {
            $(
                if let Some(ref mut wrapper) = msg.$wrapper {
                    if let Some(ref mut inner) = wrapper.message {
                        strip_nested_context_info(inner);
                    }
                }
            )+
        };
    }
    recurse_into_wrapper!(
        ephemeral_message,
        view_once_message,
        view_once_message_v2,
        document_with_caption_message,
        edited_message,
    );

    // device_sent_message has a different structure (DeviceSentMessage vs FutureProofMessage)
    // but also contains a nested message field that needs to be processed
    if let Some(ref mut wrapper) = msg.device_sent_message
        && let Some(ref mut inner) = wrapper.message
    {
        strip_nested_context_info(inner);
    }
}

/// Builds a quote context for replying to a message.
///
/// This is a standalone function that can be used without `MessageContext`,
/// useful for users who don't use the Bot API.
///
/// # Arguments
/// * `message_id` - The ID of the message being quoted
/// * `sender_jid` - The JID of the sender of the message being quoted
/// * `quoted_message` - The message being quoted
///
/// # Example
///
/// ```ignore
/// use wacore::proto_helpers::{build_quote_context, MessageExt};
///
/// let context = build_quote_context(
///     "3EB0123456789",
///     "1234567890@s.whatsapp.net",
///     &original_message,
/// );
///
/// let reply = wa::Message {
///     extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
///         text: Some("My reply".to_string()),
///         context_info: Some(Box::new(context)),
///         ..Default::default()
///     })),
///     ..Default::default()
/// };
/// ```
pub fn build_quote_context(
    message_id: impl Into<String>,
    sender_jid: impl Into<String>,
    quoted_message: &wa::Message,
) -> wa::ContextInfo {
    wa::ContextInfo {
        stanza_id: Some(message_id.into()),
        participant: Some(sender_jid.into()),
        quoted_message: Some(quoted_message.prepare_for_quote()),
        ..Default::default()
    }
}

/// Builds a quote context with proper participant resolution for special message types.
///
/// This matches WhatsApp Web's `getQuotedParticipantForContextInfo` (3JJWKHeu5-P.js:144304-144311)
/// which resolves the participant based on message type:
/// - Newsletter messages: uses the chat JID (the newsletter itself)
/// - Group status messages: uses the sender (author field not available here)
/// - Normal messages: uses the sender JID
///
/// # Arguments
/// * `message_id` - The ID of the message being quoted
/// * `sender_jid` - The JID of the sender of the message being quoted
/// * `chat_jid` - The JID of the chat where the message was sent
/// * `quoted_message` - The message being quoted
///
/// # Example
///
/// ```ignore
/// use wacore::proto_helpers::{build_quote_context_with_info, MessageExt};
///
/// let context = build_quote_context_with_info(
///     "3EB0123456789",
///     &sender_jid,
///     &chat_jid,
///     &original_message,
/// );
/// ```
pub fn build_quote_context_with_info(
    message_id: impl Into<String>,
    sender_jid: &Jid,
    chat_jid: &Jid,
    quoted_message: &wa::Message,
) -> wa::ContextInfo {
    // Resolve the correct participant based on message type
    // (matches WhatsApp Web's getQuotedParticipantForContextInfo)
    let participant = if chat_jid.is_newsletter() {
        // Newsletter: use the chat JID (newsletter itself)
        chat_jid.to_string()
    } else if chat_jid.is_status_broadcast() {
        // Group status: ideally use author, but we fall back to sender
        // (author field not available in this context)
        sender_jid.to_string()
    } else {
        // Normal: use sender
        sender_jid.to_string()
    };

    wa::ContextInfo {
        stanza_id: Some(message_id.into()),
        participant: Some(participant),
        quoted_message: Some(quoted_message.prepare_for_quote()),
        ..Default::default()
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
        use wa::group_participant::Rank;
        self.participant
            .iter()
            .filter(|p| matches!(p.rank(), Rank::Admin | Rank::Superadmin))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a message with mentions in its context_info
    fn create_message_with_mentions() -> wa::Message {
        wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Hello @user1 @user2".to_string()),
                context_info: Some(Box::new(wa::ContextInfo {
                    mentioned_jid: vec![
                        "111111@s.whatsapp.net".to_string(),
                        "222222@s.whatsapp.net".to_string(),
                    ],
                    group_mentions: vec![wa::GroupMention {
                        group_jid: Some("120363012345@g.us".to_string()),
                        group_subject: Some("Test Group".to_string()),
                    }],
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    /// Test: prepare_for_quote strips mentions from extended_text_message while preserving other fields
    ///
    /// WhatsApp Web behavior: When quoting a message, the new message's contextInfo
    /// should NOT carry over mentions from the quoted message's nested context_info.
    /// However, all other message content (text, urls, captions, etc.) MUST be preserved.
    #[test]
    fn test_prepare_for_quote_strips_mentions_preserves_content() {
        use wa::message::extended_text_message::{FontType, PreviewType};

        // Create a message with mentions AND other fields that should be preserved
        let original = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Hello @user1 @user2".to_string()),
                matched_text: Some("https://example.com".to_string()),
                description: Some("Example description".to_string()),
                title: Some("Example Title".to_string()),
                text_argb: Some(0xFFFFFF),
                background_argb: Some(0x000000),
                font: Some(FontType::SystemBold.into()),
                preview_type: Some(PreviewType::Video.into()),
                context_info: Some(Box::new(wa::ContextInfo {
                    mentioned_jid: vec![
                        "111111@s.whatsapp.net".to_string(),
                        "222222@s.whatsapp.net".to_string(),
                    ],
                    group_mentions: vec![wa::GroupMention {
                        group_jid: Some("120363012345@g.us".to_string()),
                        group_subject: Some("Test Group".to_string()),
                    }],
                    // Other context_info fields that should be preserved
                    is_forwarded: Some(true),
                    forwarding_score: Some(5),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };

        // Verify original has mentions
        let ext = original.extended_text_message.as_ref().unwrap();
        let ctx = ext.context_info.as_ref().unwrap();
        assert_eq!(ctx.mentioned_jid.len(), 2);
        assert_eq!(ctx.group_mentions.len(), 1);

        // Prepare for quote
        let prepared = original.prepare_for_quote();

        // Verify mentions were stripped
        let ext = prepared.extended_text_message.as_ref().unwrap();
        let ctx = ext.context_info.as_ref().unwrap();
        assert!(
            ctx.mentioned_jid.is_empty(),
            "mentioned_jid should be empty after prepare_for_quote"
        );
        assert!(
            ctx.group_mentions.is_empty(),
            "group_mentions should be empty after prepare_for_quote"
        );

        // Verify quote-chain fields are also cleared (matches WhatsApp Web)
        // Note: The original message didn't have these, but we verify they remain None
        assert!(
            ctx.quoted_message.is_none(),
            "quoted_message should be None after prepare_for_quote"
        );
        assert!(
            ctx.stanza_id.is_none(),
            "stanza_id should be None after prepare_for_quote"
        );
        assert!(
            ctx.participant.is_none(),
            "participant should be None after prepare_for_quote"
        );
        assert!(
            ctx.remote_jid.is_none(),
            "remote_jid should be None after prepare_for_quote"
        );

        // Verify ALL other message fields are preserved
        assert_eq!(ext.text.as_deref(), Some("Hello @user1 @user2"));
        assert_eq!(ext.matched_text.as_deref(), Some("https://example.com"));
        assert_eq!(ext.description.as_deref(), Some("Example description"));
        assert_eq!(ext.title.as_deref(), Some("Example Title"));
        assert_eq!(ext.text_argb, Some(0xFFFFFF));
        assert_eq!(ext.background_argb, Some(0x000000));
        assert_eq!(ext.font(), FontType::SystemBold);
        assert_eq!(ext.preview_type(), PreviewType::Video);

        // Other context_info fields should be preserved (only mentions + quote-chain are cleared)
        assert_eq!(ctx.is_forwarded, Some(true));
        assert_eq!(ctx.forwarding_score, Some(5));
    }

    /// Test: prepare_for_quote preserves media message fields (caption, url, dimensions, etc.)
    #[test]
    fn test_prepare_for_quote_preserves_media_fields() {
        let original = wa::Message {
            image_message: Some(Box::new(wa::message::ImageMessage {
                url: Some("https://mmg.whatsapp.net/...".to_string()),
                mimetype: Some("image/jpeg".to_string()),
                caption: Some("Check out this image!".to_string()),
                file_sha256: Some(vec![1, 2, 3, 4]),
                file_length: Some(12345),
                height: Some(1080),
                width: Some(1920),
                media_key: Some(vec![5, 6, 7, 8]),
                direct_path: Some("/v/t62.1234-5/...".to_string()),
                context_info: Some(Box::new(wa::ContextInfo {
                    mentioned_jid: vec!["someone@s.whatsapp.net".to_string()],
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };

        let prepared = original.prepare_for_quote();

        let img = prepared.image_message.as_ref().unwrap();
        let ctx = img.context_info.as_ref().unwrap();

        // Mentions should be stripped
        assert!(ctx.mentioned_jid.is_empty());

        // All media fields should be preserved
        assert_eq!(img.url.as_deref(), Some("https://mmg.whatsapp.net/..."));
        assert_eq!(img.mimetype.as_deref(), Some("image/jpeg"));
        assert_eq!(img.caption.as_deref(), Some("Check out this image!"));
        assert_eq!(img.file_sha256, Some(vec![1, 2, 3, 4]));
        assert_eq!(img.file_length, Some(12345));
        assert_eq!(img.height, Some(1080));
        assert_eq!(img.width, Some(1920));
        assert_eq!(img.media_key, Some(vec![5, 6, 7, 8]));
        assert_eq!(img.direct_path.as_deref(), Some("/v/t62.1234-5/..."));
    }

    /// Test: prepare_for_quote breaks quote chains (matches WhatsApp Web behavior)
    ///
    /// WhatsApp Web (3JJWKHeu5-P.js:48734-48742) clears these fields from nested context_info:
    /// - quoted_message (breaks the chain)
    /// - stanza_id
    /// - remote_jid
    /// - participant
    ///
    /// This means when you quote a message that was itself a reply, the nested
    /// reply's quote info is stripped - preventing infinite quote chains.
    #[test]
    fn test_prepare_for_quote_breaks_quote_chain() {
        // Create a message that is a reply to another message (has quote context)
        let original = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("This is a reply".to_string()),
                context_info: Some(Box::new(wa::ContextInfo {
                    // This message quotes another message
                    stanza_id: Some("original-msg-id".to_string()),
                    participant: Some("original-sender@s.whatsapp.net".to_string()),
                    remote_jid: Some("chat@s.whatsapp.net".to_string()),
                    quoted_message: Some(Box::new(wa::Message {
                        conversation: Some("The original message".to_string()),
                        ..Default::default()
                    })),
                    mentioned_jid: vec!["user@s.whatsapp.net".to_string()],
                    // Other fields that SHOULD be preserved
                    is_forwarded: Some(true),
                    forwarding_score: Some(3),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };

        let prepared = original.prepare_for_quote();

        let ext = prepared.extended_text_message.as_ref().unwrap();
        let ctx = ext.context_info.as_ref().unwrap();

        // Quote-chain fields should be cleared (matches WhatsApp Web)
        assert!(
            ctx.quoted_message.is_none(),
            "quoted_message should be None (quote chain broken)"
        );
        assert!(
            ctx.stanza_id.is_none(),
            "stanza_id should be None (quote chain broken)"
        );
        assert!(
            ctx.participant.is_none(),
            "participant should be None (quote chain broken)"
        );
        assert!(
            ctx.remote_jid.is_none(),
            "remote_jid should be None (quote chain broken)"
        );
        assert!(
            ctx.mentioned_jid.is_empty(),
            "mentioned_jid should be empty"
        );

        // Other fields should be preserved
        assert_eq!(
            ctx.is_forwarded,
            Some(true),
            "is_forwarded should be preserved"
        );
        assert_eq!(
            ctx.forwarding_score,
            Some(3),
            "forwarding_score should be preserved"
        );

        // Text content should be preserved
        assert_eq!(ext.text.as_deref(), Some("This is a reply"));
    }

    /// Test: set_context_info works for extended_text_message
    #[test]
    fn test_set_context_info_extended_text() {
        let mut msg = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Reply text".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let context = wa::ContextInfo {
            stanza_id: Some("test-id".to_string()),
            participant: Some("sender@s.whatsapp.net".to_string()),
            ..Default::default()
        };

        assert!(msg.set_context_info(context));

        let ext = msg.extended_text_message.as_ref().unwrap();
        let ctx = ext.context_info.as_ref().unwrap();
        assert_eq!(ctx.stanza_id.as_deref(), Some("test-id"));
        assert_eq!(ctx.participant.as_deref(), Some("sender@s.whatsapp.net"));
    }

    /// Test: set_context_info works for image_message
    #[test]
    fn test_set_context_info_image() {
        let mut msg = wa::Message {
            image_message: Some(Box::new(wa::message::ImageMessage {
                caption: Some("Image caption".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let context = wa::ContextInfo {
            stanza_id: Some("img-id".to_string()),
            ..Default::default()
        };

        assert!(msg.set_context_info(context));

        let img = msg.image_message.as_ref().unwrap();
        assert!(img.context_info.is_some());
        assert_eq!(
            img.context_info.as_ref().unwrap().stanza_id.as_deref(),
            Some("img-id")
        );
    }

    /// Test: set_context_info works for location_message
    #[test]
    fn test_set_context_info_location() {
        let mut msg = wa::Message {
            location_message: Some(Box::new(wa::message::LocationMessage {
                degrees_latitude: Some(40.7128),
                degrees_longitude: Some(-74.0060),
                name: Some("New York".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let context = wa::ContextInfo {
            stanza_id: Some("loc-id".to_string()),
            ..Default::default()
        };

        assert!(msg.set_context_info(context));

        let loc = msg.location_message.as_ref().unwrap();
        assert!(loc.context_info.is_some());
    }

    /// Test: set_context_info returns false for unsupported message types
    #[test]
    fn test_set_context_info_unsupported() {
        let mut msg = wa::Message {
            conversation: Some("Simple text".to_string()),
            ..Default::default()
        };

        let context = wa::ContextInfo {
            stanza_id: Some("test-id".to_string()),
            ..Default::default()
        };

        // conversation doesn't support context_info
        assert!(!msg.set_context_info(context));
    }

    /// Test: build_quote_context produces correct structure
    ///
    /// This tests the standalone function matches WhatsApp Web's approach.
    #[test]
    fn test_build_quote_context() {
        let original = create_message_with_mentions();

        let context = build_quote_context("3EB0123456789", "1234567890@s.whatsapp.net", &original);

        // Verify basic fields
        assert_eq!(context.stanza_id.as_deref(), Some("3EB0123456789"));
        assert_eq!(
            context.participant.as_deref(),
            Some("1234567890@s.whatsapp.net")
        );

        // Verify quoted message exists and has stripped mentions
        let quoted = context.quoted_message.as_ref().unwrap();
        let ext = quoted.extended_text_message.as_ref().unwrap();
        let quoted_ctx = ext.context_info.as_ref().unwrap();
        assert!(
            quoted_ctx.mentioned_jid.is_empty(),
            "Quoted message mentions should be stripped"
        );
    }

    /// Test: prepare_for_quote handles ephemeral wrapper
    #[test]
    fn test_prepare_for_quote_ephemeral() {
        let ephemeral_msg = wa::Message {
            ephemeral_message: Some(Box::new(wa::message::FutureProofMessage {
                message: Some(Box::new(create_message_with_mentions())),
            })),
            ..Default::default()
        };

        let prepared = ephemeral_msg.prepare_for_quote();

        // Navigate through ephemeral wrapper
        let inner = prepared
            .ephemeral_message
            .as_ref()
            .unwrap()
            .message
            .as_ref()
            .unwrap();
        let ext = inner.extended_text_message.as_ref().unwrap();
        let ctx = ext.context_info.as_ref().unwrap();

        assert!(
            ctx.mentioned_jid.is_empty(),
            "Mentions inside ephemeral wrapper should be stripped"
        );
    }

    /// Test: prepare_for_quote handles view_once wrapper
    #[test]
    fn test_prepare_for_quote_view_once() {
        let view_once_msg = wa::Message {
            view_once_message: Some(Box::new(wa::message::FutureProofMessage {
                message: Some(Box::new(wa::Message {
                    image_message: Some(Box::new(wa::message::ImageMessage {
                        context_info: Some(Box::new(wa::ContextInfo {
                            mentioned_jid: vec!["someone@s.whatsapp.net".to_string()],
                            ..Default::default()
                        })),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
            })),
            ..Default::default()
        };

        let prepared = view_once_msg.prepare_for_quote();

        let inner = prepared
            .view_once_message
            .as_ref()
            .unwrap()
            .message
            .as_ref()
            .unwrap();
        let img = inner.image_message.as_ref().unwrap();
        let ctx = img.context_info.as_ref().unwrap();

        assert!(
            ctx.mentioned_jid.is_empty(),
            "Mentions inside view_once wrapper should be stripped"
        );
    }

    /// Test: prepare_for_quote handles device_sent_message wrapper
    ///
    /// DeviceSentMessage is used when a message is sent from another device
    /// and synced to the current device. It wraps the actual message content.
    #[test]
    fn test_prepare_for_quote_device_sent_message() {
        let device_sent_msg = wa::Message {
            device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                destination_jid: Some("1234567890@s.whatsapp.net".to_string()),
                message: Some(Box::new(wa::Message {
                    extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                        text: Some("Message from other device".to_string()),
                        context_info: Some(Box::new(wa::ContextInfo {
                            mentioned_jid: vec![
                                "user1@s.whatsapp.net".to_string(),
                                "user2@s.whatsapp.net".to_string(),
                            ],
                            group_mentions: vec![wa::GroupMention {
                                group_jid: Some("group@g.us".to_string()),
                                group_subject: Some("Group Name".to_string()),
                            }],
                            ..Default::default()
                        })),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
                phash: Some("somephash".to_string()),
            })),
            ..Default::default()
        };

        let prepared = device_sent_msg.prepare_for_quote();

        // Navigate through device_sent_message wrapper
        let wrapper = prepared.device_sent_message.as_ref().unwrap();
        let inner = wrapper.message.as_ref().unwrap();
        let ext = inner.extended_text_message.as_ref().unwrap();
        let ctx = ext.context_info.as_ref().unwrap();

        // Mentions should be stripped
        assert!(
            ctx.mentioned_jid.is_empty(),
            "mentioned_jid inside device_sent_message should be stripped"
        );
        assert!(
            ctx.group_mentions.is_empty(),
            "group_mentions inside device_sent_message should be stripped"
        );

        // Other fields should be preserved
        assert_eq!(ext.text.as_deref(), Some("Message from other device"));
        assert_eq!(
            wrapper.destination_jid.as_deref(),
            Some("1234567890@s.whatsapp.net")
        );
        assert_eq!(wrapper.phash.as_deref(), Some("somephash"));
    }

    /// Test: prepare_for_quote handles edited_message wrapper
    ///
    /// EditedMessage (FutureProofMessage) wraps messages that have been edited.
    /// The nested message inside should also have its mentions stripped.
    #[test]
    fn test_prepare_for_quote_edited_message() {
        let edited_msg = wa::Message {
            edited_message: Some(Box::new(wa::message::FutureProofMessage {
                message: Some(Box::new(wa::Message {
                    extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                        text: Some("Edited message text".to_string()),
                        context_info: Some(Box::new(wa::ContextInfo {
                            mentioned_jid: vec!["mentioned@s.whatsapp.net".to_string()],
                            group_mentions: vec![wa::GroupMention {
                                group_jid: Some("editedgroup@g.us".to_string()),
                                group_subject: Some("Edited Group".to_string()),
                            }],
                            ..Default::default()
                        })),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
            })),
            ..Default::default()
        };

        let prepared = edited_msg.prepare_for_quote();

        // Navigate through edited_message wrapper
        let inner = prepared
            .edited_message
            .as_ref()
            .unwrap()
            .message
            .as_ref()
            .unwrap();
        let ext = inner.extended_text_message.as_ref().unwrap();
        let ctx = ext.context_info.as_ref().unwrap();

        // Mentions should be stripped
        assert!(
            ctx.mentioned_jid.is_empty(),
            "mentioned_jid inside edited_message should be stripped"
        );
        assert!(
            ctx.group_mentions.is_empty(),
            "group_mentions inside edited_message should be stripped"
        );

        // Text should be preserved
        assert_eq!(ext.text.as_deref(), Some("Edited message text"));
    }

    /// Test: prepare_for_quote handles nested wrappers (e.g., device_sent containing ephemeral)
    ///
    /// This tests the scenario where multiple wrapper layers exist, such as
    /// a device_sent_message containing an ephemeral_message containing the actual content.
    #[test]
    fn test_prepare_for_quote_nested_wrappers() {
        let nested_wrapper_msg = wa::Message {
            device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                destination_jid: Some("dest@s.whatsapp.net".to_string()),
                message: Some(Box::new(wa::Message {
                    ephemeral_message: Some(Box::new(wa::message::FutureProofMessage {
                        message: Some(Box::new(wa::Message {
                            image_message: Some(Box::new(wa::message::ImageMessage {
                                caption: Some("Nested image".to_string()),
                                context_info: Some(Box::new(wa::ContextInfo {
                                    mentioned_jid: vec!["deep@s.whatsapp.net".to_string()],
                                    ..Default::default()
                                })),
                                ..Default::default()
                            })),
                            ..Default::default()
                        })),
                    })),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };

        let prepared = nested_wrapper_msg.prepare_for_quote();

        // Navigate through: device_sent -> ephemeral -> image
        let device_sent = prepared.device_sent_message.as_ref().unwrap();
        let device_inner = device_sent.message.as_ref().unwrap();
        let ephemeral = device_inner.ephemeral_message.as_ref().unwrap();
        let ephemeral_inner = ephemeral.message.as_ref().unwrap();
        let img = ephemeral_inner.image_message.as_ref().unwrap();
        let ctx = img.context_info.as_ref().unwrap();

        // Mentions should be stripped even through multiple wrapper layers
        assert!(
            ctx.mentioned_jid.is_empty(),
            "Mentions in deeply nested wrappers should be stripped"
        );

        // Content should be preserved
        assert_eq!(img.caption.as_deref(), Some("Nested image"));
    }

    /// Test: Multiple message types with context_info can have it set
    #[test]
    fn test_set_context_info_various_types() {
        let test_cases: Vec<wa::Message> = vec![
            // Video
            wa::Message {
                video_message: Some(Box::default()),
                ..Default::default()
            },
            // Audio
            wa::Message {
                audio_message: Some(Box::default()),
                ..Default::default()
            },
            // Document
            wa::Message {
                document_message: Some(Box::default()),
                ..Default::default()
            },
            // Sticker
            wa::Message {
                sticker_message: Some(Box::default()),
                ..Default::default()
            },
            // Contact
            wa::Message {
                contact_message: Some(Box::default()),
                ..Default::default()
            },
            // Poll
            wa::Message {
                poll_creation_message: Some(Box::default()),
                ..Default::default()
            },
        ];

        for mut msg in test_cases {
            let context = wa::ContextInfo {
                stanza_id: Some("test".to_string()),
                ..Default::default()
            };
            assert!(
                msg.set_context_info(context),
                "set_context_info should succeed for this message type"
            );
        }
    }

    /// Test: Bot quote chains are preserved (matches WhatsApp Web behavior)
    ///
    /// WhatsApp Web (3JJWKHeu5-P.js:48737-48742) only clears quote-chain fields
    /// if the participant is NOT a bot. Bot responses should preserve their
    /// quote chains to maintain context.
    #[test]
    fn test_prepare_for_quote_preserves_bot_quote_chain() {
        // Create message with bot participant in context (phone-number based bot)
        let msg = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Bot reply".to_string()),
                context_info: Some(Box::new(wa::ContextInfo {
                    // Bot JID - starts with 1313555
                    participant: Some("131355512345@s.whatsapp.net".to_string()),
                    stanza_id: Some("bot-msg-id".to_string()),
                    remote_jid: Some("chat@g.us".to_string()),
                    quoted_message: Some(Box::new(wa::Message {
                        conversation: Some("Original user message".to_string()),
                        ..Default::default()
                    })),
                    mentioned_jid: vec!["user@s.whatsapp.net".to_string()],
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };

        let prepared = msg.prepare_for_quote();
        let ctx = prepared
            .extended_text_message
            .as_ref()
            .unwrap()
            .context_info
            .as_ref()
            .unwrap();

        // Bot quote chain should be preserved
        assert!(
            ctx.quoted_message.is_some(),
            "Bot quote chain should be preserved"
        );
        assert!(ctx.stanza_id.is_some(), "Bot stanza_id should be preserved");
        assert!(
            ctx.participant.is_some(),
            "Bot participant should be preserved"
        );
        assert!(
            ctx.remote_jid.is_some(),
            "Bot remote_jid should be preserved"
        );

        // But mentions should still be cleared
        assert!(
            ctx.mentioned_jid.is_empty(),
            "Mentions should still be cleared even for bots"
        );
    }

    /// Test: Bot with @bot server also has quote chain preserved
    #[test]
    fn test_prepare_for_quote_preserves_bot_server_quote_chain() {
        let msg = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Bot reply".to_string()),
                context_info: Some(Box::new(wa::ContextInfo {
                    // Bot JID with @bot server
                    participant: Some("mybot@bot".to_string()),
                    stanza_id: Some("bot-msg-id".to_string()),
                    quoted_message: Some(Box::new(wa::Message {
                        conversation: Some("Original".to_string()),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };

        let prepared = msg.prepare_for_quote();
        let ctx = prepared
            .extended_text_message
            .as_ref()
            .unwrap()
            .context_info
            .as_ref()
            .unwrap();

        // Bot quote chain should be preserved
        assert!(
            ctx.quoted_message.is_some(),
            "Bot (@bot server) quote chain should be preserved"
        );
    }

    /// Test: Newsletter participant resolution uses chat JID
    #[test]
    fn test_build_quote_context_newsletter() {
        let sender: Jid = "123456@s.whatsapp.net".parse().unwrap();
        let chat: Jid = "1234567890@newsletter".parse().unwrap();
        let msg = wa::Message::default();

        let ctx = build_quote_context_with_info("msg-id", &sender, &chat, &msg);

        // Newsletter should use chat JID as participant
        assert_eq!(
            ctx.participant.as_deref(),
            Some("1234567890@newsletter"),
            "Newsletter participant should be the newsletter JID"
        );
        assert_eq!(ctx.stanza_id.as_deref(), Some("msg-id"));
    }

    /// Test: Normal message participant resolution uses sender JID
    #[test]
    fn test_build_quote_context_normal_message() {
        let sender: Jid = "123456@s.whatsapp.net".parse().unwrap();
        let chat: Jid = "group@g.us".parse().unwrap();
        let msg = wa::Message::default();

        let ctx = build_quote_context_with_info("msg-id", &sender, &chat, &msg);

        // Normal message should use sender JID as participant
        assert_eq!(
            ctx.participant.as_deref(),
            Some("123456@s.whatsapp.net"),
            "Normal message participant should be the sender JID"
        );
    }

    /// Test: Status broadcast participant resolution uses sender JID (fallback)
    #[test]
    fn test_build_quote_context_status_broadcast() {
        let sender: Jid = "123456@s.whatsapp.net".parse().unwrap();
        let chat: Jid = "status@broadcast".parse().unwrap();
        let msg = wa::Message::default();

        let ctx = build_quote_context_with_info("msg-id", &sender, &chat, &msg);

        // Status broadcast uses sender as fallback (author not available)
        assert_eq!(
            ctx.participant.as_deref(),
            Some("123456@s.whatsapp.net"),
            "Status broadcast participant should fall back to sender"
        );
    }
}
