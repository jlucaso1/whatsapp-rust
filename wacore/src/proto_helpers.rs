use std::str::FromStr;
use wacore_binary::jid::Jid;
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
        strip_nested_mentions(&mut msg);
        Box::new(msg)
    }

    fn set_context_info(&mut self, context: wa::ContextInfo) -> bool {
        set_context_info_on_message!(self, Box::new(context))
    }
}

/// Strips nested context_info mentions from a message to prevent accidental tagging.
///
/// This is used internally by `MessageExt::prepare_for_quote()` but can also be called
/// directly if you need to modify a message in place.
fn strip_nested_mentions(msg: &mut wa::Message) {
    fn clear_context_mentions(ctx: &mut wa::ContextInfo) {
        ctx.mentioned_jid.clear();
        ctx.group_mentions.clear();
        if let Some(ref mut quoted) = ctx.quoted_message {
            strip_nested_mentions(quoted);
        }
    }

    for_each_context_info_message!(msg, ctx, {
        clear_context_mentions(ctx);
    });

    // Handle wrapper messages that contain nested messages
    macro_rules! recurse_into_wrapper {
        ($($wrapper:ident),+ $(,)?) => {
            $(
                if let Some(ref mut wrapper) = msg.$wrapper {
                    if let Some(ref mut inner) = wrapper.message {
                        strip_nested_mentions(inner);
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
    );
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

    /// Test: prepare_for_quote strips mentions from extended_text_message
    ///
    /// WhatsApp Web behavior: When quoting a message, the new message's contextInfo
    /// should NOT carry over mentions from the quoted message's nested context_info.
    #[test]
    fn test_prepare_for_quote_strips_mentions() {
        let original = create_message_with_mentions();

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

        // Verify text is preserved
        assert_eq!(ext.text.as_deref(), Some("Hello @user1 @user2"));
    }

    /// Test: prepare_for_quote handles nested quoted messages recursively
    #[test]
    fn test_prepare_for_quote_recursive() {
        /// Creates a message with a mention that quotes another message
        fn nested_message(level: u8, inner: Option<wa::Message>) -> wa::Message {
            wa::Message {
                extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                    text: Some(format!("Level {level}")),
                    context_info: Some(Box::new(wa::ContextInfo {
                        mentioned_jid: vec![format!("level{level}@s.whatsapp.net")],
                        quoted_message: inner.map(Box::new),
                        ..Default::default()
                    })),
                    ..Default::default()
                })),
                ..Default::default()
            }
        }

        // Build: Level 1 -> quotes Level 2 -> quotes Level 3
        let deeply_nested =
            nested_message(1, Some(nested_message(2, Some(nested_message(3, None)))));
        let prepared = deeply_nested.prepare_for_quote();

        // Helper to extract context from a message
        fn get_context(msg: &wa::Message) -> &wa::ContextInfo {
            msg.extended_text_message
                .as_ref()
                .unwrap()
                .context_info
                .as_ref()
                .unwrap()
        }

        // Verify all levels have mentions stripped
        let ctx1 = get_context(&prepared);
        assert!(
            ctx1.mentioned_jid.is_empty(),
            "Level 1 mentions should be stripped"
        );

        let ctx2 = get_context(ctx1.quoted_message.as_ref().unwrap());
        assert!(
            ctx2.mentioned_jid.is_empty(),
            "Level 2 mentions should be stripped"
        );

        let ctx3 = get_context(ctx2.quoted_message.as_ref().unwrap());
        assert!(
            ctx3.mentioned_jid.is_empty(),
            "Level 3 mentions should be stripped"
        );
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
}
