//! Message list handling for the WhatsApp UI
//!
//! This module contains types and utilities for message list rendering:
//! - `MessageListCache`: Cached data for virtual list rendering
//! - Height calculation for message bubbles

use std::rc::Rc;
use std::sync::Arc;

use gpui::{Pixels, Size, px, size};

use crate::state::{ChatMessage, MediaType};
use crate::theme::layout;

/// Cached data for message list rendering to avoid recomputing on every frame.
/// This is a significant performance optimization for typing responsiveness.
#[derive(Clone)]
pub struct MessageListCache {
    /// Message count when cache was created (invalidation check)
    pub message_count: usize,
    /// Pre-computed item sizes for virtual list
    pub item_sizes: Rc<Vec<Size<Pixels>>>,
    /// Pre-computed show_sender flags for message grouping
    pub show_sender_flags: Arc<[bool]>,
    /// Shared messages reference
    pub messages: Arc<[ChatMessage]>,
}

impl MessageListCache {
    /// Create a new message list cache from messages
    pub fn new(messages: &[ChatMessage], is_group: bool) -> Self {
        let messages_arc: Arc<[ChatMessage]> = Arc::from(messages);

        let show_sender_flags: Arc<[bool]> = Arc::from(
            messages
                .iter()
                .enumerate()
                .map(|(i, _)| should_show_sender(messages, i))
                .collect::<Vec<_>>(),
        );

        let item_sizes: Rc<Vec<Size<Pixels>>> = Rc::new(
            messages
                .iter()
                .enumerate()
                .map(|(i, msg)| {
                    let show_sender = is_group && show_sender_flags[i];
                    size(px(600.), px(calculate_message_height(msg, show_sender)))
                })
                .collect(),
        );

        Self {
            message_count: messages.len(),
            item_sizes,
            show_sender_flags,
            messages: messages_arc,
        }
    }
}

/// Check if this message should show the sender name (for grouping)
pub fn should_show_sender(messages: &[ChatMessage], index: usize) -> bool {
    if index == 0 {
        return true;
    }
    let current = &messages[index];
    let previous = &messages[index - 1];
    current.sender != previous.sender || current.is_from_me != previous.is_from_me
}

/// Calculate the height needed for a message bubble
pub fn calculate_message_height(msg: &ChatMessage, show_sender: bool) -> f32 {
    let outer_top = if show_sender {
        layout::MSG_PADDING_TOP_FIRST
    } else {
        layout::MSG_PADDING_TOP_GROUPED
    };
    let mut height = outer_top
        + layout::MSG_PADDING_BOTTOM
        + (layout::MSG_BUBBLE_PADDING_Y * 2.0)
        + layout::MSG_TIME_ROW_HEIGHT;

    let mut content_items = 1;

    if show_sender && msg.sender_name.is_some() && !msg.is_from_me {
        height += layout::MSG_SENDER_NAME_HEIGHT;
        content_items += 1;
    }

    if let Some(media) = &msg.media {
        let media_h = match media.media_type {
            MediaType::Image | MediaType::Sticker | MediaType::Video => {
                let h = media.height.unwrap_or(300) as f32;
                let w = media.width.unwrap_or(300) as f32;
                let max_size = layout::MAX_MEDIA_SIZE;
                let scale = (max_size / w).min(max_size / h).min(1.0);
                (h * scale).max(50.0)
            }
            MediaType::Audio => 44.0,
            MediaType::Document => 50.0,
        };
        height += media_h;
        content_items += 1;
    }

    if !msg.content.is_empty() {
        let char_count = msg.content.chars().count();
        let newlines = msg.content.matches('\n').count();
        let wrapped_lines = char_count.div_ceil(30);
        let lines = (wrapped_lines + newlines).max(1);
        height += lines as f32 * layout::MSG_TEXT_LINE_HEIGHT;
        content_items += 1;
    }

    if content_items > 1 {
        height += (content_items - 1) as f32 * layout::MSG_CONTENT_GAP;
    }

    if !msg.reactions.is_empty() {
        height += layout::MSG_REACTION_MARGIN_TOP + layout::MSG_REACTION_HEIGHT;
    }

    height.min(500.0)
}
