//! Message list with virtual scrolling and responsive layout.

use std::sync::Arc;

use gpui::{Entity, div, prelude::*, px, rgb};
use gpui_component::{VirtualListScrollHandle, scroll::Scrollbar, v_virtual_list};

use crate::app::{MessageListCache, WhatsAppApp};
use crate::responsive::ResponsiveLayout;
use crate::state::MediaType;
use crate::theme::colors;

use super::render_message_bubble;

/// Renders the message list using cached values to avoid recomputation on every render.
pub fn render_message_list(
    cache: MessageListCache,
    scroll_handle: &VirtualListScrollHandle,
    entity: Entity<WhatsAppApp>,
    _playing_message_id: Option<String>,
    is_group: bool,
    layout: ResponsiveLayout,
) -> impl IntoElement {
    // Use pre-computed values from cache (cheap Rc/Arc clones)
    let messages_arc = cache.messages;
    let show_sender_flags = cache.show_sender_flags;
    let item_sizes = cache.item_sizes;

    let is_empty = messages_arc.is_empty();
    let padding = layout.padding();

    div()
        .flex_1()
        .overflow_hidden()
        .relative()
        .when(is_empty, |el| {
            el.flex().justify_center().items_center().child(
                div()
                    .text_color(rgb(colors::TEXT_SECONDARY))
                    .child("No messages yet"),
            )
        })
        .when(!is_empty, |el| {
            // Clone the Arc (cheap reference count increment)
            let messages_for_render = Arc::clone(&messages_arc);
            let show_sender_for_render = Arc::clone(&show_sender_flags);
            let entity_for_render = entity.clone();
            el.child(
                v_virtual_list(
                    entity.clone(),
                    "message-list",
                    item_sizes.clone(),
                    move |app, visible_range, _scroll_handle, _cx| {
                        // Read playing_message_id fresh from app state each render
                        // This ensures we always have the current value, not a stale captured one
                        let current_playing_id = app.playing_message_id().map(|s| s.to_string());

                        visible_range
                            // Clone only visible messages (virtual list optimization)
                            .map(|ix| {
                                let msg = &messages_for_render[ix];
                                let message_id = &msg.id;

                                // Get video player state and frame for this message
                                let video_state = app.video_player_state(message_id);
                                // Returns Arc<VideoFrame> - cheap to clone, no data copy
                                let video_frame = app.video_current_frame(message_id);

                                // Get cached sticker image if this is a sticker (preserves animation state)
                                let sticker_image = msg.media.as_ref().and_then(|m| {
                                    if matches!(m.media_type, MediaType::Sticker)
                                        && !m.data.is_empty()
                                    {
                                        Some(app.get_sticker_image(
                                            message_id,
                                            &m.data,
                                            &m.mime_type,
                                        ))
                                    } else {
                                        None
                                    }
                                });

                                render_message_bubble(
                                    msg.clone(),
                                    entity_for_render.clone(),
                                    current_playing_id.clone(),
                                    is_group,
                                    show_sender_for_render[ix],
                                    video_state,
                                    video_frame,
                                    sticker_image,
                                    layout,
                                )
                            })
                            .collect()
                    },
                )
                .track_scroll(scroll_handle)
                .size_full()
                .p(px(padding)),
            )
            .child(
                div()
                    .absolute()
                    .top_0()
                    .right_0()
                    .bottom_0()
                    .child(Scrollbar::vertical(scroll_handle)),
            )
        })
}
