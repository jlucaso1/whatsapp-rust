//! Connected/chat view
//!
//! This module renders the main connected view with responsive layout support.
//! It handles different layouts for mobile, tablet, and desktop devices.

use gpui::{Context, Entity, Window, div, prelude::*, px, rgb};
use gpui_component::VirtualListScrollHandle;

use crate::app::{MessageListCache, WhatsAppApp};
use crate::components::{
    InputAreaView, render_call_popup, render_chat_header, render_chat_list, render_message_list,
    render_outgoing_call_popup,
};
use crate::responsive::ResponsiveLayout;
use crate::state::Chat;
use crate::theme::colors;

/// Render connected (main) view with chat list and messages
///
/// This view uses ResponsiveLayout to adapt to different screen sizes:
/// - **Mobile**: Single panel view (either chat list OR chat)
/// - **Tablet**: Compact two-panel layout
/// - **Desktop**: Full two-panel layout
pub fn render_connected_view(
    app: &mut WhatsAppApp,
    window: &mut Window,
    cx: &mut Context<WhatsAppApp>,
) -> impl IntoElement {
    // Ensure isolated input area and search input are initialized
    app.ensure_input_area(window, cx);
    app.ensure_chat_search_input(window, cx);

    // Get responsive layout configuration
    let layout = app.responsive_layout(window);

    let entity = cx.entity().clone();
    let selected_jid = app.selected_chat_jid();
    let chat_list_scroll = app.chat_list_scroll();
    let chat_list_focus = app.chat_list_focus();
    let chat_search_input = app.chat_search_input().cloned();
    let message_list_scroll = app.message_list_scroll();
    let input_area = app.input_area();
    let selected_chat = app.selected_chat_data();
    let playing_message_id = app.playing_message_id().map(|s| s.to_string());
    let incoming_call = app.incoming_call().cloned();
    let outgoing_call = app.outgoing_call().cloned();

    // Get cached data to avoid expensive recomputation on every render
    let chat_list_cache = app.get_chat_list_cache();
    let message_cache = selected_chat.map(|chat| {
        app.get_message_list_cache(
            &chat.jid,
            &chat.messages,
            chat.is_group,
            layout.max_media_size(),
        )
    });

    div()
        .relative() // Needed for absolute positioning of popup
        .size_full()
        // Main content
        .child(
            div()
                .flex()
                .size_full()
                .bg(rgb(colors::BG_PRIMARY))
                // Left sidebar (chat list) - conditionally visible on mobile
                .when(layout.show_sidebar(), |el| {
                    el.child(render_chat_list(
                        chat_list_cache.clone(),
                        selected_jid.clone(),
                        chat_list_scroll,
                        chat_list_focus,
                        chat_search_input.as_ref(),
                        entity.clone(),
                        layout,
                    ))
                })
                // Right side (chat area) - conditionally visible on mobile
                .when(layout.show_chat_area(), |el| {
                    el.child(render_chat_area(
                        selected_chat,
                        message_cache,
                        message_list_scroll,
                        input_area,
                        entity.clone(),
                        playing_message_id,
                        layout,
                    ))
                }),
        )
        // Incoming call popup overlay (takes priority over outgoing)
        .when_some(incoming_call, |el, call| {
            el.child(render_call_popup(&call, entity.clone()))
        })
        // Outgoing call popup overlay
        .when_some(outgoing_call, |el, call| {
            el.child(render_outgoing_call_popup(&call, entity))
        })
}

/// Render the chat area (messages + input)
fn render_chat_area(
    selected_chat: Option<&Chat>,
    message_cache: Option<MessageListCache>,
    message_scroll: &VirtualListScrollHandle,
    input_area: Option<Entity<InputAreaView>>,
    entity: Entity<WhatsAppApp>,
    playing_message_id: Option<String>,
    layout: ResponsiveLayout,
) -> impl IntoElement {
    // On mobile, take full width; otherwise flex to fill remaining space
    let base = if layout.is_mobile() {
        div().w_full()
    } else {
        div().flex_1()
    };

    base.flex()
        .flex_col()
        .h_full()
        .bg(rgb(colors::BG_CHAT))
        .when(selected_chat.is_none(), |el| {
            el.justify_center().items_center().child(
                div()
                    .text_color(rgb(colors::TEXT_SECONDARY))
                    .text_lg()
                    .child("Select a chat to start messaging"),
            )
        })
        .when_some(selected_chat, |el, chat| {
            let is_group = chat.is_group;
            // Use the cached message list data (cache should always exist when chat exists)
            let cache = message_cache.unwrap_or_else(|| MessageListCache {
                message_count: 0,
                item_sizes: std::rc::Rc::new(vec![]),
                show_sender_flags: std::sync::Arc::from([]),
                messages: std::sync::Arc::from([]),
            });
            el
                // Chat header with back button (mobile) and call buttons
                .child(render_chat_header(chat, entity.clone(), layout))
                // Messages area
                .child(render_message_list(
                    cache,
                    message_scroll,
                    entity,
                    playing_message_id,
                    is_group,
                    layout,
                ))
                // Input area (isolated component)
                .when_some(input_area, |el, input| {
                    el.child(div().h(px(layout.input_area_height())).child(input))
                })
        })
}
