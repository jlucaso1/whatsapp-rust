//! Chat list sidebar component

use std::sync::Arc;

use gpui::{Entity, FocusHandle, div, prelude::*, px, rgb};
use gpui_component::input::{Input, InputState};
use gpui_component::{Icon, IconName, VirtualListScrollHandle, scroll::Scrollbar, v_virtual_list};

use crate::app::{ChatListCache, SelectDown, SelectUp, WhatsAppApp};
use crate::theme::{colors, layout};

use super::render_chat_item;

/// Key context for chat list keyboard navigation
const CHAT_LIST_CONTEXT: &str = "ChatList";

/// Render the chat list sidebar
/// Uses cached values from ChatListCache to avoid expensive recomputation on every render.
pub fn render_chat_list(
    cache: ChatListCache,
    selected_jid: Option<String>,
    scroll_handle: &VirtualListScrollHandle,
    focus_handle: &FocusHandle,
    search_input: Option<&Entity<InputState>>,
    entity: Entity<WhatsAppApp>,
) -> impl IntoElement {
    // Use pre-computed values from cache (cheap Rc/Arc clones)
    let chats_arc = cache.chats;
    let item_sizes = cache.item_sizes;
    let selected_jid_clone = selected_jid.clone();
    let entity_clone = entity.clone();
    let entity_for_up = entity.clone();
    let entity_for_down = entity.clone();
    let is_empty = chats_arc.is_empty();

    div()
        .id("chat-list-container")
        .key_context(CHAT_LIST_CONTEXT)
        .track_focus(focus_handle)
        .on_action(move |_: &SelectUp, _window, cx| {
            entity_for_up.update(cx, |app, cx| {
                app.select_previous_chat(cx);
            });
        })
        .on_action(move |_: &SelectDown, _window, cx| {
            entity_for_down.update(cx, |app, cx| {
                app.select_next_chat(cx);
            });
        })
        .flex()
        .flex_col()
        .w(px(layout::SIDEBAR_WIDTH))
        .h_full()
        .bg(rgb(colors::BG_SECONDARY))
        .border_r_1()
        .border_color(rgb(colors::BORDER))
        // Header with title
        .child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .h(px(layout::HEADER_HEIGHT))
                .px_4()
                .border_b_1()
                .border_color(rgb(colors::BORDER))
                .child(
                    div()
                        .text_color(rgb(colors::TEXT_PRIMARY))
                        .text_xl()
                        .font_weight(gpui::FontWeight::BOLD)
                        .child("Chats"),
                ),
        )
        // Search input (only if available)
        .when_some(search_input.cloned(), |el, input| {
            el.child(
                div()
                    .px_3()
                    .py_2()
                    .border_b_1()
                    .border_color(rgb(colors::BORDER))
                    .child(
                        Input::new(&input)
                            .prefix(
                                Icon::new(IconName::Search).text_color(rgb(colors::TEXT_SECONDARY)),
                            )
                            .cleanable(true)
                            .appearance(false),
                    ),
            )
        })
        // Chat list
        .child(
            div()
                .flex_1()
                .overflow_hidden()
                .relative()
                .when(is_empty, |el| {
                    el.child(
                        div()
                            .size_full()
                            .flex()
                            .justify_center()
                            .items_center()
                            .child(
                                div()
                                    .text_color(rgb(colors::TEXT_SECONDARY))
                                    .child("No chats found"),
                            ),
                    )
                })
                .when(!is_empty, |el| {
                    el.child(
                        v_virtual_list(entity.clone(), "chat-list", item_sizes.clone(), {
                            let chats_for_render = Arc::clone(&chats_arc);
                            move |_view, visible_range, _scroll_handle, _cx| {
                                visible_range
                                    .map(|ix| {
                                        // Clone only visible chats (virtual list optimization)
                                        let chat = chats_for_render[ix].clone();
                                        let is_selected =
                                            selected_jid_clone.as_ref() == Some(&chat.jid);
                                        let jid = chat.jid.clone();

                                        render_chat_item(
                                            chat,
                                            is_selected,
                                            jid,
                                            entity_clone.clone(),
                                        )
                                    })
                                    .collect()
                            }
                        })
                        .track_scroll(scroll_handle)
                        .size_full(),
                    )
                    .child(
                        div()
                            .absolute()
                            .top_0()
                            .right_0()
                            .bottom_0()
                            .child(Scrollbar::vertical(scroll_handle)),
                    )
                }),
        )
}
