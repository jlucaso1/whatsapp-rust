//! Chat list item component with responsive dimensions.

use gpui::{Entity, SharedString, div, prelude::*, px, rgb};

use crate::app::WhatsAppApp;
use crate::responsive::ResponsiveLayout;
use crate::state::Chat;
use crate::theme::colors;

use super::Avatar;

pub fn render_chat_item(
    chat: Chat,
    is_selected: bool,
    jid: String,
    entity: Entity<WhatsAppApp>,
    layout: ResponsiveLayout,
) -> impl IntoElement {
    let name: SharedString = chat.name.into();
    let last_message: SharedString = chat
        .last_message
        .unwrap_or_else(|| "No messages".to_string())
        .into();
    let unread = chat.unread_count;
    let initial = name.chars().next().unwrap_or('?');

    let bg = if is_selected {
        rgb(colors::BG_SELECTED)
    } else {
        rgb(colors::BG_SECONDARY)
    };

    div()
        .id(SharedString::from(format!("chat-{}", jid)))
        .w_full()
        .h(px(layout.chat_item_height()))
        .flex()
        .items_center()
        .px(px(layout.padding_small()))
        .gap(px(layout.gap()))
        .cursor_pointer()
        .bg(bg)
        .when(!is_selected, |el| el.hover(|s| s.bg(rgb(colors::BG_HOVER))))
        .on_click(move |_, _, cx| {
            entity.update(cx, |this, cx| this.select_chat(jid.clone(), cx));
        })
        .child(Avatar::from_initial(initial, layout.avatar_size()))
        .child(
            div()
                .flex_1()
                .flex()
                .flex_col()
                .gap_1()
                .overflow_hidden()
                .child(
                    div().flex().justify_between().child(
                        div()
                            .text_color(rgb(colors::TEXT_PRIMARY))
                            .font_weight(gpui::FontWeight::MEDIUM)
                            .overflow_hidden()
                            .text_ellipsis()
                            .whitespace_nowrap()
                            .child(name),
                    ),
                )
                .child(
                    div()
                        .flex()
                        .justify_between()
                        .items_center()
                        .child(
                            div()
                                .text_color(rgb(colors::TEXT_SECONDARY))
                                .text_sm()
                                .overflow_hidden()
                                .text_ellipsis()
                                .whitespace_nowrap()
                                .flex_1()
                                .child(last_message),
                        )
                        .when(unread > 0, |el| {
                            el.child(
                                div()
                                    .px_2()
                                    .py_0p5()
                                    .rounded_full()
                                    .bg(rgb(colors::ACCENT_GREEN))
                                    .text_color(rgb(colors::WHITE))
                                    .text_xs()
                                    .font_weight(gpui::FontWeight::BOLD)
                                    .child(unread.to_string()),
                            )
                        }),
                ),
        )
}
