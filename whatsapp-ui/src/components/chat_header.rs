//! Chat header component

use gpui::{Entity, SharedString, div, prelude::*, px, rgb};
use gpui_component::Sizable;
use gpui_component::button::{Button, ButtonVariants as _};

use crate::app::WhatsAppApp;
use crate::state::Chat;
use crate::theme::{colors, layout};

use super::Avatar;

/// Render the chat header with call buttons
pub fn render_chat_header(chat: &Chat, entity: Entity<WhatsAppApp>) -> impl IntoElement {
    let initial = chat.name.chars().next().unwrap_or('?');
    // Use SharedString to avoid allocation when possible
    let name: SharedString = chat.name.clone().into();
    let jid = chat.jid.clone();

    // Clone entity for each button
    let audio_call_entity = entity.clone();
    let video_call_entity = entity;
    let audio_jid = jid.clone();
    let video_jid = jid;

    div()
        .h(px(layout::HEADER_HEIGHT))
        .flex()
        .items_center()
        .justify_between()
        .px_4()
        .bg(rgb(colors::BG_SECONDARY))
        .border_b_1()
        .border_color(rgb(colors::BORDER))
        // Left side: Avatar and name
        .child(
            div()
                .flex()
                .items_center()
                .gap_3()
                // Avatar
                .child(Avatar::from_initial(initial, layout::AVATAR_SIZE_MEDIUM))
                // Name
                .child(
                    div()
                        .text_color(rgb(colors::TEXT_PRIMARY))
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .child(name),
                ),
        )
        // Right side: Call buttons
        .child(
            div()
                .flex()
                .items_center()
                .gap_2()
                // Video call button
                .child(
                    Button::new("video-call")
                        .label("Video")
                        .ghost()
                        .small()
                        .on_click(move |_, _window, cx| {
                            video_call_entity.update(cx, |app, cx| {
                                app.start_call(video_jid.clone(), true, cx);
                            });
                        }),
                )
                // Audio call button
                .child(
                    Button::new("audio-call")
                        .label("Call")
                        .ghost()
                        .small()
                        .on_click(move |_, _window, cx| {
                            audio_call_entity.update(cx, |app, cx| {
                                app.start_call(audio_jid.clone(), false, cx);
                            });
                        }),
                ),
        )
}
