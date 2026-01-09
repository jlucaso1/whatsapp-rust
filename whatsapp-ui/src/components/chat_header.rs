//! Chat header with back button (mobile) and call buttons.

use gpui::{Entity, SharedString, div, prelude::*, px, rgb};
use gpui_component::Sizable;
use gpui_component::button::Button;
use gpui_component::{Icon, IconName};

use crate::app::WhatsAppApp;
use crate::responsive::ResponsiveLayout;
use crate::state::Chat;
use crate::theme::colors;

use super::Avatar;

pub fn render_chat_header(
    chat: &Chat,
    entity: Entity<WhatsAppApp>,
    layout: ResponsiveLayout,
) -> impl IntoElement {
    let initial = chat.name.chars().next().unwrap_or('?');
    let name: SharedString = chat.name.clone().into();
    let audio_jid = chat.jid.clone();
    let video_jid = chat.jid.clone();

    let back_entity = entity.clone();
    let audio_call_entity = entity.clone();
    let video_call_entity = entity;

    div()
        .h(px(layout.header_height()))
        .flex()
        .items_center()
        .justify_between()
        .px(px(layout.padding()))
        .gap(px(layout.gap()))
        .bg(rgb(colors::BG_SECONDARY))
        .border_b_1()
        .border_color(rgb(colors::BORDER))
        .child(
            div()
                .flex()
                .flex_1()
                .items_center()
                .gap(px(layout.gap()))
                .overflow_hidden()
                .when(layout.show_back_button(), |el| {
                    el.child(
                        div()
                            .id("back-button")
                            .flex()
                            .items_center()
                            .justify_center()
                            .w(px(layout.icon_button_size()))
                            .h(px(layout.icon_button_size()))
                            .rounded(px(layout.icon_button_size() / 2.0))
                            .cursor_pointer()
                            .hover(|s| s.bg(rgb(colors::BG_HOVER)))
                            .on_click(move |_, _, cx| {
                                back_entity.update(cx, |app, cx| app.navigate_back(cx));
                            })
                            .child(
                                Icon::new(IconName::ArrowLeft)
                                    .text_color(rgb(colors::TEXT_PRIMARY)),
                            ),
                    )
                })
                .child(Avatar::from_initial(
                    initial,
                    if layout.is_mobile() { 36.0 } else { 40.0 },
                ))
                .child(
                    div()
                        .flex_1()
                        .text_color(rgb(colors::TEXT_PRIMARY))
                        .font_weight(gpui::FontWeight::MEDIUM)
                        .overflow_hidden()
                        .text_ellipsis()
                        .whitespace_nowrap()
                        .child(name),
                ),
        )
        .when(layout.show_call_buttons(), |el| {
            el.child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(
                        Button::new("video-call")
                            .label("Video")
                            .outline()
                            .small()
                            .on_click(move |_, _window, cx| {
                                video_call_entity.update(cx, |app, cx| {
                                    app.start_call(video_jid.clone(), true, cx)
                                });
                            }),
                    )
                    .child(
                        Button::new("audio-call")
                            .label("Call")
                            .outline()
                            .small()
                            .on_click(move |_, _window, cx| {
                                audio_call_entity.update(cx, |app, cx| {
                                    app.start_call(audio_jid.clone(), false, cx)
                                });
                            }),
                    ),
            )
        })
}
