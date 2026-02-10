//! Call popup components (incoming and outgoing)

use gpui::{Entity, SharedString, div, prelude::*, px, rgb};

use crate::app::WhatsAppApp;
use crate::state::IncomingCall;
use crate::theme::{colors, layout};

use super::Avatar;

/// Render the base call popup structure shared by incoming and outgoing popups.
///
/// This creates the overlay, card, avatar, name, and call type display.
/// The `extra_content` closure allows adding custom content (buttons, status, etc).
pub fn render_call_popup_base(
    name: SharedString,
    initial: char,
    is_video: bool,
    extra_content: impl IntoElement,
) -> impl IntoElement {
    let call_type_text = if is_video { "Video Call" } else { "Audio Call" };

    // Overlay container - full screen semi-transparent background
    div()
        .absolute()
        .inset_0()
        .flex()
        .items_center()
        .justify_center()
        .bg(gpui::rgba(0x00000099)) // Semi-transparent black overlay
        .child(
            // Popup card
            div()
                .w(px(320.0))
                .bg(rgb(colors::BG_SECONDARY))
                .rounded(px(layout::RADIUS_MEDIUM))
                .shadow_lg()
                .p_6()
                .flex()
                .flex_col()
                .items_center()
                .gap_4()
                // Avatar
                .child(Avatar::from_initial(initial, 80.0))
                // Name
                .child(
                    div()
                        .text_xl()
                        .font_weight(gpui::FontWeight::SEMIBOLD)
                        .text_color(rgb(colors::TEXT_PRIMARY))
                        .child(name),
                )
                // Call type indicator
                .child(
                    div()
                        .text_sm()
                        .text_color(rgb(colors::TEXT_SECONDARY))
                        .child(call_type_text),
                )
                // Custom content (buttons, status, etc)
                .child(extra_content),
        )
}

/// Render the incoming call popup overlay
///
/// This popup appears centered on screen when an incoming call is received.
/// It shows the caller name, call type (audio/video), and accept/decline buttons.
pub fn render_call_popup(call: &IncomingCall, app_entity: Entity<WhatsAppApp>) -> impl IntoElement {
    let caller_name: SharedString = call.caller_name.clone().into();
    let initial = call.initial();
    let is_video = call.is_video;

    // Clone entity for callbacks
    let accept_entity = app_entity.clone();
    let decline_entity = app_entity;

    let buttons = div()
        .mt_4()
        .flex()
        .gap_6()
        .child(render_call_button(
            "Decline",
            "✕",
            0xff4444,
            move |_, _window, cx| {
                decline_entity.update(cx, |app, cx| {
                    app.decline_call(cx);
                });
            },
        ))
        .child(render_call_button(
            "Accept",
            "✓",
            colors::ACCENT_GREEN,
            move |_, _window, cx| {
                accept_entity.update(cx, |app, cx| {
                    app.accept_call(cx);
                });
            },
        ));

    render_call_popup_base(caller_name, initial, is_video, buttons)
}

/// Render a circular call action button
fn render_call_button(
    label: &'static str,
    icon: &'static str,
    color: u32,
    on_click: impl Fn(&gpui::ClickEvent, &mut gpui::Window, &mut gpui::App) + 'static,
) -> impl IntoElement {
    div()
        .flex()
        .flex_col()
        .items_center()
        .gap_2()
        .child(
            div()
                .id(SharedString::from(format!("call-btn-{}", label)))
                .w(px(56.0))
                .h(px(56.0))
                .bg(rgb(color))
                .rounded_full()
                .flex()
                .items_center()
                .justify_center()
                .cursor_pointer()
                .hover(|s| s.opacity(0.8))
                .on_click(on_click)
                .child(
                    div()
                        .text_color(rgb(colors::WHITE))
                        .text_lg()
                        .font_weight(gpui::FontWeight::BOLD)
                        .child(icon),
                ),
        )
        .child(
            div()
                .text_xs()
                .text_color(rgb(colors::TEXT_SECONDARY))
                .child(label),
        )
}
