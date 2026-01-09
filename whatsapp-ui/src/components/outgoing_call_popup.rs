//! Outgoing call popup component

use gpui::{Entity, SharedString, div, prelude::*, rgb};
use gpui_component::button::{Button, ButtonVariants as _};

use crate::app::WhatsAppApp;
use crate::state::OutgoingCall;
use crate::theme::colors;

use super::render_call_popup_base;

/// Render the outgoing call popup overlay
///
/// This popup appears centered on screen when initiating a call.
/// It shows the recipient name, call type (audio/video), status, and a cancel button.
pub fn render_outgoing_call_popup(
    call: &OutgoingCall,
    app_entity: Entity<WhatsAppApp>,
) -> impl IntoElement {
    let recipient_name: SharedString = call.recipient_name.clone().into();
    let initial = call.initial();
    let is_video = call.is_video;
    let status_text = call.status_message();

    // Custom content: status message + cancel button
    let extra_content = div()
        .flex()
        .flex_col()
        .items_center()
        .gap_4()
        // Status message (Calling..., Ringing..., etc.)
        .child(
            div()
                .text_sm()
                .text_color(rgb(colors::ACCENT_GREEN))
                .child(status_text),
        )
        // Cancel button
        .child(
            div().mt_4().child(
                Button::new("cancel-call")
                    .label("Cancel")
                    .danger()
                    .on_click(move |_, _window, cx| {
                        app_entity.update(cx, |app, cx| {
                            app.cancel_outgoing_call(cx);
                        });
                    }),
            ),
        );

    render_call_popup_base(recipient_name, initial, is_video, extra_content)
}
