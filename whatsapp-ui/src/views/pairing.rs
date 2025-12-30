//! Pairing view (QR code / pair code)

use gpui::{div, prelude::*, px, rgb};

use super::centered_view;
use crate::theme::{colors, layout};

/// Render pairing view (QR code / pair code)
pub fn render_pairing_view(
    qr_code: Option<String>,
    pair_code: Option<String>,
    timeout_secs: u64,
) -> impl IntoElement {
    let qr_display = qr_code.unwrap_or_else(|| "Waiting for QR...".to_string());

    centered_view(px(24.0))
        .child(
            div()
                .text_color(rgb(colors::TEXT_PRIMARY))
                .text_2xl()
                .font_weight(gpui::FontWeight::BOLD)
                .child("Link your phone"),
        )
        .child(
            div()
                .text_color(rgb(colors::TEXT_SECONDARY))
                .text_base()
                .child("Open WhatsApp on your phone and scan the QR code"),
        )
        .child(
            // QR code placeholder - TODO: render actual QR
            div()
                .size(px(layout::QR_CODE_SIZE))
                .bg(rgb(colors::WHITE))
                .rounded(px(layout::RADIUS_MEDIUM))
                .flex()
                .justify_center()
                .items_center()
                .child(
                    div()
                        .text_color(rgb(colors::BLACK))
                        .text_xs()
                        .child(qr_display),
                ),
        )
        .when_some(pair_code, |el, code| {
            el.child(
                div()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_2()
                    .child(
                        div()
                            .text_color(rgb(colors::TEXT_SECONDARY))
                            .text_sm()
                            .child("Or enter this code:"),
                    )
                    .child(
                        div()
                            .text_color(rgb(colors::ACCENT_GREEN))
                            .text_2xl()
                            .font_weight(gpui::FontWeight::BOLD)
                            .child(code),
                    ),
            )
        })
        .child(
            div()
                .text_color(rgb(colors::TEXT_SECONDARY))
                .text_sm()
                .child(format!("Expires in {} seconds", timeout_secs)),
        )
}
