//! Error view

use gpui::{Entity, div, prelude::*, px, rgb};
use gpui_component::button::{Button, ButtonVariants};

use super::centered_view;
use crate::app::WhatsAppApp;
use crate::theme::colors;

/// Render error view
pub fn render_error_view(error: &str, entity: Entity<WhatsAppApp>) -> impl IntoElement {
    centered_view(px(24.0))
        .child(
            div()
                .text_color(rgb(colors::ERROR))
                .text_2xl()
                .font_weight(gpui::FontWeight::BOLD)
                .child("Error"),
        )
        .child(
            div()
                .text_color(rgb(colors::TEXT_PRIMARY))
                .text_base()
                .max_w(px(400.))
                .text_center()
                .child(error.to_string()),
        )
        .child(
            Button::new("retry")
                .label("Retry")
                .primary()
                .on_click(move |_, _, cx| {
                    entity.update(cx, |this, cx| {
                        this.retry_connection(cx);
                    });
                }),
        )
}
