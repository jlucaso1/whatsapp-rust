//! Loading and connecting views

use gpui::{div, prelude::*, px, rgb};
use gpui_component::{IconName, Sizable, spinner::Spinner};

use super::centered_view;
use crate::theme::colors;

/// Render loading view
pub fn render_loading_view() -> impl IntoElement {
    render_spinner_view("Loading WhatsApp...")
}

/// Render connecting view
pub fn render_connecting_view() -> impl IntoElement {
    render_spinner_view("Connecting...")
}

/// Render syncing view (after pairing, before fully connected)
pub fn render_syncing_view() -> impl IntoElement {
    render_spinner_view("Pairing successful! Syncing...")
}

/// Render a centered spinner with message
fn render_spinner_view(message: &str) -> impl IntoElement {
    centered_view(px(16.0))
        .child(
            Spinner::new()
                .large()
                .icon(IconName::Loader)
                .color(rgb(colors::ACCENT_GREEN).into()),
        )
        .child(
            div()
                .text_color(rgb(colors::TEXT_PRIMARY))
                .text_xl()
                .child(message.to_string()),
        )
}
