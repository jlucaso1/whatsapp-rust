//! Application views

use gpui::{Div, div, prelude::*, rgb};

use crate::theme::colors;

mod chat;
mod error;
mod loading;
pub mod pairing;

pub use chat::render_connected_view;
pub use error::render_error_view;
pub use loading::{render_connecting_view, render_loading_view, render_syncing_view};
pub use pairing::render_pairing_view;

/// Create a centered full-screen view container with consistent styling.
///
/// This provides the base layout for loading, error, and pairing views.
pub fn centered_view(gap: gpui::Pixels) -> Div {
    div()
        .flex()
        .flex_col()
        .size_full()
        .bg(rgb(colors::BG_PRIMARY))
        .justify_center()
        .items_center()
        .gap(gap)
}
