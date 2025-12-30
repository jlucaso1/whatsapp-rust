//! WhatsApp UI - A GPUI-based WhatsApp client
//!
//! This is the main entry point for the WhatsApp UI application.

mod app;
mod assets;
mod audio;
mod client;
mod components;
mod state;
mod theme;
mod utils;
mod video;
mod views;

use gpui::{
    App, AppContext, Application, Bounds, SharedString, WindowBounds, WindowOptions, px, size,
};
use gpui_component::Root;

use crate::app::{WhatsAppApp, init_chat_list_bindings};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    Application::new()
        .with_assets(assets::Assets)
        .run(|cx: &mut App| {
            // Initialize gpui-component theme
            gpui_component::init(cx);

            // Initialize chat list keyboard bindings
            init_chat_list_bindings(cx);

            let bounds = Bounds::centered(None, size(px(1200.), px(800.)), cx);

            cx.open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(bounds)),
                    titlebar: Some(gpui::TitlebarOptions {
                        title: Some(SharedString::from("WhatsApp")),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                |window, cx| {
                    // Create the app view
                    let view = cx.new(WhatsAppApp::new);
                    // Wrap in Root component (required for Input and other gpui-component features)
                    cx.new(|cx| Root::new(view, window, cx))
                },
            )
            .unwrap();
        });
}
