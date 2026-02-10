//! WhatsApp UI - A GPUI-based WhatsApp client
//!
//! This is the main entry point for the WhatsApp UI application.

// Allow dead code for WIP features (calls, media playback, etc.)
#![allow(dead_code)]
#![allow(clippy::too_many_arguments)]

mod app;
mod assets;
mod audio;
mod client;
mod components;
mod responsive;
mod state;
mod theme;
mod utils;
mod video;
mod views;

use gpui::{
    App, AppContext, Application, Bounds, SharedString, WindowBounds, WindowOptions, px, size,
};
use gpui_component::Root;
use gpui_component::theme::{Theme, ThemeMode};

use crate::app::{WhatsAppApp, init_chat_list_bindings};

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .filter_module("blade_graphics", log::LevelFilter::Warn)
        .filter_module("naga", log::LevelFilter::Warn)
        .filter_module("zbus", log::LevelFilter::Warn)
        .filter_module("tracing", log::LevelFilter::Warn)
        .filter_module("gpui", log::LevelFilter::Warn)
        .init();

    Application::new()
        .with_assets(assets::Assets)
        .run(|cx: &mut App| {
            gpui_component::init(cx);
            Theme::change(ThemeMode::Dark, None, cx);
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
                    let view = cx.new(WhatsAppApp::new);
                    cx.new(|cx| Root::new(view, window, cx))
                },
            )
            .unwrap();
        });
}
