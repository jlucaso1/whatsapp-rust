//! Avatar component wrapper using gpui-component Avatar

use gpui::prelude::*;
use gpui_component::Sizable;
use gpui_component::avatar::Avatar as GpuiAvatar;

/// Avatar helper for rendering user avatars with fallback initials
pub struct Avatar;

impl Avatar {
    /// Render an avatar with the given name (uses initials as fallback)
    #[allow(dead_code)]
    pub fn render(name: impl Into<gpui::SharedString>, size: f32) -> impl IntoElement {
        GpuiAvatar::new()
            .name(name)
            .with_size(gpui_component::Size::Large)
            .size(gpui::px(size))
    }

    /// Render an avatar with just an initial character
    pub fn from_initial(initial: char, size: f32) -> impl IntoElement {
        GpuiAvatar::new()
            .name(initial.to_string())
            .with_size(gpui_component::Size::Large)
            .size(gpui::px(size))
    }
}
