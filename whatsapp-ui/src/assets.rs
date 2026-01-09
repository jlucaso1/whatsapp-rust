//! Custom asset source that combines gpui-component-assets with our custom icons

use anyhow::anyhow;
use gpui::{AssetSource, Result, SharedString};
use rust_embed::RustEmbed;
use std::borrow::Cow;

/// Our custom icons embedded at compile time
#[derive(RustEmbed)]
#[folder = "assets"]
#[include = "icons/**/*.svg"]
pub struct CustomIcons;

/// Combined asset source that first checks our custom icons,
/// then falls back to gpui-component-assets
pub struct Assets;

impl AssetSource for Assets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if path.is_empty() {
            return Ok(None);
        }

        // First try our custom icons
        if let Some(data) = CustomIcons::get(path) {
            return Ok(Some(data.data));
        }

        // Fall back to gpui-component-assets
        gpui_component_assets::Assets
            .load(path)
            .map_err(|e| anyhow!("could not find asset at path \"{path}\": {e}"))
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        // Combine both lists
        let mut items: Vec<SharedString> = CustomIcons::iter()
            .filter_map(|p| p.starts_with(path).then(|| p.into()))
            .collect();

        if let Ok(component_items) = gpui_component_assets::Assets.list(path) {
            for item in component_items {
                if !items.contains(&item) {
                    items.push(item);
                }
            }
        }

        Ok(items)
    }
}
