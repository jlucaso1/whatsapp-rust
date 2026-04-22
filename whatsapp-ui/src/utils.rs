//! Shared utility functions for the WhatsApp UI

use chrono::{DateTime, Local, Utc};
use gpui::ImageFormat;

/// Convert a MIME type string to a GPUI ImageFormat
pub fn mime_to_image_format(mime: &str) -> ImageFormat {
    match mime {
        "image/jpeg" | "image/jpg" => ImageFormat::Jpeg,
        "image/png" => ImageFormat::Png,
        "image/gif" => ImageFormat::Gif,
        "image/webp" => ImageFormat::Webp,
        "image/bmp" => ImageFormat::Bmp,
        _ => ImageFormat::Png, // Default fallback
    }
}

/// Format a UTC timestamp as local time (HH:MM format).
///
/// Converts from UTC to the system's local timezone before formatting.
/// This ensures timestamps are displayed correctly regardless of where
/// the user is located.
pub fn format_time_local(timestamp: &DateTime<Utc>) -> String {
    let local: DateTime<Local> = timestamp.with_timezone(&Local);
    local.format("%H:%M").to_string()
}
