//! Shared utility functions for the WhatsApp UI

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
