//! Pairing view (QR code / pair code)

use std::sync::Arc;

use gpui::{Image, ImageFormat, ImageSource, div, img, prelude::*, px, rgb};

use super::centered_view;
use crate::state::CachedQrCode;
use crate::theme::{colors, layout};

/// Generate QR code as PNG bytes (called once when QR data changes)
pub fn generate_qr_png(data: &str) -> Option<Vec<u8>> {
    use image::ImageEncoder;
    use qrcode::QrCode;

    let code = QrCode::new(data.as_bytes()).ok()?;
    let image = code.render::<image::Luma<u8>>().build();

    let mut png_bytes = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
    encoder
        .write_image(
            image.as_raw(),
            image.width(),
            image.height(),
            image::ExtendedColorType::L8,
        )
        .ok()?;

    Some(png_bytes)
}

/// Render pairing view (QR code / pair code)
pub fn render_pairing_view(
    qr_code: Option<&CachedQrCode>,
    pair_code: Option<String>,
    timeout_secs: u64,
) -> impl IntoElement {
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
            div()
                .size(px(layout::QR_CODE_SIZE))
                .bg(rgb(colors::WHITE))
                .rounded(px(layout::RADIUS_MEDIUM))
                .flex()
                .justify_center()
                .items_center()
                .child(if let Some(cached) = qr_code {
                    let image =
                        Image::from_bytes(ImageFormat::Png, cached.png_bytes.as_ref().clone());
                    img(ImageSource::Image(Arc::new(image)))
                        .size(px(layout::QR_CODE_SIZE - 16.0))
                        .into_any_element()
                } else {
                    div()
                        .text_color(rgb(colors::BLACK))
                        .text_sm()
                        .child("Waiting for QR...")
                        .into_any_element()
                }),
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
