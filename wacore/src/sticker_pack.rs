//! Sticker pack creation helpers.
//!
//! Same pattern as album messages: proto-level helpers, no dedicated send method.
//!
//! ```rust,ignore
//! let stickers = vec![
//!     StickerInput::new(&webp_bytes).with_emojis(vec!["😀".into()]),
//!     StickerInput::new(&webp_bytes_2),
//! ];
//! let zip_result = create_sticker_pack_zip("pack-id", &stickers, &cover_webp)?;
//!
//! let zip_upload = client.upload(zip_result.zip_bytes.clone(), MediaType::StickerPack, Default::default()).await?;
//! let thumb_upload = client.upload(
//!     thumbnail_jpeg, MediaType::StickerPackThumbnail,
//!     UploadOptions::new().with_media_key(zip_upload.media_key),
//! ).await?;
//!
//! let metadata = StickerPackMetadata::new(pack_id, "My Pack".into(), "Me".into());
//! let msg = build_sticker_pack_message(&zip_result, &zip_upload.into(), &thumb_upload.into(), metadata)?;
//! client.send_message(jid, msg).await?;
//! ```
//!
//! Sticker format requirements (user's responsibility):
//! - Stickers: 512x512 WebP
//! - Cover: WebP, stored in ZIP as `{pack_id}.webp`
//! - Thumbnail: JPEG, uploaded separately with the same `media_key`

use crate::webp;
use crate::zip::ZipWriter;
use anyhow::{Result, bail};
use sha2::{Digest, Sha256};
use waproto::whatsapp as wa;

#[non_exhaustive]
pub struct StickerInput<'a> {
    pub data: &'a [u8],
    pub emojis: Vec<String>,
    pub accessibility_label: Option<String>,
}

impl<'a> StickerInput<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            emojis: Vec::new(),
            accessibility_label: None,
        }
    }

    pub fn with_emojis(mut self, emojis: Vec<String>) -> Self {
        self.emojis = emojis;
        self
    }

    pub fn with_accessibility_label(mut self, label: String) -> Self {
        self.accessibility_label = Some(label);
        self
    }
}

#[non_exhaustive]
pub struct StickerPackZipResult {
    pub zip_bytes: Vec<u8>,
    pub stickers: Vec<wa::message::sticker_pack_message::Sticker>,
    pub tray_icon_file_name: String,
}

#[non_exhaustive]
pub struct StickerPackMetadata {
    pub pack_id: String,
    pub name: String,
    pub publisher: String,
    pub description: Option<String>,
    pub caption: Option<String>,
}

impl StickerPackMetadata {
    pub fn new(pack_id: String, name: String, publisher: String) -> Self {
        Self {
            pack_id,
            name,
            publisher,
            description: None,
            caption: None,
        }
    }

    pub fn with_description(mut self, desc: String) -> Self {
        self.description = Some(desc);
        self
    }

    pub fn with_caption(mut self, caption: String) -> Self {
        self.caption = Some(caption);
        self
    }
}

/// Upload result fields for proto construction.
/// The high-level crate provides `From<UploadResponse>`.
#[non_exhaustive]
pub struct MediaUploadInfo {
    pub direct_path: String,
    pub media_key: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_enc_sha256: [u8; 32],
    pub file_length: u64,
    pub media_key_timestamp: i64,
}

impl MediaUploadInfo {
    pub fn new(
        direct_path: String,
        media_key: [u8; 32],
        file_sha256: [u8; 32],
        file_enc_sha256: [u8; 32],
        file_length: u64,
        media_key_timestamp: i64,
    ) -> Self {
        Self {
            direct_path,
            media_key,
            file_sha256,
            file_enc_sha256,
            file_length,
            media_key_timestamp,
        }
    }
}

const MAX_STICKERS: usize = 60;

/// Bundles stickers into a store-only ZIP and builds proto metadata.
/// Filenames use `{base64url(sha256)}.webp`. Identical stickers are deduplicated.
pub fn create_sticker_pack_zip(
    pack_id: &str,
    stickers: &[StickerInput],
    cover: &[u8],
) -> Result<StickerPackZipResult> {
    if pack_id.is_empty()
        || pack_id.len() > 128
        || pack_id
            .bytes()
            .any(|b| b == b'/' || b == b'\\' || b == b'.' || b < 0x20)
    {
        bail!(
            "invalid pack_id: must be non-empty, <= 128 bytes, no path separators or control chars"
        );
    }
    if stickers.is_empty() {
        bail!("sticker pack must contain at least 1 sticker");
    }
    if stickers.len() > MAX_STICKERS {
        bail!(
            "sticker pack exceeds maximum of {} stickers (got {})",
            MAX_STICKERS,
            stickers.len()
        );
    }

    let mut zip = ZipWriter::new();
    let mut proto_stickers = Vec::with_capacity(stickers.len());

    let tray_icon_file_name = format!("{pack_id}.webp");
    zip.add_file(&tray_icon_file_name, cover);

    let mut seen_hashes = std::collections::HashSet::new();

    for input in stickers {
        let hash: [u8; 32] = Sha256::digest(input.data).into();
        let file_name = format!("{}.webp", base64url_encode(&hash));

        if seen_hashes.insert(hash) {
            zip.add_file(&file_name, input.data);
        }

        let is_animated = webp::is_animated(input.data);
        proto_stickers.push(wa::message::sticker_pack_message::Sticker {
            file_name: Some(file_name),
            is_animated: Some(is_animated),
            emojis: input.emojis.clone(),
            accessibility_label: input.accessibility_label.clone(),
            is_lottie: Some(false),
            mimetype: Some("image/webp".to_string()),
            premium: None,
        });
    }

    Ok(StickerPackZipResult {
        zip_bytes: zip.finish(),
        stickers: proto_stickers,
        tray_icon_file_name,
    })
}

/// Builds a `wa::Message` with `StickerPackMessage` from upload results.
///
/// Proto fields match WA Web's `GenerateStickerPackMessageProto.js` exactly.
/// Caller must supply a JPEG thumbnail uploaded with the same `media_key` as
/// the zip (via `UploadOptions::with_media_key(zip_upload.media_key)`).
///
/// # Errors
///
/// Returns an error if the thumbnail was uploaded with a different media key
/// than the zip, since the proto only carries one `media_key` for both.
pub fn build_sticker_pack_message(
    zip_result: &StickerPackZipResult,
    zip_upload: &MediaUploadInfo,
    thumb_upload: &MediaUploadInfo,
    metadata: StickerPackMetadata,
) -> Result<wa::Message> {
    if zip_upload.media_key != thumb_upload.media_key {
        bail!("thumbnail must be uploaded with the same media_key as the zip");
    }

    let pack_msg = wa::message::StickerPackMessage {
        sticker_pack_id: Some(metadata.pack_id),
        name: Some(metadata.name),
        publisher: Some(metadata.publisher),
        stickers: zip_result.stickers.clone(),
        file_length: Some(zip_upload.file_length),
        file_sha256: Some(zip_upload.file_sha256.to_vec()),
        file_enc_sha256: Some(zip_upload.file_enc_sha256.to_vec()),
        media_key: Some(zip_upload.media_key.to_vec()),
        direct_path: Some(zip_upload.direct_path.clone()),
        caption: metadata.caption,
        pack_description: metadata.description,
        thumbnail_sha256: Some(thumb_upload.file_sha256.to_vec()),
        thumbnail_enc_sha256: Some(thumb_upload.file_enc_sha256.to_vec()),
        thumbnail_direct_path: Some(thumb_upload.direct_path.clone()),
        sticker_pack_size: Some(zip_result.zip_bytes.len() as u64),
        tray_icon_file_name: Some(zip_result.tray_icon_file_name.clone()),
        ..Default::default()
    };

    Ok(wa::Message {
        sticker_pack_message: Some(Box::new(pack_msg)),
        ..Default::default()
    })
}

fn base64url_encode(data: &[u8]) -> String {
    use base64::engine::{Engine, general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_webp(extra: u8) -> Vec<u8> {
        // Minimal valid-ish WebP (just RIFF+WEBP+VP8 header, not animated)
        let mut buf = Vec::new();
        buf.extend_from_slice(b"RIFF");
        buf.extend_from_slice(&0u32.to_le_bytes());
        buf.extend_from_slice(b"WEBP");
        buf.extend_from_slice(b"VP8 ");
        buf.extend_from_slice(&4u32.to_le_bytes());
        buf.extend_from_slice(&[extra, 0, 0, 0]);
        let riff_size = (buf.len() - 8) as u32;
        buf[4..8].copy_from_slice(&riff_size.to_le_bytes());
        buf
    }

    #[test]
    fn create_zip_basic() {
        let s1 = dummy_webp(1);
        let s2 = dummy_webp(2);
        let cover = dummy_webp(0);

        let stickers = vec![StickerInput::new(&s1), StickerInput::new(&s2)];
        let result = create_sticker_pack_zip("test-pack", &stickers, &cover).unwrap();

        assert_eq!(result.stickers.len(), 2);
        assert_eq!(result.tray_icon_file_name, "test-pack.webp");
        assert!(
            result.stickers[0]
                .file_name
                .as_ref()
                .unwrap()
                .ends_with(".webp")
        );
        assert!(
            result.stickers[1]
                .file_name
                .as_ref()
                .unwrap()
                .ends_with(".webp")
        );
        assert_ne!(result.stickers[0].file_name, result.stickers[1].file_name);
        // ZIP should start with local file header magic
        assert_eq!(&result.zip_bytes[0..4], &[0x50, 0x4B, 0x03, 0x04]);
    }

    #[test]
    fn create_zip_deduplication() {
        let s1 = dummy_webp(1);
        let cover = dummy_webp(0);

        // Two identical stickers
        let stickers = vec![StickerInput::new(&s1), StickerInput::new(&s1)];
        let result = create_sticker_pack_zip("dedup-test", &stickers, &cover).unwrap();

        // Both proto entries exist with same filename
        assert_eq!(result.stickers.len(), 2);
        assert_eq!(result.stickers[0].file_name, result.stickers[1].file_name);

        // But ZIP should be smaller than if we added both (only 2 entries: cover + 1 sticker)
        let s2 = dummy_webp(2);
        let non_dedup_stickers = vec![StickerInput::new(&s1), StickerInput::new(&s2)];
        let non_dedup =
            create_sticker_pack_zip("dedup-test2", &non_dedup_stickers, &cover).unwrap();
        assert!(result.zip_bytes.len() < non_dedup.zip_bytes.len());
    }

    #[test]
    fn create_zip_empty_rejected() {
        let cover = dummy_webp(0);
        let result = create_sticker_pack_zip("empty", &[], &cover);
        assert!(result.is_err());
    }

    #[test]
    fn create_zip_too_many_rejected() {
        let sticker = dummy_webp(1);
        let cover = dummy_webp(0);
        let stickers: Vec<_> = (0..61).map(|_| StickerInput::new(&sticker)).collect();
        let result = create_sticker_pack_zip("big", &stickers, &cover);
        assert!(result.is_err());
    }

    #[test]
    fn create_zip_with_emojis() {
        let s1 = dummy_webp(1);
        let cover = dummy_webp(0);

        let stickers = vec![
            StickerInput::new(&s1)
                .with_emojis(vec!["😀".into(), "🎉".into()])
                .with_accessibility_label("happy face".into()),
        ];
        let result = create_sticker_pack_zip("emoji-test", &stickers, &cover).unwrap();

        let sticker = &result.stickers[0];
        assert_eq!(sticker.emojis, vec!["😀", "🎉"]);
        assert_eq!(sticker.accessibility_label.as_deref(), Some("happy face"));
    }

    #[test]
    fn invalid_pack_id_rejected() {
        let s = dummy_webp(1);
        let cover = dummy_webp(0);
        let stickers = vec![StickerInput::new(&s)];

        assert!(create_sticker_pack_zip("", &stickers, &cover).is_err());
        assert!(create_sticker_pack_zip("../evil", &stickers, &cover).is_err());
        assert!(create_sticker_pack_zip("a/b", &stickers, &cover).is_err());
        assert!(create_sticker_pack_zip("a\\b", &stickers, &cover).is_err());
        assert!(create_sticker_pack_zip("has.dot", &stickers, &cover).is_err());
        assert!(create_sticker_pack_zip("valid-pack_id", &stickers, &cover).is_ok());
    }

    #[test]
    fn build_message_fields() {
        let s1 = dummy_webp(1);
        let cover = dummy_webp(0);
        let stickers = vec![StickerInput::new(&s1)];
        let zip_result = create_sticker_pack_zip("msg-test", &stickers, &cover).unwrap();

        let zip_upload = MediaUploadInfo::new(
            "/mms/sticker-pack/abc".into(),
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            zip_result.zip_bytes.len() as u64,
            1234567890,
        );
        let thumb_upload = MediaUploadInfo::new(
            "/mms/thumbnail-sticker-pack/def".into(),
            [0u8; 32],
            [3u8; 32],
            [4u8; 32],
            1000,
            1234567890,
        );

        let metadata = StickerPackMetadata::new(
            "msg-test".into(),
            "Test Pack".into(),
            "Test Publisher".into(),
        )
        .with_description("A test pack".into());

        let msg =
            build_sticker_pack_message(&zip_result, &zip_upload, &thumb_upload, metadata).unwrap();
        let pack = msg.sticker_pack_message.unwrap();

        assert_eq!(pack.sticker_pack_id.as_deref(), Some("msg-test"));
        assert_eq!(pack.name.as_deref(), Some("Test Pack"));
        assert_eq!(pack.publisher.as_deref(), Some("Test Publisher"));
        assert_eq!(pack.pack_description.as_deref(), Some("A test pack"));
        assert_eq!(pack.stickers.len(), 1);
        assert_eq!(pack.direct_path.as_deref(), Some("/mms/sticker-pack/abc"));
        assert_eq!(
            pack.thumbnail_direct_path.as_deref(),
            Some("/mms/thumbnail-sticker-pack/def")
        );
        assert_eq!(pack.tray_icon_file_name.as_deref(), Some("msg-test.webp"));
        // WA Web doesn't set these on outgoing sticker packs
        assert_eq!(pack.thumbnail_height, None);
        assert_eq!(pack.thumbnail_width, None);
        assert_eq!(pack.sticker_pack_origin, None);
        assert_eq!(pack.media_key_timestamp, None);
        assert_eq!(pack.image_data_hash, None);
    }
}
