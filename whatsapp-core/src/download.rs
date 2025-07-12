use crate::crypto::{cbc, hkdf};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use whatsapp_proto::whatsapp::ExternalBlobReference;

/// The app_info string is used in HKDF to derive the decryption keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Image,
    Video,
    Audio,
    Document,
    History,
    AppState,
}

impl MediaType {
    pub fn app_info(&self) -> &'static str {
        match self {
            MediaType::Image => "WhatsApp Image Keys",
            MediaType::Video => "WhatsApp Video Keys",
            MediaType::Audio => "WhatsApp Audio Keys",
            MediaType::Document => "WhatsApp Document Keys",
            MediaType::History => "WhatsApp History Keys",
            MediaType::AppState => "WhatsApp App State Keys",
        }
    }
}

/// This trait defines the necessary methods for an object to be downloaded.
#[async_trait]
pub trait Downloadable: Sync + Send {
    fn direct_path(&self) -> Option<&str>;
    fn media_key(&self) -> Option<&[u8]>;
    fn file_enc_sha256(&self) -> Option<&[u8]>;
    fn file_sha256(&self) -> Option<&[u8]>;
    fn file_length(&self) -> Option<u64>;
    fn app_info(&self) -> MediaType;
}

// Implement the trait for the struct we care about right now.
#[async_trait]
impl Downloadable for ExternalBlobReference {
    fn direct_path(&self) -> Option<&str> {
        self.direct_path.as_deref()
    }

    fn media_key(&self) -> Option<&[u8]> {
        self.media_key.as_deref()
    }

    fn file_enc_sha256(&self) -> Option<&[u8]> {
        self.file_enc_sha256.as_deref()
    }

    fn file_sha256(&self) -> Option<&[u8]> {
        self.file_sha256.as_deref()
    }

    fn file_length(&self) -> Option<u64> {
        self.file_size_bytes
    }

    fn app_info(&self) -> MediaType {
        MediaType::AppState // This is specifically for app state blobs
    }
}

/// Information needed to prepare a download request
#[derive(Debug)]
pub struct DownloadRequest {
    pub url: String,
    pub media_key: Vec<u8>,
    pub app_info: MediaType,
}

/// Media connection info for constructing download URLs
pub struct MediaConnection {
    pub hosts: Vec<MediaHost>,
    pub auth: String,
}

/// Media host information
pub struct MediaHost {
    pub hostname: String,
}

/// Core download utilities that are platform-independent
pub struct DownloadUtils;

impl DownloadUtils {
    /// Prepares download requests for all hosts, returning the first successful request info
    pub fn prepare_download_requests(
        downloadable: &dyn Downloadable,
        media_conn: &MediaConnection,
    ) -> Result<Vec<DownloadRequest>> {
        let direct_path = downloadable
            .direct_path()
            .ok_or_else(|| anyhow!("Missing direct_path"))?;
        let media_key = downloadable
            .media_key()
            .ok_or_else(|| anyhow!("Missing media_key"))?;
        let file_enc_sha256 = downloadable
            .file_enc_sha256()
            .ok_or_else(|| anyhow!("Missing file_enc_sha256"))?;
        let app_info = downloadable.app_info();

        let mut requests = Vec::new();
        for host in &media_conn.hosts {
            let url = format!(
                "https://{hostname}{direct_path}?auth={auth}&token={token}",
                hostname = host.hostname,
                direct_path = direct_path,
                auth = media_conn.auth,
                token = URL_SAFE_NO_PAD.encode(file_enc_sha256)
            );

            requests.push(DownloadRequest {
                url,
                media_key: media_key.to_vec(),
                app_info,
            });
        }

        Ok(requests)
    }

    /// Decrypts downloaded encrypted data
    pub fn decrypt_downloaded_media(
        encrypted_data: &[u8],
        media_key: &[u8],
        app_info: MediaType,
    ) -> Result<Vec<u8>> {
        // The last 10 bytes are the MAC
        if encrypted_data.len() < 10 {
            return Err(anyhow!("Downloaded data too short"));
        }
        let (ciphertext, mac) = encrypted_data.split_at(encrypted_data.len() - 10);

        let (iv, cipher_key, mac_key) = Self::get_media_keys(media_key, app_info);

        // Verify MAC
        let mut hmac = <Hmac<Sha256>>::new_from_slice(&mac_key).unwrap();
        hmac.update(&iv);
        hmac.update(ciphertext);
        let expected_mac = &hmac.finalize().into_bytes()[..10];

        if mac != expected_mac {
            return Err(anyhow!("MAC mismatch"));
        }

        // Decrypt using AES-CBC
        let plaintext = cbc::decrypt(&cipher_key, &iv, ciphertext)?;

        Ok(plaintext)
    }

    /// Helper to derive keys for decryption (port of whatsmeow getMediaKeys)
    pub fn get_media_keys(media_key: &[u8], app_info: MediaType) -> ([u8; 16], [u8; 32], [u8; 32]) {
        let expanded = hkdf::sha256(media_key, None, app_info.app_info().as_bytes(), 112).unwrap();
        let iv: [u8; 16] = expanded[0..16].try_into().unwrap();
        let cipher_key: [u8; 32] = expanded[16..48].try_into().unwrap();
        let mac_key: [u8; 32] = expanded[48..80].try_into().unwrap();
        (iv, cipher_key, mac_key)
    }
}
