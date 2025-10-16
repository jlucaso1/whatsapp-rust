use crate::libsignal::crypto::{CryptographicMac, aes_256_cbc_decrypt};
use anyhow::{Result, anyhow};
use async_trait::async_trait;
use base64::Engine as _;
use base64::prelude::*;
use hkdf::Hkdf;
use hmac::Hmac;
use hmac::Mac;
use sha2::Sha256;
use waproto::whatsapp as wa;
use waproto::whatsapp::ExternalBlobReference;
use waproto::whatsapp::message::HistorySyncNotification;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaType {
    Image,
    Video,
    Audio,
    Document,
    History,
    AppState,
    Sticker,
    StickerPack,
    LinkThumbnail,
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
            MediaType::Sticker => "WhatsApp Image Keys",
            MediaType::StickerPack => "WhatsApp Sticker Pack Keys",
            MediaType::LinkThumbnail => "WhatsApp Link Thumbnail Keys",
        }
    }

    pub fn mms_type(&self) -> &'static str {
        match self {
            MediaType::Image | MediaType::Sticker => "image",
            MediaType::Video => "video",
            MediaType::Audio => "audio",
            MediaType::Document => "document",
            MediaType::History => "md-msg-hist",
            MediaType::AppState => "md-app-state",
            MediaType::StickerPack => "sticker-pack",
            MediaType::LinkThumbnail => "thumbnail-link",
        }
    }
}

#[async_trait]
pub trait Downloadable: Sync + Send {
    fn direct_path(&self) -> Option<&str>;
    fn media_key(&self) -> Option<&[u8]>;
    fn file_enc_sha256(&self) -> Option<&[u8]>;
    fn file_sha256(&self) -> Option<&[u8]>;
    fn file_length(&self) -> Option<u64>;
    fn app_info(&self) -> MediaType;
}

macro_rules! impl_downloadable {
    ($type:ty, $media_type:expr, $file_length_field:ident) => {
        #[async_trait]
        impl Downloadable for $type {
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
                self.$file_length_field
            }

            fn app_info(&self) -> MediaType {
                $media_type
            }
        }
    };
}

impl_downloadable!(wa::message::ImageMessage, MediaType::Image, file_length);
impl_downloadable!(wa::message::VideoMessage, MediaType::Video, file_length);
impl_downloadable!(
    wa::message::DocumentMessage,
    MediaType::Document,
    file_length
);
impl_downloadable!(wa::message::AudioMessage, MediaType::Audio, file_length);
impl_downloadable!(wa::message::StickerMessage, MediaType::Sticker, file_length);
impl_downloadable!(ExternalBlobReference, MediaType::AppState, file_size_bytes);
impl_downloadable!(HistorySyncNotification, MediaType::History, file_length);

#[derive(Debug)]
pub struct DownloadRequest {
    pub url: String,
    pub media_key: Vec<u8>,
    pub app_info: MediaType,
}

pub struct MediaConnection {
    pub hosts: Vec<MediaHost>,
    pub auth: String,
}

pub struct MediaHost {
    pub hostname: String,
}

pub struct DownloadUtils;

impl DownloadUtils {
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
                token = BASE64_URL_SAFE_NO_PAD.encode(file_enc_sha256)
            );

            requests.push(DownloadRequest {
                url,
                media_key: media_key.to_vec(),
                app_info,
            });
        }

        Ok(requests)
    }

    pub fn decrypt_stream<R: std::io::Read>(
        mut reader: R,
        media_key: &[u8],
        app_info: MediaType,
    ) -> Result<Vec<u8>> {
        use aes::Aes256;
        #[allow(deprecated)]
        use aes::cipher::generic_array::GenericArray;
        use aes::cipher::{BlockDecrypt, KeyInit};

        const MAC_SIZE: usize = 10;
        const BLOCK: usize = 16;
        const CHUNK: usize = 8 * 1024;

        let (iv, cipher_key, mac_key) = Self::get_media_keys(media_key, app_info);

        let mut hmac = <Hmac<Sha256> as hmac::Mac>::new_from_slice(&mac_key)
            .map_err(|_| anyhow!("Failed to init HMAC"))?;
        hmac.update(&iv);

        let cipher =
            Aes256::new_from_slice(&cipher_key).map_err(|_| anyhow!("Bad AES key length"))?;

        let mut plaintext: Vec<u8> = Vec::new();
        let mut tail: Vec<u8> = Vec::with_capacity(BLOCK + MAC_SIZE);
        let mut prev_block = iv;

        let mut read_buf = [0u8; CHUNK];

        loop {
            let n = reader.read(&mut read_buf)?;
            if n == 0 {
                break;
            }
            tail.extend_from_slice(&read_buf[..n]);

            if tail.len() > MAC_SIZE + BLOCK {
                let mut processable_len = tail.len() - (MAC_SIZE + BLOCK);
                processable_len -= processable_len % BLOCK;
                if processable_len >= BLOCK {
                    let (to_process, rest) = tail.split_at(processable_len);
                    hmac.update(to_process);
                    for cblock in to_process.chunks_exact(BLOCK) {
                        #[allow(deprecated)]
                        let mut block = GenericArray::clone_from_slice(cblock);
                        cipher.decrypt_block(&mut block);
                        for (b, p) in block.iter_mut().zip(prev_block.iter()) {
                            *b ^= *p;
                        }
                        plaintext.extend_from_slice(&block);
                        prev_block = match <[u8; BLOCK]>::try_from(cblock) {
                            Ok(arr) => arr,
                            Err(_) => return Err(anyhow!("Failed to convert block to array")),
                        };
                    }
                    tail = rest.to_vec();
                }
            }
        }

        if tail.len() < MAC_SIZE + BLOCK || !(tail.len() - MAC_SIZE).is_multiple_of(BLOCK) {
            return Err(anyhow!("Invalid final media size"));
        }
        let mac_index = tail.len() - MAC_SIZE;
        let (final_ciphertext, mac_bytes) = tail.split_at(mac_index);
        hmac.update(final_ciphertext);
        let expected_mac_full = hmac.finalize().into_bytes();
        let expected_mac = &expected_mac_full[..MAC_SIZE];
        if mac_bytes != expected_mac {
            return Err(anyhow!("MAC mismatch"));
        }

        let mut final_plain = Vec::with_capacity(final_ciphertext.len());
        for cblock in final_ciphertext.chunks_exact(BLOCK) {
            #[allow(deprecated)]
            let mut block = GenericArray::clone_from_slice(cblock);
            cipher.decrypt_block(&mut block);
            for (b, p) in block.iter_mut().zip(prev_block.iter()) {
                *b ^= *p;
            }
            final_plain.extend_from_slice(&block);
        }
        if final_plain.is_empty() {
            return Err(anyhow!("Empty plaintext after decrypt"));
        }
        let pad_len = match final_plain.last() {
            Some(&v) => v as usize,
            None => return Err(anyhow!("Empty plaintext after decrypt")),
        };
        if pad_len == 0 || pad_len > BLOCK || pad_len > final_plain.len() {
            return Err(anyhow!("Invalid PKCS7 padding"));
        }
        if !final_plain[final_plain.len() - pad_len..]
            .iter()
            .all(|&b| b as usize == pad_len)
        {
            return Err(anyhow!("Bad PKCS7 padding bytes"));
        }
        final_plain.truncate(final_plain.len() - pad_len);
        plaintext.extend_from_slice(&final_plain);

        Ok(plaintext)
    }

    pub fn get_media_keys(media_key: &[u8], app_info: MediaType) -> ([u8; 16], [u8; 32], [u8; 32]) {
        let hk = Hkdf::<Sha256>::new(None, media_key);
        let mut expanded = vec![0u8; 112];
        hk.expand(app_info.app_info().as_bytes(), &mut expanded)
            .unwrap();
        let iv: [u8; 16] = expanded[0..16].try_into().unwrap();
        let cipher_key: [u8; 32] = expanded[16..48].try_into().unwrap();
        let mac_key: [u8; 32] = expanded[48..80].try_into().unwrap();
        (iv, cipher_key, mac_key)
    }

    pub fn decrypt_cbc(cipher_key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        aes_256_cbc_decrypt(ciphertext, cipher_key, iv).map_err(|e| anyhow!(e.to_string()))
    }

    pub fn verify_and_decrypt(
        encrypted_payload: &[u8],
        media_key: &[u8],
        media_type: MediaType,
    ) -> Result<Vec<u8>> {
        const MAC_SIZE: usize = 10;
        if encrypted_payload.len() <= MAC_SIZE {
            return Err(anyhow!("Downloaded file is too short to contain MAC"));
        }

        let (ciphertext, received_mac) =
            encrypted_payload.split_at(encrypted_payload.len() - MAC_SIZE);

        let (iv, cipher_key, mac_key) = Self::get_media_keys(media_key, media_type);

        let computed_mac_full = {
            let mut mac = CryptographicMac::new("HmacSha256", &mac_key)
                .map_err(|e| anyhow!(e.to_string()))?;
            mac.update(&iv);
            mac.update(ciphertext);
            mac.finalize()
        };
        if &computed_mac_full[..MAC_SIZE] != received_mac {
            return Err(anyhow!("Invalid MAC signature"));
        }

        aes_256_cbc_decrypt(ciphertext, &cipher_key, &iv).map_err(|e| anyhow!(e.to_string()))
    }
}
