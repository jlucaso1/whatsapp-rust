use crate::download::MediaType;
use crate::libsignal::crypto::{CryptographicHash, CryptographicMac, aes_256_cbc_encrypt_into};
use anyhow::Result;
use rand::Rng;
use rand::rng;

pub struct EncryptedMedia {
    pub data_to_upload: Vec<u8>,
    pub media_key: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_enc_sha256: [u8; 32],
}

pub fn encrypt_media(plaintext: &[u8], media_type: MediaType) -> Result<EncryptedMedia> {
    // Use finalize_sha256_array() for zero-allocation hash finalization
    let file_sha256 = {
        let mut hasher = CryptographicHash::new("SHA-256").map_err(|e| anyhow::anyhow!(e))?;
        hasher.update(plaintext);
        hasher
            .finalize_sha256_array()
            .map_err(|e| anyhow::anyhow!(e))?
    };

    let mut media_key = [0u8; 32];
    rng().fill(&mut media_key);
    let (iv, cipher_key, mac_key) =
        crate::download::DownloadUtils::get_media_keys(&media_key, media_type)?;

    let mut data = Vec::new();
    aes_256_cbc_encrypt_into(plaintext, &cipher_key, &iv, &mut data)?;

    // Use finalize_sha256_array() for zero-allocation MAC finalization
    let mac_full = {
        let mut mac =
            CryptographicMac::new("HmacSha256", &mac_key).map_err(|e| anyhow::anyhow!(e))?;
        mac.update(&iv);
        mac.update(&data);
        mac.finalize_sha256_array()
            .map_err(|e| anyhow::anyhow!(e))?
    };

    let mut upload = data;
    upload.extend_from_slice(&mac_full[..10]);

    // Use finalize_sha256_array() for zero-allocation hash finalization
    let file_enc_sha256 = {
        let mut hasher = CryptographicHash::new("SHA-256").map_err(|e| anyhow::anyhow!(e))?;
        hasher.update(&upload);
        hasher
            .finalize_sha256_array()
            .map_err(|e| anyhow::anyhow!(e))?
    };

    Ok(EncryptedMedia {
        data_to_upload: upload,
        media_key,
        file_sha256,
        file_enc_sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::download::DownloadUtils;

    #[test]
    fn roundtrip_decrypt_stream() {
        let msg = b"Roundtrip encryption test payload.";
        let enc = encrypt_media(msg, MediaType::Image).expect("media operation should succeed");
        use std::io::Cursor;
        let cursor = Cursor::new(enc.data_to_upload.clone());
        let plain = DownloadUtils::decrypt_stream(cursor, &enc.media_key, MediaType::Image)
            .expect("media operation should succeed");
        assert_eq!(plain, msg);
    }
}
