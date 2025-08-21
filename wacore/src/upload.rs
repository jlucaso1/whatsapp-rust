use crate::crypto::{aes_256_cbc_encrypt, hmac_sha256, sha256};
use crate::download::MediaType;
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
    let file_sha256 = sha256(plaintext);

    let mut media_key = [0u8; 32];
    rng().fill(&mut media_key);
    let (iv, cipher_key, mac_key) =
        crate::download::DownloadUtils::get_media_keys(&media_key, media_type);

    let data = aes_256_cbc_encrypt(plaintext, &cipher_key, &iv)?;

    let mac_full = hmac_sha256(&mac_key, &[&iv, &data]);

    let mut upload = data;
    upload.extend_from_slice(&mac_full[..10]);

    let file_enc_sha256 = sha256(&upload);

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
        let enc = encrypt_media(msg, MediaType::Image).unwrap();
        use std::io::Cursor;
        let cursor = Cursor::new(enc.data_to_upload.clone());
        let plain =
            DownloadUtils::decrypt_stream(cursor, &enc.media_key, MediaType::Image).unwrap();
        assert_eq!(plain, msg);
    }
}
