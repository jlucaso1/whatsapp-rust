use anyhow::{Result, anyhow};
use hmac::Hmac;
use hmac::Mac;
use rand::Rng;
use rand::rng;
use sha2::{Digest, Sha256};

use crate::download::MediaType;

pub struct EncryptedMedia {
    pub data_to_upload: Vec<u8>,
    pub media_key: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_enc_sha256: [u8; 32],
}

fn pkcs7_pad(data: &[u8], block: usize) -> Vec<u8> {
    let pad = block - (data.len() % block);
    let mut out = Vec::with_capacity(data.len() + pad);
    out.extend_from_slice(data);
    out.extend(std::iter::repeat_n(pad as u8, pad));
    out
}

pub fn encrypt_media(plaintext: &[u8], media_type: MediaType) -> Result<EncryptedMedia> {
    use aes::Aes256;
    use aes::cipher::generic_array::GenericArray;
    use aes::cipher::{BlockEncrypt, KeyInit};

    let file_sha256: [u8; 32] = Sha256::digest(plaintext).into();

    let mut media_key = [0u8; 32];
    rng().fill(&mut media_key);
    let (iv, cipher_key, mac_key) =
        crate::download::DownloadUtils::get_media_keys(&media_key, media_type);

    let mut data = pkcs7_pad(plaintext, 16);
    let cipher = Aes256::new_from_slice(&cipher_key).map_err(|_| anyhow!("Bad AES key"))?;
    let mut prev_block = iv;
    for chunk in data.chunks_mut(16) {
        let mut block = GenericArray::clone_from_slice(chunk);
        for (b, p) in block.iter_mut().zip(prev_block.iter()) {
            *b ^= *p;
        }
        cipher.encrypt_block(&mut block);
        chunk.copy_from_slice(&block);
        prev_block.copy_from_slice(&block);
    }

    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&mac_key).map_err(|_| anyhow!("HMAC init"))?;
    mac.update(&iv);
    mac.update(&data);
    let mac_full = mac.finalize().into_bytes();
    let mut upload = data;
    upload.extend_from_slice(&mac_full[..10]);

    let file_enc_sha256: [u8; 32] = Sha256::digest(&upload).into();

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
    fn padding_non_aligned() {
        let p = super::pkcs7_pad(b"hello", 16);
        assert_eq!(p.len(), 16);
        assert_eq!(&p[5..], &[11u8; 11]);
    }

    #[test]
    fn padding_aligned() {
        let p = super::pkcs7_pad(&[0u8; 16], 16);
        assert_eq!(p.len(), 32);
        assert!(p[16..].iter().all(|b| *b == 16));
    }

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
