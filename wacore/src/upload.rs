use crate::download::{DownloadUtils, MediaType};
use crate::libsignal::crypto::{CryptographicHash, CryptographicMac};
use anyhow::Result;
use rand::RngExt;
use rand::rng;
use std::io::{Cursor, Read, Write};

pub struct EncryptedMedia {
    pub data_to_upload: Vec<u8>,
    pub media_key: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_enc_sha256: [u8; 32],
}

/// Encryption metadata returned by streaming encryption.
/// Contains keys and hashes but NOT the encrypted data (which was written to the writer).
pub struct EncryptedMediaInfo {
    pub media_key: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_enc_sha256: [u8; 32],
    pub file_length: u64,
}

/// Encrypt media in a streaming fashion with constant memory usage (~40KB).
///
/// Reads plaintext from `reader` in 8KB chunks, encrypts with AES-256-CBC,
/// and writes ciphertext + 10-byte HMAC-SHA256 MAC to `writer`.
/// Computes SHA-256 hashes of both plaintext and ciphertext on the fly.
///
/// This is the streaming counterpart of [`encrypt_media`] — same crypto,
/// but processes data incrementally instead of buffering the entire file.
///
/// The writer receives the exact bytes that should be uploaded to WhatsApp
/// CDN servers (ciphertext + MAC), identical to `EncryptedMedia::data_to_upload`.
pub fn encrypt_media_streaming<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    media_type: MediaType,
) -> Result<EncryptedMediaInfo> {
    use aes::Aes256;
    use aes::cipher::{Block, BlockEncrypt, KeyInit};

    const BLOCK: usize = 16;
    const CHUNK: usize = 8 * 1024;

    // Generate random media key and derive AES/HMAC keys via HKDF
    let mut media_key = [0u8; 32];
    rng().fill(&mut media_key);
    let (iv, cipher_key, mac_key) = DownloadUtils::get_media_keys(&media_key, media_type)?;

    let cipher = Aes256::new_from_slice(&cipher_key).map_err(|_| anyhow::anyhow!("Bad AES key"))?;
    let mut hmac = CryptographicMac::new("HmacSha256", &mac_key)?;
    let mut sha256_plain = CryptographicHash::new("SHA-256")?;
    let mut sha256_enc = CryptographicHash::new("SHA-256")?;

    // HMAC covers IV + ciphertext
    hmac.update(&iv);

    let mut prev_block: [u8; BLOCK] = iv;
    let mut file_length: u64 = 0;
    let mut remainder = Vec::with_capacity(CHUNK + BLOCK);
    let mut read_buf = [0u8; CHUNK];

    // Closure scope: borrows writer, hmac, sha256_enc, prev_block, cipher
    {
        let mut encrypt_cbc_block = |block_data: &[u8]| -> Result<()> {
            let mut data: [u8; BLOCK] = block_data
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid block size"))?;
            for (b, &p) in data.iter_mut().zip(prev_block.iter()) {
                *b ^= p;
            }
            let mut block: Block<Aes256> = data.into();
            cipher.encrypt_block(&mut block);
            prev_block = block.into();
            writer.write_all(&prev_block)?;
            hmac.update(&prev_block);
            sha256_enc.update(&prev_block);
            Ok(())
        };

        // Read and encrypt in chunks
        loop {
            let n = reader.read(&mut read_buf)?;
            if n == 0 {
                break;
            }

            sha256_plain.update(&read_buf[..n]);
            file_length += n as u64;
            remainder.extend_from_slice(&read_buf[..n]);

            // Encrypt all complete blocks, keep partial remainder for next iteration
            let full_blocks = (remainder.len() / BLOCK) * BLOCK;
            if full_blocks > 0 {
                for block_data in remainder[..full_blocks].chunks_exact(BLOCK) {
                    encrypt_cbc_block(block_data)?;
                }
                remainder.drain(..full_blocks);
            }
        }

        // Final block(s) with PKCS7 padding
        let pad_len = BLOCK - (remainder.len() % BLOCK);
        remainder.extend(std::iter::repeat_n(pad_len as u8, pad_len));
        for block_data in remainder.chunks_exact(BLOCK) {
            encrypt_cbc_block(block_data)?;
        }
    }

    // Write 10-byte truncated HMAC
    let mac_full = hmac.finalize_sha256_array()?;
    let mac_truncated = &mac_full[..10];
    writer.write_all(mac_truncated)?;
    sha256_enc.update(mac_truncated);

    writer.flush()?;

    let file_sha256 = sha256_plain.finalize_sha256_array()?;
    let file_enc_sha256 = sha256_enc.finalize_sha256_array()?;

    Ok(EncryptedMediaInfo {
        media_key,
        file_sha256,
        file_enc_sha256,
        file_length,
    })
}

/// Encrypt media in memory, returning the encrypted payload and metadata.
///
/// This is a convenience wrapper around [`encrypt_media_streaming`] that
/// buffers the entire ciphertext in a `Vec<u8>`.
pub fn encrypt_media(plaintext: &[u8], media_type: MediaType) -> Result<EncryptedMedia> {
    let mut data_to_upload = Vec::new();
    let info = encrypt_media_streaming(Cursor::new(plaintext), &mut data_to_upload, media_type)?;
    Ok(EncryptedMedia {
        data_to_upload,
        media_key: info.media_key,
        file_sha256: info.file_sha256,
        file_enc_sha256: info.file_enc_sha256,
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
        let cursor = Cursor::new(enc.data_to_upload);
        let plain = DownloadUtils::decrypt_stream(cursor, &enc.media_key, MediaType::Image)
            .expect("media operation should succeed");
        assert_eq!(plain, msg);
    }

    #[test]
    fn streaming_roundtrip() {
        let msg = b"Streaming encryption roundtrip test with enough data to span multiple blocks.";
        let reader = Cursor::new(msg.as_slice());
        let mut encrypted = Vec::new();

        let info = encrypt_media_streaming(reader, &mut encrypted, MediaType::Image)
            .expect("streaming encrypt should succeed");

        assert_eq!(info.file_length, msg.len() as u64);

        // Decrypt and verify roundtrip
        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(encrypted),
            &info.media_key,
            MediaType::Image,
        )
        .expect("decrypt should succeed");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn streaming_matches_buffered() {
        // Verify streaming encryption produces data that can be decrypted,
        // and that hashes are computed correctly.
        let msg = vec![0xABu8; 8192 * 3 + 7]; // non-aligned size spanning multiple chunks
        let reader = Cursor::new(msg.as_slice());
        let mut encrypted = Vec::new();

        let info = encrypt_media_streaming(reader, &mut encrypted, MediaType::Video)
            .expect("streaming encrypt should succeed");

        // Verify plaintext hash
        let expected_sha256 = {
            let mut h = CryptographicHash::new("SHA-256").unwrap();
            h.update(&msg);
            h.finalize_sha256_array().unwrap()
        };
        assert_eq!(info.file_sha256, expected_sha256);

        // Verify encrypted hash matches what we compute from the output
        let actual_enc_sha256 = {
            let mut h = CryptographicHash::new("SHA-256").unwrap();
            h.update(&encrypted);
            h.finalize_sha256_array().unwrap()
        };
        assert_eq!(info.file_enc_sha256, actual_enc_sha256);

        // Verify decrypt roundtrip
        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(encrypted),
            &info.media_key,
            MediaType::Video,
        )
        .expect("decrypt should succeed");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn streaming_empty_input() {
        let reader = Cursor::new(Vec::<u8>::new());
        let mut encrypted = Vec::new();

        let info = encrypt_media_streaming(reader, &mut encrypted, MediaType::Document)
            .expect("streaming encrypt of empty input should succeed");

        assert_eq!(info.file_length, 0);
        // Should have one block of PKCS7 padding + 10-byte MAC
        assert_eq!(encrypted.len(), 16 + 10);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(encrypted),
            &info.media_key,
            MediaType::Document,
        )
        .expect("decrypt should succeed");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn streaming_exact_block_boundary() {
        // Exactly 16 bytes — PKCS7 should add a full padding block
        let msg = vec![0x42u8; 16];
        let reader = Cursor::new(msg.as_slice());
        let mut encrypted = Vec::new();

        let info = encrypt_media_streaming(reader, &mut encrypted, MediaType::Audio)
            .expect("streaming encrypt should succeed");

        assert_eq!(info.file_length, 16);
        // 16 bytes plaintext + 16 bytes padding = 32 bytes ciphertext + 10 MAC
        assert_eq!(encrypted.len(), 32 + 10);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(encrypted),
            &info.media_key,
            MediaType::Audio,
        )
        .expect("decrypt should succeed");
        assert_eq!(decrypted, msg);
    }
}
