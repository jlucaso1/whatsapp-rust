use crate::download::{DownloadUtils, MediaType};
use crate::libsignal::crypto::{CryptographicHash, CryptographicMac};
use aes::Aes256;
use aes::cipher::{Block, BlockEncrypt, KeyInit};
use anyhow::Result;
use rand::RngExt;
use rand::rng;
use std::io::{Cursor, Read, Write};

const BLOCK: usize = 16;

pub struct EncryptedMedia {
    pub data_to_upload: Vec<u8>,
    pub media_key: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_enc_sha256: [u8; 32],
}

pub struct EncryptedMediaInfo {
    pub media_key: [u8; 32],
    pub file_sha256: [u8; 32],
    pub file_enc_sha256: [u8; 32],
    pub file_length: u64,
}

/// Chunk-based AES-256-CBC media encryptor.
///
/// Processes plaintext incrementally without requiring sync `Read`, enabling
/// use with async streams, network sources, or any chunk-at-a-time producer.
///
/// Two output modes (zero duplicated crypto logic):
/// - `update()` / `finalize()` — append to a `Vec<u8>`
/// - `update_to_writer()` / `finalize_to_writer()` — write directly, zero intermediate buffer
#[must_use = "call finalize() or finalize_to_writer() to complete encryption"]
pub struct MediaEncryptor {
    cipher: Aes256,
    hmac: CryptographicMac,
    sha256_plain: CryptographicHash,
    sha256_enc: CryptographicHash,
    prev_block: [u8; BLOCK],
    /// Partial plaintext that didn't fill a complete AES block (≤15 bytes).
    remainder: Vec<u8>,
    media_key: [u8; 32],
    file_length: u64,
}

impl MediaEncryptor {
    /// Initialize with a random media key.
    pub fn new(media_type: MediaType) -> Result<Self> {
        let mut media_key = [0u8; 32];
        rng().fill(&mut media_key);
        Self::with_key(media_key, media_type)
    }

    /// Initialize with a caller-supplied key. The key must be 32
    /// cryptographically random bytes; reusing keys breaks confidentiality.
    pub fn with_key(media_key: [u8; 32], media_type: MediaType) -> Result<Self> {
        let (iv, cipher_key, mac_key) = DownloadUtils::get_media_keys(&media_key, media_type)?;
        let cipher =
            Aes256::new_from_slice(&cipher_key).map_err(|_| anyhow::anyhow!("Bad AES key"))?;
        let mut hmac = CryptographicMac::new("HmacSha256", &mac_key)?;
        hmac.update(&iv);

        Ok(Self {
            cipher,
            hmac,
            sha256_plain: CryptographicHash::new("SHA-256")?,
            sha256_enc: CryptographicHash::new("SHA-256")?,
            prev_block: iv,
            remainder: Vec::with_capacity(BLOCK),
            media_key,
            file_length: 0,
        })
    }

    /// Feed plaintext, append encrypted blocks to `out`.
    pub fn update(&mut self, plaintext: &[u8], out: &mut Vec<u8>) {
        self.feed(plaintext, |block| out.extend_from_slice(block));
    }

    /// Feed plaintext, write encrypted blocks directly to `writer`.
    ///
    /// On error the encryptor state is unspecified — discard it.
    pub fn update_to_writer<W: Write>(
        &mut self,
        plaintext: &[u8],
        writer: &mut W,
    ) -> std::io::Result<()> {
        let mut err = Ok(());
        self.feed(plaintext, |block| {
            if err.is_ok() {
                err = writer.write_all(block);
            }
        });
        err
    }

    /// PKCS7 pad + 10-byte MAC. Appends final bytes to `out`.
    pub fn finalize(mut self, out: &mut Vec<u8>) -> Result<EncryptedMediaInfo> {
        self.pad_and_encrypt(|block| out.extend_from_slice(block));
        let mac = self.compute_mac()?;
        out.extend_from_slice(&mac);
        self.finish_hashes(&mac)
    }

    /// PKCS7 pad + 10-byte MAC. Writes directly to `writer`.
    pub fn finalize_to_writer<W: Write>(mut self, writer: &mut W) -> Result<EncryptedMediaInfo> {
        let mut io_err: std::io::Result<()> = Ok(());
        self.pad_and_encrypt(|block| {
            if io_err.is_ok() {
                io_err = writer.write_all(block);
            }
        });
        io_err?;

        let mac = self.compute_mac()?;
        writer.write_all(&mac)?;
        self.finish_hashes(&mac)
    }

    /// Hash plaintext, then encrypt complete blocks directly from the input
    /// without copying everything into `remainder` first. Only the trailing
    /// partial block (≤15 bytes) is buffered.
    fn feed(&mut self, plaintext: &[u8], mut emit: impl FnMut(&[u8; BLOCK])) {
        self.sha256_plain.update(plaintext);
        self.file_length += plaintext.len() as u64;

        // If there's leftover from the previous call, try to complete a block.
        let input = if !self.remainder.is_empty() {
            let need = BLOCK - self.remainder.len();
            if plaintext.len() < need {
                // Not enough to complete a block — just buffer.
                self.remainder.extend_from_slice(plaintext);
                return;
            }
            // Complete the partial block from remainder + head of plaintext.
            self.remainder.extend_from_slice(&plaintext[..need]);
            self.encrypt_and_emit(&self.remainder.clone(), &mut emit);
            self.remainder.clear();
            &plaintext[need..]
        } else {
            plaintext
        };

        // Process full blocks directly from input (no copy).
        let full = (input.len() / BLOCK) * BLOCK;
        if full > 0 {
            self.encrypt_and_emit(&input[..full], &mut emit);
        }

        // Buffer the leftover tail.
        let tail = &input[full..];
        if !tail.is_empty() {
            self.remainder.extend_from_slice(tail);
        }
    }

    /// Encrypt one or more complete blocks from `data` and emit each.
    fn encrypt_and_emit(&mut self, data: &[u8], emit: &mut impl FnMut(&[u8; BLOCK])) {
        debug_assert!(data.len().is_multiple_of(BLOCK));
        for chunk in data.chunks_exact(BLOCK) {
            self.cbc_encrypt(chunk.try_into().unwrap());
            emit(&self.prev_block);
            self.hmac.update(&self.prev_block);
            self.sha256_enc.update(&self.prev_block);
        }
    }

    fn pad_and_encrypt(&mut self, mut emit: impl FnMut(&[u8; BLOCK])) {
        let pad_len = BLOCK - (self.remainder.len() % BLOCK);
        self.remainder
            .extend(std::iter::repeat_n(pad_len as u8, pad_len));
        let rem = std::mem::take(&mut self.remainder);
        self.encrypt_and_emit(&rem, &mut emit);
    }

    fn cbc_encrypt(&mut self, block_data: &[u8; BLOCK]) {
        let mut data = *block_data;
        for (b, &p) in data.iter_mut().zip(self.prev_block.iter()) {
            *b ^= p;
        }
        let mut block: Block<Aes256> = data.into();
        self.cipher.encrypt_block(&mut block);
        self.prev_block = block.into();
    }

    fn compute_mac(&mut self) -> Result<[u8; 10]> {
        let mac_full = self.hmac.finalize_sha256_array()?;
        let mut mac = [0u8; 10];
        mac.copy_from_slice(&mac_full[..10]);
        Ok(mac)
    }

    fn finish_hashes(mut self, mac: &[u8; 10]) -> Result<EncryptedMediaInfo> {
        self.sha256_enc.update(mac);
        Ok(EncryptedMediaInfo {
            media_key: self.media_key,
            file_sha256: self.sha256_plain.finalize_sha256_array()?,
            file_enc_sha256: self.sha256_enc.finalize_sha256_array()?,
            file_length: self.file_length,
        })
    }
}

/// Encrypt media streaming with constant memory.
pub fn encrypt_media_streaming<R: Read, W: Write>(
    mut reader: R,
    mut writer: W,
    media_type: MediaType,
) -> Result<EncryptedMediaInfo> {
    let mut enc = MediaEncryptor::new(media_type)?;
    let mut buf = [0u8; 8 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        enc.update_to_writer(&buf[..n], &mut writer)?;
    }
    let info = enc.finalize_to_writer(&mut writer)?;
    writer.flush()?;
    Ok(info)
}

/// Encrypt media in memory.
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
        let enc = encrypt_media(msg, MediaType::Image).expect("encrypt");
        let plain = DownloadUtils::decrypt_stream(
            Cursor::new(enc.data_to_upload),
            &enc.media_key,
            MediaType::Image,
        )
        .expect("decrypt");
        assert_eq!(plain, msg);
    }

    #[test]
    fn streaming_roundtrip() {
        let msg = b"Streaming encryption roundtrip test with enough data to span multiple blocks.";
        let mut encrypted = Vec::new();
        let info = encrypt_media_streaming(
            Cursor::new(msg.as_slice()),
            &mut encrypted,
            MediaType::Image,
        )
        .expect("encrypt");

        assert_eq!(info.file_length, msg.len() as u64);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(encrypted),
            &info.media_key,
            MediaType::Image,
        )
        .expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn streaming_matches_buffered() {
        let msg = vec![0xABu8; 8192 * 3 + 7];
        let mut encrypted = Vec::new();
        let info = encrypt_media_streaming(
            Cursor::new(msg.as_slice()),
            &mut encrypted,
            MediaType::Video,
        )
        .expect("encrypt");

        let expected_sha256 = {
            let mut h = CryptographicHash::new("SHA-256").unwrap();
            h.update(&msg);
            h.finalize_sha256_array().unwrap()
        };
        assert_eq!(info.file_sha256, expected_sha256);

        let actual_enc_sha256 = {
            let mut h = CryptographicHash::new("SHA-256").unwrap();
            h.update(&encrypted);
            h.finalize_sha256_array().unwrap()
        };
        assert_eq!(info.file_enc_sha256, actual_enc_sha256);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(encrypted),
            &info.media_key,
            MediaType::Video,
        )
        .expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn streaming_empty_input() {
        let mut encrypted = Vec::new();
        let info = encrypt_media_streaming(
            Cursor::new(Vec::<u8>::new()),
            &mut encrypted,
            MediaType::Document,
        )
        .expect("encrypt");

        assert_eq!(info.file_length, 0);
        assert_eq!(encrypted.len(), 16 + 10);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(encrypted),
            &info.media_key,
            MediaType::Document,
        )
        .expect("decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn streaming_exact_block_boundary() {
        let msg = vec![0x42u8; 16];
        let mut encrypted = Vec::new();
        let info = encrypt_media_streaming(
            Cursor::new(msg.as_slice()),
            &mut encrypted,
            MediaType::Audio,
        )
        .expect("encrypt");

        assert_eq!(encrypted.len(), 32 + 10);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(encrypted),
            &info.media_key,
            MediaType::Audio,
        )
        .expect("decrypt");
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn media_encryptor_chunk_api() {
        let msg = b"Test the chunk-based MediaEncryptor API directly.";
        let mut enc = MediaEncryptor::new(MediaType::Image).unwrap();

        let mut all_encrypted = Vec::new();
        for chunk in msg.chunks(7) {
            enc.update(chunk, &mut all_encrypted);
        }
        let info = enc.finalize(&mut all_encrypted).unwrap();

        assert_eq!(info.file_length, msg.len() as u64);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(all_encrypted),
            &info.media_key,
            MediaType::Image,
        )
        .expect("decrypt");
        assert_eq!(decrypted, msg.as_slice());
    }

    #[test]
    fn media_encryptor_single_byte_chunks() {
        let msg = b"One byte at a time to stress the remainder logic.";
        let mut enc = MediaEncryptor::new(MediaType::Document).unwrap();

        let mut all_encrypted = Vec::new();
        for &byte in msg.iter() {
            enc.update(&[byte], &mut all_encrypted);
        }
        let info = enc.finalize(&mut all_encrypted).unwrap();

        assert_eq!(info.file_length, msg.len() as u64);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(all_encrypted),
            &info.media_key,
            MediaType::Document,
        )
        .expect("decrypt");
        assert_eq!(decrypted, msg.as_slice());
    }

    #[test]
    fn media_encryptor_large_single_chunk() {
        let msg = vec![0xCDu8; 1024 * 1024]; // 1MB in one call
        let mut enc = MediaEncryptor::new(MediaType::Video).unwrap();

        let mut all_encrypted = Vec::new();
        enc.update(&msg, &mut all_encrypted);
        let info = enc.finalize(&mut all_encrypted).unwrap();

        assert_eq!(info.file_length, msg.len() as u64);

        let decrypted = DownloadUtils::decrypt_stream(
            Cursor::new(all_encrypted),
            &info.media_key,
            MediaType::Video,
        )
        .expect("decrypt");
        assert_eq!(decrypted, msg);
    }
}
