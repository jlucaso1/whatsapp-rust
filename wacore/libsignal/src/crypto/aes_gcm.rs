//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes::Aes256;
#[allow(deprecated)]
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use ghash::GHash;
use ghash::universal_hash::UniversalHash;
use subtle::ConstantTimeEq;

use crate::crypto::{Aes256Ctr32, Error, Result};

pub const TAG_SIZE: usize = 16;
pub const NONCE_SIZE: usize = 12;

#[derive(Clone)]
struct GcmGhash {
    ghash: GHash,
    ghash_pad: [u8; TAG_SIZE],
    msg_buf: [u8; TAG_SIZE],
    msg_buf_offset: usize,
    ad_len: usize,
    msg_len: usize,
}

impl GcmGhash {
    fn new(h: &[u8; TAG_SIZE], ghash_pad: [u8; TAG_SIZE], associated_data: &[u8]) -> Result<Self> {
        let mut ghash = GHash::new(h.into());

        ghash.update_padded(associated_data);

        Ok(Self {
            ghash,
            ghash_pad,
            msg_buf: [0u8; TAG_SIZE],
            msg_buf_offset: 0,
            ad_len: associated_data.len(),
            msg_len: 0,
        })
    }

    fn update(&mut self, msg: &[u8]) {
        if self.msg_buf_offset > 0 {
            let taking = std::cmp::min(msg.len(), TAG_SIZE - self.msg_buf_offset);
            self.msg_buf[self.msg_buf_offset..self.msg_buf_offset + taking]
                .copy_from_slice(&msg[..taking]);
            self.msg_buf_offset += taking;
            assert!(self.msg_buf_offset <= TAG_SIZE);

            self.msg_len += taking;

            if self.msg_buf_offset == TAG_SIZE {
                #[allow(deprecated)]
                self.ghash
                    .update(std::slice::from_ref(ghash::Block::from_slice(
                        &self.msg_buf,
                    )));
                self.msg_buf_offset = 0;
                return self.update(&msg[taking..]);
            } else {
                return;
            }
        }

        self.msg_len += msg.len();

        assert_eq!(self.msg_buf_offset, 0);
        let full_blocks = msg.len() / 16;
        let leftover = msg.len() - 16 * full_blocks;
        assert!(leftover < TAG_SIZE);

        let (chunks, _) = msg[..16 * full_blocks].as_chunks::<16>();
        for chunk in chunks {
            #[allow(deprecated)]
            self.ghash
                .update(std::slice::from_ref(ghash::Block::from_slice(chunk)));
        }

        self.msg_buf[0..leftover].copy_from_slice(&msg[full_blocks * 16..]);
        self.msg_buf_offset = leftover;
        assert!(self.msg_buf_offset < TAG_SIZE);
    }

    fn finalize(mut self) -> [u8; TAG_SIZE] {
        if self.msg_buf_offset > 0 {
            self.ghash
                .update_padded(&self.msg_buf[..self.msg_buf_offset]);
        }

        let mut final_block = [0u8; 16];
        final_block[..8].copy_from_slice(&(8 * self.ad_len as u64).to_be_bytes());
        final_block[8..].copy_from_slice(&(8 * self.msg_len as u64).to_be_bytes());

        self.ghash.update(&[final_block.into()]);
        let mut hash = self.ghash.finalize();

        for (i, b) in hash.iter_mut().enumerate() {
            *b ^= self.ghash_pad[i];
        }

        hash.into()
    }
}

fn setup_gcm(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<(Aes256Ctr32, GcmGhash)> {
    /*
    GCM supports other sizes but 12 bytes is standard and other
    sizes require special handling
     */
    if nonce.len() != NONCE_SIZE {
        return Err(Error::InvalidNonceSize);
    }

    let aes256 = Aes256::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?;
    let mut h = [0u8; TAG_SIZE];
    #[allow(deprecated)]
    aes256.encrypt_block(GenericArray::from_mut_slice(&mut h));

    let mut ctr = Aes256Ctr32::new(aes256, nonce, 1)?;

    let mut ghash_pad = [0u8; 16];
    ctr.process(&mut ghash_pad);

    let ghash = GcmGhash::new(&h, ghash_pad, associated_data)?;
    Ok((ctr, ghash))
}

pub struct Aes256GcmEncryption {
    ctr: Aes256Ctr32,
    ghash: GcmGhash,
}

impl Aes256GcmEncryption {
    pub const TAG_SIZE: usize = TAG_SIZE;
    pub const NONCE_SIZE: usize = NONCE_SIZE;

    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self> {
        let (ctr, ghash) = setup_gcm(key, nonce, associated_data)?;
        Ok(Self { ctr, ghash })
    }

    pub fn encrypt(&mut self, buf: &mut [u8]) {
        self.ctr.process(buf);
        self.ghash.update(buf);
    }

    pub fn compute_tag(self) -> [u8; TAG_SIZE] {
        self.ghash.finalize()
    }
}

pub struct Aes256GcmDecryption {
    ctr: Aes256Ctr32,
    ghash: GcmGhash,
}

impl Aes256GcmDecryption {
    pub const TAG_SIZE: usize = TAG_SIZE;
    pub const NONCE_SIZE: usize = NONCE_SIZE;

    pub fn new(key: &[u8], nonce: &[u8], associated_data: &[u8]) -> Result<Self> {
        let (ctr, ghash) = setup_gcm(key, nonce, associated_data)?;
        Ok(Self { ctr, ghash })
    }

    pub fn decrypt(&mut self, buf: &mut [u8]) {
        self.ghash.update(buf);
        self.ctr.process(buf);
    }

    pub fn verify_tag(self, tag: &[u8]) -> Result<()> {
        if tag.len() != TAG_SIZE {
            return Err(Error::InvalidTag);
        }

        let computed_tag = self.ghash.finalize();

        let tag_ok = tag.ct_eq(&computed_tag);

        if !bool::from(tag_ok) {
            return Err(Error::InvalidTag);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test AES-256-GCM encryption and decryption roundtrip
    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"additional authenticated data";
        let plaintext = b"hello world, this is a test message";

        // Encrypt
        let mut ciphertext = plaintext.to_vec();
        let mut enc = Aes256GcmEncryption::new(&key, &nonce, aad).unwrap();
        enc.encrypt(&mut ciphertext);
        let tag = enc.compute_tag();

        // Verify ciphertext is different from plaintext
        assert_ne!(&ciphertext[..], &plaintext[..]);

        // Decrypt
        let mut decrypted = ciphertext.clone();
        let mut dec = Aes256GcmDecryption::new(&key, &nonce, aad).unwrap();
        dec.decrypt(&mut decrypted);
        dec.verify_tag(&tag).unwrap();

        // Verify decrypted matches original plaintext
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    /// Test that different keys produce different ciphertext
    #[test]
    fn test_aes_gcm_different_keys() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"aad";
        let plaintext = b"test message";

        let mut ct1 = plaintext.to_vec();
        let mut enc1 = Aes256GcmEncryption::new(&key1, &nonce, aad).unwrap();
        enc1.encrypt(&mut ct1);
        let tag1 = enc1.compute_tag();

        let mut ct2 = plaintext.to_vec();
        let mut enc2 = Aes256GcmEncryption::new(&key2, &nonce, aad).unwrap();
        enc2.encrypt(&mut ct2);
        let tag2 = enc2.compute_tag();

        assert_ne!(ct1, ct2);
        assert_ne!(tag1, tag2);
    }

    /// Test that different nonces produce different ciphertext
    #[test]
    fn test_aes_gcm_different_nonces() {
        let key = [0x42u8; 32];
        let nonce1 = [0x11u8; NONCE_SIZE];
        let nonce2 = [0x22u8; NONCE_SIZE];
        let aad = b"aad";
        let plaintext = b"test message";

        let mut ct1 = plaintext.to_vec();
        let mut enc1 = Aes256GcmEncryption::new(&key, &nonce1, aad).unwrap();
        enc1.encrypt(&mut ct1);

        let mut ct2 = plaintext.to_vec();
        let mut enc2 = Aes256GcmEncryption::new(&key, &nonce2, aad).unwrap();
        enc2.encrypt(&mut ct2);

        assert_ne!(ct1, ct2);
    }

    /// Test that tampering with AAD causes tag verification failure
    #[test]
    fn test_aes_gcm_aad_integrity() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"original aad";
        let wrong_aad = b"tampered aad";
        let plaintext = b"secret message";

        // Encrypt with original AAD
        let mut ciphertext = plaintext.to_vec();
        let mut enc = Aes256GcmEncryption::new(&key, &nonce, aad).unwrap();
        enc.encrypt(&mut ciphertext);
        let tag = enc.compute_tag();

        // Try to decrypt with wrong AAD
        let mut decrypted = ciphertext.clone();
        let mut dec = Aes256GcmDecryption::new(&key, &nonce, wrong_aad).unwrap();
        dec.decrypt(&mut decrypted);
        let result = dec.verify_tag(&tag);

        assert!(result.is_err());
    }

    /// Test that tampering with ciphertext causes tag verification failure
    #[test]
    fn test_aes_gcm_ciphertext_integrity() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"aad";
        let plaintext = b"secret message";

        // Encrypt
        let mut ciphertext = plaintext.to_vec();
        let mut enc = Aes256GcmEncryption::new(&key, &nonce, aad).unwrap();
        enc.encrypt(&mut ciphertext);
        let tag = enc.compute_tag();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xFF;

        // Try to verify
        let mut dec = Aes256GcmDecryption::new(&key, &nonce, aad).unwrap();
        dec.decrypt(&mut ciphertext);
        let result = dec.verify_tag(&tag);

        assert!(result.is_err());
    }

    /// Test invalid tag size rejection
    #[test]
    fn test_aes_gcm_invalid_tag_size() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"aad";
        let plaintext = b"message";

        let mut ciphertext = plaintext.to_vec();
        let mut enc = Aes256GcmEncryption::new(&key, &nonce, aad).unwrap();
        enc.encrypt(&mut ciphertext);

        // Try with wrong tag size
        let wrong_tag = [0u8; 8]; // Should be 16

        let mut dec = Aes256GcmDecryption::new(&key, &nonce, aad).unwrap();
        dec.decrypt(&mut ciphertext);
        let result = dec.verify_tag(&wrong_tag);

        assert!(result.is_err());
    }

    /// Test invalid nonce size rejection
    #[test]
    fn test_aes_gcm_invalid_nonce_size() {
        let key = [0x42u8; 32];
        let bad_nonce = [0x11u8; 8]; // Should be 12
        let aad = b"aad";

        let result = Aes256GcmEncryption::new(&key, &bad_nonce, aad);
        assert!(result.is_err());
    }

    /// Test invalid key size rejection
    #[test]
    fn test_aes_gcm_invalid_key_size() {
        let bad_key = [0x42u8; 16]; // Should be 32
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"aad";

        let result = Aes256GcmEncryption::new(&bad_key, &nonce, aad);
        assert!(result.is_err());
    }

    /// Test empty plaintext
    #[test]
    fn test_aes_gcm_empty_plaintext() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"aad";
        let plaintext = b"";

        let mut ciphertext = plaintext.to_vec();
        let mut enc = Aes256GcmEncryption::new(&key, &nonce, aad).unwrap();
        enc.encrypt(&mut ciphertext);
        let tag = enc.compute_tag();

        // Empty ciphertext
        assert!(ciphertext.is_empty());

        // But tag should still be valid
        let mut dec = Aes256GcmDecryption::new(&key, &nonce, aad).unwrap();
        dec.decrypt(&mut ciphertext);
        dec.verify_tag(&tag).unwrap();
    }

    /// Test empty AAD
    #[test]
    fn test_aes_gcm_empty_aad() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"";
        let plaintext = b"message";

        let mut ciphertext = plaintext.to_vec();
        let mut enc = Aes256GcmEncryption::new(&key, &nonce, aad).unwrap();
        enc.encrypt(&mut ciphertext);
        let tag = enc.compute_tag();

        let mut decrypted = ciphertext.clone();
        let mut dec = Aes256GcmDecryption::new(&key, &nonce, aad).unwrap();
        dec.decrypt(&mut decrypted);
        dec.verify_tag(&tag).unwrap();

        assert_eq!(&decrypted[..], plaintext);
    }

    /// Test chunked encryption (multiple encrypt calls)
    #[test]
    fn test_aes_gcm_chunked_encryption() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; NONCE_SIZE];
        let aad = b"aad";
        let plaintext = b"first part second part third part";

        // Encrypt in chunks
        let mut chunk1 = b"first part ".to_vec();
        let mut chunk2 = b"second part ".to_vec();
        let mut chunk3 = b"third part".to_vec();

        let mut enc = Aes256GcmEncryption::new(&key, &nonce, aad).unwrap();
        enc.encrypt(&mut chunk1);
        enc.encrypt(&mut chunk2);
        enc.encrypt(&mut chunk3);
        let tag = enc.compute_tag();

        // Combine chunks
        let mut combined_ct: Vec<u8> = Vec::new();
        combined_ct.extend_from_slice(&chunk1);
        combined_ct.extend_from_slice(&chunk2);
        combined_ct.extend_from_slice(&chunk3);

        // Decrypt all at once
        let mut dec = Aes256GcmDecryption::new(&key, &nonce, aad).unwrap();
        dec.decrypt(&mut combined_ct);
        dec.verify_tag(&tag).unwrap();

        assert_eq!(&combined_ct[..], plaintext);
    }
}
