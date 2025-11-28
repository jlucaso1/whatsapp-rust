//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use aes::Aes256;
use aes::cipher::typenum::Unsigned;
use aes::cipher::{InnerIvInit, KeyInit, StreamCipher, StreamCipherSeek};

use crate::crypto::{Error, Result};

/// A wrapper around [`ctr::Ctr32BE`] that uses a smaller nonce and supports an initial counter.
pub struct Aes256Ctr32(ctr::Ctr32BE<Aes256>);

impl Aes256Ctr32 {
    pub const NONCE_SIZE: usize = <Aes256 as aes::cipher::BlockSizeUser>::BlockSize::USIZE - 4;

    pub fn new(aes256: Aes256, nonce: &[u8], init_ctr: u32) -> Result<Self> {
        if nonce.len() != Self::NONCE_SIZE {
            return Err(Error::InvalidNonceSize);
        }

        let mut nonce_block = [0u8; <Aes256 as aes::cipher::BlockSizeUser>::BlockSize::USIZE];
        nonce_block[0..Self::NONCE_SIZE].copy_from_slice(nonce);

        let mut ctr =
            ctr::Ctr32BE::from_core(ctr::CtrCore::inner_iv_init(aes256, &nonce_block.into()));
        ctr.seek(
            (<Aes256 as aes::cipher::BlockSizeUser>::BlockSize::USIZE as u64) * (init_ctr as u64),
        );

        Ok(Self(ctr))
    }

    pub fn from_key(key: &[u8], nonce: &[u8], init_ctr: u32) -> Result<Self> {
        Self::new(
            Aes256::new_from_slice(key).map_err(|_| Error::InvalidKeySize)?,
            nonce,
            init_ctr,
        )
    }

    pub fn process(&mut self, buf: &mut [u8]) {
        self.0.apply_keystream(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::KeyInit;

    /// Test AES-256-CTR encryption and decryption roundtrip
    #[test]
    fn test_aes_ctr_roundtrip() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; Aes256Ctr32::NONCE_SIZE];
        let plaintext = b"hello world, this is a test message";

        // Encrypt
        let mut ciphertext = plaintext.to_vec();
        let mut enc = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
        enc.process(&mut ciphertext);

        // Verify ciphertext is different from plaintext
        assert_ne!(&ciphertext[..], &plaintext[..]);

        // Decrypt (CTR mode is symmetric)
        let mut decrypted = ciphertext.clone();
        let mut dec = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
        dec.process(&mut decrypted);

        // Verify decrypted matches original plaintext
        assert_eq!(&decrypted[..], &plaintext[..]);
    }

    /// Test that different keys produce different ciphertext
    #[test]
    fn test_aes_ctr_different_keys() {
        let key1 = [0x42u8; 32];
        let key2 = [0x43u8; 32];
        let nonce = [0x11u8; Aes256Ctr32::NONCE_SIZE];
        let plaintext = b"test message";

        let mut ct1 = plaintext.to_vec();
        let mut enc1 = Aes256Ctr32::from_key(&key1, &nonce, 0).unwrap();
        enc1.process(&mut ct1);

        let mut ct2 = plaintext.to_vec();
        let mut enc2 = Aes256Ctr32::from_key(&key2, &nonce, 0).unwrap();
        enc2.process(&mut ct2);

        assert_ne!(ct1, ct2);
    }

    /// Test that different nonces produce different ciphertext
    #[test]
    fn test_aes_ctr_different_nonces() {
        let key = [0x42u8; 32];
        let nonce1 = [0x11u8; Aes256Ctr32::NONCE_SIZE];
        let nonce2 = [0x22u8; Aes256Ctr32::NONCE_SIZE];
        let plaintext = b"test message";

        let mut ct1 = plaintext.to_vec();
        let mut enc1 = Aes256Ctr32::from_key(&key, &nonce1, 0).unwrap();
        enc1.process(&mut ct1);

        let mut ct2 = plaintext.to_vec();
        let mut enc2 = Aes256Ctr32::from_key(&key, &nonce2, 0).unwrap();
        enc2.process(&mut ct2);

        assert_ne!(ct1, ct2);
    }

    /// Test that different initial counters produce different ciphertext
    #[test]
    fn test_aes_ctr_different_counters() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; Aes256Ctr32::NONCE_SIZE];
        let plaintext = b"test message";

        let mut ct1 = plaintext.to_vec();
        let mut enc1 = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
        enc1.process(&mut ct1);

        let mut ct2 = plaintext.to_vec();
        let mut enc2 = Aes256Ctr32::from_key(&key, &nonce, 1).unwrap();
        enc2.process(&mut ct2);

        assert_ne!(ct1, ct2);
    }

    /// Test invalid nonce size rejection
    #[test]
    fn test_aes_ctr_invalid_nonce_size() {
        let key = [0x42u8; 32];
        let bad_nonce = [0x11u8; 8]; // Should be 12

        let result = Aes256Ctr32::from_key(&key, &bad_nonce, 0);
        assert!(result.is_err());
    }

    /// Test invalid key size rejection
    #[test]
    fn test_aes_ctr_invalid_key_size() {
        let bad_key = [0x42u8; 16]; // Should be 32
        let nonce = [0x11u8; Aes256Ctr32::NONCE_SIZE];

        let result = Aes256Ctr32::from_key(&bad_key, &nonce, 0);
        assert!(result.is_err());
    }

    /// Test empty input
    #[test]
    fn test_aes_ctr_empty_input() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; Aes256Ctr32::NONCE_SIZE];

        let mut empty: Vec<u8> = vec![];
        let mut ctr = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
        ctr.process(&mut empty);

        assert!(empty.is_empty());
    }

    /// Test streaming encryption (multiple process calls)
    #[test]
    fn test_aes_ctr_streaming() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; Aes256Ctr32::NONCE_SIZE];
        let plaintext = b"first part second part third part";

        // Encrypt all at once
        let mut ct_all = plaintext.to_vec();
        let mut enc_all = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
        enc_all.process(&mut ct_all);

        // Encrypt in chunks
        let mut chunk1 = b"first part ".to_vec();
        let mut chunk2 = b"second part ".to_vec();
        let mut chunk3 = b"third part".to_vec();

        let mut enc_stream = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
        enc_stream.process(&mut chunk1);
        enc_stream.process(&mut chunk2);
        enc_stream.process(&mut chunk3);

        // Combine chunks
        let mut ct_chunks: Vec<u8> = Vec::new();
        ct_chunks.extend_from_slice(&chunk1);
        ct_chunks.extend_from_slice(&chunk2);
        ct_chunks.extend_from_slice(&chunk3);

        // Results should be identical
        assert_eq!(ct_all, ct_chunks);
    }

    /// Test with pre-initialized Aes256
    #[test]
    fn test_aes_ctr_with_aes_instance() {
        let key = [0x42u8; 32];
        let nonce = [0x11u8; Aes256Ctr32::NONCE_SIZE];
        let plaintext = b"test message";

        let aes256 = Aes256::new_from_slice(&key).unwrap();
        let mut ctr = Aes256Ctr32::new(aes256, &nonce, 0).unwrap();

        let mut ciphertext = plaintext.to_vec();
        ctr.process(&mut ciphertext);

        // Compare with from_key version
        let mut ct2 = plaintext.to_vec();
        let mut ctr2 = Aes256Ctr32::from_key(&key, &nonce, 0).unwrap();
        ctr2.process(&mut ct2);

        assert_eq!(ciphertext, ct2);
    }
}
