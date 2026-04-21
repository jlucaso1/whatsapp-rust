//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::result::Result;

use crate::crypto::provider::provider;

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum EncryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
    /// Padding error during encryption.
    BadPadding,
}

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum DecryptionError {
    /// The key or IV is the wrong length.
    BadKeyOrIv,
    /// These cases should not be distinguished; message corruption can cause either problem.
    BadCiphertext(&'static str),
}

pub fn aes_256_cbc_encrypt_into(
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), EncryptionError> {
    let key: &[u8; 32] = key.try_into().map_err(|_| EncryptionError::BadKeyOrIv)?;
    let iv: &[u8; 16] = iv.try_into().map_err(|_| EncryptionError::BadKeyOrIv)?;
    provider()
        .aes_256_cbc_encrypt(key, iv, ptext, output)
        .map_err(|_| EncryptionError::BadPadding)
}

/// The output buffer is cleared and filled with the decrypted plaintext.
pub fn aes_256_cbc_decrypt_into(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), DecryptionError> {
    let key: &[u8; 32] = key.try_into().map_err(|_| DecryptionError::BadKeyOrIv)?;
    let iv: &[u8; 16] = iv.try_into().map_err(|_| DecryptionError::BadKeyOrIv)?;
    provider()
        .aes_256_cbc_decrypt(key, iv, ctext, output)
        .map_err(|_| DecryptionError::BadCiphertext("failed to decrypt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_into_appends_to_existing_buffer() {
        let plaintext = b"test message";
        let key = [3u8; 32];
        let iv = [4u8; 16];

        let mut buffer = vec![1, 2, 3, 4]; // Pre-existing data
        let initial_len = buffer.len();

        aes_256_cbc_encrypt_into(plaintext, &key, &iv, &mut buffer).expect("Encryption failed");

        // Check that original data is preserved
        assert_eq!(&buffer[..initial_len], &[1, 2, 3, 4]);

        // Check that encrypted data was appended
        let encrypted_part = &buffer[initial_len..];
        let mut decrypted = Vec::new();
        aes_256_cbc_decrypt_into(encrypted_part, &key, &iv, &mut decrypted)
            .expect("Decryption failed");
        assert_eq!(decrypted, plaintext);
    }

    /// Basic encrypt/decrypt roundtrip
    #[test]
    fn test_aes_cbc_roundtrip() {
        let key = [0x42u8; 32];
        let iv = [0x11u8; 16];
        let plaintext = b"hello world, this is a roundtrip test!";

        let mut ciphertext = Vec::new();
        aes_256_cbc_encrypt_into(plaintext, &key, &iv, &mut ciphertext).unwrap();

        // Ciphertext must differ from plaintext
        assert_ne!(&ciphertext[..], &plaintext[..]);

        let mut decrypted = Vec::new();
        aes_256_cbc_decrypt_into(&ciphertext, &key, &iv, &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// NIST AES-256-CBC known-answer vector (from NIST SP 800-38A, Section F.2.5/F.2.6)
    /// Key: 603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
    /// IV:  000102030405060708090a0b0c0d0e0f
    /// Plaintext block 1: 6bc1bee22e409f96e93d7e117393172a
    /// Ciphertext block 1: f58c4c04d6e5f1ba779eabfb5f7bfbd6
    ///
    /// We test a single block here. Because our API uses PKCS7 padding and the NIST
    /// vector does not include padding, we verify only the first ciphertext block.
    #[test]
    fn test_aes_256_cbc_nist_vector() {
        let key: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
            0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3,
            0x09, 0x14, 0xdf, 0xf4,
        ];
        let iv: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93,
            0x17, 0x2a,
        ];
        let expected_ct_block: [u8; 16] = [
            0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b,
            0xfb, 0xd6,
        ];

        let mut ciphertext = Vec::new();
        aes_256_cbc_encrypt_into(&plaintext, &key, &iv, &mut ciphertext).unwrap();

        // Our output has PKCS7 padding (2 blocks), but the first block must match NIST
        assert_eq!(ciphertext.len(), 32, "16-byte input + PKCS7 = 32 bytes");
        assert_eq!(
            &ciphertext[..16],
            &expected_ct_block,
            "First ciphertext block must match NIST vector"
        );

        // Verify full roundtrip
        let mut decrypted = Vec::new();
        aes_256_cbc_decrypt_into(&ciphertext, &key, &iv, &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Empty plaintext produces exactly one padding block (16 bytes)
    #[test]
    fn test_aes_cbc_empty_plaintext() {
        let key = [0x42u8; 32];
        let iv = [0x11u8; 16];

        let mut ciphertext = Vec::new();
        aes_256_cbc_encrypt_into(b"", &key, &iv, &mut ciphertext).unwrap();

        // PKCS7 on empty input adds a full 16-byte padding block
        assert_eq!(ciphertext.len(), 16);

        let mut decrypted = Vec::new();
        aes_256_cbc_decrypt_into(&ciphertext, &key, &iv, &mut decrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    /// Exact block-boundary plaintext (16 bytes) must add a full padding block
    #[test]
    fn test_aes_cbc_exact_block_boundary() {
        let key = [0x42u8; 32];
        let iv = [0x11u8; 16];
        let plaintext = [0xAA; 16]; // exactly one block

        let mut ciphertext = Vec::new();
        aes_256_cbc_encrypt_into(&plaintext, &key, &iv, &mut ciphertext).unwrap();

        // 16 bytes plaintext + 16 bytes PKCS7 padding = 32 bytes
        assert_eq!(ciphertext.len(), 32);

        let mut decrypted = Vec::new();
        aes_256_cbc_decrypt_into(&ciphertext, &key, &iv, &mut decrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Decrypt with wrong key returns error
    #[test]
    fn test_aes_cbc_decrypt_wrong_key() {
        let key = [0x42u8; 32];
        let wrong_key = [0x43u8; 32];
        let iv = [0x11u8; 16];
        let plaintext = b"secret message";

        let mut ciphertext = Vec::new();
        aes_256_cbc_encrypt_into(plaintext, &key, &iv, &mut ciphertext).unwrap();

        let mut decrypted = Vec::new();
        let result = aes_256_cbc_decrypt_into(&ciphertext, &wrong_key, &iv, &mut decrypted);
        assert!(result.is_err());
    }

    /// Decrypt with bad ciphertext length returns error
    #[test]
    fn test_aes_cbc_decrypt_bad_ciphertext_length() {
        let key = [0x42u8; 32];
        let iv = [0x11u8; 16];

        // Empty ciphertext
        let mut output = Vec::new();
        let result = aes_256_cbc_decrypt_into(&[], &key, &iv, &mut output);
        assert!(result.is_err());

        // Non-multiple-of-16 ciphertext
        let bad_ct = vec![0xAA; 15];
        let result = aes_256_cbc_decrypt_into(&bad_ct, &key, &iv, &mut output);
        assert!(result.is_err());

        // Another non-multiple-of-16
        let bad_ct = vec![0xBB; 17];
        let result = aes_256_cbc_decrypt_into(&bad_ct, &key, &iv, &mut output);
        assert!(result.is_err());
    }
}
