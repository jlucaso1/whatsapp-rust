//
// Copyright 2023 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::result::Result;

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};

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

pub fn aes_256_cbc_encrypt(
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, EncryptionError> {
    Ok(cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| EncryptionError::BadKeyOrIv)?
        .encrypt_padded_vec_mut::<Pkcs7>(ptext))
}

pub fn aes_256_cbc_encrypt_into(
    ptext: &[u8],
    key: &[u8],
    iv: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), EncryptionError> {
    // Calculate the space needed for encryption + PKCS7 padding
    // PKCS7 padding can add 1-16 bytes (always adds at least 1 byte)
    let padding_needed = 16 - (ptext.len() % 16);
    let encrypted_size = ptext.len() + padding_needed;

    let start_pos = output.len();

    // Reserve space for the encrypted data
    output.resize(start_pos + encrypted_size, 0);

    // Copy plaintext to the buffer
    output[start_pos..start_pos + ptext.len()].copy_from_slice(ptext);

    // Create encryptor and encrypt in place
    let encryptor = cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| EncryptionError::BadKeyOrIv)?;

    // Encrypt the data in place with proper padding
    let encrypted_len = {
        let encrypted_slice = encryptor
            .encrypt_padded_mut::<Pkcs7>(&mut output[start_pos..], ptext.len())
            .map_err(|_| EncryptionError::BadPadding)?;
        encrypted_slice.len()
    };

    // Resize to actual encrypted length
    output.truncate(start_pos + encrypted_len);

    Ok(())
}

pub fn aes_256_cbc_decrypt(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if ctext.is_empty() || !ctext.len().is_multiple_of(16) {
        return Err(DecryptionError::BadCiphertext(
            "ciphertext length must be a non-zero multiple of 16",
        ));
    }

    cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| DecryptionError::BadKeyOrIv)?
        .decrypt_padded_vec_mut::<Pkcs7>(ctext)
        .map_err(|_| DecryptionError::BadCiphertext("failed to decrypt"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_into_matches_original() {
        // Test data
        let test_cases = vec![
            b"".to_vec(),                                            // Empty
            b"a".to_vec(),                                           // Single byte
            b"hello world".to_vec(),                                 // Short message
            b"0123456789abcdef".to_vec(),                            // Exactly 16 bytes
            b"0123456789abcdef0".to_vec(),                           // 17 bytes (padding edge case)
            b"The quick brown fox jumps over the lazy dog".to_vec(), // Longer message
        ];

        let key = [0u8; 32]; // 256-bit key
        let iv = [0u8; 16]; // 128-bit IV

        for (i, plaintext) in test_cases.iter().enumerate() {
            // Test original function
            let original_result = aes_256_cbc_encrypt(plaintext, &key, &iv)
                .expect(&format!("Original encrypt failed for test case {}", i));

            // Test new buffer reuse function
            let mut buffer = Vec::new();
            aes_256_cbc_encrypt_into(plaintext, &key, &iv, &mut buffer)
                .expect(&format!("Buffer encrypt failed for test case {}", i));

            // Results should be identical
            assert_eq!(
                original_result,
                buffer,
                "Encryption results don't match for test case {} (length: {})",
                i,
                plaintext.len()
            );

            // Test that both can be decrypted to same plaintext
            let decrypted1 = aes_256_cbc_decrypt(&original_result, &key, &iv).expect(&format!(
                "Failed to decrypt original result for test case {}",
                i
            ));
            let decrypted2 = aes_256_cbc_decrypt(&buffer, &key, &iv).expect(&format!(
                "Failed to decrypt buffer result for test case {}",
                i
            ));

            assert_eq!(
                decrypted1, *plaintext,
                "Original decrypt doesn't match plaintext for test case {}",
                i
            );
            assert_eq!(
                decrypted2, *plaintext,
                "Buffer decrypt doesn't match plaintext for test case {}",
                i
            );
        }
    }

    #[test]
    fn test_encrypt_into_buffer_reuse() {
        let plaintext1 = b"first message";
        let plaintext2 = b"second message that is longer";
        let key = [1u8; 32];
        let iv = [2u8; 16];

        let mut buffer = Vec::new();

        // First encryption
        aes_256_cbc_encrypt_into(plaintext1, &key, &iv, &mut buffer)
            .expect("First encryption failed");
        let first_result = buffer.clone();

        // Second encryption should reuse buffer
        buffer.clear();
        aes_256_cbc_encrypt_into(plaintext2, &key, &iv, &mut buffer)
            .expect("Second encryption failed");
        let second_result = buffer.clone();

        // Verify both results decrypt correctly
        let decrypted1 =
            aes_256_cbc_decrypt(&first_result, &key, &iv).expect("Failed to decrypt first result");
        let decrypted2 = aes_256_cbc_decrypt(&second_result, &key, &iv)
            .expect("Failed to decrypt second result");

        assert_eq!(decrypted1, plaintext1);
        assert_eq!(decrypted2, plaintext2);
    }

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
        let decrypted = aes_256_cbc_decrypt(encrypted_part, &key, &iv).expect("Failed to decrypt");
        assert_eq!(decrypted, plaintext);
    }
}
