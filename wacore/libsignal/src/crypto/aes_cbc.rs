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

/// The output buffer is cleared and filled with the decrypted plaintext.
pub fn aes_256_cbc_decrypt_into(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), DecryptionError> {
    if ctext.is_empty() || !ctext.len().is_multiple_of(16) {
        return Err(DecryptionError::BadCiphertext(
            "ciphertext length must be a non-zero multiple of 16",
        ));
    }

    output.clear();
    output.reserve(ctext.len());
    output.extend_from_slice(ctext);

    let decryptor = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| DecryptionError::BadKeyOrIv)?;

    let decrypted = decryptor
        .decrypt_padded_mut::<Pkcs7>(output)
        .map_err(|_| DecryptionError::BadCiphertext("failed to decrypt"))?;

    let decrypted_len = decrypted.len();
    output.truncate(decrypted_len);

    Ok(())
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
}
