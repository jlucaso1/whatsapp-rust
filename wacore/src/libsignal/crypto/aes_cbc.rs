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

pub fn aes_256_cbc_decrypt(
    ctext: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, DecryptionError> {
    if ctext.is_empty() || ctext.len() % 16 != 0 {
        return Err(DecryptionError::BadCiphertext(
            "ciphertext length must be a non-zero multiple of 16",
        ));
    }

    cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|_| DecryptionError::BadKeyOrIv)?
        .decrypt_padded_vec_mut::<Pkcs7>(ctext)
        .map_err(|_| DecryptionError::BadCiphertext("failed to decrypt"))
}
