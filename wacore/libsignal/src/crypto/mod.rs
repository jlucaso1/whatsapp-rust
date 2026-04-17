//
// Copyright 2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

mod error;
mod hash;

mod aes_cbc;
mod aes_ctr;
pub(crate) mod aes_gcm;
mod provider;

pub use aes_cbc::{
    DecryptionError, EncryptionError, aes_256_cbc_decrypt_into, aes_256_cbc_encrypt_into,
};
pub use aes_ctr::Aes256Ctr32;
pub use aes_gcm::{Aes256GcmDecryption, Aes256GcmEncryption};
pub use error::{Error, Result};
pub use hash::{
    CryptographicHash, CryptographicMac, SHA1_OUTPUT_SIZE, SHA256_OUTPUT_SIZE, SHA512_OUTPUT_SIZE,
};
pub use provider::{
    CryptoProviderError, GcmInPlaceBuffer, RustCryptoProvider, SignalCryptoProvider,
    set_crypto_provider,
};

/// AES-256-GCM seal. Appends `ciphertext || tag(16)` to `out`.
/// Delegates to the active [`SignalCryptoProvider`].
#[inline]
pub fn aes_256_gcm_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> std::result::Result<(), CryptoProviderError> {
    provider::provider().aes_256_gcm_encrypt(key, nonce, aad, plaintext, out)
}

/// AES-256-GCM open. `ciphertext_with_tag` must end with the 16-byte tag.
/// Appends plaintext to `out` on success.
#[inline]
pub fn aes_256_gcm_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext_with_tag: &[u8],
    out: &mut Vec<u8>,
) -> std::result::Result<(), CryptoProviderError> {
    provider::provider().aes_256_gcm_decrypt(key, nonce, aad, ciphertext_with_tag, out)
}

/// HMAC-SHA256 one-shot. Delegates to the active [`SignalCryptoProvider`].
#[inline]
pub fn hmac_sha256(key: &[u8], input: &[u8]) -> [u8; 32] {
    provider::provider().hmac_sha256(key, input)
}

/// In-place AES-256-GCM seal. On entry `buffer` holds the plaintext; on return
/// it holds `ciphertext || tag` (length grown by 16). Zero allocations with
/// the default [`RustCryptoProvider`].
#[inline]
pub fn aes_256_gcm_encrypt_in_place<B: GcmInPlaceBuffer>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut B,
) -> std::result::Result<(), CryptoProviderError> {
    provider::provider().aes_256_gcm_encrypt_in_place(key, nonce, aad, buffer)
}

/// In-place AES-256-GCM open. On entry `buffer` holds `ciphertext || tag`; on
/// success it holds plaintext (length shrunk by 16).
#[inline]
pub fn aes_256_gcm_decrypt_in_place<B: GcmInPlaceBuffer>(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buffer: &mut B,
) -> std::result::Result<(), CryptoProviderError> {
    provider::provider().aes_256_gcm_decrypt_in_place(key, nonce, aad, buffer)
}
