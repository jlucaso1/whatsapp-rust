//! Pluggable Signal crypto provider.
//!
//! Default uses RustCrypto (soft). Override via [`set_crypto_provider`] to
//! delegate hot-path primitives to a faster backend (e.g. `node:crypto`
//! over a WASM bridge). Must be set before any crypto call.

use std::sync::OnceLock;

use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockModeDecrypt, BlockModeEncrypt, KeyIvInit};
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::crypto::aes_gcm::{Aes256GcmDecryption, Aes256GcmEncryption};

#[derive(Debug, displaydoc::Display, thiserror::Error)]
pub enum CryptoProviderError {
    /// bad key/iv/nonce size or malformed input
    BadInput,
    /// authentication tag verification failed
    AuthFailed,
    /// provider backend reported failure
    BackendFailed,
}

/// Pluggable crypto primitives used by libsignal and higher-level callers.
///
/// All methods are one-shot (no streaming state): inputs fully known at call
/// time, output appended to `out`. Key/nonce sizes are compile-time arrays so
/// implementations can skip size checks.
pub trait SignalCryptoProvider: Send + Sync + 'static {
    /// AES-256-CBC encrypt with PKCS7 padding. Ciphertext appended to `out`.
    fn aes_256_cbc_encrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 16],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoProviderError>;

    /// AES-256-CBC decrypt with PKCS7 unpadding. `out` is cleared, then filled.
    fn aes_256_cbc_decrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 16],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoProviderError>;

    /// AES-256-GCM seal. Appends `ciphertext || tag(16)` to `out`.
    /// Ciphertext length equals plaintext length.
    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoProviderError>;

    /// AES-256-GCM open. `ciphertext_with_tag` must end with the 16-byte tag.
    /// On success appends plaintext to `out`. On tag failure, `out` is left
    /// unchanged and [`CryptoProviderError::AuthFailed`] is returned.
    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoProviderError>;

    /// HMAC-SHA256 one-shot. Zero-alloc output.
    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> [u8; 32];
}

static CRYPTO_PROVIDER: OnceLock<Box<dyn SignalCryptoProvider>> = OnceLock::new();

/// Install a custom provider. Must be called before any crypto call. Returns
/// `Err` if a provider was already set (including by `get_or_init` of the
/// default fallback).
pub fn set_crypto_provider(provider: impl SignalCryptoProvider) -> Result<(), &'static str> {
    CRYPTO_PROVIDER
        .set(Box::new(provider))
        .map_err(|_| "crypto provider already set")
}

#[inline]
pub(crate) fn provider() -> &'static dyn SignalCryptoProvider {
    CRYPTO_PROVIDER
        .get_or_init(|| Box::new(RustCryptoProvider))
        .as_ref()
}

/// Pure-Rust fallback implementation. Always used when no custom provider is
/// installed; also used by tests for deterministic behavior.
pub struct RustCryptoProvider;

impl SignalCryptoProvider for RustCryptoProvider {
    fn aes_256_cbc_encrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 16],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoProviderError> {
        let padding = 16 - (plaintext.len() % 16);
        let encrypted_size = plaintext.len() + padding;
        let start = out.len();

        out.resize(start + encrypted_size, 0);
        out[start..start + plaintext.len()].copy_from_slice(plaintext);

        let encryptor = cbc::Encryptor::<Aes256>::new(key.into(), iv.into());
        let written = encryptor
            .encrypt_padded::<Pkcs7>(&mut out[start..], plaintext.len())
            .map_err(|_| CryptoProviderError::BadInput)?
            .len();
        out.truncate(start + written);
        Ok(())
    }

    fn aes_256_cbc_decrypt(
        &self,
        key: &[u8; 32],
        iv: &[u8; 16],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoProviderError> {
        if ciphertext.is_empty() || !ciphertext.len().is_multiple_of(16) {
            return Err(CryptoProviderError::BadInput);
        }

        out.clear();
        out.reserve(ciphertext.len());
        out.extend_from_slice(ciphertext);

        let decryptor = cbc::Decryptor::<Aes256>::new(key.into(), iv.into());
        let decrypted_len = decryptor
            .decrypt_padded::<Pkcs7>(out)
            .map_err(|_| CryptoProviderError::BadInput)?
            .len();
        out.truncate(decrypted_len);
        Ok(())
    }

    fn aes_256_gcm_encrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoProviderError> {
        let mut enc =
            Aes256GcmEncryption::new(key, nonce, aad).map_err(|_| CryptoProviderError::BadInput)?;
        let start = out.len();
        out.extend_from_slice(plaintext);
        enc.encrypt(&mut out[start..]);
        let tag = enc.compute_tag();
        out.extend_from_slice(&tag);
        Ok(())
    }

    fn aes_256_gcm_decrypt(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        ciphertext_with_tag: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), CryptoProviderError> {
        const TAG: usize = 16;
        if ciphertext_with_tag.len() < TAG {
            return Err(CryptoProviderError::BadInput);
        }
        let (ct, tag) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - TAG);

        // Decrypt into a scratch, verify tag; only commit to `out` on success
        // so failures leave it untouched.
        let mut scratch = ct.to_vec();
        let mut dec =
            Aes256GcmDecryption::new(key, nonce, aad).map_err(|_| CryptoProviderError::BadInput)?;
        dec.decrypt(&mut scratch);
        dec.verify_tag(tag)
            .map_err(|_| CryptoProviderError::AuthFailed)?;

        out.extend_from_slice(&scratch);
        Ok(())
    }

    fn hmac_sha256(&self, key: &[u8], input: &[u8]) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
            .expect("HMAC-SHA256 accepts any key length");
        mac.update(input);
        mac.finalize().into_bytes().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_provider_cbc_roundtrip() {
        let p = RustCryptoProvider;
        let key = [0x42; 32];
        let iv = [0x11; 16];
        let pt = b"hello cbc provider test";

        let mut ct = Vec::new();
        p.aes_256_cbc_encrypt(&key, &iv, pt, &mut ct).unwrap();

        let mut out = Vec::new();
        p.aes_256_cbc_decrypt(&key, &iv, &ct, &mut out).unwrap();
        assert_eq!(&out[..], pt);
    }

    #[test]
    fn rust_provider_gcm_roundtrip_with_aad() {
        let p = RustCryptoProvider;
        let key = [0x7f; 32];
        let nonce = [0x13; 12];
        let aad = b"extra auth data";
        let pt = b"hello gcm provider test with aad";

        let mut sealed = Vec::new();
        p.aes_256_gcm_encrypt(&key, &nonce, aad, pt, &mut sealed)
            .unwrap();
        assert_eq!(sealed.len(), pt.len() + 16);

        let mut opened = Vec::new();
        p.aes_256_gcm_decrypt(&key, &nonce, aad, &sealed, &mut opened)
            .unwrap();
        assert_eq!(&opened[..], pt);

        // Wrong AAD -> AuthFailed, `out` untouched.
        let mut bad = Vec::new();
        let err = p
            .aes_256_gcm_decrypt(&key, &nonce, b"different", &sealed, &mut bad)
            .unwrap_err();
        assert!(matches!(err, CryptoProviderError::AuthFailed));
        assert!(bad.is_empty());
    }

    #[test]
    fn rust_provider_hmac_matches_direct() {
        let p = RustCryptoProvider;
        let key = b"mac key";
        let data = b"message body";
        let got = p.hmac_sha256(key, data);

        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
        mac.update(data);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();
        assert_eq!(got, expected);
    }

    /// NIST SP 800-38D Test Case 14: all-zero key/nonce, 128-bit plaintext.
    #[test]
    fn rust_provider_gcm_nist_tc14() {
        let p = RustCryptoProvider;
        let key = [0u8; 32];
        let nonce = [0u8; 12];
        let pt = [0u8; 16];

        let expected_ct: [u8; 16] = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e, 0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3,
            0x9d, 0x18,
        ];
        let expected_tag: [u8; 16] = [
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0, 0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a,
            0xb9, 0x19,
        ];

        let mut sealed = Vec::new();
        p.aes_256_gcm_encrypt(&key, &nonce, b"", &pt, &mut sealed)
            .unwrap();
        assert_eq!(&sealed[..16], &expected_ct);
        assert_eq!(&sealed[16..], &expected_tag);
    }
}
