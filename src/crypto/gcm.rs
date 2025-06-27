use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GcmError {
    #[error("Invalid key or nonce size for AES-GCM")]
    InvalidSize,
    #[error("AES-GCM cipher operation failed")]
    CipherError,
}

type Result<T> = std::result::Result<T, GcmError>;

/// Prepares an AES-256-GCM cipher instance from a secret key.
pub fn prepare(secret_key: &[u8]) -> Result<Aes256Gcm> {
    Aes256Gcm::new_from_slice(secret_key).map_err(|_| GcmError::InvalidSize)
}

/// Encrypts plaintext using AES-256-GCM.
pub fn encrypt(
    secret_key: &[u8],
    iv: &[u8],
    plaintext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = prepare(secret_key)?;
    let nonce = aes_gcm::Nonce::from_slice(iv);
    let payload = Payload {
        msg: plaintext,
        aad: additional_data,
    };
    cipher
        .encrypt(nonce, payload)
        .map_err(|_| GcmError::CipherError)
}

/// Decrypts ciphertext using AES-256-GCM.
pub fn decrypt(
    secret_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    additional_data: &[u8],
) -> Result<Vec<u8>> {
    let cipher = prepare(secret_key)?;
    let nonce = aes_gcm::Nonce::from_slice(iv);
    let payload = Payload {
        msg: ciphertext,
        aad: additional_data,
    };
    cipher
        .decrypt(nonce, payload)
        .map_err(|_| GcmError::CipherError)
}
