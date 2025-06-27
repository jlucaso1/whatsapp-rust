use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use thiserror::Error;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

#[derive(Debug, Error)]
pub enum CbcError {
    #[error("Invalid key or IV length for CBC mode: {0}")]
    InvalidLength(#[from] cipher::InvalidLength),
    #[error("Cipher operation failed during padding/unpadding")]
    CipherError,
}

type Result<T> = std::result::Result<T, CbcError>;

/// Decrypts ciphertext using AES-256-CBC with PKCS#7 padding.
pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let dec = Aes256CbcDec::new_from_slices(key, iv)?;
    let mut buf = ciphertext.to_vec();
    let pt = dec
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .map_err(|_| CbcError::CipherError)?;
    Ok(pt.to_vec())
}

/// Encrypts plaintext using AES-256-CBC with PKCS#7 padding.
pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let enc = Aes256CbcEnc::new_from_slices(key, iv)?;
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}
