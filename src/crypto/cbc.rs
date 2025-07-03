use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{
    block_padding::{NoPadding, Pkcs7},
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
};
use thiserror::Error;

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

#[derive(Debug, Error)]
pub enum CbcError {
    #[error("Invalid key or IV length for CBC mode: {0}")]
    InvalidLength(#[from] cipher::InvalidLength),
    #[error("Cipher operation failed during padding/unpadding")]
    CipherError,
    #[error("Invalid padding")]
    InvalidPadding,
}

type Result<T> = std::result::Result<T, CbcError>;

/// Decrypts ciphertext using AES-256-CBC with manual padding removal.
pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CbcError::InvalidLength(cipher::InvalidLength));
    }
    let mut buf = ciphertext.to_vec();
    Aes256CbcDec::new_from_slices(key, iv)?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| CbcError::CipherError)?;

    // Manual unpad (Signal/WhatsApp compatible)
    fn unpad(data: &[u8]) -> Result<&[u8]> {
        if data.is_empty() {
            return Err(CbcError::InvalidPadding);
        }
        let pad_len_byte = data[data.len() - 1];
        let pad_len = pad_len_byte as usize;

        if pad_len == 0 || pad_len > data.len() {
            return Err(CbcError::InvalidPadding);
        }

        let (unpadded_data, padding) = data.split_at(data.len() - pad_len);
        for &byte in padding {
            if byte != pad_len_byte {
                return Err(CbcError::InvalidPadding);
            }
        }
        Ok(unpadded_data)
    }

    unpad(&buf).map(|d| d.to_vec())
}

/// Encrypts plaintext using AES-256-CBC with PKCS#7 padding.
pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let enc = Aes256CbcEnc::new_from_slices(key, iv)?;
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}
