use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{
    BlockDecryptMut, BlockEncryptMut, KeyIvInit,
    block_padding::{NoPadding, Pkcs7},
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

pub fn decrypt(key: &[u8], iv: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(CbcError::InvalidLength(cipher::InvalidLength));
    }
    let mut buf = ciphertext.to_vec();
    Aes256CbcDec::new_from_slices(key, iv)?
        .decrypt_padded_mut::<NoPadding>(&mut buf)
        .map_err(|_| CbcError::CipherError)?;

    fn unpad(data: &[u8]) -> Result<&[u8]> {
        if data.is_empty() {
            return Err(CbcError::InvalidPadding);
        }
        let pad_len = data[data.len() - 1] as usize;

        if pad_len == 0 || pad_len > data.len() {
            return Err(CbcError::InvalidPadding);
        }

        Ok(&data[..data.len() - pad_len])
    }

    unpad(&buf).map(|d| d.to_vec())
}

pub fn encrypt(key: &[u8], iv: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    let enc = Aes256CbcEnc::new_from_slices(key, iv)?;
    Ok(enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}
