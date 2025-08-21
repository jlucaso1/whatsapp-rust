use aes::Aes256;
use aes::cipher::block_padding::Pkcs7;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use anyhow::Error;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn hmac_sha256(key: &[u8], data_parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 can accept any key size");
    for part in data_parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub fn hmac_sha512(key: &[u8], data_parts: &[&[u8]]) -> [u8; 64] {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC-SHA512 can accept any key size");
    for part in data_parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub fn aes_256_cbc_encrypt(plaintext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    let cipher = cbc::Encryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| anyhow::anyhow!("Failed to create AES encryptor: {}", e))?;
    Ok(cipher.encrypt_padded_vec_mut::<Pkcs7>(plaintext))
}

pub fn aes_256_cbc_decrypt(ciphertext: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, Error> {
    if ciphertext.is_empty() || ciphertext.len() % 16 != 0 {
        return Err(anyhow::anyhow!(
            "Ciphertext length must be a non-zero multiple of 16"
        ));
    }
    let cipher = cbc::Decryptor::<Aes256>::new_from_slices(key, iv)
        .map_err(|e| anyhow::anyhow!("Failed to create AES decryptor: {}", e))?;
    cipher
        .decrypt_padded_vec_mut::<Pkcs7>(ciphertext)
        .map_err(|e| anyhow::anyhow!("Failed to decrypt or unpad data: {}", e))
}
