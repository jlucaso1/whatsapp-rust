use crate::crypto;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KdfError {
    #[error("HKDF error: {0}")]
    Hkdf(#[from] crypto::hkdf::HkdfError),
}

// Corresponds to kdf.DeriveSecrets()
pub fn derive_secrets(
    input_key_material: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_length: usize,
) -> Result<Vec<u8>, KdfError> {
    Ok(crypto::hkdf::sha256(
        input_key_material,
        salt,
        info,
        output_length,
    )?)
}

// KeyMaterial is a simple struct to hold derived secrets.
pub struct KeyMaterial {
    pub cipher_key: Vec<u8>,
    pub mac_key: Vec<u8>,
    pub iv: Vec<u8>,
}
