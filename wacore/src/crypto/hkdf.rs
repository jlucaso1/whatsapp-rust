use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HkdfError {
    #[error("Invalid output length for HKDF expand")]
    InvalidLength,
}

pub fn sha256(
    key: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> Result<Vec<u8>, HkdfError> {
    let hk = Hkdf::<Sha256>::new(salt, key);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .map_err(|_| HkdfError::InvalidLength)?;
    Ok(okm)
}
