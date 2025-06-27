use hkdf::Hkdf;
use sha2::Sha256;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HkdfError {
    #[error("Invalid output length for HKDF expand")]
    InvalidLength,
}

/// Expands a key using HKDF-SHA256.
///
/// # Arguments
///
/// * `key`: The input keying material.
/// * `salt`: An optional salt.
/// * `info`: Optional context and application specific information.
/// * `length`: The desired length of the output key.
///
/// Returns a `Result` containing the output key material (`Vec<u8>`) or an error.
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
