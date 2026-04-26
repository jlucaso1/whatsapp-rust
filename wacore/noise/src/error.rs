use thiserror::Error;
use wacore_libsignal::crypto::CryptoProviderError;

/// Errors that can occur during Noise protocol operations.
#[derive(Debug, Error)]
pub enum NoiseError {
    #[error("invalid pattern length: expected {expected}, got {got}")]
    InvalidPatternLength { expected: usize, got: usize },

    #[error("AES-GCM encryption failed")]
    Encrypt(#[source] CryptoProviderError),

    #[error("AES-GCM decryption failed")]
    Decrypt(#[source] CryptoProviderError),

    #[error("ciphertext too short to contain authentication tag")]
    CiphertextTooShort,

    #[error("HKDF expansion failed")]
    HkdfExpandFailed,

    #[error("invalid key length for {name}: expected {expected}, got {got}")]
    InvalidKeyLength {
        name: &'static str,
        expected: usize,
        got: usize,
    },

    #[error("counter exhausted: nonce would be reused after 2^32 messages")]
    CounterExhausted,
}

pub type Result<T> = std::result::Result<T, NoiseError>;
