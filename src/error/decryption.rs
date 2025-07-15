use thiserror::Error;

#[derive(Debug, Error)]
pub enum DecryptionError {
    #[error("underlying crypto error: {0}")]
    Crypto(#[from] anyhow::Error),
}
