use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization/deserialization error: {0}")]
    Serialization(String),

    #[error("Item not found: {0}")]
    NotFound(String),

    #[error("Database backend error: {0}")]
    Backend(#[from] Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, StoreError>;
