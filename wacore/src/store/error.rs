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

    #[error("Database connection error: {0}")]
    Connection(String),

    #[error("Database operation error: {0}")]
    Database(String),

    #[error("Migration error: {0}")]
    Migration(String),

    #[error("Device with ID {0} not found")]
    DeviceNotFound(i32),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Helper to convert any Display error into StoreError::Database.
/// Use with `.map_err(db_err)?` instead of `.map_err(|e| StoreError::Database(e.to_string()))?`
#[inline]
pub fn db_err<E: std::fmt::Display>(e: E) -> StoreError {
    StoreError::Database(e.to_string())
}
