//! Call-related error types.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CallError {
    #[error("call not found: {0}")]
    NotFound(String),

    #[error("invalid call state transition: {0}")]
    InvalidTransition(#[from] super::state::InvalidTransition),

    #[error("call already exists: {0}")]
    AlreadyExists(String),

    #[error("missing required attribute: {0}")]
    MissingAttribute(&'static str),

    #[error("invalid signaling type: {0}")]
    InvalidSignalingType(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("encryption error: {0}")]
    Encryption(String),

    #[error("not connected")]
    NotConnected,
}
