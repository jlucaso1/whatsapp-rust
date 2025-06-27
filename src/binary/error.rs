use crate::types::jid::JidError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum BinaryError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Invalid token read from stream: {0}")]
    InvalidToken(u8),
    #[error("Invalid node format")]
    InvalidNode,
    #[error("Attribute key was not a string")]
    NonStringKey,
    #[error("Attribute parsing failed: {0}")]
    AttrParse(String),
    #[error("Data is not valid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    #[error("Zlib decompression error: {0}")]
    Zlib(String),
    #[error("JID parsing error: {0}")]
    Jid(#[from] JidError),
    #[error("Reached end of file unexpectedly")]
    Eof,
    #[error("Leftover data after decoding: {0} bytes")]
    LeftoverData(usize),
    #[error("Multiple attribute parsing errors: {0:?}")]
    AttrList(Vec<BinaryError>),
}

// Manual Clone implementation for BinaryError
impl Clone for BinaryError {
    fn clone(&self) -> Self {
        match self {
            BinaryError::Io(e) => {
                // std::io::Error is not Clone, so clone as new error with same kind and message
                BinaryError::Io(std::io::Error::new(e.kind(), e.to_string()))
            }
            BinaryError::InvalidToken(u) => BinaryError::InvalidToken(*u),
            BinaryError::InvalidNode => BinaryError::InvalidNode,
            BinaryError::NonStringKey => BinaryError::NonStringKey,
            BinaryError::AttrParse(s) => BinaryError::AttrParse(s.clone()),
            BinaryError::InvalidUtf8(e) => BinaryError::InvalidUtf8(*e),
            BinaryError::Zlib(s) => BinaryError::Zlib(s.clone()),
            BinaryError::Jid(e) => BinaryError::Jid(JidError::InvalidFormat(e.to_string())),
            BinaryError::Eof => BinaryError::Eof,
            BinaryError::LeftoverData(n) => BinaryError::LeftoverData(*n),
            BinaryError::AttrList(list) => BinaryError::AttrList(list.clone()),
        }
    }
}

pub type Result<T> = std::result::Result<T, BinaryError>;
