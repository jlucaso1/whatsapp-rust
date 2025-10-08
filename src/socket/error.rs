use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("Socket is closed")]
    SocketClosed,
    #[error("Noise handshake failed: {0}")]
    NoiseHandshake(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, SocketError>;
