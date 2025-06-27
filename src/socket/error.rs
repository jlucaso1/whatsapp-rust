use thiserror::Error;

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("Frame is too large (max: {max}, got: {got})")]
    FrameTooLarge { max: usize, got: usize },
    #[error("Socket is closed")]
    SocketClosed,
    #[error("Socket is already open")]
    SocketAlreadyOpen,
    #[error("Noise handshake failed: {0}")]
    NoiseHandshake(String),
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Crypto error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, SocketError>;
