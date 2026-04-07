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

#[derive(Debug, thiserror::Error)]
pub enum EncryptSendErrorKind {
    #[error("cryptography error")]
    Crypto,
    #[error("framing error")]
    Framing,
    #[error("transport error")]
    Transport,
    #[error("task join error")]
    Join,
    #[error("sender channel closed")]
    ChannelClosed,
}

#[derive(Debug, thiserror::Error)]
#[error("{kind}")]
pub struct EncryptSendError {
    pub kind: EncryptSendErrorKind,
    #[source]
    pub source: anyhow::Error,
}

impl EncryptSendError {
    pub fn crypto(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: EncryptSendErrorKind::Crypto,
            source: source.into(),
        }
    }

    pub fn framing(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: EncryptSendErrorKind::Framing,
            source: source.into(),
        }
    }

    pub fn transport(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: EncryptSendErrorKind::Transport,
            source: source.into(),
        }
    }

    pub fn join(source: impl Into<anyhow::Error>) -> Self {
        Self {
            kind: EncryptSendErrorKind::Join,
            source: source.into(),
        }
    }

    pub fn channel_closed() -> Self {
        Self {
            kind: EncryptSendErrorKind::ChannelClosed,
            source: anyhow::anyhow!("sender task channel closed unexpectedly"),
        }
    }
}
