use thiserror::Error;
use tokio::task::JoinError;

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
    #[error("tokio join error")]
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
    pub plaintext_buf: Vec<u8>,
    pub out_buf: Vec<u8>,
}

impl EncryptSendError {
    pub fn crypto(
        source: impl Into<anyhow::Error>,
        plaintext_buf: Vec<u8>,
        out_buf: Vec<u8>,
    ) -> Self {
        Self {
            kind: EncryptSendErrorKind::Crypto,
            source: source.into(),
            plaintext_buf,
            out_buf,
        }
    }

    pub fn framing(
        source: impl Into<anyhow::Error>,
        plaintext_buf: Vec<u8>,
        out_buf: Vec<u8>,
    ) -> Self {
        Self {
            kind: EncryptSendErrorKind::Framing,
            source: source.into(),
            plaintext_buf,
            out_buf,
        }
    }

    pub fn transport(
        source: impl Into<anyhow::Error>,
        plaintext_buf: Vec<u8>,
        out_buf: Vec<u8>,
    ) -> Self {
        Self {
            kind: EncryptSendErrorKind::Transport,
            source: source.into(),
            plaintext_buf,
            out_buf,
        }
    }

    pub fn join(source: JoinError, plaintext_buf: Vec<u8>, out_buf: Vec<u8>) -> Self {
        Self {
            kind: EncryptSendErrorKind::Join,
            source: source.into(),
            plaintext_buf,
            out_buf,
        }
    }

    pub fn channel_closed(plaintext_buf: Vec<u8>, out_buf: Vec<u8>) -> Self {
        Self {
            kind: EncryptSendErrorKind::ChannelClosed,
            source: anyhow::anyhow!("sender task channel closed unexpectedly"),
            plaintext_buf,
            out_buf,
        }
    }
}
