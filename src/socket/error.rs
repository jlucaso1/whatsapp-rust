use thiserror::Error;
use wacore::handshake::NoiseError;
use wacore_binary::error::BinaryError;

#[derive(Debug, Error)]
pub enum SocketError {
    #[error("socket is closed")]
    SocketClosed,
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("noise cipher operation failed")]
    Cipher(#[from] NoiseError),
    #[error("binary protocol marshalling failed")]
    Marshal(#[source] BinaryError),
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

    /// The transport is gone (broken pipe, closed connection, channel dropped).
    pub fn is_transport_unavailable(&self) -> bool {
        matches!(
            self.kind,
            EncryptSendErrorKind::Transport | EncryptSendErrorKind::ChannelClosed
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore::libsignal::crypto::CryptoProviderError;

    #[test]
    fn cipher_preserves_noise_source_through_socket_error() {
        let noise = NoiseError::Decrypt(CryptoProviderError::AuthFailed);
        let se: SocketError = noise.into();
        // First hop: SocketError → NoiseError
        let src = std::error::Error::source(&se).expect("source preserved");
        let ne = src
            .downcast_ref::<NoiseError>()
            .expect("downcasts to NoiseError");
        assert!(matches!(ne, NoiseError::Decrypt(_)));
        // Second hop: NoiseError → CryptoProviderError
        let inner = std::error::Error::source(ne).expect("inner source preserved");
        let cpe = inner
            .downcast_ref::<CryptoProviderError>()
            .expect("downcasts to CryptoProviderError");
        assert!(matches!(cpe, CryptoProviderError::AuthFailed));
    }

    #[test]
    fn marshal_preserves_binary_error_source() {
        let be = BinaryError::InvalidNode;
        let se = SocketError::Marshal(be);
        let src = std::error::Error::source(&se).expect("source preserved");
        let inner = src
            .downcast_ref::<BinaryError>()
            .expect("downcasts to BinaryError");
        assert!(matches!(inner, BinaryError::InvalidNode));
    }
}
