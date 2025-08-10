use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("bad MAC")]
    BadMac,
    #[error("invalid message version: {0}")]
    InvalidVersion(u8),
    #[error("incomplete message")]
    IncompleteMessage,
    #[error("invalid proto message: {0}")]
    Proto(#[from] prost::DecodeError),
    #[error("invalid key: {0}")]
    InvalidKey(#[from] super::ecc::curve::CurveError),
    #[error("untrusted identity")]
    UntrustedIdentity,
    #[error("old counter: current={0}, received={1}")]
    OldCounter(u32, u32),
}
