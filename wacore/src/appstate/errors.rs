use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppStateError {
    #[error("missing value MAC of previous SET operation for index {0}")]
    MissingPreviousSetValue(String),
    #[error("mismatching LTHash")]
    MismatchingLTHash,
    #[error("mismatching patch MAC")]
    MismatchingPatchMAC,
    #[error("mismatching content MAC")]
    MismatchingContentMAC(String),
    #[error("mismatching index MAC")]
    MismatchingIndexMAC,
    #[error("app state sync key(s) not found")]
    KeysNotFound(Vec<Vec<u8>>),
    #[error("failed to get app state key {0:?}: {1}")]
    GetKeyFailed(Vec<u8>, Box<dyn std::error::Error + Send + Sync>),
    #[error("failed to decrypt mutation: {0}")]
    Decrypt(#[from] crate::crypto::cbc::CbcError),
    #[error("failed to unmarshal mutation protobuf: {0}")]
    Unmarshal(#[from] prost::DecodeError),
    #[error("failed to unmarshal index json: {0}")]
    UnmarshalIndex(#[from] serde_json::Error),
    #[error("failed to update state hash: {0}")]
    UpdateHash(Box<dyn std::error::Error + Send + Sync>),
}

pub type Result<T> = std::result::Result<T, AppStateError>;
