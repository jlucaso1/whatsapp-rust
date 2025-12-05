use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppStateError {
    #[error("missing value MAC of previous SET operation")]
    MissingPreviousSetValueOperation,
    #[error("mismatching LTHash")]
    MismatchingLTHash,
    #[error("mismatching patch MAC")]
    MismatchingPatchMAC,
    #[error("mismatching content MAC")]
    MismatchingContentMAC,
    #[error("mismatching index MAC")]
    MismatchingIndexMAC,
    #[error("didn't find app state key")]
    KeyNotFound,
    #[error("missing value blob in record")]
    MissingValueBlob,
    #[error("value blob too short (need at least 48 bytes for IV + MAC)")]
    ValueBlobTooShort,
    #[error("decryption failed")]
    DecryptionFailed,
    #[error("failed to decode protobuf")]
    DecodeFailed,
    #[error("missing index MAC in record")]
    MissingIndexMAC,
    #[error("missing key ID in record")]
    MissingKeyId,
    #[error("snapshot MAC mismatch")]
    SnapshotMACMismatch,
    #[error("patch snapshot MAC mismatch")]
    PatchSnapshotMACMismatch,
    #[error("patch MAC mismatch")]
    PatchMACMismatch,
}

pub type Result<T> = std::result::Result<T, AppStateError>;
