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
}

pub type Result<T> = std::result::Result<T, AppStateError>;
