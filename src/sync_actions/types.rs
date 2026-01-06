//! Types and errors for sync actions.

use thiserror::Error;
use wacore::appstate::patch_decode::WAPatchName;
pub use waproto::whatsapp::syncd_mutation::SyncdOperation;

/// The collection a sync action belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SyncCollection {
    /// Regular priority actions (star, archive, mute, pin, delete for me, etc.)
    Regular,
    /// High priority regular actions (settings, push name, locale)
    RegularHigh,
    /// Low priority regular actions
    RegularLow,
    /// Critical blocking actions
    CriticalBlock,
    /// Critical unblocking low priority actions
    CriticalUnblockLow,
}

impl SyncCollection {
    /// Get the string representation used in the protocol.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Regular => "regular",
            Self::RegularHigh => "regular_high",
            Self::RegularLow => "regular_low",
            Self::CriticalBlock => "critical_block",
            Self::CriticalUnblockLow => "critical_unblock_low",
        }
    }

    /// Convert to the corresponding WAPatchName for app state sync.
    pub fn to_patch_name(&self) -> WAPatchName {
        match self {
            Self::Regular => WAPatchName::Regular,
            Self::RegularHigh => WAPatchName::RegularHigh,
            Self::RegularLow => WAPatchName::RegularLow,
            Self::CriticalBlock => WAPatchName::CriticalBlock,
            Self::CriticalUnblockLow => WAPatchName::CriticalUnblockLow,
        }
    }
}

impl std::fmt::Display for SyncCollection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Error during sync action push.
#[derive(Debug, Error)]
pub enum SyncError {
    #[error("Not logged in")]
    NotLoggedIn,

    #[error("App state key not found")]
    KeyNotFound,

    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Version conflict - sync required")]
    VersionConflict,

    #[error("Server rejected patch: {0}")]
    ServerRejected(String),

    #[error("Network error: {0}")]
    Network(#[from] anyhow::Error),

    #[error("IQ request error: {0}")]
    IqError(String),
}
