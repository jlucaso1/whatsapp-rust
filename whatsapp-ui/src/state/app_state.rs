//! Application state enum.

use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct CachedQrCode {
    pub data: String,
    pub png_bytes: Arc<Vec<u8>>,
}

impl PartialEq for CachedQrCode {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    Loading,
    Connecting,
    WaitingForPairing {
        qr_code: Option<CachedQrCode>,
        pair_code: Option<String>,
        timeout_secs: u64,
    },
    Syncing,
    Connected,
    Error(String),
}

#[allow(dead_code)]
impl AppState {
    pub fn is_loading(&self) -> bool {
        matches!(self, Self::Loading | Self::Connecting)
    }

    pub fn is_ready(&self) -> bool {
        matches!(self, Self::Connected)
    }

    pub fn needs_pairing(&self) -> bool {
        matches!(self, Self::WaitingForPairing { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, Self::Error(_))
    }

    pub fn error_message(&self) -> Option<&str> {
        if let Self::Error(msg) = self {
            Some(msg)
        } else {
            None
        }
    }
}
