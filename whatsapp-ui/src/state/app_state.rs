//! Application state enum

use std::sync::Arc;

/// Cached QR code with pre-rendered PNG bytes
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

/// Application state representing the current phase of the app
#[derive(Debug, Clone, PartialEq)]
pub enum AppState {
    /// Initial loading state (initializing database)
    Loading,
    /// Connecting to WhatsApp (session exists, authenticating)
    Connecting,
    /// Waiting for QR code scan or pair code entry (no session)
    WaitingForPairing {
        qr_code: Option<CachedQrCode>,
        pair_code: Option<String>,
        timeout_secs: u64,
    },
    /// Pairing successful, syncing data
    Syncing,
    /// Connected and ready
    Connected,
    /// Error occurred
    Error(String),
}

#[allow(dead_code)]
impl AppState {
    /// Check if the app is in a loading or connecting state
    pub fn is_loading(&self) -> bool {
        matches!(self, AppState::Loading | AppState::Connecting)
    }

    /// Check if the app is ready for user interaction
    pub fn is_ready(&self) -> bool {
        matches!(self, AppState::Connected)
    }

    /// Check if pairing is required
    pub fn needs_pairing(&self) -> bool {
        matches!(self, AppState::WaitingForPairing { .. })
    }

    /// Check if there's an error
    pub fn is_error(&self) -> bool {
        matches!(self, AppState::Error(_))
    }

    /// Get error message if in error state
    pub fn error_message(&self) -> Option<&str> {
        match self {
            AppState::Error(msg) => Some(msg),
            _ => None,
        }
    }
}
