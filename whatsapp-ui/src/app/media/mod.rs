//! Media handling for the WhatsApp UI
//!
//! This module contains types and utilities for media handling:
//! - `RecordingState`: PTT recording state machine
//!
//! Note: The actual recording/playback methods remain in `WhatsAppApp` for now
//! due to tight coupling with client, chat state, and UI updates.
//! Future refactoring could introduce a `MediaManager` that owns the
//! `AudioRecorder` and `AudioPlayer` with message-passing to the app.

/// Recording state for PTT voice messages
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordingState {
    /// Not recording
    #[default]
    Idle,
    /// Currently recording audio
    Recording,
    /// Processing recorded audio (encoding, sending)
    Processing,
}

impl RecordingState {
    /// Check if currently recording
    pub fn is_recording(&self) -> bool {
        matches!(self, Self::Recording)
    }

    /// Check if processing (encoding/sending)
    pub fn is_processing(&self) -> bool {
        matches!(self, Self::Processing)
    }

    /// Check if idle (not recording or processing)
    pub fn is_idle(&self) -> bool {
        matches!(self, Self::Idle)
    }
}
