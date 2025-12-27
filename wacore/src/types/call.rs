//! Core call types that complement waproto definitions.
//!
//! For protobuf types, use `waproto::whatsapp`:
//! - `CallLogRecord` with `call_log_record::{CallResult, CallType, SilenceReason}`
//! - `message::CallLogMessage` with `call_log_message::{CallOutcome, CallType}`
//! - `message::BCallMessage` with `b_call_message::MediaType`
//!
//! This module provides additional types needed for call signaling and state management
//! that are not part of the protobuf definitions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;
use wacore_binary::jid::Jid;

// Re-export waproto call types for convenience
pub use waproto::whatsapp::CallLogRecord;
pub use waproto::whatsapp::call_log_record::{
    CallResult, CallType, ParticipantInfo, SilenceReason,
};
pub use waproto::whatsapp::message::b_call_message::MediaType as CallMediaType;
pub use waproto::whatsapp::message::call_log_message::CallOutcome;

/// Basic metadata for a call, extracted from the call stanza.
#[derive(Debug, Clone, Serialize)]
pub struct BasicCallMeta {
    pub from: Jid,
    pub timestamp: DateTime<Utc>,
    pub call_creator: Jid,
    pub call_id: String,
}

/// Metadata about the remote peer in a call.
#[derive(Debug, Clone, Serialize)]
pub struct CallRemoteMeta {
    pub remote_platform: String,
    pub remote_version: String,
}

/// Unique identifier for a call session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CallId(pub String);

impl CallId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Generate a new random call ID (32 uppercase hex characters).
    ///
    /// WhatsApp uses 32-character uppercase hexadecimal call IDs.
    /// Pattern: `[A-F0-9]{32}`
    /// Examples: `AC90CFD09DF712D981142B172706F9F2`, `BC5BD1EDE9BBE601F408EF3795479E93`
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        // Convert to uppercase hex (16 bytes = 32 hex chars)
        let id: String = bytes.iter().map(|b| format!("{:02X}", b)).collect();
        Self(id)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CallId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl AsRef<str> for CallId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<String> for CallId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for CallId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

/// Call direction from our perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CallDirection {
    Outgoing,
    Incoming,
}

/// Reason for ending a call (from WhatsApp Web JS EndCallReason enum).
///
/// This is different from `CallResult` which is used in call logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum EndCallReason {
    #[default]
    Unknown = 0,
    Timeout = 1,
    UserEnded = 2,
    RejectDoNotDisturb = 3,
    RejectBlocked = 4,
    MicPermissionDenied = 5,
    CameraPermissionDenied = 6,
    Declined = 7,
    Busy = 8,
    NetworkError = 9,
    Cancelled = 10,
    AcceptedElsewhere = 11,
}

impl EndCallReason {
    /// Convert to CallOutcome for logging.
    pub fn to_outcome(self) -> CallOutcome {
        match self {
            Self::Unknown | Self::UserEnded => CallOutcome::Connected,
            Self::Timeout | Self::Cancelled => CallOutcome::Missed,
            Self::NetworkError | Self::MicPermissionDenied | Self::CameraPermissionDenied => {
                CallOutcome::Failed
            }
            Self::Declined | Self::RejectBlocked | Self::Busy => CallOutcome::Rejected,
            Self::AcceptedElsewhere => CallOutcome::AcceptedElsewhere,
            Self::RejectDoNotDisturb => CallOutcome::SilencedByDnd,
        }
    }
}

/// Platform of the remote peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum CallPlatform {
    Android,
    IOS,
    Web,
    Windows,
    MacOS,
    #[default]
    Unknown,
}

impl From<&str> for CallPlatform {
    fn from(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "android" | "smba" | "smbi" => Self::Android,
            "ios" | "iphone" => Self::IOS,
            "web" => Self::Web,
            "windows" => Self::Windows,
            "macos" | "darwin" => Self::MacOS,
            _ => Self::Unknown,
        }
    }
}

/// Information about a participant in a group call (runtime representation).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupCallParticipant {
    pub jid: Jid,
    pub phone_number: Option<String>,
    pub username: Option<String>,
    pub audio_muted: bool,
    pub video_off: bool,
}

impl GroupCallParticipant {
    pub fn new(jid: Jid) -> Self {
        Self {
            jid,
            phone_number: None,
            username: None,
            audio_muted: false,
            video_off: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test CallId format matches WhatsApp's 32-char uppercase hex format.
    /// Real examples from logs:
    /// - AC90CFD09DF712D981142B172706F9F2
    /// - BC5BD1EDE9BBE601F408EF3795479E93
    /// - ACCEA86C861462148DDDA364442F8584
    #[test]
    fn test_call_id_format() {
        for _ in 0..100 {
            let call_id = CallId::generate();
            let id = call_id.as_str();

            // Must be exactly 32 characters
            assert_eq!(id.len(), 32, "CallId should be 32 chars, got {}", id.len());

            // Must be uppercase hex only [A-F0-9]
            for c in id.chars() {
                assert!(
                    c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_uppercase()),
                    "CallId should only contain uppercase hex chars, got '{}'",
                    c
                );
            }
        }
    }

    /// Test CallId parsing from real WhatsApp call IDs.
    #[test]
    fn test_call_id_from_real_examples() {
        // Real call IDs from captured logs
        let real_ids = [
            "AC90CFD09DF712D981142B172706F9F2",
            "BC5BD1EDE9BBE601F408EF3795479E93",
            "ACCEA86C861462148DDDA364442F8584",
            "AC712CC33BFDE233AE328CE6349007DD",
            "ACFA2CE9BFADCC1F6D5A9346149B3F57",
        ];

        for id in real_ids {
            let call_id = CallId::new(id);
            assert_eq!(call_id.as_str(), id);
            assert_eq!(call_id.to_string(), id);
        }
    }

    /// Test EndCallReason values match WhatsApp Web JS enum.
    #[test]
    fn test_end_call_reason_values() {
        // From WAWebVoipEndCallReasons in captured JS
        assert_eq!(EndCallReason::Unknown as u8, 0);
        assert_eq!(EndCallReason::Timeout as u8, 1);
        assert_eq!(EndCallReason::UserEnded as u8, 2); // "Self" in JS
        assert_eq!(EndCallReason::RejectDoNotDisturb as u8, 3);
        assert_eq!(EndCallReason::RejectBlocked as u8, 4);
        assert_eq!(EndCallReason::MicPermissionDenied as u8, 5);
        assert_eq!(EndCallReason::CameraPermissionDenied as u8, 6);
    }

    /// Test EndCallReason to CallOutcome mapping.
    #[test]
    fn test_end_call_reason_to_outcome() {
        assert_eq!(
            EndCallReason::UserEnded.to_outcome(),
            CallOutcome::Connected
        );
        assert_eq!(EndCallReason::Timeout.to_outcome(), CallOutcome::Missed);
        assert_eq!(EndCallReason::Declined.to_outcome(), CallOutcome::Rejected);
        assert_eq!(EndCallReason::Busy.to_outcome(), CallOutcome::Rejected);
        assert_eq!(
            EndCallReason::RejectDoNotDisturb.to_outcome(),
            CallOutcome::SilencedByDnd
        );
        assert_eq!(
            EndCallReason::AcceptedElsewhere.to_outcome(),
            CallOutcome::AcceptedElsewhere
        );
    }

    /// Test CallPlatform parsing from platform strings.
    #[test]
    fn test_call_platform_from_str() {
        assert_eq!(CallPlatform::from("android"), CallPlatform::Android);
        assert_eq!(CallPlatform::from("smba"), CallPlatform::Android);
        assert_eq!(CallPlatform::from("ios"), CallPlatform::IOS);
        assert_eq!(CallPlatform::from("iphone"), CallPlatform::IOS);
        assert_eq!(CallPlatform::from("web"), CallPlatform::Web);
        assert_eq!(CallPlatform::from("windows"), CallPlatform::Windows);
        assert_eq!(CallPlatform::from("macos"), CallPlatform::MacOS);
        assert_eq!(CallPlatform::from("darwin"), CallPlatform::MacOS);
        assert_eq!(
            CallPlatform::from("unknown_platform"),
            CallPlatform::Unknown
        );
    }
}
