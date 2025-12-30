//! Call state structures
//!
//! This module provides types for managing call state in the UI:
//! - `IncomingCall`: Received calls waiting for accept/decline
//! - `OutgoingCall`: Calls we initiated, waiting for answer
//! - `ActiveCall`: Connected calls in progress

use chrono::{DateTime, Utc};

// Re-export CallId from wacore for DRY
pub use wacore::types::call::CallId;

/// Outgoing call state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutgoingCallState {
    /// Call is being initiated (sending offer)
    Initiating,
    /// Waiting for the recipient to answer (ringing)
    Ringing,
    /// Call was accepted and is now connected
    Connected,
    /// Call was declined by recipient
    Declined,
    /// Call timed out (no answer)
    Timeout,
}

/// Outgoing call information
#[derive(Debug, Clone)]
pub struct OutgoingCall {
    /// Unique call ID (using wacore's CallId type)
    pub call_id: CallId,
    /// Recipient display name
    pub recipient_name: String,
    /// Recipient JID
    pub recipient_jid: String,
    /// Whether this is a video call
    pub is_video: bool,
    /// Current state of the outgoing call
    pub state: OutgoingCallState,
    /// When the call was initiated
    pub initiated_at: DateTime<Utc>,
}

impl OutgoingCall {
    /// Create a new outgoing call
    pub fn new(
        call_id: impl Into<CallId>,
        recipient_jid: String,
        recipient_name: String,
        is_video: bool,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            recipient_name,
            recipient_jid,
            is_video,
            state: OutgoingCallState::Initiating,
            initiated_at: Utc::now(),
        }
    }

    /// Get the initial letter for avatar display
    pub fn initial(&self) -> char {
        self.recipient_name.chars().next().unwrap_or('?')
    }

    /// Update the call state
    pub fn set_state(&mut self, state: OutgoingCallState) {
        self.state = state;
    }

    /// Check if the call is still active (not ended)
    pub fn is_active(&self) -> bool {
        matches!(
            self.state,
            OutgoingCallState::Initiating
                | OutgoingCallState::Ringing
                | OutgoingCallState::Connected
        )
    }

    /// Get a status message for display
    pub fn status_message(&self) -> &'static str {
        match self.state {
            OutgoingCallState::Initiating => "Calling...",
            OutgoingCallState::Ringing => "Ringing...",
            OutgoingCallState::Connected => "Connected",
            OutgoingCallState::Declined => "Call declined",
            OutgoingCallState::Timeout => "No answer",
        }
    }
}

/// Incoming call information
#[derive(Debug, Clone)]
pub struct IncomingCall {
    /// Unique call ID (using wacore's CallId type)
    pub call_id: CallId,
    /// Caller display name
    pub caller_name: String,
    /// Caller JID
    pub caller_jid: String,
    /// Whether this is a video call
    pub is_video: bool,
    /// Whether this call was received during offline sync (stale call)
    pub is_offline: bool,
    /// When the call was received
    pub received_at: DateTime<Utc>,
}

impl IncomingCall {
    /// Create a new incoming call
    pub fn new(
        call_id: impl Into<CallId>,
        caller_jid: String,
        is_video: bool,
        is_offline: bool,
    ) -> Self {
        let caller_name = caller_jid
            .split('@')
            .next()
            .unwrap_or(&caller_jid)
            .to_string();

        Self {
            call_id: call_id.into(),
            caller_name,
            caller_jid,
            is_video,
            is_offline,
            received_at: Utc::now(),
        }
    }

    /// Create with a custom caller name
    pub fn with_name(
        call_id: impl Into<CallId>,
        caller_name: String,
        caller_jid: String,
        is_video: bool,
        is_offline: bool,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            caller_name,
            caller_jid,
            is_video,
            is_offline,
            received_at: Utc::now(),
        }
    }

    /// Get the initial letter for avatar display
    pub fn initial(&self) -> char {
        self.caller_name.chars().next().unwrap_or('?')
    }
}

/// Active call information
#[derive(Debug, Clone)]
pub struct ActiveCall {
    /// Unique call ID (using wacore's CallId type)
    pub call_id: CallId,
    /// Peer display name
    pub peer_name: String,
    /// Peer JID
    pub peer_jid: String,
    /// Whether this is a video call
    pub is_video: bool,
    /// Whether local audio is muted
    pub is_muted: bool,
    /// When the call started
    pub started_at: DateTime<Utc>,
}

impl ActiveCall {
    /// Create a new active call from an incoming call
    pub fn from_incoming(call: IncomingCall) -> Self {
        Self {
            call_id: call.call_id,
            peer_name: call.caller_name,
            peer_jid: call.caller_jid,
            is_video: call.is_video,
            is_muted: false,
            started_at: Utc::now(),
        }
    }

    /// Toggle mute state
    pub fn toggle_mute(&mut self) {
        self.is_muted = !self.is_muted;
    }

    /// Get call duration in seconds
    pub fn duration_secs(&self) -> i64 {
        Utc::now()
            .signed_duration_since(self.started_at)
            .num_seconds()
    }

    /// Get formatted duration string (MM:SS)
    pub fn duration_formatted(&self) -> String {
        let total_secs = self.duration_secs();
        let minutes = total_secs / 60;
        let seconds = total_secs % 60;
        format!("{:02}:{:02}", minutes, seconds)
    }

    /// Get the initial letter for avatar display
    pub fn initial(&self) -> char {
        self.peer_name.chars().next().unwrap_or('?')
    }
}
