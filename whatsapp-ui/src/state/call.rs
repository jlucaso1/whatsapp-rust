//! Call state structures for the UI.

use chrono::{DateTime, Utc};

pub use wacore::types::call::CallId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutgoingCallState {
    Initiating,
    Ringing,
    Connected,
    Declined,
    Timeout,
}

#[derive(Debug, Clone)]
pub struct OutgoingCall {
    pub call_id: CallId,
    pub recipient_name: String,
    pub recipient_jid: String,
    pub is_video: bool,
    pub state: OutgoingCallState,
    pub initiated_at: DateTime<Utc>,
}

impl OutgoingCall {
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

    pub fn initial(&self) -> char {
        self.recipient_name.chars().next().unwrap_or('?')
    }

    pub fn set_state(&mut self, state: OutgoingCallState) {
        self.state = state;
    }

    pub fn is_active(&self) -> bool {
        !matches!(
            self.state,
            OutgoingCallState::Declined | OutgoingCallState::Timeout
        )
    }

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

#[derive(Debug, Clone)]
pub struct IncomingCall {
    pub call_id: CallId,
    pub caller_name: String,
    pub caller_jid: String,
    pub is_video: bool,
    pub is_offline: bool,
    pub received_at: DateTime<Utc>,
}

impl IncomingCall {
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

    pub fn initial(&self) -> char {
        self.caller_name.chars().next().unwrap_or('?')
    }
}

#[derive(Debug, Clone)]
pub struct ActiveCall {
    pub call_id: CallId,
    pub peer_name: String,
    pub peer_jid: String,
    pub is_video: bool,
    pub is_muted: bool,
    pub started_at: DateTime<Utc>,
}

impl ActiveCall {
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

    pub fn toggle_mute(&mut self) {
        self.is_muted = !self.is_muted;
    }

    pub fn duration_secs(&self) -> i64 {
        Utc::now()
            .signed_duration_since(self.started_at)
            .num_seconds()
    }

    pub fn duration_formatted(&self) -> String {
        let total_secs = self.duration_secs();
        format!("{:02}:{:02}", total_secs / 60, total_secs % 60)
    }

    pub fn initial(&self) -> char {
        self.peer_name.chars().next().unwrap_or('?')
    }
}
