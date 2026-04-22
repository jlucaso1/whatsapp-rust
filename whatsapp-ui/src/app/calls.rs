//! Call state management for the WhatsApp UI
//!
//! This module manages incoming and outgoing call state.

use crate::state::{CallId, IncomingCall, OutgoingCall, OutgoingCallState};

/// Unified call state management
#[derive(Default)]
pub struct CallState {
    /// Current incoming call (if any)
    incoming: Option<IncomingCall>,
    /// Current outgoing call (if any)
    outgoing: Option<OutgoingCall>,
}

impl CallState {
    /// Create a new call state
    pub fn new() -> Self {
        Self::default()
    }

    // ========== Incoming Call ==========

    /// Get the current incoming call (if any)
    pub fn incoming(&self) -> Option<&IncomingCall> {
        self.incoming.as_ref()
    }

    /// Set an incoming call
    pub fn set_incoming(&mut self, call: IncomingCall) {
        self.incoming = Some(call);
    }

    /// Take and clear the incoming call (for accept/decline)
    pub fn take_incoming(&mut self) -> Option<IncomingCall> {
        self.incoming.take()
    }

    /// Dismiss incoming call if it matches the given call ID
    pub fn dismiss_incoming(&mut self, call_id: &CallId) -> bool {
        self.incoming.take_if(|c| c.call_id == *call_id).is_some()
    }

    // ========== Outgoing Call ==========

    /// Get the current outgoing call (if any)
    pub fn outgoing(&self) -> Option<&OutgoingCall> {
        self.outgoing.as_ref()
    }

    /// Get the current outgoing call mutably
    pub fn outgoing_mut(&mut self) -> Option<&mut OutgoingCall> {
        self.outgoing.as_mut()
    }

    /// Check if there's an active outgoing call
    pub fn has_outgoing(&self) -> bool {
        self.outgoing.is_some()
    }

    /// Check if there's an active incoming call
    pub fn has_incoming(&self) -> bool {
        self.incoming.is_some()
    }

    /// Set an outgoing call
    pub fn set_outgoing(&mut self, call: OutgoingCall) {
        self.outgoing = Some(call);
    }

    /// Take and clear the outgoing call (for cancel)
    pub fn take_outgoing(&mut self) -> Option<OutgoingCall> {
        self.outgoing.take()
    }

    /// Dismiss outgoing call if it matches the given call ID
    pub fn dismiss_outgoing(&mut self, call_id: &CallId) -> bool {
        self.outgoing.take_if(|c| c.call_id == *call_id).is_some()
    }

    /// Update outgoing call state to connected
    pub fn set_outgoing_connected(&mut self, call_id: &CallId) -> bool {
        self.outgoing
            .as_mut()
            .filter(|c| c.call_id == *call_id)
            .map(|c| c.set_state(OutgoingCallState::Connected))
            .is_some()
    }

    /// Update outgoing call ID (when real ID comes from CallManager)
    pub fn update_outgoing_call_id(&mut self, recipient_jid: &str, new_call_id: CallId) -> bool {
        self.outgoing
            .as_mut()
            .filter(|c| c.recipient_jid == recipient_jid)
            .map(|c| c.call_id = new_call_id)
            .is_some()
    }

    /// Dismiss outgoing call for a recipient (on failure)
    pub fn dismiss_outgoing_for_recipient(&mut self, recipient_jid: &str) -> bool {
        self.outgoing
            .take_if(|c| c.recipient_jid == recipient_jid)
            .is_some()
    }
}
