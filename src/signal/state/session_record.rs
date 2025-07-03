// src/signal/state/session_record.rs
use super::session_state::SessionState;
use std::collections::VecDeque;

const MAX_ARCHIVED_STATES: usize = 40;

// Corresponds to state/record/SessionRecord.go
pub struct SessionRecord {
    session_state: SessionState,
    previous_states: VecDeque<SessionState>,
}

impl SessionRecord {
    pub fn new() -> Self {
        Self {
            session_state: SessionState::new(),
            previous_states: VecDeque::with_capacity(MAX_ARCHIVED_STATES),
        }
    }

    pub fn session_state(&self) -> &SessionState {
        &self.session_state
    }

    pub fn session_state_mut(&mut self) -> &mut SessionState {
        &mut self.session_state
    }

    pub fn archive_current_state(&mut self) {
        let new_state = SessionState::new();
        let old_state = std::mem::replace(&mut self.session_state, new_state);

        if self.previous_states.len() >= MAX_ARCHIVED_STATES {
            self.previous_states.pop_front();
        }
        self.previous_states.push_back(old_state);
    }
}

impl Default for SessionRecord {
    fn default() -> Self {
        Self::new()
    }
}
