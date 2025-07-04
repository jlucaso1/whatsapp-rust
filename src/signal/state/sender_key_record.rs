use super::sender_key_state::SenderKeyState;
use crate::signal::ecc;
use crate::signal::ecc::key_pair::EcKeyPair;
use serde::{Deserialize, Serialize};

const MAX_STATES: usize = 5;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SenderKeyRecord {
    sender_key_states: Vec<SenderKeyState>,
}

impl SenderKeyRecord {
    pub fn new() -> Self {
        Self {
            sender_key_states: Vec::with_capacity(MAX_STATES),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sender_key_states.is_empty()
    }

    pub fn sender_key_state(&self) -> Option<&SenderKeyState> {
        self.sender_key_states.first()
    }

    pub fn get_sender_key_state_mut(&mut self) -> Option<&mut SenderKeyState> {
        self.sender_key_states.first_mut()
    }

    pub fn get_sender_key_state_by_id(&self, key_id: u32) -> Option<&SenderKeyState> {
        self.sender_key_states.iter().find(|s| s.key_id() == key_id)
    }

    pub fn get_sender_key_state_by_id_mut(&mut self, key_id: u32) -> Option<&mut SenderKeyState> {
        self.sender_key_states
            .iter_mut()
            .find(|s| s.key_id() == key_id)
    }

    pub fn add_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: ecc::keys::DjbEcPublicKey,
    ) {
        let new_state =
            SenderKeyState::new_from_public_key(id, iteration, chain_key, signature_key);
        self.sender_key_states.insert(0, new_state);
        self.sender_key_states.truncate(MAX_STATES);
    }

    pub fn set_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: EcKeyPair,
    ) {
        let new_state = SenderKeyState::new(id, iteration, chain_key, signature_key);
        self.sender_key_states.clear();
        self.sender_key_states.push(new_state);
    }
}
