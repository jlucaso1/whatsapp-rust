pub mod sender_chain_key;
pub mod sender_message_key;

use crate::signal::{
    groups::ratchet::sender_message_key::SenderMessageKey, state::sender_key_state::SenderKeyState,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("old counter: current={current}, received={received}")]
    OldCounter { current: u32, received: u32 },
    #[error("message is too far in the future")]
    TooFarInFuture,
}

/// Corresponds to libsignal-protocol-go/groups/GroupCipher.go#getSenderKey
pub fn get_sender_key(
    state: &mut SenderKeyState,
    iteration: u32,
) -> Result<SenderMessageKey, RatchetError> {
    let mut sender_chain_key = state.sender_chain_key().clone();
    if sender_chain_key.iteration() > iteration {
        if let Some(key) = state.remove_sender_message_key(iteration) {
            return Ok(key);
        }
        return Err(RatchetError::OldCounter {
            current: sender_chain_key.iteration(),
            received: iteration,
        });
    }

    if iteration - sender_chain_key.iteration() > 2000 {
        return Err(RatchetError::TooFarInFuture);
    }

    while sender_chain_key.iteration() < iteration {
        state.add_sender_message_key(sender_chain_key.sender_message_key());
        sender_chain_key = sender_chain_key.next();
    }

    state.set_sender_chain_key(sender_chain_key.next());
    Ok(sender_chain_key.sender_message_key())
}
