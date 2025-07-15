use crate::crypto::hkdf::sha256;
use crate::signal::state::sender_key_record::SenderKeyRecord;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use thiserror::Error;
use waproto::whatsapp as wa;

const KDF_INFO: &str = "WhisperGroup";
const MESSAGE_KEY_SEED: &[u8] = &[0x01];
const CHAIN_KEY_SEED: &[u8] = &[0x02];

type SenderChainKeyStructure = wa::sender_key_state_structure::SenderChainKey;
type SenderMessageKeyStructure = wa::sender_key_state_structure::SenderMessageKey;
type SenderKeyStateStructure = wa::SenderKeyStateStructure;

#[derive(Debug, Error)]
pub enum RatchetError {
    #[error("old counter: current={current}, received={received}")]
    OldCounter { current: u32, received: u32 },
    #[error("message is too far in the future")]
    TooFarInFuture,
}

fn get_derivative(key: &[u8], seed: &[u8]) -> [u8; 32] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(seed);
    mac.finalize().into_bytes().into()
}

pub fn create_sender_message_key(iteration: u32, seed: &[u8]) -> SenderMessageKeyStructure {
    SenderMessageKeyStructure {
        iteration: Some(iteration),
        seed: Some(seed.to_vec()),
    }
}

pub fn get_sender_message_key(chain_key: &SenderChainKeyStructure) -> SenderMessageKeyStructure {
    let seed = get_derivative(chain_key.seed(), MESSAGE_KEY_SEED);
    create_sender_message_key(chain_key.iteration.unwrap_or(0), &seed)
}

pub fn get_next_sender_chain_key(chain_key: &SenderChainKeyStructure) -> SenderChainKeyStructure {
    let next_seed = get_derivative(chain_key.seed(), CHAIN_KEY_SEED);
    SenderChainKeyStructure {
        iteration: Some(chain_key.iteration.unwrap_or(0) + 1),
        seed: Some(next_seed.to_vec()),
    }
}

pub fn get_sender_key(
    state: &mut SenderKeyStateStructure,
    iteration: u32,
) -> Result<SenderMessageKeyStructure, RatchetError> {
    let chain_iter = state
        .sender_chain_key
        .as_ref()
        .and_then(|c| c.iteration)
        .unwrap_or(0);

    if chain_iter > iteration {
        if let Some(pos) = state
            .sender_message_keys
            .iter()
            .position(|k| k.iteration == Some(iteration))
        {
            return Ok(state.sender_message_keys.remove(pos));
        }
        return Err(RatchetError::OldCounter {
            current: chain_iter,
            received: iteration,
        });
    }

    if iteration - chain_iter > 2000 {
        return Err(RatchetError::TooFarInFuture);
    }

    // Avoid double mutable borrow: collect message keys to add
    let mut temp_chain_key = state
        .sender_chain_key
        .clone()
        .ok_or(RatchetError::TooFarInFuture)?;
    let mut keys_to_add = Vec::new();

    while temp_chain_key.iteration.unwrap_or(0) < iteration {
        keys_to_add.push(get_sender_message_key(&temp_chain_key));
        temp_chain_key = get_next_sender_chain_key(&temp_chain_key);
    }

    // Now update the real chain_key and state
    if let Some(chain_key) = state.sender_chain_key.as_mut() {
        *chain_key = temp_chain_key.clone();
    }
    for key in keys_to_add {
        SenderKeyRecord::add_sender_message_key(state, key);
    }

    let message_key = get_sender_message_key(
        state
            .sender_chain_key
            .as_ref()
            .ok_or(RatchetError::TooFarInFuture)?,
    );
    if let Some(chain_key) = state.sender_chain_key.as_mut() {
        *chain_key = get_next_sender_chain_key(chain_key);
    }
    Ok(message_key)
}

/// Helper to derive IV and cipher key from a SenderMessageKeyStructure
pub fn derive_message_key_material(msg_key: &SenderMessageKeyStructure) -> (Vec<u8>, Vec<u8>) {
    let seed = msg_key.seed.as_deref().unwrap_or(&[]);
    let derived = sha256(seed, None, KDF_INFO.as_bytes(), 48).unwrap();
    let iv = derived[0..16].to_vec();
    let cipher_key = derived[16..48].to_vec();
    (iv, cipher_key)
}
