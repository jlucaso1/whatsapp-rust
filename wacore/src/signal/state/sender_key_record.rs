use crate::signal::ecc::key_pair::EcKeyPair;
use serde::{Deserialize, Serialize};
use waproto::whatsapp as wa;

type SenderKeyStateStructure = wa::SenderKeyStateStructure;
type SenderMessageKeyStructure = wa::sender_key_state_structure::SenderMessageKey;

const MAX_STATES: usize = 5;
const MAX_MESSAGE_KEYS: usize = 2000;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct SenderKeyRecord {
    sender_key_states: Vec<SenderKeyStateStructure>,
}

impl SenderKeyRecord {
    pub fn new() -> Self {
        Self {
            sender_key_states: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.sender_key_states.is_empty()
    }

    pub fn sender_key_state(&self) -> Option<&SenderKeyStateStructure> {
        self.sender_key_states.first()
    }

    pub fn get_sender_key_state_mut(&mut self) -> Option<&mut SenderKeyStateStructure> {
        self.sender_key_states.first_mut()
    }

    pub fn get_sender_key_state_by_id(&self, key_id: u32) -> Option<&SenderKeyStateStructure> {
        self.sender_key_states
            .iter()
            .find(|s| s.sender_key_id == Some(key_id))
    }

    pub fn get_sender_key_state_by_id_mut(
        &mut self,
        key_id: u32,
    ) -> Option<&mut SenderKeyStateStructure> {
        self.sender_key_states
            .iter_mut()
            .find(|s| s.sender_key_id == Some(key_id))
    }

    pub fn add_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signing_key_pub: &[u8],
    ) {
        // Normalize: If the key is 33 bytes and starts with DJB_TYPE (0x05), strip the prefix.
        let pub_key_to_store = if signing_key_pub.len() == 33
            && signing_key_pub[0] == crate::signal::ecc::keys::DJB_TYPE
        {
            &signing_key_pub[1..]
        } else {
            signing_key_pub
        };

        // Check if we already have this public key (i.e., it's our own from a linked device)
        for state in self.sender_key_states.iter_mut() {
            if let Some(signing_key) = &state.sender_signing_key {
                if let Some(public) = &signing_key.public {
                    if public.as_slice() == pub_key_to_store {
                        // It's our key. Just update the chain, don't create a new state.
                        state.sender_chain_key =
                            Some(wa::sender_key_state_structure::SenderChainKey {
                                iteration: Some(iteration),
                                seed: Some(chain_key.to_vec()),
                            });
                        state.sender_key_id = Some(id);
                        state.sender_message_keys.clear();
                        return;
                    }
                }
            }
        }

        // It's a key from another participant. Create a new state without a private key.
        let new_state = SenderKeyStateStructure {
            sender_key_id: Some(id),
            sender_chain_key: Some(wa::sender_key_state_structure::SenderChainKey {
                iteration: Some(iteration),
                seed: Some(chain_key.to_vec()),
            }),
            sender_signing_key: Some(wa::sender_key_state_structure::SenderSigningKey {
                public: Some(pub_key_to_store.to_vec()),
                private: None,
            }),
            sender_message_keys: Vec::new(),
        };
        self.sender_key_states.insert(0, new_state);
        self.sender_key_states.truncate(MAX_STATES);
    }

    pub fn set_sender_key_state(
        &mut self,
        id: u32,
        iteration: u32,
        chain_key: &[u8],
        signing_key: EcKeyPair,
    ) {
        let new_state = SenderKeyStateStructure {
            sender_key_id: Some(id),
            sender_chain_key: Some(wa::sender_key_state_structure::SenderChainKey {
                iteration: Some(iteration),
                seed: Some(chain_key.to_vec()),
            }),
            sender_signing_key: Some(wa::sender_key_state_structure::SenderSigningKey {
                public: Some(signing_key.public_key.public_key.to_vec()),
                private: Some(signing_key.private_key.private_key.to_vec()),
            }),
            sender_message_keys: Vec::new(),
        };
        self.sender_key_states.clear();
        self.sender_key_states.push(new_state);
    }

    pub fn add_sender_message_key(
        state: &mut SenderKeyStateStructure,
        key: SenderMessageKeyStructure,
    ) {
        state.sender_message_keys.push(key);
        if state.sender_message_keys.len() > MAX_MESSAGE_KEYS {
            state.sender_message_keys.remove(0);
        }
    }
}
