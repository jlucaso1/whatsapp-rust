use crate::signal::{
    ecc,
    groups::ratchet::{sender_chain_key::SenderChainKey, sender_message_key::SenderMessageKey},
};
use serde::{Deserialize, Serialize};

const MAX_MESSAGE_KEYS: usize = 2000;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SenderKeyState {
    key_id: u32,
    sender_chain_key: SenderChainKey,
    signing_key: ecc::key_pair::EcKeyPair,
    message_keys: Vec<SenderMessageKey>,
}

impl SenderKeyState {
    pub fn new(
        key_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signing_key: ecc::key_pair::EcKeyPair,
    ) -> Self {
        Self {
            key_id,
            sender_chain_key: SenderChainKey::new(iteration, chain_key),
            signing_key,
            message_keys: Vec::new(),
        }
    }

    pub fn new_from_public_key(
        key_id: u32,
        iteration: u32,
        chain_key: &[u8],
        signature_key: ecc::keys::DjbEcPublicKey,
    ) -> Self {
        let key_pair = ecc::key_pair::EcKeyPair {
            public_key: signature_key,
            private_key: ecc::keys::DjbEcPrivateKey::new([0; 32]), // Private key is not available here
        };
        Self::new(key_id, iteration, chain_key, key_pair)
    }

    pub fn key_id(&self) -> u32 {
        self.key_id
    }

    pub fn sender_chain_key(&self) -> &SenderChainKey {
        &self.sender_chain_key
    }

    pub fn set_sender_chain_key(&mut self, sender_chain_key: SenderChainKey) {
        self.sender_chain_key = sender_chain_key;
    }

    pub fn signing_key(&self) -> &ecc::key_pair::EcKeyPair {
        &self.signing_key
    }

    pub fn add_sender_message_key(&mut self, key: SenderMessageKey) {
        self.message_keys.push(key);
        if self.message_keys.len() > MAX_MESSAGE_KEYS {
            self.message_keys.remove(0);
        }
    }

    pub fn remove_sender_message_key(&mut self, iteration: u32) -> Option<SenderMessageKey> {
        if let Some(pos) = self
            .message_keys
            .iter()
            .position(|k| k.iteration() == iteration)
        {
            return self.message_keys.get(pos).cloned();
        }
        None
    }
}
