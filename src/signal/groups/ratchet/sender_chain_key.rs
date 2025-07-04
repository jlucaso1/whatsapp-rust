use super::sender_message_key::SenderMessageKey;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

const MESSAGE_KEY_SEED: &[u8] = &[0x01];
const CHAIN_KEY_SEED: &[u8] = &[0x02];

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SenderChainKey {
    iteration: u32,
    chain_key: [u8; 32],
}

impl SenderChainKey {
    pub fn new(iteration: u32, chain_key: &[u8]) -> Self {
        Self {
            iteration,
            chain_key: chain_key.try_into().unwrap(),
        }
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn sender_message_key(&self) -> SenderMessageKey {
        SenderMessageKey::new(self.iteration, &self.get_derivative(MESSAGE_KEY_SEED))
    }

    pub fn next(&self) -> Self {
        Self::new(self.iteration + 1, &self.get_derivative(CHAIN_KEY_SEED))
    }

    fn get_derivative(&self, seed: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.chain_key).unwrap();
        mac.update(seed);
        mac.finalize().into_bytes().into()
    }
}
