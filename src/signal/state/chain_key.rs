use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::signal::{kdf, message_key::MessageKeys};

const MESSAGE_KEY_SEED: &[u8] = &[0x01];
const CHAIN_KEY_SEED: &[u8] = &[0x02];

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ChainKey {
    key: [u8; 32],
    index: u32,
}

impl ChainKey {
    pub fn new(key: [u8; 32], index: u32) -> Self {
        Self { key, index }
    }

    pub fn key(&self) -> [u8; 32] {
        self.key
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn message_keys(&self) -> MessageKeys {
        let mk = kdf::derive_secrets(&self.key, Some(MESSAGE_KEY_SEED), b"MessageKeys", 80)
            .expect("KDF failed for message keys");
        let cipher_key = mk[0..32].to_vec();
        let mac_key = mk[32..64].to_vec();
        let iv = mk[64..80].to_vec();
        MessageKeys::new(cipher_key, mac_key, iv, self.index)
    }

    pub fn next_key(&self) -> Self {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(CHAIN_KEY_SEED);
        let result = mac.finalize().into_bytes();
        ChainKey {
            key: result[..32].try_into().unwrap(),
            index: self.index + 1,
        }
    }
}
