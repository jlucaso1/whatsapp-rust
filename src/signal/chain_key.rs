use super::kdf::{self, KeyMaterial};
use super::message_key::{self, MessageKeys};
use hmac::{Hmac, Mac};
use sha2::Sha256;

const MESSAGE_KEY_SEED: &[u8] = &[0x01];
const CHAIN_KEY_SEED: &[u8] = &[0x02];

use serde::{Deserialize, Serialize};
// Corresponds to keys/chain/ChainKey.go
#[derive(Serialize, Deserialize, Clone, Debug)]
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

    pub fn next_key(&self) -> ChainKey {
        let next_key_bytes = self.base_material(CHAIN_KEY_SEED);
        ChainKey::new(next_key_bytes, self.index + 1)
    }

    pub fn message_keys(&self) -> MessageKeys {
        let input_key_material = self.base_material(MESSAGE_KEY_SEED);
        let key_material_bytes = kdf::derive_secrets(
            &input_key_material,
            None,
            message_key::KDF_SALT.as_bytes(),
            message_key::DERIVED_SECRETS_SIZE,
        )
        .unwrap(); // In a real implementation, handle this error

        let key_material = Self::new_key_material(&key_material_bytes);

        MessageKeys::new(
            key_material.cipher_key,
            key_material.mac_key,
            key_material.iv,
            self.index,
        )
    }

    fn base_material(&self, seed: &[u8]) -> [u8; 32] {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key).unwrap();
        mac.update(seed);
        mac.finalize().into_bytes().into()
    }

    fn new_key_material(key_material_bytes: &[u8]) -> KeyMaterial {
        KeyMaterial {
            cipher_key: key_material_bytes[0..32].to_vec(),
            mac_key: key_material_bytes[32..64].to_vec(),
            iv: key_material_bytes[64..80].to_vec(),
        }
    }
}
