pub const DERIVED_SECRETS_SIZE: usize = 80;
pub const KDF_SALT: &str = "WhisperMessageKeys";

use serde::{Deserialize, Serialize};
// Corresponds to keys/message/MessageKey.go
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MessageKeys {
    cipher_key: Vec<u8>,
    mac_key: Vec<u8>,
    iv: Vec<u8>,
    index: u32,
}

impl MessageKeys {
    pub fn new(cipher_key: Vec<u8>, mac_key: Vec<u8>, iv: Vec<u8>, index: u32) -> Self {
        Self {
            cipher_key,
            mac_key,
            iv,
            index,
        }
    }

    pub fn cipher_key(&self) -> &[u8] {
        &self.cipher_key
    }
    pub fn mac_key(&self) -> &[u8] {
        &self.mac_key
    }
    pub fn iv(&self) -> &[u8] {
        &self.iv
    }
    pub fn index(&self) -> u32 {
        self.index
    }
}
