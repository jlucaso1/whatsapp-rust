use crate::crypto::hkdf;
use serde::{Deserialize, Serialize};

const KDF_INFO: &str = "WhisperGroup";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SenderMessageKey {
    iteration: u32,
    iv: [u8; 16],
    cipher_key: [u8; 32],
}

impl SenderMessageKey {
    pub fn new(iteration: u32, seed: &[u8]) -> Self {
        let derivative = hkdf::sha256(seed, None, KDF_INFO.as_bytes(), 48).unwrap();
        Self {
            iteration,
            iv: derivative[0..16].try_into().unwrap(),
            cipher_key: derivative[16..48].try_into().unwrap(),
        }
    }

    pub fn iteration(&self) -> u32 {
        self.iteration
    }

    pub fn iv(&self) -> &[u8] {
        &self.iv
    }

    pub fn cipher_key(&self) -> &[u8] {
        &self.cipher_key
    }
}
