// src/signal/state/prekey_record.rs
use crate::signal::ecc::key_pair::EcKeyPair;

// Corresponds to state/record/PreKeyRecord.go
#[derive(Clone)]
pub struct PreKeyRecord {
    id: u32,
    key_pair: EcKeyPair,
}

impl PreKeyRecord {
    pub fn new(id: u32, key_pair: EcKeyPair) -> Self {
        Self { id, key_pair }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn key_pair(&self) -> &EcKeyPair {
        &self.key_pair
    }
}
