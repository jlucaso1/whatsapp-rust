// src/signal/state/signed_prekey_record.rs
use crate::signal::ecc::key_pair::EcKeyPair;
use chrono::{DateTime, Utc};

// Corresponds to state/record/SignedPreKeyRecord.go
#[derive(Clone)]
pub struct SignedPreKeyRecord {
    id: u32,
    key_pair: EcKeyPair,
    signature: [u8; 64],
    timestamp: DateTime<Utc>,
}

impl SignedPreKeyRecord {
    pub fn new(
        id: u32,
        key_pair: EcKeyPair,
        signature: [u8; 64],
        timestamp: DateTime<Utc>,
    ) -> Self {
        Self {
            id,
            key_pair,
            signature,
            timestamp,
        }
    }

    pub fn id(&self) -> u32 {
        self.id
    }

    pub fn key_pair(&self) -> &EcKeyPair {
        &self.key_pair
    }

    pub fn signature(&self) -> [u8; 64] {
        self.signature
    }
}
