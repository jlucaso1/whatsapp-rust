// src/signal/state/pending_key_exchange_state.rs
// Corresponds to libsignal-protocol-go/state/record/PendingKeyExchangeState.go

use crate::signal::ecc::key_pair::EcKeyPair;
use crate::signal::identity::IdentityKeyPair;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PendingKeyExchange {
    sequence: u32,
    local_base_key_pair: EcKeyPair,
    local_ratchet_key_pair: EcKeyPair,
    local_identity_key_pair: IdentityKeyPair,
}

impl PendingKeyExchange {
    pub fn new(
        sequence: u32,
        local_base_key_pair: EcKeyPair,
        local_ratchet_key_pair: EcKeyPair,
        local_identity_key_pair: IdentityKeyPair,
    ) -> Self {
        Self {
            sequence,
            local_base_key_pair,
            local_ratchet_key_pair,
            local_identity_key_pair,
        }
    }

    pub fn sequence(&self) -> u32 {
        self.sequence
    }
    pub fn local_base_key_pair(&self) -> &EcKeyPair {
        &self.local_base_key_pair
    }
    pub fn local_ratchet_key_pair(&self) -> &EcKeyPair {
        &self.local_ratchet_key_pair
    }
    pub fn local_identity_key_pair(&self) -> &IdentityKeyPair {
        &self.local_identity_key_pair
    }
}
