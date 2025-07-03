use super::keys::{DjbEcPrivateKey, DjbEcPublicKey};
use serde::{Deserialize, Serialize};

// Refactored to use concrete key types for serialization
#[derive(Serialize, Deserialize, Clone)]
pub struct EcKeyPair {
    pub public_key: DjbEcPublicKey,
    pub private_key: DjbEcPrivateKey,
}

impl EcKeyPair {
    pub fn new(public_key: DjbEcPublicKey, private_key: DjbEcPrivateKey) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}
