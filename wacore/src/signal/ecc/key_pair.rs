use super::keys::{DjbEcPrivateKey, DjbEcPublicKey, EcPrivateKey, EcPublicKey};
use serde::{Deserialize, Serialize};

// Refactored to use concrete key types for serialization
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
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

    pub fn public_key(&self) -> &impl EcPublicKey {
        &self.public_key
    }
    pub fn private_key(&self) -> &impl EcPrivateKey {
        &self.private_key
    }
}
