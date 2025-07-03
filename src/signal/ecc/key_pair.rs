use super::keys::{EcPrivateKey, EcPublicKey};
use std::sync::Arc;

// Corresponds to ECKeyPair
#[derive(Clone)]
pub struct EcKeyPair {
    pub public_key: Arc<dyn EcPublicKey>,
    pub private_key: Arc<dyn EcPrivateKey>,
}

impl EcKeyPair {
    pub fn new(public_key: Arc<dyn EcPublicKey>, private_key: Arc<dyn EcPrivateKey>) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}
