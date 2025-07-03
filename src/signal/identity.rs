use super::ecc::key_pair::EcKeyPair;
use super::ecc::keys::EcPublicKey;
use std::sync::Arc;

// Corresponds to keys/identity/IdentityKey.go
#[derive(Clone)]
pub struct IdentityKey {
    public_key: Arc<dyn EcPublicKey>,
}

impl IdentityKey {
    pub fn new(public_key: Arc<dyn EcPublicKey>) -> Self {
        Self { public_key }
    }

    pub fn public_key(&self) -> Arc<dyn EcPublicKey> {
        self.public_key.clone()
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.public_key.serialize()
    }
}

// Corresponds to keys/identity/IdentityKeyPair.go
#[derive(Clone)]
pub struct IdentityKeyPair {
    pub public_key: IdentityKey,
    pub private_key: EcKeyPair,
}

impl IdentityKeyPair {
    pub fn new(public_key: IdentityKey, private_key: EcKeyPair) -> Self {
        Self {
            public_key,
            private_key,
        }
    }
}
