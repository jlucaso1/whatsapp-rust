use crate::libsignal::core::curve::{KeyPair, PrivateKey, PublicKey};
use crate::libsignal::protocol::SignalProtocolError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityKey {
    public_key: PublicKey,
}

impl IdentityKey {
    pub fn new(public_key: PublicKey) -> Self {
        Self { public_key }
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        Ok(Self {
            public_key: PublicKey::deserialize(bytes)?,
        })
    }

    pub fn serialize(&self) -> Box<[u8]> {
        self.public_key.serialize()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityKeyPair {
    public_key: IdentityKey,
    private_key: PrivateKey,
}

impl IdentityKeyPair {
    pub fn new(identity_key: IdentityKey, private_key: PrivateKey) -> Self {
        Self {
            public_key: identity_key,
            private_key,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, SignalProtocolError> {
        let private_key = PrivateKey::deserialize(bytes)?;
        let public_key = private_key.to_public_key()?;
        Ok(Self {
            public_key: IdentityKey::new(public_key),
            private_key,
        })
    }

    pub fn identity_key(&self) -> &IdentityKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }

    pub fn to_keypair(self) -> KeyPair {
        KeyPair::new(self.public_key.public_key, self.private_key)
    }

    pub fn serialize(&self) -> Vec<u8> {
        self.private_key.serialize()
    }
}