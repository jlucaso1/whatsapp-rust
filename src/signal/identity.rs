use super::ecc::key_pair::EcKeyPair;
use super::ecc::keys::{DjbEcPublicKey, EcPublicKey};
use serde::{Deserialize, Serialize};

// Corresponds to keys/identity/IdentityKey.go
#[derive(Serialize, Deserialize, Clone)]
pub struct IdentityKey {
    public_key: DjbEcPublicKey,
}

impl IdentityKey {
    pub fn new(public_key: DjbEcPublicKey) -> Self {
        Self { public_key }
    }

    pub fn public_key(&self) -> DjbEcPublicKey {
        self.public_key.clone()
    }

    pub fn serialize(&self) -> Vec<u8> {
        EcPublicKey::serialize(&self.public_key)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, crate::signal::protocol::ProtocolError> {
        // Directly parse as DjbEcPublicKey
        if bytes.is_empty() || bytes[0] != crate::signal::ecc::keys::DJB_TYPE {
            return Err(crate::signal::ecc::curve::CurveError::BadKeyType(0).into());
        }
        let key_bytes: [u8; 32] = bytes[1..].try_into().map_err(|_| {
            crate::signal::protocol::ProtocolError::InvalidKey(
                crate::signal::ecc::curve::CurveError::BadKeyType(0),
            )
        })?;
        Ok(IdentityKey::new(
            crate::signal::ecc::keys::DjbEcPublicKey::new(key_bytes),
        ))
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
