pub const DJB_TYPE: u8 = 0x05;

use serde::{Deserialize, Serialize};
// Corresponds to ECPublicKeyable
pub trait EcPublicKey: Send + Sync + std::fmt::Debug {
    fn serialize(&self) -> Vec<u8>;
    fn q_type(&self) -> u8;
    fn as_any(&self) -> &dyn std::any::Any;
    fn public_key(&self) -> [u8; 32];
}

// Corresponds to ECPrivateKeyable
pub trait EcPrivateKey: Send + Sync + std::fmt::Debug {
    fn serialize(&self) -> [u8; 32];
    fn q_type(&self) -> u8;
}

// Corresponds to DjbECPublicKey
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct DjbEcPublicKey {
    pub public_key: [u8; 32],
}

impl DjbEcPublicKey {
    pub fn new(public_key: [u8; 32]) -> Self {
        Self { public_key }
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.public_key
    }
}

impl EcPublicKey for DjbEcPublicKey {
    fn serialize(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(33);
        v.push(DJB_TYPE);
        v.extend_from_slice(&self.public_key);
        v
    }

    fn q_type(&self) -> u8 {
        DJB_TYPE
    }

    fn public_key(&self) -> [u8; 32] {
        self.public_key
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct DjbEcPrivateKey {
    private_key: [u8; 32],
}

impl DjbEcPrivateKey {
    pub fn new(private_key: [u8; 32]) -> Self {
        Self { private_key }
    }
}

impl EcPrivateKey for DjbEcPrivateKey {
    fn serialize(&self) -> [u8; 32] {
        self.private_key
    }

    fn q_type(&self) -> u8 {
        DJB_TYPE
    }
}
