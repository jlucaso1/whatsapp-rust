use crate::proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};
use crate::signal::ecc::key_pair::EcKeyPair;
use crate::signal::ecc::keys::{DjbEcPrivateKey, DjbEcPublicKey};
use chrono::Utc;

impl PreKeyRecordStructure {
    pub fn new(id: u32, key_pair: EcKeyPair) -> Self {
        Self {
            id: Some(id),
            public_key: Some(key_pair.public_key.public_key.to_vec()),
            private_key: Some(key_pair.private_key.private_key.to_vec()),
        }
    }

    pub fn key_pair(&self) -> EcKeyPair {
        let public_bytes: [u8; 32] = self
            .public_key()
            .try_into()
            .expect("invalid public key length in PreKeyRecordStructure");

        let private_bytes: [u8; 32] = self
            .private_key()
            .try_into()
            .expect("invalid private key length in PreKeyRecordStructure");

        EcKeyPair::new(
            DjbEcPublicKey::new(public_bytes),
            DjbEcPrivateKey::new(private_bytes),
        )
    }
}

impl SignedPreKeyRecordStructure {
    pub fn new(
        id: u32,
        key_pair: EcKeyPair,
        signature: [u8; 64],
        timestamp: chrono::DateTime<Utc>,
    ) -> Self {
        Self {
            id: Some(id),
            public_key: Some(key_pair.public_key.public_key.to_vec()),
            private_key: Some(key_pair.private_key.private_key.to_vec()),
            signature: Some(signature.to_vec()),
            timestamp: Some(timestamp.timestamp().try_into().unwrap()),
        }
    }

    pub fn key_pair(&self) -> EcKeyPair {
        let public_bytes: [u8; 32] = self
            .public_key()
            .try_into()
            .expect("invalid public key length in SignedPreKeyRecordStructure");

        let private_bytes: [u8; 32] = self
            .private_key()
            .try_into()
            .expect("invalid private key length in SignedPreKeyRecordStructure");

        EcKeyPair::new(
            DjbEcPublicKey::new(public_bytes),
            DjbEcPrivateKey::new(private_bytes),
        )
    }
}

pub use super::session_record::*;
pub use super::session_state::*;
