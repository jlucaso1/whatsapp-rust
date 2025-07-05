use crate::signal::ecc::key_pair::EcKeyPair;
use crate::signal::ecc::keys::{DjbEcPrivateKey, DjbEcPublicKey};
use chrono::Utc;
// Correctly import from the new crate
use whatsapp_proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

// 1. Define the extension trait for PreKeyRecordStructure
pub trait PreKeyRecordStructureExt {
    fn new(id: u32, key_pair: EcKeyPair) -> Self;
    fn key_pair(&self) -> EcKeyPair;
}

// 2. Implement the trait for the foreign type
impl PreKeyRecordStructureExt for PreKeyRecordStructure {
    fn new(id: u32, key_pair: EcKeyPair) -> Self {
        Self {
            id: Some(id),
            public_key: Some(key_pair.public_key.public_key.to_vec()),
            private_key: Some(key_pair.private_key.private_key.to_vec()),
        }
    }

    fn key_pair(&self) -> EcKeyPair {
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

// 3. Do the same for SignedPreKeyRecordStructure
pub trait SignedPreKeyRecordStructureExt {
    fn new(
        id: u32,
        key_pair: EcKeyPair,
        signature: [u8; 64],
        timestamp: chrono::DateTime<Utc>,
    ) -> Self;
    fn key_pair(&self) -> EcKeyPair;
}

impl SignedPreKeyRecordStructureExt for SignedPreKeyRecordStructure {
    fn new(
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

    fn key_pair(&self) -> EcKeyPair {
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
