use crate::signal::ecc::key_pair::EcKeyPair;
use crate::signal::ecc::keys::{DjbEcPrivateKey, DjbEcPublicKey};
use chrono::Utc;
// Correctly import from the new crate
use waproto::whatsapp as wa;

// Helper functions for PreKeyRecordStructure and SignedPreKeyRecordStructure

pub fn new_pre_key_record(id: u32, key_pair: EcKeyPair) -> wa::PreKeyRecordStructure {
    wa::PreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key.to_vec()),
        private_key: Some(key_pair.private_key.private_key.to_vec()),
    }
}

pub fn pre_key_record_key_pair(record: &wa::PreKeyRecordStructure) -> EcKeyPair {
    let public_bytes: [u8; 32] = record
        .public_key()
        .try_into()
        .expect("invalid public key length in PreKeyRecordStructure");

    let private_bytes: [u8; 32] = record
        .private_key()
        .try_into()
        .expect("invalid private key length in PreKeyRecordStructure");

    EcKeyPair::new(
        DjbEcPublicKey::new(public_bytes),
        DjbEcPrivateKey::new(private_bytes),
    )
}

pub fn new_signed_pre_key_record(
    id: u32,
    key_pair: EcKeyPair,
    signature: [u8; 64],
    timestamp: chrono::DateTime<Utc>,
) -> wa::SignedPreKeyRecordStructure {
    wa::SignedPreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key.to_vec()),
        private_key: Some(key_pair.private_key.private_key.to_vec()),
        signature: Some(signature.to_vec()),
        timestamp: Some(timestamp.timestamp().try_into().unwrap()),
    }
}

pub fn signed_pre_key_record_key_pair(record: &wa::SignedPreKeyRecordStructure) -> EcKeyPair {
    let public_bytes: [u8; 32] = record
        .public_key()
        .try_into()
        .expect("invalid public key length in SignedPreKeyRecordStructure");

    let private_bytes: [u8; 32] = record
        .private_key()
        .try_into()
        .expect("invalid private key length in SignedPreKeyRecordStructure");

    EcKeyPair::new(
        DjbEcPublicKey::new(public_bytes),
        DjbEcPrivateKey::new(private_bytes),
    )
}
