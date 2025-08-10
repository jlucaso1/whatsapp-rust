use chrono::Utc;
use libsignal_protocol::{KeyPair, PrivateKey, PublicKey};
use waproto::whatsapp as wa;

pub fn new_pre_key_record(id: u32, key_pair: &KeyPair) -> wa::PreKeyRecordStructure {
    wa::PreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key_bytes().to_vec()),
        private_key: Some(key_pair.private_key.serialize()),
    }
}

pub fn pre_key_record_key_pair(record: &wa::PreKeyRecordStructure) -> KeyPair {
    let public_bytes = record.public_key();
    let private_bytes = record.private_key();

    let public_key = PublicKey::from_djb_public_key_bytes(public_bytes)
        .expect("invalid public key in PreKeyRecordStructure");
    let private_key = PrivateKey::deserialize(private_bytes)
        .expect("invalid private key in PreKeyRecordStructure");

    KeyPair::new(public_key, private_key)
}

pub fn new_signed_pre_key_record(
    id: u32,
    key_pair: &KeyPair,
    signature: [u8; 64],
    timestamp: chrono::DateTime<Utc>,
) -> wa::SignedPreKeyRecordStructure {
    wa::SignedPreKeyRecordStructure {
        id: Some(id),
        public_key: Some(key_pair.public_key.public_key_bytes().to_vec()),
        private_key: Some(key_pair.private_key.serialize()),
        signature: Some(signature.to_vec()),
        timestamp: Some(timestamp.timestamp().try_into().unwrap()),
    }
}

pub fn signed_pre_key_record_key_pair(record: &wa::SignedPreKeyRecordStructure) -> KeyPair {
    let public_bytes = record.public_key();
    let private_bytes = record.private_key();

    let public_key = PublicKey::from_djb_public_key_bytes(public_bytes)
        .expect("invalid public key in SignedPreKeyRecordStructure");
    let private_key = PrivateKey::deserialize(private_bytes)
        .expect("invalid private key in SignedPreKeyRecordStructure");

    KeyPair::new(public_key, private_key)
}
