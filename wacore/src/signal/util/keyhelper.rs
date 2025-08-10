use crate::signal::state::record;
use chrono::Utc;
use libsignal_protocol::IdentityKeyPair;
use libsignal_protocol::KeyPair;
use rand::{Rng, TryRngCore, rng, rngs::OsRng};
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

pub fn generate_identity_key_pair() -> IdentityKeyPair {
    IdentityKeyPair::generate(&mut OsRng.unwrap_err())
}

pub fn generate_pre_keys(start: u32, count: u32) -> Vec<PreKeyRecordStructure> {
    let mut pre_keys = Vec::with_capacity(count as usize);
    for i in start..start + count {
        let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
        pre_keys.push(record::new_pre_key_record(i, &key_pair));
    }
    pre_keys
}

pub fn generate_signed_pre_key(
    identity_key_pair: &IdentityKeyPair,
    signed_pre_key_id: u32,
) -> SignedPreKeyRecordStructure {
    let key_pair = KeyPair::generate(&mut OsRng.unwrap_err());
    let public_key_bytes = key_pair.public_key.serialize();
    let signature_box = identity_key_pair
        .private_key()
        .calculate_signature(&public_key_bytes, &mut OsRng.unwrap_err())
        .expect("Failed to calculate signature for signed pre-key");

    let signature: [u8; 64] = signature_box
        .as_ref()
        .try_into()
        .expect("Signature was not 64 bytes");
    let timestamp = Utc::now();
    record::new_signed_pre_key_record(signed_pre_key_id, &key_pair, signature, timestamp)
}

pub fn generate_sender_signing_key() -> KeyPair {
    KeyPair::generate(&mut OsRng.unwrap_err())
}

pub fn generate_sender_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    OsRng
        .try_fill_bytes(&mut key[..])
        .expect("CSPRNG failure for sender key");
    key
}

pub fn generate_sender_key_id() -> u32 {
    rng().random::<u32>()
}

pub fn generate_registration_id() -> u32 {
    rng().random_range(1..=16380)
}
