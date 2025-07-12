// Corresponds to libsignal-protocol-go/util/keyhelper.go

use crate::signal::ecc;
use crate::signal::ecc::key_pair::EcKeyPair;
use crate::signal::ecc::keys::EcPublicKey;
use crate::signal::identity::{IdentityKey, IdentityKeyPair};
use crate::signal::state::record;
use chrono::Utc;
use rand::{Rng, rng};
use whatsapp_proto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

pub fn generate_identity_key_pair() -> IdentityKeyPair {
    let key_pair = ecc::curve::generate_key_pair();
    let public_key = IdentityKey::new(key_pair.public_key.clone());
    IdentityKeyPair::new(public_key, key_pair)
}

pub fn generate_pre_keys(start: u32, count: u32) -> Vec<PreKeyRecordStructure> {
    let mut pre_keys = Vec::with_capacity(count as usize);
    for i in start..start + count {
        let key_pair = ecc::curve::generate_key_pair();
        pre_keys.push(record::new_pre_key_record(i, key_pair));
    }
    pre_keys
}

pub fn generate_signed_pre_key(
    identity_key_pair: &IdentityKeyPair,
    signed_pre_key_id: u32,
) -> SignedPreKeyRecordStructure {
    let key_pair = ecc::curve::generate_key_pair();
    use crate::signal::ecc::keys::{DjbEcPrivateKey, EcPrivateKey};
    let signature = ecc::curve::calculate_signature(
        DjbEcPrivateKey::new(EcPrivateKey::serialize(
            &identity_key_pair.private_key().private_key,
        )),
        &EcPublicKey::serialize(&key_pair.public_key),
    );
    let timestamp = Utc::now();
    record::new_signed_pre_key_record(signed_pre_key_id, key_pair, signature, timestamp)
}

pub fn generate_sender_signing_key() -> EcKeyPair {
    ecc::curve::generate_key_pair()
}
pub fn generate_sender_key() -> Vec<u8> {
    let mut key = vec![0u8; 32];
    rng().fill(&mut key[..]);
    key
}
pub fn generate_sender_key_id() -> u32 {
    rng().random::<u32>()
}
/// Generates a registration ID. Clients should only do this once, at install time.
pub fn generate_registration_id() -> u32 {
    // The valid range is 1-16380
    rng().random_range(1..=16380)
}
