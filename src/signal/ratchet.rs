use super::ecc::curve;
use super::ecc::key_pair::EcKeyPair;
use super::ecc::keys::{EcPrivateKey, EcPublicKey};
use super::identity::{IdentityKey, IdentityKeyPair};
use super::kdf;
use super::root_key::{RootKey, SessionKeyPair};
use std::sync::Arc;

// Corresponds to ratchet.CalculateAliceSession
pub fn calculate_sender_session(
    our_identity_key: &IdentityKeyPair,
    our_base_key: &EcKeyPair,
    their_identity_key: &IdentityKey,
    their_signed_pre_key: Arc<dyn EcPublicKey>,
    their_one_time_pre_key: Option<Arc<dyn EcPublicKey>>,
) -> Result<SessionKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    let mut master_secret = vec![0xFF; 32];

    // DH1: our identity key & their signed pre-key
    let dh1 = curve::calculate_shared_secret(
        our_identity_key.private_key.private_key.serialize(),
        their_signed_pre_key.public_key(),
    );
    master_secret.extend_from_slice(&dh1);

    // DH2: our base key & their identity key
    let dh2 = curve::calculate_shared_secret(
        our_base_key.private_key.serialize(),
        their_identity_key.public_key().public_key(),
    );
    master_secret.extend_from_slice(&dh2);

    // DH3: our base key & their signed pre-key
    let dh3 = curve::calculate_shared_secret(
        our_base_key.private_key.serialize(),
        their_signed_pre_key.public_key(),
    );
    master_secret.extend_from_slice(&dh3);

    // DH4 (optional): our base key & their one-time pre-key
    if let Some(otpk) = their_one_time_pre_key {
        let dh4 =
            curve::calculate_shared_secret(our_base_key.private_key.serialize(), otpk.public_key());
        master_secret.extend_from_slice(&dh4);
    }

    let derived_keys_bytes =
        kdf::derive_secrets(&master_secret, None, "WhisperText".as_bytes(), 64)?;
    let root_key = RootKey::new(derived_keys_bytes[0..32].try_into().unwrap());

    let sending_ratchet_key = curve::generate_key_pair();

    let session_key_pair =
        root_key.create_chain(their_signed_pre_key.clone(), &sending_ratchet_key)?;

    Ok(session_key_pair)
}

// Corresponds to ratchet.CalculateReceiverSession
pub fn calculate_receiver_session(
    our_identity_key_pair: &IdentityKeyPair,
    our_signed_pre_key: &EcKeyPair,
    our_one_time_pre_key: Option<&EcKeyPair>,
    their_identity_key: &IdentityKey,
    their_base_key: Arc<dyn EcPublicKey>,
) -> Result<SessionKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    let mut master_secret = vec![0xFF; 32];

    // DH1: our signed pre-key & their identity key
    let dh1 = curve::calculate_shared_secret(
        our_signed_pre_key.private_key.serialize(),
        their_identity_key.public_key().public_key(),
    );
    master_secret.extend_from_slice(&dh1);

    // DH2: our identity key & their base key
    let dh2 = curve::calculate_shared_secret(
        our_identity_key_pair.private_key.private_key.serialize(),
        their_base_key.public_key(),
    );
    master_secret.extend_from_slice(&dh2);

    // DH3: our signed pre-key & their base key
    let dh3 = curve::calculate_shared_secret(
        our_signed_pre_key.private_key.serialize(),
        their_base_key.public_key(),
    );
    master_secret.extend_from_slice(&dh3);

    // DH4 (optional): our one-time pre-key & their base key
    if let Some(otpk) = our_one_time_pre_key {
        let dh4 = curve::calculate_shared_secret(
            otpk.private_key.serialize(),
            their_base_key.public_key(),
        );
        master_secret.extend_from_slice(&dh4);
    }

    let derived_keys_bytes =
        kdf::derive_secrets(&master_secret, None, "WhisperText".as_bytes(), 64)?;
    let root_key = RootKey::new(derived_keys_bytes[0..32].try_into().unwrap());
    let chain_key =
        super::chain_key::ChainKey::new(derived_keys_bytes[32..64].try_into().unwrap(), 0);

    Ok(SessionKeyPair {
        root_key,
        chain_key,
    })
}
