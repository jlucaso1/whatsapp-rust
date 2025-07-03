use super::ecc::curve;
use super::ecc::key_pair::EcKeyPair;
use super::ecc::keys::EcPublicKey;
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
) -> Result<SessionKeyPair, Box<dyn std::error::Error>> {
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
    let chain_key_bytes: [u8; 32] = derived_keys_bytes[32..64].try_into().unwrap();

    let sending_ratchet_key = curve::generate_key_pair();

    let session_key_pair =
        root_key.create_chain(their_signed_pre_key.clone(), &sending_ratchet_key)?;

    Ok(session_key_pair)
}
// Note: We'll add `calculate_receiver_session` when implementing the decryption logic.
