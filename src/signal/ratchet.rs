use super::ecc::curve;
use super::ecc::key_pair::EcKeyPair;
use super::ecc::keys::{EcPrivateKey, EcPublicKey};
use super::identity::{IdentityKey, IdentityKeyPair};
use super::kdf;
use super::root_key::{RootKey, SessionKeyPair, ROOT_KEY_DERIVED_SECRETS_SIZE};
use std::sync::Arc;

const DISCONTINUITY: [u8; 32] = [0xFF; 32];

#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("Old counter: current={current}, received={received}")]
    OldCounter { current: u32, received: u32 },
    #[error("Message is too far in the future")]
    TooFarInFuture,
}

// Corresponds to ratchet.CalculateSenderSession
pub fn calculate_sender_session(
    our_identity_key_pair: &IdentityKeyPair,
    our_base_key: &EcKeyPair,
    their_identity_key: &IdentityKey,
    their_signed_pre_key: Arc<dyn EcPublicKey>,
    their_one_time_pre_key: Option<Arc<dyn EcPublicKey>>,
) -> Result<SessionKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    let mut master_secret = DISCONTINUITY.to_vec();

    // DH1: our identity key & their signed pre-key (IK_A, SPK_B)
    let dh1 = curve::calculate_shared_secret(
        our_identity_key_pair.private_key().private_key.serialize(),
        their_signed_pre_key.public_key(),
    );
    master_secret.extend_from_slice(&dh1);

    // DH2: our ephemeral key & their identity key (EK_A, IK_B)
    let dh2 = curve::calculate_shared_secret(
        our_base_key.private_key.serialize(),
        their_identity_key.public_key().public_key(),
    );
    master_secret.extend_from_slice(&dh2);

    // DH3: our ephemeral key & their signed pre-key (EK_A, SPK_B)
    let dh3 = curve::calculate_shared_secret(
        our_base_key.private_key.serialize(),
        their_signed_pre_key.public_key(),
    );
    master_secret.extend_from_slice(&dh3);

    // DH4 (optional): our ephemeral key & their one-time pre-key (EK_A, OPK_B)
    if let Some(otpk) = their_one_time_pre_key {
        let dh4 =
            curve::calculate_shared_secret(our_base_key.private_key.serialize(), otpk.public_key());
        master_secret.extend_from_slice(&dh4);
    }

    let derived_keys_bytes = kdf::derive_secrets(
        &master_secret,
        None,
        "WhisperText".as_bytes(),
        ROOT_KEY_DERIVED_SECRETS_SIZE,
    )?;
    let root_key = RootKey::new(derived_keys_bytes[0..32].try_into().unwrap());
    let chain_key =
        super::chain_key::ChainKey::new(derived_keys_bytes[32..64].try_into().unwrap(), 0);

    Ok(SessionKeyPair {
        root_key,
        chain_key,
    })
}

// Corresponds to ratchet.CalculateReceiverSession
pub fn calculate_receiver_session(
    our_identity_key_pair: &IdentityKeyPair,
    our_signed_pre_key: &EcKeyPair,
    our_one_time_pre_key: Option<&EcKeyPair>,
    their_identity_key: &IdentityKey,
    their_base_key: Arc<dyn EcPublicKey>,
) -> Result<SessionKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    let mut master_secret = DISCONTINUITY.to_vec();

    // DH1: our signed pre-key & their identity key (SPK_B, IK_A)
    let dh1 = curve::calculate_shared_secret(
        our_signed_pre_key.private_key.serialize(),
        their_identity_key.public_key().public_key(),
    );
    master_secret.extend_from_slice(&dh1);

    // DH2: our identity key & their base key (IK_B, EK_A)
    let dh2 = curve::calculate_shared_secret(
        our_identity_key_pair.private_key().private_key.serialize(),
        their_base_key.public_key(),
    );
    master_secret.extend_from_slice(&dh2);

    // DH3: our signed pre-key & their base key (SPK_B, EK_A)
    let dh3 = curve::calculate_shared_secret(
        our_signed_pre_key.private_key.serialize(),
        their_base_key.public_key(),
    );
    master_secret.extend_from_slice(&dh3);

    // DH4 (optional): our one-time pre-key & their base key (OPK_B, EK_A)
    if let Some(otpk) = our_one_time_pre_key {
        let dh4 = curve::calculate_shared_secret(
            otpk.private_key.serialize(),
            their_base_key.public_key(),
        );
        master_secret.extend_from_slice(&dh4);
    }

    let derived_keys_bytes = kdf::derive_secrets(
        &master_secret,
        None,
        "WhisperText".as_bytes(),
        ROOT_KEY_DERIVED_SECRETS_SIZE,
    )?;
    let root_key = RootKey::new(derived_keys_bytes[0..32].try_into().unwrap());
    let chain_key =
        super::chain_key::ChainKey::new(derived_keys_bytes[32..64].try_into().unwrap(), 0);

    Ok(SessionKeyPair {
        root_key,
        chain_key,
    })
}
