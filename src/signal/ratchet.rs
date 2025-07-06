use self::parameters::SymmetricParameters;
use super::ecc::curve;
use super::ecc::keys::{EcPrivateKey, EcPublicKey};
use super::kdf;
use super::root_key::{RootKey, SessionKeyPair, ROOT_KEY_DERIVED_SECRETS_SIZE};

pub mod parameters;
const DISCONTINUITY: [u8; 32] = [0xFF; 32];

#[derive(Debug, thiserror::Error)]
pub enum RatchetError {
    #[error("Old counter: current={current}, received={received}")]
    OldCounter { current: u32, received: u32 },
    #[error("Message is too far in the future")]
    TooFarInFuture,
}

// Add this use statement at the top of the file if not present
use self::parameters::{ReceiverParameters, SenderParameters};

// Corresponds to ratchet.CalculateSenderSession
pub fn calculate_sender_session(
    params: &SenderParameters,
) -> Result<SessionKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    let mut master_secret = DISCONTINUITY.to_vec();

    // DH1: our identity key & their signed pre-key (IK_A, SPK_B)
    let dh1 = curve::calculate_shared_secret(
        params
            .our_identity_key_pair
            .private_key()
            .private_key
            .serialize(),
        params.their_signed_pre_key.public_key(),
    );
    master_secret.extend_from_slice(&dh1);

    // DH2: our ephemeral key & their identity key (EK_A, IK_B)
    let dh2 = curve::calculate_shared_secret(
        params.our_base_key.private_key.serialize(),
        params.their_identity_key.public_key().public_key(),
    );
    master_secret.extend_from_slice(&dh2);

    // DH3: our ephemeral key & their signed pre-key (EK_A, SPK_B)
    let dh3 = curve::calculate_shared_secret(
        params.our_base_key.private_key.serialize(),
        params.their_signed_pre_key.public_key(),
    );
    master_secret.extend_from_slice(&dh3);

    // DH4 (optional): our ephemeral key & their one-time pre-key (EK_A, OPK_B)
    if let Some(otpk) = &params.their_one_time_pre_key {
        let dh4 = curve::calculate_shared_secret(
            params.our_base_key.private_key.serialize(),
            otpk.public_key(),
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

// Corresponds to ratchet.CalculateReceiverSession
pub fn calculate_receiver_session(
    params: &ReceiverParameters,
) -> Result<SessionKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    let mut master_secret = DISCONTINUITY.to_vec();

    // DH1: our signed pre-key & their identity key (SPK_B, IK_A)
    let dh1 = curve::calculate_shared_secret(
        params.our_signed_pre_key.private_key.serialize(),
        params.their_identity_key.public_key().public_key(),
    );
    master_secret.extend_from_slice(&dh1);

    // DH2: our identity key & their base key (IK_B, EK_A)
    let dh2 = curve::calculate_shared_secret(
        params
            .our_identity_key_pair
            .private_key()
            .private_key
            .serialize(),
        params.their_base_key.public_key(),
    );
    master_secret.extend_from_slice(&dh2);

    // DH3: our signed pre-key & their base key (SPK_B, EK_A)
    let dh3 = curve::calculate_shared_secret(
        params.our_signed_pre_key.private_key.serialize(),
        params.their_base_key.public_key(),
    );
    master_secret.extend_from_slice(&dh3);

    // DH4 (optional): our one-time pre-key & their base key (OPK_B, EK_A)
    if let Some(otpk) = params.our_one_time_pre_key {
        let dh4 = curve::calculate_shared_secret(
            otpk.private_key.serialize(),
            params.their_base_key.public_key(),
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

// Determines if we are the sender in a symmetric session setup.
fn is_sender(our_key: &dyn EcPublicKey, their_key: &dyn EcPublicKey) -> bool {
    let our_key_bytes = our_key.public_key();
    let their_key_bytes = their_key.public_key();
    let our_key_int = u32::from_be_bytes(our_key_bytes[0..4].try_into().unwrap());
    let their_key_int = u32::from_be_bytes(their_key_bytes[0..4].try_into().unwrap());
    our_key_int < their_key_int
}

// Establishes a symmetric session between two online parties.
pub fn calculate_symmetric_session(
    params: &SymmetricParameters,
) -> Result<SessionKeyPair, Box<dyn std::error::Error + Send + Sync>> {
    if is_sender(&params.our_base_key.public_key, &*params.their_base_key) {
        let sender_params = SenderParameters {
            our_identity_key_pair: params.our_identity_key_pair.clone(),
            our_base_key: params.our_base_key.clone(),
            their_identity_key: params.their_identity_key.clone(),
            their_signed_pre_key: params.their_base_key.clone(),
            their_one_time_pre_key: None,
        };
        calculate_sender_session(&sender_params)
    } else {
        let receiver_params = ReceiverParameters {
            our_identity_key_pair: params.our_identity_key_pair.clone(),
            our_signed_pre_key: params.our_base_key.clone(),
            our_one_time_pre_key: None,
            their_identity_key: params.their_identity_key.clone(),
            their_base_key: params.their_base_key.clone(),
        };
        calculate_receiver_session(&receiver_params)
    }
}
