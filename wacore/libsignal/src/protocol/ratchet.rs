//
// Copyright 2020 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

pub mod keys;
mod params;

use rand::{CryptoRng, Rng};

pub use self::keys::{ChainKey, MessageKeyGenerator, RootKey};
pub use self::params::{AliceSignalProtocolParameters, BobSignalProtocolParameters, UsePQRatchet};
use crate::protocol::state::SessionState;
use crate::protocol::{KeyPair, Result, SessionRecord};

type InitialPQRKey = [u8; 32];

pub fn derive_keys(secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    derive_keys_with_label(b"WhisperText".as_slice(), secret_input)
}

fn message_version() -> u8 {
    3
}

fn derive_keys_with_label(label: &[u8], secret_input: &[u8]) -> (RootKey, ChainKey, InitialPQRKey) {
    let mut secrets = [0; 96];
    hkdf::Hkdf::<sha2::Sha256>::new(None, secret_input)
        .expand(label, &mut secrets)
        .expect("valid length");
    let (root_key_bytes, chain_key_bytes, pqr_bytes) =
        (&secrets[0..32], &secrets[32..64], &secrets[64..96]);

    let root_key = RootKey::new(root_key_bytes.try_into().expect("correct length"));
    let chain_key = ChainKey::new(chain_key_bytes.try_into().expect("correct length"), 0);
    let pqr_key: InitialPQRKey = pqr_bytes.try_into().expect("correct length");

    (root_key, chain_key, pqr_key)
}

pub fn initialize_alice_session<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    mut csprng: &mut R,
) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    let sending_ratchet_key = KeyPair::generate(&mut csprng);

    // Stack-allocated buffer for up to 5 shared secrets (160 bytes max)
    let mut secrets = [0u8; 160];
    let mut secrets_len = 0usize;

    // "discontinuity bytes"
    secrets[..32].copy_from_slice(&[0xFFu8; 32]);
    secrets_len += 32;

    let our_base_private_key = parameters.our_base_key_pair().private_key.clone();

    // Each agreement is 32 bytes. We have: discontinuity (32) + up to 4 agreements (128) = 160 max.
    // The buffer is [u8; 160], so bounds are statically guaranteed.
    let agreement = parameters
        .our_identity_key_pair()
        .private_key()
        .calculate_agreement(parameters.their_signed_pre_key())?;
    secrets[secrets_len..secrets_len + 32].copy_from_slice(&agreement);
    secrets_len += 32;

    let agreement =
        our_base_private_key.calculate_agreement(parameters.their_identity_key().public_key())?;
    secrets[secrets_len..secrets_len + 32].copy_from_slice(&agreement);
    secrets_len += 32;

    let agreement = our_base_private_key.calculate_agreement(parameters.their_signed_pre_key())?;
    secrets[secrets_len..secrets_len + 32].copy_from_slice(&agreement);
    secrets_len += 32;

    if let Some(their_one_time_prekey) = parameters.their_one_time_pre_key() {
        let agreement = our_base_private_key.calculate_agreement(their_one_time_prekey)?;
        secrets[secrets_len..secrets_len + 32].copy_from_slice(&agreement);
        secrets_len += 32;
    }

    let (root_key, chain_key, _) = derive_keys(&secrets[..secrets_len]);

    let (sending_chain_root_key, sending_chain_chain_key) = root_key.create_chain(
        parameters.their_ratchet_key(),
        &sending_ratchet_key.private_key,
    )?;

    let session = SessionState::new(
        message_version(),
        local_identity,
        parameters.their_identity_key(),
        &sending_chain_root_key,
        &parameters.our_base_key_pair().public_key,
    )
    .with_receiver_chain(parameters.their_ratchet_key(), &chain_key)
    .with_sender_chain(&sending_ratchet_key, &sending_chain_chain_key);

    Ok(session)
}

pub fn initialize_bob_session(parameters: &BobSignalProtocolParameters) -> Result<SessionState> {
    let local_identity = parameters.our_identity_key_pair().identity_key();

    // Stack-allocated buffer for up to 5 shared secrets (160 bytes max)
    let mut secrets = [0u8; 160];
    let mut secrets_len = 0usize;

    // "discontinuity bytes"
    secrets[..32].copy_from_slice(&[0xFFu8; 32]);
    secrets_len += 32;

    // Each agreement is 32 bytes. We have: discontinuity (32) + up to 4 agreements (128) = 160 max.
    // The buffer is [u8; 160], so bounds are statically guaranteed.
    let agreement = parameters
        .our_signed_pre_key_pair()
        .private_key
        .calculate_agreement(parameters.their_identity_key().public_key())?;
    secrets[secrets_len..secrets_len + 32].copy_from_slice(&agreement);
    secrets_len += 32;

    let agreement = parameters
        .our_identity_key_pair()
        .private_key()
        .calculate_agreement(parameters.their_base_key())?;
    secrets[secrets_len..secrets_len + 32].copy_from_slice(&agreement);
    secrets_len += 32;

    let agreement = parameters
        .our_signed_pre_key_pair()
        .private_key
        .calculate_agreement(parameters.their_base_key())?;
    secrets[secrets_len..secrets_len + 32].copy_from_slice(&agreement);
    secrets_len += 32;

    if let Some(our_one_time_pre_key_pair) = parameters.our_one_time_pre_key_pair() {
        let agreement = our_one_time_pre_key_pair
            .private_key
            .calculate_agreement(parameters.their_base_key())?;
        secrets[secrets_len..secrets_len + 32].copy_from_slice(&agreement);
        secrets_len += 32;
    }

    let (root_key, chain_key, _) = derive_keys(&secrets[..secrets_len]);

    let session = SessionState::new(
        message_version(),
        local_identity,
        parameters.their_identity_key(),
        &root_key,
        parameters.their_base_key(),
    )
    .with_sender_chain(parameters.our_ratchet_key_pair(), &chain_key);

    Ok(session)
}

pub fn initialize_alice_session_record<R: Rng + CryptoRng>(
    parameters: &AliceSignalProtocolParameters,
    csprng: &mut R,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_alice_session(
        parameters, csprng,
    )?))
}

pub fn initialize_bob_session_record(
    parameters: &BobSignalProtocolParameters,
) -> Result<SessionRecord> {
    Ok(SessionRecord::new(initialize_bob_session(parameters)?))
}
