//
// Copyright 2020-2022 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use rand::{CryptoRng, Rng};

use crate::protocol::state::GenericSignedPreKey;
use crate::protocol::{AliceSignalProtocolParameters, BobSignalProtocolParameters};
use crate::protocol::{
    Direction, IdentityKey, IdentityKeyStore, KeyPair, PreKeyBundle, PreKeyId, PreKeySignalMessage,
    PreKeyStore, ProtocolAddress, Result, SessionRecord, SessionStore, SignalProtocolError,
    SignedPreKeyStore, ratchet,
};

#[derive(Default)]
pub struct PreKeysUsed {
    pub pre_key_id: Option<PreKeyId>,
}

/// Expected [`IdentityKeyStore`] change when [`process_prekey`] succeeds.
///
/// This represents a deferred action. Assuming later operations succeed, the
/// caller of `process_prekey` should apply this to the `IdentityKeyStore` that
/// was provided.
#[must_use]
pub struct IdentityToSave<'a> {
    pub remote_address: &'a ProtocolAddress,
    pub their_identity_key: &'a IdentityKey,
}

/*
These functions are on SessionBuilder in Java

However using SessionBuilder + SessionCipher at the same time causes
&mut sharing issues. And as SessionBuilder has no actual state beyond
its reference to the various data stores, instead the functions are
free standing.
 */

pub async fn process_prekey<'a>(
    message: &'a PreKeySignalMessage,
    remote_address: &'a ProtocolAddress,
    session_record: &mut SessionRecord,
    identity_store: &dyn IdentityKeyStore,
    pre_key_store: &dyn PreKeyStore,
    signed_prekey_store: &dyn SignedPreKeyStore,
    use_pq_ratchet: ratchet::UsePQRatchet,
) -> Result<(PreKeysUsed, IdentityToSave<'a>)> {
    let their_identity_key = message.identity_key();

    if !identity_store
        .is_trusted_identity(remote_address, their_identity_key, Direction::Receiving)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    let pre_keys_used = process_prekey_impl(
        message,
        remote_address,
        session_record,
        signed_prekey_store,
        pre_key_store,
        identity_store,
        use_pq_ratchet,
    )
    .await?;

    let identity_to_save = IdentityToSave {
        remote_address,
        their_identity_key,
    };

    Ok((pre_keys_used, identity_to_save))
}

async fn process_prekey_impl(
    message: &PreKeySignalMessage,
    remote_address: &ProtocolAddress,
    session_record: &mut SessionRecord,
    signed_prekey_store: &dyn SignedPreKeyStore,
    pre_key_store: &dyn PreKeyStore,
    identity_store: &dyn IdentityKeyStore,
    use_pq_ratchet: ratchet::UsePQRatchet,
) -> Result<PreKeysUsed> {
    if session_record.promote_matching_session(
        message.message_version() as u32,
        &message.base_key().serialize(),
    )? {
        // We've already set up a session for this message, we can exit early.
        return Ok(Default::default());
    }

    let our_signed_pre_key_pair = signed_prekey_store
        .get_signed_pre_key(message.signed_pre_key_id())
        .await?
        .key_pair()?;

    let our_one_time_pre_key_pair = if let Some(pre_key_id) = message.pre_key_id() {
        log::info!(
            "processing PreKey message from {remote_address} with one-time prekey {pre_key_id}"
        );
        Some(pre_key_store.get_pre_key(pre_key_id).await?.key_pair()?)
    } else {
        // This is normal Signal Protocol behavior - one-time prekeys are optional.
        // Common scenarios:
        // - Newly paired device hasn't uploaded prekeys yet
        // - Server's one-time prekey pool is exhausted
        // - App state sync messages during initial pairing
        // Security: Session still provides strong guarantees via signed prekey.
        // Perfect forward secrecy begins after first reply exchange.
        log::debug!(
            "processing PreKey message from {remote_address} without one-time prekey (using signed prekey only)"
        );
        None
    };

    let parameters = BobSignalProtocolParameters::new(
        identity_store.get_identity_key_pair().await?,
        our_signed_pre_key_pair.clone(), // signed pre key
        our_one_time_pre_key_pair,
        our_signed_pre_key_pair, // ratchet key
        *message.identity_key(),
        *message.base_key(),
        use_pq_ratchet,
    );

    let mut new_session = ratchet::initialize_bob_session(&parameters)?;

    new_session.set_local_registration_id(identity_store.get_local_registration_id().await?);
    new_session.set_remote_registration_id(message.registration_id());

    session_record.promote_state(new_session);

    let pre_keys_used = PreKeysUsed {
        pre_key_id: message.pre_key_id(),
    };
    Ok(pre_keys_used)
}

pub async fn process_prekey_bundle<R: Rng + CryptoRng>(
    remote_address: &ProtocolAddress,
    session_store: &mut dyn SessionStore,
    identity_store: &mut dyn IdentityKeyStore,
    bundle: &PreKeyBundle,
    mut csprng: &mut R,
    use_pq_ratchet: ratchet::UsePQRatchet,
) -> Result<()> {
    let their_identity_key = bundle.identity_key()?;

    if !identity_store
        .is_trusted_identity(remote_address, their_identity_key, Direction::Sending)
        .await?
    {
        return Err(SignalProtocolError::UntrustedIdentity(
            remote_address.clone(),
        ));
    }

    if !their_identity_key.public_key().verify_signature(
        &bundle.signed_pre_key_public()?.serialize(),
        bundle.signed_pre_key_signature()?,
    ) {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let mut session_record = session_store
        .load_session(remote_address)
        .await?
        .unwrap_or_else(SessionRecord::new_fresh);

    let our_base_key_pair = KeyPair::generate(&mut csprng);
    let our_base_public_key = our_base_key_pair.public_key; // Save before moving
    let their_signed_prekey = bundle.signed_pre_key_public()?;

    let their_one_time_prekey_id = bundle.pre_key_id()?;

    let our_identity_key_pair = identity_store.get_identity_key_pair().await?;

    let mut parameters = AliceSignalProtocolParameters::new(
        our_identity_key_pair,
        our_base_key_pair,
        *their_identity_key,
        their_signed_prekey,
        their_signed_prekey,
        use_pq_ratchet,
    );
    if let Some(key) = bundle.pre_key_public()? {
        parameters.set_their_one_time_pre_key(key);
    }

    let mut session = ratchet::initialize_alice_session(&parameters, csprng)?;

    log::info!(
        "set_unacknowledged_pre_key_message for: {} with preKeyId: {}",
        remote_address,
        their_one_time_prekey_id.map_or_else(|| "<none>".to_string(), |id| id.to_string())
    );

    session.set_unacknowledged_pre_key_message(
        their_one_time_prekey_id,
        bundle.signed_pre_key_id()?,
        &our_base_public_key,
    );

    session.set_local_registration_id(identity_store.get_local_registration_id().await?);
    session.set_remote_registration_id(bundle.registration_id()?);

    identity_store
        .save_identity(remote_address, their_identity_key)
        .await?;

    session_record.promote_state(session);

    session_store
        .store_session(remote_address, &session_record)
        .await?;

    Ok(())
}
