//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use rand::{CryptoRng, Rng};

use crate::libsignal::crypto::DecryptionError as DecryptionErrorCrypto;
use crate::libsignal::crypto::{aes_256_cbc_decrypt, aes_256_cbc_encrypt};
use crate::libsignal::protocol::SENDERKEY_MESSAGE_CURRENT_VERSION;
use crate::libsignal::protocol::sender_keys::{SenderKeyState, SenderMessageKey};
use crate::libsignal::protocol::{
    CiphertextMessageType, KeyPair, ProtocolAddress, Result, SenderKeyDistributionMessage,
    SenderKeyMessage, SenderKeyRecord, SenderKeyStore, SignalProtocolError, consts,
};

pub async fn group_encrypt<R: Rng + CryptoRng>(
    sender_key_store: &mut dyn SenderKeyStore,
    sender: &ProtocolAddress,
    plaintext: &[u8],
    csprng: &mut R,
) -> Result<SenderKeyMessage> {
    let mut record = sender_key_store
        .load_sender_key(sender)
        .await?
        .ok_or(SignalProtocolError::NoSenderKeyState)?;

    let sender_key_state = record
        .sender_key_state_mut()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession)?;

    let message_version = sender_key_state
        .message_version()
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession)?;

    let sender_chain_key = sender_key_state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession)?;

    let message_keys = sender_chain_key.sender_message_key();

    let ciphertext = aes_256_cbc_encrypt(plaintext, message_keys.cipher_key(), message_keys.iv())
        .map_err(|_| {
        log::error!("outgoing sender key state corrupt for distribution",);
        SignalProtocolError::InvalidSenderKeySession
    })?;

    let signing_key = sender_key_state
        .signing_key_private()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession)?;

    let skm = SenderKeyMessage::new(
        message_version,
        sender_key_state.chain_id(),
        message_keys.iteration(),
        ciphertext.into_boxed_slice(),
        csprng,
        &signing_key,
    )?;

    sender_key_state.set_sender_chain_key(sender_chain_key.next()?);

    sender_key_store.store_sender_key(sender, &record).await?;

    Ok(skm)
}

fn get_sender_key(state: &mut SenderKeyState, iteration: u32) -> Result<SenderMessageKey> {
    let sender_chain_key = state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession)?;
    let current_iteration = sender_chain_key.iteration();

    if current_iteration > iteration {
        if let Some(smk) = state.remove_sender_message_key(iteration) {
            return Ok(smk);
        } else {
            log::info!("SenderKey Duplicate message for iteration: {iteration}");
            return Err(SignalProtocolError::DuplicatedMessage(
                current_iteration,
                iteration,
            ));
        }
    }

    let jump = (iteration - current_iteration) as usize;
    if jump > consts::MAX_FORWARD_JUMPS {
        log::error!(
            "SenderKey Exceeded future message limit: {}, current iteration: {})",
            consts::MAX_FORWARD_JUMPS,
            current_iteration
        );
        return Err(SignalProtocolError::InvalidMessage(
            CiphertextMessageType::SenderKey,
            "message from too far into the future",
        ));
    }

    let mut sender_chain_key = sender_chain_key;

    while sender_chain_key.iteration() < iteration {
        state.add_sender_message_key(&sender_chain_key.sender_message_key());
        sender_chain_key = sender_chain_key.next()?;
    }

    state.set_sender_chain_key(sender_chain_key.next()?);
    Ok(sender_chain_key.sender_message_key())
}

pub async fn group_decrypt(
    skm_bytes: &[u8],
    sender_key_store: &mut dyn SenderKeyStore,
    sender: &ProtocolAddress,
) -> Result<Vec<u8>> {
    let skm = SenderKeyMessage::try_from(skm_bytes)?;

    let chain_id = skm.chain_id();

    let mut record = sender_key_store
        .load_sender_key(sender)
        .await?
        .ok_or(SignalProtocolError::NoSenderKeyState)?;

    let sender_key_state = match record.sender_key_state_for_chain_id(chain_id) {
        Some(state) => state,
        None => {
            log::error!(
                "SenderKey could not find chain ID {} (known chain IDs: {:?})",
                chain_id,
                record.chain_ids_for_logging().collect::<Vec<_>>(),
            );
            return Err(SignalProtocolError::NoSenderKeyState);
        }
    };

    let message_version = skm.message_version() as u32;
    if message_version != sender_key_state.message_version() {
        return Err(SignalProtocolError::UnrecognizedMessageVersion(
            message_version,
        ));
    }

    let signing_key = sender_key_state
        .signing_key_public()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession)?;
    if !skm.verify_signature(&signing_key)? {
        return Err(SignalProtocolError::SignatureValidationFailed);
    }

    let sender_key = get_sender_key(sender_key_state, skm.iteration())?;

    let plaintext =
        match aes_256_cbc_decrypt(skm.ciphertext(), sender_key.cipher_key(), sender_key.iv()) {
            Ok(plaintext) => plaintext,
            Err(DecryptionErrorCrypto::BadKeyOrIv) => {
                log::error!("incoming sender key state corrupt for {sender}, chain ID {chain_id}",);
                return Err(SignalProtocolError::InvalidSenderKeySession);
            }
            Err(DecryptionErrorCrypto::BadCiphertext(msg)) => {
                log::error!("sender key decryption failed: {msg}");
                return Err(SignalProtocolError::InvalidMessage(
                    CiphertextMessageType::SenderKey,
                    "decryption failed",
                ));
            }
        };

    sender_key_store.store_sender_key(sender, &record).await?;

    Ok(plaintext)
}

pub async fn process_sender_key_distribution_message(
    sender: &ProtocolAddress,
    skdm: &SenderKeyDistributionMessage,
    sender_key_store: &mut dyn SenderKeyStore,
) -> Result<()> {
    log::info!(
        "{} Processing SenderKey distribution with chain ID {}",
        sender,
        skdm.chain_id()?
    );

    let mut sender_key_record = sender_key_store
        .load_sender_key(sender)
        .await?
        .unwrap_or_else(SenderKeyRecord::new_empty);

    sender_key_record.add_sender_key_state(
        skdm.message_version(),
        skdm.chain_id()?,
        skdm.iteration()?,
        skdm.chain_key()?,
        *skdm.signing_key()?,
        None,
    );
    sender_key_store
        .store_sender_key(sender, &sender_key_record)
        .await?;
    Ok(())
}

pub async fn create_sender_key_distribution_message<R: Rng + CryptoRng>(
    sender: &ProtocolAddress,
    sender_key_store: &mut dyn SenderKeyStore,
    csprng: &mut R,
) -> Result<SenderKeyDistributionMessage> {
    let sender_key_record = sender_key_store.load_sender_key(sender).await?;

    let sender_key_record = match sender_key_record {
        Some(record) => record,
        None => {
            // libsignal-protocol-java uses 31-bit integers for sender key chain IDs
            let chain_id = (csprng.random::<u32>()) >> 1;
            log::info!("Creating SenderKey with chain ID {chain_id}");

            let iteration = 0;
            let sender_key: [u8; 32] = csprng.random();
            let signing_key = KeyPair::generate(csprng);
            let mut record = SenderKeyRecord::new_empty();
            record.add_sender_key_state(
                SENDERKEY_MESSAGE_CURRENT_VERSION,
                chain_id,
                iteration,
                &sender_key,
                signing_key.public_key,
                Some(signing_key.private_key),
            );
            sender_key_store.store_sender_key(sender, &record).await?;
            record
        }
    };

    let state = sender_key_record
        .sender_key_state()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession)?;
    let sender_chain_key = state
        .sender_chain_key()
        .ok_or(SignalProtocolError::InvalidSenderKeySession)?;
    let message_version = state
        .message_version()
        .try_into()
        .map_err(|_| SignalProtocolError::InvalidSenderKeySession)?;

    SenderKeyDistributionMessage::new(
        message_version,
        state.chain_id(),
        sender_chain_key.iteration(),
        sender_chain_key.seed().to_vec(),
        state
            .signing_key_public()
            .map_err(|_| SignalProtocolError::InvalidSenderKeySession)?,
    )
}
