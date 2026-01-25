//
// Copyright 2020-2021 Signal Messenger, LLC.
// SPDX-License-Identifier: AGPL-3.0-only
//

use std::cell::RefCell;

use rand::{CryptoRng, Rng};

use crate::crypto::aes_256_cbc_decrypt_into;
use crate::crypto::{DecryptionError as DecryptionErrorCrypto, aes_256_cbc_encrypt_into};
use crate::protocol::SENDERKEY_MESSAGE_CURRENT_VERSION;
use crate::protocol::sender_keys::{SenderKeyState, SenderMessageKey};
use crate::protocol::{
    CiphertextMessageType, KeyPair, Result, SenderKeyDistributionMessage, SenderKeyMessage,
    SenderKeyRecord, SenderKeyStore, SignalProtocolError, consts,
};
use crate::store::sender_key_name::SenderKeyName;

/// Reusable buffer for cryptographic operations (encryption and decryption).
/// Named generically since it's used for both ENCRYPTION_BUFFER and DECRYPTION_BUFFER.
struct CryptoBuffer {
    buffer: Vec<u8>,
}

impl CryptoBuffer {
    const INITIAL_CAPACITY: usize = 1024;

    fn new() -> Self {
        Self {
            buffer: Vec::with_capacity(Self::INITIAL_CAPACITY),
        }
    }

    /// Clears the buffer and returns a mutable reference for writing.
    fn get_buffer(&mut self) -> &mut Vec<u8> {
        self.buffer.clear();
        &mut self.buffer
    }

    /// Takes ownership of the buffer contents, replacing with a fresh pre-allocated buffer.
    /// More efficient than `mem::take` + `reserve` since we swap with an already-allocated buffer.
    fn take_buffer(&mut self) -> Vec<u8> {
        std::mem::replace(&mut self.buffer, Vec::with_capacity(Self::INITIAL_CAPACITY))
    }
}

thread_local! {
    static ENCRYPTION_BUFFER: RefCell<CryptoBuffer> = RefCell::new(CryptoBuffer::new());
    static DECRYPTION_BUFFER: RefCell<CryptoBuffer> = RefCell::new(CryptoBuffer::new());
}

pub async fn group_encrypt<R: Rng + CryptoRng>(
    sender_key_store: &mut dyn SenderKeyStore,
    sender_key_name: &SenderKeyName,
    plaintext: &[u8],
    csprng: &mut R,
) -> Result<SenderKeyMessage> {
    let mut record = sender_key_store
        .load_sender_key(sender_key_name)
        .await?
        .ok_or_else(|| {
            SignalProtocolError::NoSenderKeyState(format!(
                "no sender key record for group {} sender {}",
                sender_key_name.group_id(),
                sender_key_name.sender_id()
            ))
        })?;

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

    let (message_keys, next_sender_chain_key) = sender_chain_key.step_with_message_key()?;

    let ciphertext = ENCRYPTION_BUFFER.with(|buffer| {
        let mut buf_wrapper = buffer.borrow_mut();
        let buf = buf_wrapper.get_buffer();
        aes_256_cbc_encrypt_into(plaintext, message_keys.cipher_key(), message_keys.iv(), buf)
            .map_err(|_| {
                log::error!("outgoing sender key state corrupt for distribution");
                SignalProtocolError::InvalidSenderKeySession
            })?;
        Ok::<Vec<u8>, SignalProtocolError>(buf_wrapper.take_buffer())
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

    sender_key_state.set_sender_chain_key(next_sender_chain_key);

    sender_key_store
        .store_sender_key(sender_key_name, &record)
        .await?;

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
            log::debug!("SenderKey Duplicate message for iteration: {iteration}");
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
        let (message_key, next_chain) = sender_chain_key.step_with_message_key()?;
        state.add_sender_message_key(&message_key);
        sender_chain_key = next_chain;
    }

    let (result_message_key, next_chain) = sender_chain_key.step_with_message_key()?;
    state.set_sender_chain_key(next_chain);
    Ok(result_message_key)
}

pub async fn group_decrypt(
    skm_bytes: &[u8],
    sender_key_store: &mut dyn SenderKeyStore,
    sender_key_name: &SenderKeyName,
) -> Result<Vec<u8>> {
    let skm = SenderKeyMessage::try_from(skm_bytes)?;

    let chain_id = skm.chain_id();

    let mut record = sender_key_store
        .load_sender_key(sender_key_name)
        .await?
        .ok_or_else(|| {
            SignalProtocolError::NoSenderKeyState(format!(
                "no sender key record for group {} sender {}",
                sender_key_name.group_id(),
                sender_key_name.sender_id()
            ))
        })?;

    let sender_key_state = match record.sender_key_state_for_chain_id(chain_id) {
        Some(state) => state,
        None => {
            log::error!(
                "SenderKey could not find chain ID {} (known chain IDs: {:?})",
                chain_id,
                record.chain_ids_for_logging().collect::<Vec<_>>(),
            );
            return Err(SignalProtocolError::NoSenderKeyState(format!(
                "no sender key state for chain id {} (known chain IDs: {:?})",
                chain_id,
                record.chain_ids_for_logging().collect::<Vec<_>>()
            )));
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

    let plaintext = DECRYPTION_BUFFER.with(|buffer| {
        let mut buf_wrapper = buffer.borrow_mut();
        let buf = buf_wrapper.get_buffer();
        let ciphertext = skm.ciphertext()?;
        if let Err(e) = aes_256_cbc_decrypt_into(
            ciphertext,
            sender_key.cipher_key(),
            sender_key.iv(),
            buf,
        ) {
            match e {
                DecryptionErrorCrypto::BadKeyOrIv => {
                    log::error!(
                        "incoming sender key state corrupt for group {} sender {} (chain ID {chain_id})",
                        sender_key_name.group_id(),
                        sender_key_name.sender_id()
                    );
                    return Err(SignalProtocolError::InvalidSenderKeySession);
                }
                DecryptionErrorCrypto::BadCiphertext(msg) => {
                    log::error!("sender key decryption failed: {msg}");
                    return Err(SignalProtocolError::InvalidMessage(
                        CiphertextMessageType::SenderKey,
                        "decryption failed",
                    ));
                }
            }
        }
        Ok::<Vec<u8>, SignalProtocolError>(buf_wrapper.take_buffer())
    })?;

    sender_key_store
        .store_sender_key(sender_key_name, &record)
        .await?;

    Ok(plaintext)
}

pub async fn process_sender_key_distribution_message(
    sender_key_name: &SenderKeyName,
    skdm: &SenderKeyDistributionMessage,
    sender_key_store: &mut dyn SenderKeyStore,
) -> Result<()> {
    log::info!(
        "Processing SenderKey distribution for group {} from sender {} with chain ID {}",
        sender_key_name.group_id(),
        sender_key_name.sender_id(),
        skdm.chain_id()
    );

    let mut sender_key_record = sender_key_store
        .load_sender_key(sender_key_name)
        .await?
        .unwrap_or_else(SenderKeyRecord::new_empty);

    sender_key_record.add_sender_key_state(
        skdm.message_version(),
        skdm.chain_id(),
        skdm.iteration(),
        skdm.chain_key(),
        *skdm.signing_key(),
        None,
    );
    sender_key_store
        .store_sender_key(sender_key_name, &sender_key_record)
        .await?;
    Ok(())
}

pub async fn create_sender_key_distribution_message<R: Rng + CryptoRng>(
    sender_key_name: &SenderKeyName,
    sender_key_store: &mut dyn SenderKeyStore,
    csprng: &mut R,
) -> Result<SenderKeyDistributionMessage> {
    let sender_key_record = sender_key_store.load_sender_key(sender_key_name).await?;

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
            sender_key_store
                .store_sender_key(sender_key_name, &record)
                .await?;
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
        *sender_chain_key.seed(),
        state
            .signing_key_public()
            .map_err(|_| SignalProtocolError::InvalidSenderKeySession)?,
    )
}
