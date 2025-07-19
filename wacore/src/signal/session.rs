use super::address::SignalAddress;
use super::kdf;
use super::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use super::store::SignalProtocolStore;
use crate::signal::ecc::{
    curve,
    keys::{DjbEcPublicKey, EcPublicKey},
};
use crate::signal::protocol::ProtocolError;
use crate::signal::state::prekey_bundle::PreKeyBundle;
use crate::signal::state::record;
use crate::signal::state::session_record::SessionRecord;
use crate::signal::state::session_state::SessionState;
use hmac::{Hmac, Mac};
use log;
use sha2::Sha256;
use std::sync::Arc;
use waproto::whatsapp::PreKeyRecordStructure;
use waproto::whatsapp::session_structure::chain::{ChainKey, MessageKey};

pub struct SessionCipher<S: SignalProtocolStore> {
    store: S,
    remote_address: SignalAddress,
}

impl<S: SignalProtocolStore + Clone + 'static> SessionCipher<S> {
    pub fn new(store: S, remote_address: SignalAddress) -> Self {
        Self {
            store,
            remote_address,
        }
    }

    pub async fn encrypt(
        &self,
        session_record: &mut SessionRecord,
        plaintext: &[u8],
    ) -> Result<Box<dyn CiphertextMessage>, Box<dyn std::error::Error + Send + Sync>> {
        let session_state = session_record.session_state_mut();

        let mut chain_key = session_state.sender_chain_key();
        let message_keys = get_message_keys(&chain_key);

        let ciphertext = self.encrypt_internal(&message_keys, plaintext)?;

        let signal_message = SignalMessage::new(
            message_keys.mac_key.as_deref().unwrap_or_default(),
            session_state.sender_ratchet_key(),
            message_keys.index(),
            session_state.previous_counter(),
            ciphertext.clone(),
            &session_state.local_identity_public(),
            &session_state.remote_identity_public(),
        )?;

        let final_message: Box<dyn CiphertextMessage> =
            if session_state.has_unacknowledged_prekey_message() {
                let pending = session_state.unack_pre_key_message_items().unwrap();
                let local_reg_id = self.store.get_local_registration_id().await?;

                Box::new(PreKeySignalMessage::new(
                    local_reg_id,
                    pending.pre_key_id(),
                    pending.signed_pre_key_id(),
                    Arc::new(pending.base_key().clone())
                        as Arc<dyn crate::signal::ecc::keys::EcPublicKey>,
                    session_state.local_identity_public().as_ref().clone(),
                    signal_message,
                )?)
            } else {
                Box::new(signal_message)
            };

        chain_key = get_next_chain_key(&chain_key);
        session_state.set_sender_chain_key(chain_key);

        Ok(final_message)
    }

    fn encrypt_internal(
        &self,
        message_keys: &MessageKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        use crate::crypto::cbc;
        let cipher_key = message_keys.cipher_key.as_deref().unwrap_or_default();
        let iv = message_keys.iv.as_deref().unwrap_or_default();
        cbc::encrypt(cipher_key, iv, plaintext).map_err(|e| e.into())
    }
}

impl<S: SignalProtocolStore + Clone + 'static> SessionCipher<S> {
    fn get_or_create_message_keys(
        &self,
        session_state: &mut SessionState,
        their_ephemeral: &DjbEcPublicKey,
        counter: u32,
    ) -> Result<(ChainKey, MessageKey), DecryptionError> {
        let key = their_ephemeral.public_key();
        let chain_index = session_state
            .receiver_chains_mut()
            .iter()
            .position(|c| c.sender_ratchet_key_pair.public_key.public_key == key);
        if let Some(idx) = chain_index {
            let chain_key_index;
            {
                let chain = &mut session_state.receiver_chains_mut()[idx];
                chain_key_index = chain.chain_key.index.unwrap_or(0);
            }
            if chain_key_index > counter {
                if let Some(keys) =
                    session_state.receiver_chains_mut()[idx].remove_message_keys(counter)
                {
                    let chain_key = session_state.receiver_chains_mut()[idx].chain_key.clone();
                    return Ok((chain_key, keys));
                }
                return Err(ProtocolError::OldCounter(chain_key_index, counter).into());
            }
            if counter > chain_key_index + 2000 {
                return Err(DecryptionError::TooFarInFuture);
            }
            while session_state.receiver_chains_mut()[idx]
                .chain_key
                .index
                .unwrap_or(0)
                < counter
            {
                let chain_key_clone = session_state.receiver_chains_mut()[idx].chain_key.clone();
                let mk = get_message_keys(&chain_key_clone);
                session_state.receiver_chains_mut()[idx].add_message_keys(mk);
                let next = get_next_chain_key(&chain_key_clone);
                session_state.receiver_chains_mut()[idx].chain_key = next;
            }
            let chain_key = session_state.receiver_chains_mut()[idx].chain_key.clone();
            let message_keys = get_message_keys(&chain_key);
            session_state.receiver_chains_mut()[idx].chain_key = get_next_chain_key(&chain_key);
            Ok((chain_key, message_keys))
        } else {
            let root_key = session_state.root_key().clone();
            let our_ephemeral = session_state.sender_ratchet_key_pair().clone();
            let their_ephemeral_arc =
                Arc::new(their_ephemeral.clone()) as Arc<dyn crate::signal::ecc::keys::EcPublicKey>;

            let receiver_chain_pair =
                root_key.create_chain(their_ephemeral_arc.clone(), &our_ephemeral)?;

            let new_our_ephemeral = curve::generate_key_pair();
            let sender_chain_pair = receiver_chain_pair
                .root_key
                .create_chain(their_ephemeral_arc.clone(), &new_our_ephemeral)?;

            session_state.set_root_key(sender_chain_pair.root_key);
            session_state.add_receiver_chain(
                their_ephemeral_arc.clone(),
                receiver_chain_pair.chain_key.clone(),
            );
            session_state.set_previous_counter(
                session_state
                    .sender_chain_key()
                    .index
                    .unwrap_or(0)
                    .saturating_sub(1),
            );
            session_state.set_sender_chain(new_our_ephemeral, sender_chain_pair.chain_key);

            let chain_key = receiver_chain_pair.chain_key;
            let message_keys = get_message_keys(&chain_key);
            if let Some(chain) = session_state.find_receiver_chain_mut(&their_ephemeral.public_key)
            {
                chain.chain_key = get_next_chain_key(&chain_key);
            }
            Ok((chain_key, message_keys))
        }
    }

    fn decrypt_internal(
        &self,
        message_keys: &MessageKey,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        use crate::crypto::cbc;
        let cipher_key = message_keys.cipher_key.as_deref().unwrap_or_default();
        let iv = message_keys.iv.as_deref().unwrap_or_default();
        cbc::decrypt(cipher_key, iv, ciphertext).map_err(DecryptionError::Cbc)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecryptionError {
    #[error("protocol error: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("cbc error: {0}")]
    Cbc(#[from] crate::crypto::cbc::CbcError),
    #[error("store error: {0}")]
    Store(Box<dyn std::error::Error + Send + Sync>),
    #[error("no valid sessions")]
    NoValidSessions,
    #[error("uninitialized session")]
    UninitializedSession,
    #[error("message is too far in the future")]
    TooFarInFuture,
}

impl From<crate::signal::root_key::RootKeyError> for DecryptionError {
    fn from(e: crate::signal::root_key::RootKeyError) -> Self {
        DecryptionError::Protocol(ProtocolError::from(e))
    }
}

impl<S: SignalProtocolStore + Clone + 'static> SessionCipher<S> {
    pub async fn decrypt(
        &self,
        ciphertext: crate::signal::protocol::Ciphertext,
    ) -> Result<Vec<u8>, DecryptionError> {
        match ciphertext {
            crate::signal::protocol::Ciphertext::PreKey(prekey_msg) => {
                self.decrypt_prekey_message(&prekey_msg).await
            }
            crate::signal::protocol::Ciphertext::Whisper(whisper_msg) => {
                let mut session_record = self
                    .store
                    .load_session(&self.remote_address)
                    .await
                    .map_err(DecryptionError::Store)?;
                let plaintext = self
                    .decrypt_whisper_message(&mut session_record, &whisper_msg)
                    .await?;
                self.store
                    .store_session(&self.remote_address, &session_record)
                    .await
                    .map_err(DecryptionError::Store)?;
                Ok(plaintext)
            }
        }
    }

    async fn decrypt_prekey_message(
        &self,
        message: &PreKeySignalMessage,
    ) -> Result<Vec<u8>, DecryptionError> {
        let mut session_record: SessionRecord = self
            .store
            .load_session(&self.remote_address)
            .await
            .map_err(DecryptionError::Store)?;

        // First, try the re-keying scenario: decrypt first with current session, then process prekey
        // This handles the case where the sender used the existing session state for encryption
        if !session_record.is_fresh() {
            let decrypt_result = self
                .decrypt_whisper_message(&mut session_record, &message.message)
                .await;
            
            if let Ok(plaintext) = decrypt_result {
                // Successful decryption with current session - now process prekey for future messages
                let builder = SessionBuilder::new(self.store.clone(), self.remote_address.clone());
                let used_prekey_id = builder
                    .process_prekey_message(&mut session_record, message)
                    .await
                    .map_err(|e| DecryptionError::Store(Box::new(e)))?;

                if let Some(id) = used_prekey_id {
                    self.store
                        .remove_prekey(id)
                        .await
                        .map_err(DecryptionError::Store)?;
                }

                self.store
                    .store_session(&self.remote_address, &session_record)
                    .await
                    .map_err(DecryptionError::Store)?;

                return Ok(plaintext);
            }
        }

        // If re-keying approach failed or session is fresh, use initial session establishment approach:
        // Process prekey first to establish/update session, then decrypt
        let builder = SessionBuilder::new(self.store.clone(), self.remote_address.clone());
        let used_prekey_id = builder
            .process_prekey_message(&mut session_record, message)
            .await
            .map_err(|e| DecryptionError::Store(Box::new(e)))?;

        let plaintext = self
            .decrypt_whisper_message(&mut session_record, &message.message)
            .await?;

        if let Some(id) = used_prekey_id {
            self.store
                .remove_prekey(id)
                .await
                .map_err(DecryptionError::Store)?;
        }

        self.store
            .store_session(&self.remote_address, &session_record)
            .await
            .map_err(DecryptionError::Store)?;

        Ok(plaintext)
    }

    pub async fn decrypt_whisper_message(
        &self,
        session_record: &mut SessionRecord,
        message: &SignalMessage,
    ) -> Result<Vec<u8>, DecryptionError> {
        // Try with current session state
        let pt_result = self
            .try_decrypt_with_state(session_record.session_state_mut(), message)
            .await;

        if pt_result.is_ok() {
            return pt_result;
        }

        // If that fails, try with previous states
        for (i, state) in session_record.previous_states_mut().iter_mut().enumerate() {
            if let Ok(pt) = self.try_decrypt_with_state(state, message).await {
                session_record.promote_state(i);
                return Ok(pt);
            }
        }

        // If all states failed, return the error from the original attempt
        match pt_result {
            Err(e) => Err(e),
            Ok(_) => Err(DecryptionError::NoValidSessions),
        }
    }

    async fn try_decrypt_with_state(
        &self,
        session_state: &mut SessionState,
        ciphertext: &SignalMessage,
    ) -> Result<Vec<u8>, DecryptionError> {
        self.decrypt_with_state(session_state, ciphertext).await
    }

    async fn decrypt_with_state(
        &self,
        session_state: &mut SessionState,
        message: &SignalMessage,
    ) -> Result<Vec<u8>, DecryptionError> {
        if !session_state.has_sender_chain() {
            return Err(DecryptionError::UninitializedSession);
        }
        if message.message_version != session_state.session_version() as u8 {
            return Err(DecryptionError::Protocol(ProtocolError::InvalidVersion(
                message.message_version,
            )));
        }

        let their_ephemeral = message
            .sender_ratchet_key
            .as_any()
            .downcast_ref::<DjbEcPublicKey>()
            .expect("Expected DjbEcPublicKey in sender_ratchet_key");
        let (chain_key, message_keys) =
            self.get_or_create_message_keys(session_state, their_ephemeral, message.counter())?;

        crate::signal::protocol::SignalMessage::deserialize_and_verify(
            &message.serialized_form,
            message_keys.mac_key.as_deref().unwrap_or_default(),
            &session_state.remote_identity_public(),
            session_state.local_identity_public().as_ref(),
        )?;

        let decrypted_plaintext = self.decrypt_internal(&message_keys, message.ciphertext())?;

        session_state.set_receiver_chain_key(message.sender_ratchet_key.clone(), chain_key);

        Ok(decrypted_plaintext)
    }
}

use std::error::Error;

#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    #[error("Store error: {0}")]
    Store(Box<dyn Error + Send + Sync>),
    #[error("Untrusted identity key")]
    UntrustedIdentity,
    #[error("Invalid signature on prekey bundle")]
    InvalidSignature,
    #[error("No signed prekey found in bundle")]
    NoSignedPreKey,
    #[error("No one-time prekey found for ID {0}")]
    NoOneTimePreKeyFound(u32),
    #[error("Session setup error: {0}")]
    SessionSetup(Box<dyn Error + Send + Sync>),
}

impl From<Box<dyn Error + Send + Sync>> for BuilderError {
    fn from(err: Box<dyn Error + Send + Sync>) -> Self {
        BuilderError::Store(err)
    }
}

impl From<crate::signal::root_key::RootKeyError> for BuilderError {
    fn from(e: crate::signal::root_key::RootKeyError) -> Self {
        BuilderError::SessionSetup(Box::new(e))
    }
}

const MESSAGE_KEY_SEED: &[u8] = &[0x01];
const CHAIN_KEY_SEED: &[u8] = &[0x02];
const KDF_SALT: &str = "WhisperMessageKeys";
const DERIVED_SECRETS_SIZE: usize = 80;

fn get_next_chain_key(current: &ChainKey) -> ChainKey {
    let current_key = current.key.as_deref().unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(current_key).unwrap();
    mac.update(CHAIN_KEY_SEED);
    let next_key_bytes: [u8; 32] = mac.finalize().into_bytes().into();
    ChainKey {
        key: Some(next_key_bytes.to_vec()),
        index: Some(current.index.unwrap_or(0) + 1),
    }
}

fn get_message_keys(current: &ChainKey) -> MessageKey {
    let current_key = current.key.as_deref().unwrap_or_default();
    let mut mac = Hmac::<Sha256>::new_from_slice(current_key).unwrap();
    mac.update(MESSAGE_KEY_SEED);
    let input_key_material: [u8; 32] = mac.finalize().into_bytes().into();

    let key_material_bytes = kdf::derive_secrets(
        &input_key_material,
        None,
        KDF_SALT.as_bytes(),
        DERIVED_SECRETS_SIZE,
    )
    .unwrap();

    MessageKey {
        index: current.index,
        cipher_key: Some(key_material_bytes[0..32].to_vec()),
        mac_key: Some(key_material_bytes[32..64].to_vec()),
        iv: Some(key_material_bytes[64..80].to_vec()),
    }
}

// Corresponds to session/Builder
pub struct SessionBuilder<S: SignalProtocolStore> {
    store: S,
    remote_address: SignalAddress,
}

impl<S: SignalProtocolStore + Clone> SessionBuilder<S> {
    pub fn new(store: S, remote_address: SignalAddress) -> Self {
        Self {
            store,
            remote_address,
        }
    }

    // Corresponds to SessionBuilder.Process
    pub async fn process_prekey_message(
        &self,
        session_record: &mut SessionRecord,
        message: &PreKeySignalMessage,
    ) -> Result<Option<u32>, BuilderError> {
        let their_identity_key = &message.identity_key;
        if !self
            .store
            .is_trusted_identity(&self.remote_address, their_identity_key)
            .await
            .map_err(BuilderError::Store)?
        {
            return Err(BuilderError::UntrustedIdentity);
        }

        let our_identity = self.store.get_identity_key_pair().await?;
        let our_signed_prekey = self
            .store
            .load_signed_prekey(message.signed_pre_key_id())
            .await?
            .ok_or_else(|| BuilderError::NoSignedPreKey)?;

        let mut our_one_time_prekey: Option<PreKeyRecordStructure> = None;
        if let Some(id) = message.pre_key_id() {
            match self.store.load_prekey(id).await? {
                Some(record) => our_one_time_prekey = Some(record),
                None => {
                    log::warn!(
                        "One-time prekey {id} not found, proceeding without it (multi-device race condition)"
                    );
                    // Proceed with None, do not return error
                }
            }
        }

        let our_signed_prekey_keypair = record::signed_pre_key_record_key_pair(&our_signed_prekey);
        let our_one_time_prekey_keypair = our_one_time_prekey
            .as_ref()
            .map(record::pre_key_record_key_pair);

        let receiver_params = crate::signal::ratchet::parameters::ReceiverParameters {
            our_identity_key_pair: our_identity.clone(),
            our_signed_pre_key: our_signed_prekey_keypair.clone(),
            our_one_time_pre_key: our_one_time_prekey_keypair.as_ref(),
            their_identity_key: their_identity_key.clone(),
            their_base_key: message.base_key.clone(),
        };
        let session_key_pair = crate::signal::ratchet::calculate_receiver_session(&receiver_params)
            .map_err(BuilderError::SessionSetup)?;

        if !session_record.is_fresh() {
            session_record.archive_current_state();
        }

        let state = session_record.session_state_mut();
        state.set_session_version(3);
        state.set_remote_identity_key(their_identity_key.clone());
        state.set_local_identity_key(our_identity.public_key().clone());
        state.set_root_key(session_key_pair.root_key);
        state.set_sender_chain(
            our_signed_prekey_keypair,
            session_key_pair.chain_key.clone(),
        );
        state.set_sender_base_key(message.base_key.public_key());

        self.store
            .save_identity(&self.remote_address, their_identity_key)
            .await
            .map_err(BuilderError::Store)?;

        Ok(message.pre_key_id())
    }
    /// Build a session from a PreKeyBundle (for outgoing messages)
    pub async fn process_bundle(
        &self,
        session_record: &mut SessionRecord,
        bundle: &PreKeyBundle,
    ) -> Result<(), BuilderError> {
        let our_identity = self.store.get_identity_key_pair().await?;
        let our_base_key = crate::signal::ecc::curve::generate_key_pair();

        let their_identity_key = &bundle.identity_key;
        if !self
            .store
            .is_trusted_identity(&self.remote_address, their_identity_key)
            .await?
        {
            return Err(BuilderError::UntrustedIdentity);
        }
        // Signature verification
        let signed_pre_key_public = crate::signal::ecc::keys::DjbEcPublicKey::new(
            bundle.signed_pre_key_public.public_key(),
        );

        if !crate::signal::ecc::curve::verify_signature(
            their_identity_key.public_key(),
            &signed_pre_key_public.serialize(),
            &bundle.signed_pre_key_signature,
        ) {
            return Err(BuilderError::InvalidSignature);
        }

        let sender_params = crate::signal::ratchet::parameters::SenderParameters {
            our_identity_key_pair: our_identity.clone(),
            our_base_key: our_base_key.clone(),
            their_identity_key: their_identity_key.clone(),
            their_signed_pre_key: std::sync::Arc::new(bundle.signed_pre_key_public.clone())
                as std::sync::Arc<dyn crate::signal::ecc::keys::EcPublicKey>,
            their_one_time_pre_key: bundle
                .pre_key_public
                .clone()
                .map(|k| Arc::new(k) as Arc<dyn crate::signal::ecc::keys::EcPublicKey>),
        };
        let session_key_pair = crate::signal::ratchet::calculate_sender_session(&sender_params)
            .map_err(BuilderError::SessionSetup)?;

        if !session_record.is_fresh() {
            session_record.archive_current_state();
        }

        let state = session_record.session_state_mut();
        state.set_session_version(3);
        state.set_remote_identity_key(their_identity_key.clone());
        state.set_local_identity_key(our_identity.public_key().clone());

        let sending_ratchet_key = crate::signal::ecc::curve::generate_key_pair();
        let sending_chain = session_key_pair.root_key.create_chain(
            std::sync::Arc::new(bundle.signed_pre_key_public.clone())
                as std::sync::Arc<dyn crate::signal::ecc::keys::EcPublicKey>,
            &sending_ratchet_key,
        )?;

        state.add_receiver_chain(
            std::sync::Arc::new(bundle.signed_pre_key_public.clone())
                as std::sync::Arc<dyn crate::signal::ecc::keys::EcPublicKey>,
            session_key_pair.chain_key,
        );
        state.set_sender_chain(sending_ratchet_key, sending_chain.chain_key);
        state.set_root_key(sending_chain.root_key);

        state.set_unacknowledged_prekey_message(
            bundle.pre_key_id,
            bundle.signed_pre_key_id,
            our_base_key.public_key,
        );

        self.store
            .save_identity(&self.remote_address, their_identity_key)
            .await
            .map_err(BuilderError::Store)?;

        Ok(())
    }
}
