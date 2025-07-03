use super::address::SignalAddress;
use super::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use super::store::SignalProtocolStore;
use crate::signal::protocol::ProtocolError;
use crate::signal::state::record::PreKeyRecord;
use crate::signal::state::session_record::SessionRecord;
use crate::signal::state::session_state::SessionState;
use std::sync::Arc;

pub struct SessionCipher<S: SignalProtocolStore> {
    store: Arc<S>,
    remote_address: SignalAddress,
}

impl<S: SignalProtocolStore + 'static> SessionCipher<S> {
    pub fn new(store: Arc<S>, remote_address: SignalAddress) -> Self {
        Self {
            store,
            remote_address,
        }
    }

    pub async fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<Box<dyn CiphertextMessage>, Box<dyn std::error::Error>> {
        let mut session_record: SessionRecord = self
            .store
            .load_session(&self.remote_address)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;
        let session_state = session_record.session_state_mut();

        let chain_key = session_state.sender_chain_key();
        let message_keys = chain_key.message_keys();

        let ciphertext = self.encrypt_internal(&message_keys, plaintext)?;

        let signal_message = SignalMessage::new(
            message_keys.mac_key(),
            session_state.sender_ratchet_key(),
            chain_key.index(),
            session_state.previous_counter(),
            ciphertext,
            &*session_state.local_identity_public(),
            &*session_state.remote_identity_public(),
        )?;

        let final_message: Box<dyn CiphertextMessage> =
            if session_state.has_unacknowledged_prekey_message() {
                let pending = session_state
                    .pending_pre_key
                    .as_ref()
                    .ok_or("Pending pre-key not found")?;
                let local_reg_id = self
                    .store
                    .get_local_registration_id()
                    .await
                    .map_err(|e| -> Box<dyn std::error::Error> { e })?;

                Box::new(PreKeySignalMessage::new(
                    local_reg_id,
                    pending.pre_key_id,
                    pending.signed_pre_key_id,
                    Arc::new(pending.base_key.clone())
                        as Arc<dyn crate::signal::ecc::keys::EcPublicKey>,
                    session_state.local_identity_public().as_ref().clone(),
                    signal_message,
                )?)
            } else {
                Box::new(signal_message)
            };

        session_state.set_sender_chain_key(chain_key.next_key());
        self.store
            .store_session(&self.remote_address, &session_record)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;

        Ok(final_message)
    }

    fn encrypt_internal(
        &self,
        message_keys: &super::message_key::MessageKeys,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use crate::crypto::cbc;
        cbc::encrypt(message_keys.cipher_key(), message_keys.iv(), plaintext).map_err(|e| e.into())
    }
}

impl<S: SignalProtocolStore + 'static> SessionCipher<S> {
    fn get_or_create_message_keys(
        &self,
        session_state: &mut crate::signal::state::session_state::SessionState,
        ciphertext: &SignalMessage,
    ) -> Result<
        (
            crate::signal::chain_key::ChainKey,
            crate::signal::message_key::MessageKeys,
        ),
        DecryptionError,
    > {
        if let Some(chain) = session_state
            .receiver_chains_mut()
            .get_mut(&ciphertext.sender_ratchet_key.public_key())
        {
            let mut chain_key = chain.chain_key.clone();
            if chain_key.index() > ciphertext.counter {
                if let Some(keys) = chain.remove_message_keys(ciphertext.counter) {
                    return Ok((chain_key, keys));
                }
                return Err(DecryptionError::OldCounter {
                    current: chain_key.index(),
                    received: ciphertext.counter,
                });
            }

            if ciphertext.counter > chain_key.index() + 2000 {
                return Err(DecryptionError::TooFarInFuture);
            }

            while chain_key.index() < ciphertext.counter {
                chain.add_message_keys(chain_key.message_keys());
                chain_key = chain_key.next_key();
            }

            let message_keys = chain_key.message_keys();
            chain_key = chain_key.next_key();
            return Ok((chain_key, message_keys));
        } else {
            // This is the DH ratchet step for the receiver.
            let their_ephemeral = ciphertext.sender_ratchet_key.clone();

            let root_key = session_state.root_key().clone();
            let our_ephemeral = session_state.sender_ratchet_key_pair().clone();

            // This calculates the new root and chain key for the receiving chain
            let receiver_chain_pair =
                root_key.create_chain(their_ephemeral.clone(), &our_ephemeral)?;

            // We must also calculate a new sending chain for ourselves
            let new_our_ephemeral = super::ecc::curve::generate_key_pair();
            let sender_chain_pair = receiver_chain_pair
                .root_key
                .create_chain(their_ephemeral.clone(), &new_our_ephemeral)?;

            // Update the state with the new keys
            session_state.set_root_key(sender_chain_pair.root_key);
            session_state.add_receiver_chain(their_ephemeral, receiver_chain_pair.chain_key);
            session_state.set_sender_chain(new_our_ephemeral, sender_chain_pair.chain_key);

            // Now that the new chain exists, get the keys from it.
            // This logic is the same as the `if` block above.
            let chain = session_state
                .receiver_chains_mut()
                .get_mut(&ciphertext.sender_ratchet_key.public_key())
                .unwrap();
            let mut chain_key = chain.chain_key.clone();

            while chain_key.index() < ciphertext.counter {
                chain.add_message_keys(chain_key.message_keys());
                chain_key = chain_key.next_key();
            }

            let message_keys = chain_key.message_keys();
            chain_key = chain_key.next_key();
            Ok((chain_key, message_keys))
        }
    }

    fn decrypt_internal(
        &self,
        message_keys: &super::message_key::MessageKeys,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        use crate::crypto::cbc;
        cbc::decrypt(message_keys.cipher_key(), message_keys.iv(), ciphertext)
            .map_err(|e| DecryptionError::Cbc(e)) // Mapped to CbcError
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
    #[error("old counter (current: {current}, received: {received})")]
    OldCounter { current: u32, received: u32 },
    #[error("message is too far in the future")]
    TooFarInFuture,
}

impl From<crate::signal::root_key::RootKeyError> for DecryptionError {
    fn from(e: crate::signal::root_key::RootKeyError) -> Self {
        DecryptionError::Protocol(ProtocolError::from(e))
    }
}

impl<S: SignalProtocolStore + 'static> SessionCipher<S> {
    pub async fn decrypt(&self, ciphertext_bytes: &[u8]) -> Result<Vec<u8>, DecryptionError> {
        let mut session_record = self
            .store
            .load_session(&self.remote_address)
            .await
            .map_err(|e| DecryptionError::Store(e.into()))?;

        // First, try to parse the message as a PreKeySignalMessage
        if let Ok(prekey_msg) = PreKeySignalMessage::deserialize(ciphertext_bytes) {
            let builder = super::session::SessionBuilder::new(
                self.store.clone(),
                self.remote_address.clone(),
            );
            let _unsigned_prekey_id = builder
                .process_prekey_message(&prekey_msg)
                .await
                .map_err(|e| DecryptionError::Store(e.into()))?;
            // Now decrypt the inner SignalMessage
            return self
                .decrypt_with_state(session_record.session_state_mut(), &prekey_msg.message)
                .await;
        }

        // If not a pkmsg, try as a regular SignalMessage
        if let Ok(msg) = SignalMessage::deserialize(ciphertext_bytes) {
            if let Ok(plaintext) = self
                .try_decrypt_with_state(session_record.session_state_mut(), &msg)
                .await
            {
                self.store
                    .store_session(&self.remote_address, &session_record)
                    .await
                    .map_err(|e| DecryptionError::Store(e))?;
                return Ok(plaintext);
            }

            // Try previous states
            for i in 0..session_record.previous_states().len() {
                let mut state_clone = session_record.previous_states()[i].clone();
                if let Ok(plaintext) = self.try_decrypt_with_state(&mut state_clone, &msg).await {
                    session_record.promote_state(i);
                    self.store
                        .store_session(&self.remote_address, &session_record)
                        .await
                        .map_err(DecryptionError::Store)?;
                    return Ok(plaintext);
                }
            }
        }

        Err(DecryptionError::NoValidSessions)
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
        ciphertext: &SignalMessage,
    ) -> Result<Vec<u8>, DecryptionError> {
        if session_state.sender_chain_opt().is_none() {
            return Err(DecryptionError::UninitializedSession);
        }
        let (chain_key, message_keys) =
            self.get_or_create_message_keys(session_state, ciphertext)?;
        // MAC verification
        crate::signal::protocol::signal_message_deserialize_and_verify(
            &ciphertext.serialized_form,
            message_keys.mac_key(),
            session_state.remote_identity_public().as_ref(),
            session_state.local_identity_public().as_ref(),
        )?;
        let decrypted_plaintext = self.decrypt_internal(&message_keys, &ciphertext.ciphertext)?;
        session_state.set_receiver_chain_key(ciphertext.sender_ratchet_key.clone(), chain_key);
        Ok(decrypted_plaintext)
    }
}

// Corresponds to session/Builder
pub struct SessionBuilder<S: SignalProtocolStore> {
    store: Arc<S>,
    remote_address: SignalAddress,
}

impl<S: SignalProtocolStore> SessionBuilder<S> {
    pub fn new(store: Arc<S>, remote_address: SignalAddress) -> Self {
        Self {
            store,
            remote_address,
        }
    }

    // Corresponds to SessionBuilder.Process
    pub async fn process_prekey_message(
        &self,
        message: &PreKeySignalMessage,
    ) -> Result<Option<u32>, Box<dyn std::error::Error + Send + Sync>> {
        let their_identity_key = &message.identity_key;
        if !self
            .store
            .is_trusted_identity(&self.remote_address, their_identity_key)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?
        {
            return Err("Untrusted identity key".into());
        }

        let our_identity = self
            .store
            .get_identity_key_pair()
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;
        let our_signed_prekey = self
            .store
            .load_signed_prekey(message.signed_pre_key_id)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?
            .ok_or("Signed pre-key not found in store")?;

        let mut our_one_time_prekey: Option<PreKeyRecord> = None;
        if let Some(id) = message.pre_key_id {
            our_one_time_prekey = self
                .store
                .load_prekey(id)
                .await
                .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;
        }

        let session_key_pair = super::ratchet::calculate_receiver_session(
            &our_identity,
            our_signed_prekey.key_pair(),
            our_one_time_prekey.as_ref().map(|r| r.key_pair()),
            their_identity_key,
            message.base_key.clone(),
        )?;

        let mut session_record = self
            .store
            .load_session(&self.remote_address)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;
        if session_record.is_fresh() {
            session_record.archive_current_state();
        }

        let state = session_record.session_state_mut();
        state.set_session_version(3);
        state.set_remote_identity_key(their_identity_key.clone());
        state.set_local_identity_key(our_identity.public_key.clone());
        state.set_sender_chain(
            our_signed_prekey.key_pair().clone(),
            session_key_pair.chain_key,
        );
        state.set_root_key(session_key_pair.root_key);

        self.store
            .store_session(&self.remote_address, &session_record)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;
        self.store
            .save_identity(&self.remote_address, their_identity_key)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })?;

        Ok(message.pre_key_id)
    }
}
