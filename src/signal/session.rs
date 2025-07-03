use super::address::SignalAddress;
use super::protocol::{CiphertextMessage, PreKeySignalMessage, SignalMessage};
use super::store::SignalProtocolStore;
use std::sync::Arc;
use crate::signal::state::session_record::SessionRecord;

pub struct SessionCipher<S: SignalProtocolStore> {
    store: Arc<S>,
    remote_address: SignalAddress,
}

impl<S: SignalProtocolStore + 'static> SessionCipher<S> {
    pub fn new(store: Arc<S>, remote_address: SignalAddress) -> Self {
        Self { store, remote_address }
    }

    pub async fn encrypt(&self, plaintext: &[u8]) -> Result<Box<dyn CiphertextMessage>, Box<dyn std::error::Error>> {
        let mut session_record: SessionRecord = self.store
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

        // If we need to wrap in a PreKeySignalMessage, do so directly
        let result: Box<dyn CiphertextMessage> = if session_state.has_unacknowledged_prekey_message() {
            let pending = session_state.pending_pre_key.as_ref().unwrap();
            let local_reg_id = self.store
                .get_local_registration_id()
                .await
                .map_err(|e| -> Box<dyn std::error::Error> { e })?;
            let prekey_message = PreKeySignalMessage::new(
                local_reg_id,
                pending.pre_key_id,
                pending.signed_pre_key_id,
                pending.base_key.clone(),
                session_state.local_identity_public().as_ref().clone(),
                signal_message,
            )?;
            Box::new(prekey_message)
        } else {
            Box::new(signal_message)
        };

        session_state.set_sender_chain_key(chain_key.next_key());
        self.store
            .store_session(&self.remote_address, &session_record)
            .await
            .map_err(|e| -> Box<dyn std::error::Error> { e })?;

        Ok(result)
    }

    fn encrypt_internal(
        &self,
        message_keys: &super::message_key::MessageKeys,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut ciphertext = plaintext.to_vec();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= message_keys.iv()[i % message_keys.iv().len()];
        }
        Ok(ciphertext)
    }
}
