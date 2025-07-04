// Corresponds to libsignal-protocol-go/groups/GroupCipher.go

use super::builder::GroupSessionBuilder;
use crate::crypto::cbc;
use crate::signal::groups::message::SenderKeyMessage;
use crate::signal::sender_key_name::SenderKeyName;
use crate::signal::store::SenderKeyStore;
use std::error::Error;
use std::sync::Arc;

pub struct GroupCipher<S: SenderKeyStore> {
    sender_key_id: SenderKeyName,
    sender_key_store: Arc<S>,
    #[allow(dead_code)]
    session_builder: GroupSessionBuilder<S>,
}

impl<S: SenderKeyStore> GroupCipher<S> {
    pub fn new(
        sender_key_id: SenderKeyName,
        sender_key_store: Arc<S>,
        session_builder: GroupSessionBuilder<S>,
    ) -> Self {
        Self {
            sender_key_id,
            sender_key_store,
            session_builder,
        }
    }

    pub async fn encrypt(
        &self,
        plaintext: &[u8],
    ) -> Result<SenderKeyMessage, Box<dyn Error + Send + Sync>> {
        let mut key_record = self
            .sender_key_store
            .load_sender_key(&self.sender_key_id)
            .await?;
        let state = key_record
            .get_sender_key_state_mut()
            .ok_or("No sender key state")?;

        let sender_key = state.sender_chain_key().sender_message_key();
        let ciphertext = cbc::encrypt(sender_key.cipher_key(), sender_key.iv(), plaintext)?;

        let sender_key_message = SenderKeyMessage::new(
            state.key_id(),
            sender_key.iteration(),
            ciphertext.clone(),
            vec![], // TODO: Add signature logic
        );

        state.set_sender_chain_key(state.sender_chain_key().next());
        self.sender_key_store
            .store_sender_key(&self.sender_key_id, key_record)
            .await?;

        Ok(sender_key_message)
    }

    pub async fn decrypt(
        &self,
        sender_key_message: &SenderKeyMessage,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
        let mut key_record = self
            .sender_key_store
            .load_sender_key(&self.sender_key_id)
            .await?;
        let state = key_record
            .get_sender_key_state_by_id_mut(sender_key_message.key_id())
            .ok_or("No sender key state")?;
        // TODO: Implement signature verification if needed
        let sender_key =
            crate::signal::groups::ratchet::get_sender_key(state, sender_key_message.iteration())?;
        let plaintext = cbc::decrypt(
            sender_key.cipher_key(),
            sender_key.iv(),
            sender_key_message.ciphertext(),
        )?;
        self.sender_key_store
            .store_sender_key(&self.sender_key_id, key_record)
            .await?;
        Ok(plaintext)
    }
}
