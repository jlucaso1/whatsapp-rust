// Corresponds to libsignal-protocol-go/groups/GroupCipher.go

use super::builder::GroupSessionBuilder;
use super::ratchet::{
    derive_message_key_material, get_next_sender_chain_key, get_sender_message_key,
};
use crate::crypto::cbc;
use crate::signal::ecc;
use crate::signal::groups::message::SenderKeyMessage;
use crate::signal::groups::ratchet::get_sender_key;
use crate::signal::sender_key_name::SenderKeyName;
use crate::signal::store::SenderKeyStore;
use std::error::Error;

pub struct GroupCipher<S: SenderKeyStore> {
    sender_key_id: SenderKeyName,
    sender_key_store: S,
    #[allow(dead_code)]
    session_builder: GroupSessionBuilder<S>,
}

impl<S: SenderKeyStore> GroupCipher<S> {
    pub fn new(
        sender_key_id: SenderKeyName,
        sender_key_store: S,
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
    ) -> Result<SenderKeyMessage, Box<dyn Error + Send + Sync + 'static>> {
        let mut key_record = self
            .sender_key_store
            .load_sender_key(&self.sender_key_id)
            .await?;
        let state = key_record
            .get_sender_key_state_mut()
            .ok_or("No sender key state")?;

        let chain_key = state
            .sender_chain_key
            .as_ref()
            .ok_or("SenderKeyState has no chain key")?;
        let sender_key = get_sender_message_key(chain_key);
        let (iv, cipher_key) = derive_message_key_material(&sender_key);
        let ciphertext = cbc::encrypt(&cipher_key, &iv, plaintext)?;

        // Efficiently serialize the message components for signing without creating an intermediate struct
        let mut buf = Vec::with_capacity(128);
        buf.push((3 << 4) | 3); // version byte
        let proto_msg = whatsapp_proto::whatsapp::SenderKeyMessage {
            id: state.sender_key_id,
            iteration: sender_key.iteration,
            ciphertext: Some(ciphertext.clone()),
        };
        prost::Message::encode(&proto_msg, &mut buf).unwrap();

        let signing_key_proto = state
            .sender_signing_key
            .as_ref()
            .ok_or("Missing signing key")?;
        let private_key_bytes: [u8; 32] = signing_key_proto
            .private
            .as_deref()
            .ok_or("No private key")?
            .try_into()
            .map_err(|_| "Invalid private key length")?;
        let private_key = ecc::keys::DjbEcPrivateKey::new(private_key_bytes);
        let signature = ecc::curve::calculate_signature(private_key, &buf);

        let sender_key_message = SenderKeyMessage::new(
            state.sender_key_id.unwrap_or(0),
            sender_key.iteration.unwrap_or(0),
            ciphertext.clone(),
            signature,
        );

        let next_chain_key = get_next_sender_chain_key(chain_key);
        state.sender_chain_key = Some(next_chain_key);

        self.sender_key_store
            .store_sender_key(&self.sender_key_id, key_record)
            .await?;

        Ok(sender_key_message)
    }

    pub async fn decrypt(
        &self,
        sender_key_message: &SenderKeyMessage,
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync + 'static>> {
        let mut key_record = self
            .sender_key_store
            .load_sender_key(&self.sender_key_id)
            .await?;
        let state = key_record
            .get_sender_key_state_by_id_mut(sender_key_message.key_id())
            .ok_or("No sender key state for given key ID")?;
        // TODO: Implement signature verification if needed
        let sender_key = get_sender_key(state, sender_key_message.iteration())?;
        let (iv, cipher_key) = super::ratchet::derive_message_key_material(&sender_key);
        let plaintext = cbc::decrypt(&cipher_key, &iv, sender_key_message.ciphertext())?;
        self.sender_key_store
            .store_sender_key(&self.sender_key_id, key_record)
            .await?;
        Ok(plaintext)
    }
}
