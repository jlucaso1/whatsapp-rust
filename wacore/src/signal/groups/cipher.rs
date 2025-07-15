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

        let proto_msg = waproto::whatsapp::SenderKeyMessage {
            id: state.sender_key_id,
            iteration: sender_key.iteration,
            ciphertext: Some(ciphertext.clone()),
        };

        // 1. Assemble the data to be signed: version_byte | serialized_proto
        let mut proto_buf = Vec::new();
        prost::Message::encode(&proto_msg, &mut proto_buf).unwrap();
        let mut data_to_sign = Vec::with_capacity(1 + proto_buf.len());
        data_to_sign.push((3 << 4) | 3); // version byte
        data_to_sign.extend_from_slice(&proto_buf);

        // 2. Sign the assembled data.
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
        let signature_bytes = ecc::curve::calculate_signature(private_key, &data_to_sign);

        let sender_key_message = SenderKeyMessage {
            proto: proto_msg,
            signature: signature_bytes,
        };

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
        data_to_verify: &[u8],
    ) -> Result<Vec<u8>, Box<dyn Error + Send + Sync + 'static>> {
        let mut key_record = self
            .sender_key_store
            .load_sender_key(&self.sender_key_id)
            .await?;
        let state = key_record
            .get_sender_key_state_by_id_mut(sender_key_message.key_id())
            .ok_or("No sender key state for given key ID")?;

        // Get the public key for signature verification.
        let signing_key_pub_bytes: [u8; 32] = state
            .sender_signing_key
            .as_ref()
            .and_then(|sk| sk.public.as_deref())
            .ok_or("No public key in sender key state")?
            .try_into()
            .map_err(|_| "Invalid public key length in state")?;
        let signing_key_pub = ecc::keys::DjbEcPublicKey::new(signing_key_pub_bytes);

        let is_valid = ecc::curve::verify_signature(
            signing_key_pub,
            data_to_verify,
            &sender_key_message.signature,
        );

        if !is_valid {
            return Err("Invalid signature on SenderKeyMessage".into());
        }

        let sender_key = get_sender_key(state, sender_key_message.iteration())?;
        let (iv, cipher_key) = super::ratchet::derive_message_key_material(&sender_key);
        let plaintext = cbc::decrypt(&cipher_key, &iv, sender_key_message.ciphertext())?;
        self.sender_key_store
            .store_sender_key(&self.sender_key_id, key_record)
            .await?;
        Ok(plaintext)
    }
}
