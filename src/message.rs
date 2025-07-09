use crate::appstate::keys::ALL_PATCH_NAMES;
use crate::appstate_sync::app_state_sync;
use crate::binary::node::Node;
use crate::client::Client;
use crate::proto_helpers::MessageExt;
use crate::signal::{address::SignalAddress, session::SessionCipher};
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use prost::Message as ProtoMessage;
use std::sync::Arc;

use whatsapp_proto::whatsapp as wa;

// --- Deduplication imports ---
use crate::error::decryption::DecryptionError;

use sha2::{Digest, Sha256};

// Helper to unpad messages after decryption
fn unpad_message_ref(plaintext: &[u8], version: u8) -> Result<&[u8], anyhow::Error> {
    if version < 3 {
        if plaintext.is_empty() {
            return Err(anyhow::anyhow!("plaintext is empty, cannot unpad"));
        }
        let pad_len = plaintext[plaintext.len() - 1] as usize;
        if pad_len == 0 || pad_len > plaintext.len() {
            return Err(anyhow::anyhow!("invalid padding length: {}", pad_len));
        }
        Ok(&plaintext[..plaintext.len() - pad_len])
    } else {
        Ok(plaintext)
    }
}

// --- Buffered decrypt wrapper for deduplication ---
impl Client {
    async fn buffered_decrypt<F, Fut>(
        &self,
        ciphertext: &[u8],
        decrypt_fn: F,
    ) -> Result<Vec<u8>, DecryptionError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>, anyhow::Error>>,
    {
        let ciphertext_hash: [u8; 32] = Sha256::digest(ciphertext).into();

        let backend = { self.store.read().await.backend.clone() };

        if let Some(_buffered_event) = backend
            .get_buffered_event(&ciphertext_hash)
            .await
            .unwrap_or(None)
        {
            log::debug!(target: "Client/Recv", "Ignoring message: event was already processed (hash: {})", hex::encode(ciphertext_hash));
            return Err(DecryptionError::AlreadyProcessed);
        }

        match decrypt_fn().await {
            Ok(plaintext) => {
                // Store the hash and plaintext to prevent reprocessing
                if let Err(e) = backend
                    .put_buffered_event(
                        &ciphertext_hash,
                        Some(plaintext.clone()),
                        chrono::Utc::now(),
                    )
                    .await
                {
                    log::warn!("Failed to save decrypted event to buffer: {:?}", e);
                }
                Ok(plaintext)
            }
            Err(e) => {
                // Store only the hash to mark it as seen, even if decryption fails,
                // to avoid retrying a known-bad message.
                if let Err(store_err) = backend
                    .put_buffered_event(&ciphertext_hash, None, chrono::Utc::now())
                    .await
                {
                    log::warn!(
                        "Failed to save failed event hash to buffer: {:?}",
                        store_err
                    );
                }
                Err(DecryptionError::Crypto(e))
            }
        }
    }

    /// Handles an incoming `<message>` stanza, which contains an encrypted payload.
    pub async fn handle_encrypted_message(self: Arc<Self>, node: Node) {
        let info = match self.parse_message_info(&node).await {
            Ok(info) => info,
            Err(e) => {
                log::warn!("Failed to parse message info: {e:?}");
                return;
            }
        };

        let enc_node = match node.get_optional_child("enc") {
            Some(node) => node,
            None => {
                log::warn!("Received message without <enc> child: {}", node.tag);
                return;
            }
        };

        let ciphertext = match &enc_node.content {
            Some(crate::binary::node::NodeContent::Bytes(b)) => b.clone(),
            _ => {
                log::warn!("Enc node has no byte content");
                return;
            }
        };

        // --- Deduplication: use buffered_decrypt ---
        let decrypt_closure = || async {
            let enc_version = enc_node
                .attrs()
                .optional_string("v")
                .unwrap_or("2")
                .parse::<u8>()
                .unwrap_or(2);

            let signal_address = SignalAddress::new(
                info.source.sender.user.clone(),
                info.source.sender.device as u32,
            );
            let store_arc = self.store.clone();
            let cipher = SessionCipher::new(store_arc, signal_address);

            let enc_type = enc_node.attrs().string("type");
            use crate::signal::protocol::{Ciphertext, PreKeySignalMessage, SignalMessage};
            let ciphertext_enum = match enc_type.as_str() {
                "pkmsg" => PreKeySignalMessage::deserialize(&ciphertext).map(Ciphertext::PreKey),
                "msg" => SignalMessage::deserialize(&ciphertext).map(Ciphertext::Whisper),
                _ => return Err(anyhow::anyhow!("Unsupported enc type: {enc_type}")),
            }
            .map_err(|e| anyhow::anyhow!("Failed to deserialize Signal message: {:?}", e))?;

            let padded_plaintext = cipher.decrypt(ciphertext_enum).await?;
            unpad_message_ref(&padded_plaintext, enc_version).map(|b| b.to_vec())
        };

        match self.buffered_decrypt(&ciphertext, decrypt_closure).await {
            Ok(plaintext) => {
                log::info!(
                    "Successfully decrypted and unpadded message from {}: {} bytes",
                    info.source.sender,
                    plaintext.len()
                );

                if let Ok(mut msg) = wa::Message::decode(plaintext.as_slice()) {
                    if let Some(protocol_msg) = msg.protocol_message.take() {
                        if protocol_msg.r#type()
                            == wa::message::protocol_message::Type::AppStateSyncKeyShare
                        {
                            if let Some(key_share) = protocol_msg.app_state_sync_key_share.as_ref()
                            {
                                log::info!(
                                    "Found AppStateSyncKeyShare with {} keys. Storing them now.",
                                    key_share.keys.len()
                                );
                                self.handle_app_state_sync_key_share(key_share).await;

                                for name in ALL_PATCH_NAMES {
                                    app_state_sync(&self, name, false).await;
                                }
                            }
                        } else {
                            log::warn!(
                                "Received unhandled protocol message of type: {:?}",
                                protocol_msg.r#type()
                            );
                        }
                    } else if msg.sender_key_distribution_message.is_some() {
                        log::warn!("Received unhandled SenderKeyDistributionMessage");
                    } else {
                        let base_msg = msg.get_base_message();

                        log::debug!(
                            target: "Client/Recv",
                            "Decrypted message content: {base_msg:?}"
                        );

                        let _ = self
                            .dispatch_event(Event::Message(Box::new(msg), info.clone()))
                            .await;
                    }
                } else {
                    log::warn!("Failed to unmarshal decrypted plaintext into wa::Message");
                }
            }
            Err(DecryptionError::AlreadyProcessed) => {
                // This is the expected case for a duplicate message.
                // It has been successfully de-duplicated.
            }
            Err(DecryptionError::Crypto(e)) => {
                log::error!(
                    "Failed to decrypt message from {}: {:?}",
                    info.source.sender,
                    e
                );
            }
        }
    }

    /// Parses a `<message>` node to extract common information.
    pub async fn parse_message_info(&self, node: &Node) -> Result<MessageInfo, anyhow::Error> {
        let mut attrs = node.attrs();
        let own_jid = self.store.read().await.id.clone().unwrap_or_default();
        let from = attrs.jid("from");

        let mut source = if from.is_group() {
            let sender = attrs.jid("participant");
            crate::types::message::MessageSource {
                chat: from.clone(),
                sender: sender.clone(),
                is_from_me: sender.user == own_jid.user,
                is_group: true,
                ..Default::default()
            }
        } else if from.user == own_jid.user {
            crate::types::message::MessageSource {
                chat: attrs.jid("recipient").to_non_ad(),
                sender: from.clone(),
                is_from_me: true,
                ..Default::default()
            }
        } else {
            crate::types::message::MessageSource {
                chat: from.to_non_ad(),
                sender: from.clone(),
                is_from_me: false,
                ..Default::default()
            }
        };

        // Manual parse for AddressingMode
        source.addressing_mode = attrs
            .optional_string("addressing_mode")
            .and_then(|s| match s {
                "Pn" => Some(crate::types::message::AddressingMode::Pn),
                "Lid" => Some(crate::types::message::AddressingMode::Lid),
                _ => None,
            });

        Ok(MessageInfo {
            source,
            id: attrs.string("id"),
            push_name: attrs
                .optional_string("notify")
                .map(|s| s.to_string())
                .unwrap_or_default(),
            timestamp: attrs.unix_time("t"),
            ..Default::default()
        })
    }

    /// Stores app state sync keys received from a key share message.
    pub async fn handle_app_state_sync_key_share(&self, keys: &wa::message::AppStateSyncKeyShare) {
        let key_store = {
            let guard = self.store.read().await;
            guard.backend.clone()
        };
        for key in &keys.keys {
            if let Some(key_id_proto) = &key.key_id {
                if let Some(key_id) = &key_id_proto.key_id {
                    if let Some(key_data) = &key.key_data {
                        if let Some(fingerprint) = &key_data.fingerprint {
                            if let Some(data) = &key_data.key_data {
                                let fingerprint_bytes = fingerprint.encode_to_vec();
                                let new_key = crate::store::traits::AppStateSyncKey {
                                    key_data: data.clone(),
                                    fingerprint: fingerprint_bytes,
                                    timestamp: key_data.timestamp(),
                                };

                                if let Err(e) =
                                    key_store.set_app_state_sync_key(key_id, new_key).await
                                {
                                    log::error!(
                                        "Failed to store app state sync key {:?}: {:?}",
                                        hex::encode(key_id),
                                        e
                                    );
                                } else {
                                    log::info!(
                                        "Stored new app state sync key with ID {:?}",
                                        hex::encode(key_id)
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
