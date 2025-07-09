use crate::appstate::keys::ALL_PATCH_NAMES;
use crate::appstate_sync::app_state_sync;
use crate::binary;
use crate::binary::node::Node;
use crate::client::Client;
use crate::proto_helpers::MessageExt;
use crate::signal::{address::SignalAddress, session::SessionCipher};
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use prost::Message as ProtoMessage;
use std::sync::Arc;

use whatsapp_proto::whatsapp as wa;

// Helper to unpad messages after decryption
fn unpad_message_ref(plaintext: &[u8], version: u8) -> Result<Vec<u8>, anyhow::Error> {
    if version < 3 {
        if plaintext.is_empty() {
            return Err(anyhow::anyhow!("plaintext is empty, cannot unpad"));
        }
        let pad_len = plaintext[plaintext.len() - 1] as usize;
        if pad_len == 0 || pad_len > plaintext.len() {
            return Err(anyhow::anyhow!("invalid padding length: {}", pad_len));
        }
        Ok(plaintext[..plaintext.len() - pad_len].to_vec())
    } else {
        Ok(plaintext.to_vec())
    }
}

impl Client {
    /// Processes an encrypted frame from the WebSocket.
    /// This is the entry point for all incoming frames after the handshake.
    pub(crate) async fn process_encrypted_frame(self: &Arc<Self>, encrypted_frame: &bytes::Bytes) {
        let noise_socket_arc = { self.noise_socket.lock().await.clone() };
        let noise_socket = match noise_socket_arc {
            Some(s) => s,
            None => {
                log::error!("Cannot process frame: not connected (no noise socket)");
                return;
            }
        };

        let decrypted_payload = match noise_socket.decrypt_frame(encrypted_frame) {
            Ok(p) => p,
            Err(e) => {
                log::error!(target: "Client", "Failed to decrypt frame: {e}");
                return;
            }
        };

        let unpacked_data_cow = match binary::util::unpack(&decrypted_payload) {
            Ok(data) => data,
            Err(e) => {
                log::warn!(target: "Client/Recv", "Failed to decompress frame: {e}");
                return;
            }
        };

        match binary::unmarshal_ref(unpacked_data_cow.as_ref()) {
            Ok(node_ref) => {
                // Convert to owned only when needed for processing
                let node = node_ref.to_owned();
                self.process_node(node).await;
            }
            Err(e) => log::warn!(target: "Client/Recv", "Failed to unmarshal node: {e}"),
        };
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
        let store_arc: std::sync::Arc<tokio::sync::RwLock<crate::store::Device>> =
            self.store.clone();
        let cipher = SessionCipher::new(store_arc, signal_address);

        let enc_type = enc_node.attrs().string("type");
        use crate::signal::protocol::{Ciphertext, PreKeySignalMessage, SignalMessage};
        let ciphertext_enum = match enc_type.as_str() {
            "pkmsg" => match PreKeySignalMessage::deserialize(&ciphertext) {
                Ok(msg) => Ciphertext::PreKey(msg),
                Err(e) => {
                    log::warn!("Failed to deserialize PreKeySignalMessage: {e:?}");
                    return;
                }
            },
            "msg" => match SignalMessage::deserialize(&ciphertext) {
                Ok(msg) => Ciphertext::Whisper(msg),
                Err(e) => {
                    log::warn!("Failed to deserialize SignalMessage: {e:?}");
                    return;
                }
            },
            _ => {
                log::warn!("Unsupported enc type: {enc_type}");
                return;
            }
        };

        match cipher.decrypt(ciphertext_enum).await {
            Ok(padded_plaintext) => {
                let plaintext_vec = match unpad_message_ref(&padded_plaintext, enc_version) {
                    Ok(pt) => pt,
                    Err(e) => {
                        log::error!("Failed to unpad message from {}: {}", info.source.sender, e);
                        return;
                    }
                };

                log::info!(
                    "Successfully decrypted and unpadded message from {}: {} bytes",
                    info.source.sender,
                    plaintext_vec.len()
                );

                if let Ok(mut msg) = wa::Message::decode(&plaintext_vec[..]) {
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
            Err(e) => {
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
