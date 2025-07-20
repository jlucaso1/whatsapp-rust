use crate::binary::node::Node;
use crate::client::Client;
use crate::proto_helpers::MessageExt;

use crate::signal::groups::cipher::GroupCipher;
use crate::signal::groups::message::SenderKeyMessage;
use crate::signal::sender_key_name::SenderKeyName;
use crate::signal::{address::SignalAddress, session::SessionCipher};
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use prost::Message as ProtoMessage;
use std::sync::Arc;

use waproto::whatsapp::{self as wa, SenderKeyDistributionMessage};

use crate::client::RecentMessageKey;
use crate::error::decryption::DecryptionError;

fn unpad_message_ref(plaintext: &[u8], version: u8) -> Result<&[u8], anyhow::Error> {
    if version < 3 {
        if plaintext.is_empty() {
            return Err(anyhow::anyhow!("plaintext is empty, cannot unpad"));
        }
        let pad_len = plaintext[plaintext.len() - 1] as usize;
        if pad_len == 0 || pad_len > plaintext.len() {
            return Err(anyhow::anyhow!("invalid padding length: {}", pad_len));
        }

        // Validate that all padding bytes are correct
        let (data, padding) = plaintext.split_at(plaintext.len() - pad_len);
        for &byte in padding {
            if byte != pad_len as u8 {
                return Err(anyhow::anyhow!("invalid padding bytes"));
            }
        }
        Ok(data)
    } else {
        Ok(plaintext)
    }
}

impl Client {
    pub async fn handle_encrypted_message(self: Arc<Self>, node: Node) {
        let info = match self.parse_message_info(&node).await {
            Ok(info) => info,
            Err(e) => {
                log::warn!("Failed to parse message info: {e:?}");
                return;
            }
        };

        // Create message key for deduplication
        let message_key = RecentMessageKey {
            to: info.source.chat.clone(),
            id: info.id.clone(),
        };

        // Check if message has already been processed
        if self.has_message_been_processed(&message_key).await {
            log::debug!(target: "Client/Recv", "Ignoring message: already processed (to: {}, id: {})", message_key.to, message_key.id);
            return;
        }

        // Collect all encryption nodes that need processing
        let mut all_enc_nodes = Vec::new();

        // First, get direct enc children
        let direct_enc_nodes = node.get_children_by_tag("enc");
        all_enc_nodes.extend(direct_enc_nodes);

        // Next, look for enc nodes under participants/to structure
        let participants = node.get_optional_child_by_tag(&["participants"]);
        if let Some(participants_node) = participants {
            let to_nodes = participants_node.get_children_by_tag("to");
            for to_node in to_nodes {
                let to_jid = to_node.attrs().string("jid");
                let own_jid = self.get_jid().await;

                // Only process enc nodes for this device/jid
                if let Some(our_jid) = own_jid {
                    if to_jid == our_jid.to_string() {
                        let enc_children = to_node.get_children_by_tag("enc");
                        all_enc_nodes.extend(enc_children);
                    }
                }
            }
        }

        if all_enc_nodes.is_empty() {
            log::warn!("Received message without <enc> child: {}", node.tag);
            return;
        }

        // Separate enc nodes into two categories for two-pass processing
        let mut session_enc_nodes = Vec::new(); // pkmsg and msg - for session establishment
        let mut group_content_enc_nodes = Vec::new(); // skmsg - for group message content

        for enc_node in &all_enc_nodes {
            let enc_type = enc_node.attrs().string("type");
            match enc_type.as_str() {
                "pkmsg" | "msg" => session_enc_nodes.push(enc_node),
                "skmsg" => group_content_enc_nodes.push(enc_node),
                _ => {
                    log::warn!("Unknown enc type: {enc_type}");
                }
            }
        }

        // PASS 1: Process session establishment messages (pkmsg/msg) first
        // This ensures SenderKeyDistributionMessages are processed before group content
        log::debug!(
            "Starting PASS 1: Processing {} session establishment messages (pkmsg/msg)",
            session_enc_nodes.len()
        );
        for enc_node in session_enc_nodes {
            self.clone()
                .process_enc_node(enc_node, &info, &message_key)
                .await;
        }

        // PASS 2: Process group content messages (skmsg) after session establishment
        log::debug!(
            "Starting PASS 2: Processing {} group content messages (skmsg)",
            group_content_enc_nodes.len()
        );
        for enc_node in group_content_enc_nodes {
            self.clone()
                .process_enc_node(enc_node, &info, &message_key)
                .await;
        }
    }

    /// Process a single encrypted node (common logic for both passes)
    async fn process_enc_node(
        self: Arc<Self>,
        enc_node: &crate::binary::node::Node,
        info: &MessageInfo,
        message_key: &RecentMessageKey,
    ) {
        let ciphertext = match &enc_node.content {
            Some(crate::binary::node::NodeContent::Bytes(b)) => b.clone(),
            _ => {
                log::warn!("Enc node has no byte content");
                return;
            }
        };

        let enc_type = enc_node.attrs().string("type");
        let enc_version = enc_node
            .attrs()
            .optional_string("v")
            .unwrap_or("2")
            .parse::<u8>()
            .unwrap_or(2);

        let result = match enc_type.as_str() {
            "pkmsg" | "msg" => {
                self.decrypt_dm_ciphertext(info, &enc_type, &ciphertext)
                    .await
            }
            "skmsg" => {
                if !info.source.is_group {
                    log::warn!("Received skmsg in non-group chat, skipping.");
                    return;
                }
                let sk_msg_result = SenderKeyMessage::deserialize(&ciphertext)
                    .map_err(|e| anyhow::anyhow!("Failed to decode SenderKeyMessage: {:?}", e));

                match sk_msg_result {
                    Ok((sk_msg, data_to_verify)) => {
                        let sender_address = SignalAddress::new(
                            info.source.sender.user.clone(),
                            info.source.sender.device as u32,
                        );
                        let sender_key_name = SenderKeyName::new(
                            info.source.chat.to_string(),
                            sender_address.to_string(),
                        );
                        let device_store_for_group =
                            self.persistence_manager.get_device_arc().await;
                        let device_store_wrapper =
                            crate::store::signal::DeviceStore::new(device_store_for_group.clone());
                        let builder = crate::signal::groups::builder::GroupSessionBuilder::new(
                            device_store_wrapper.clone(),
                        );
                        let cipher =
                            GroupCipher::new(sender_key_name, device_store_wrapper, builder);
                        cipher
                            .decrypt(&sk_msg, data_to_verify)
                            .await
                            .map_err(|e| DecryptionError::Crypto(anyhow::anyhow!("{e}")))
                    }
                    Err(e) => Err(DecryptionError::Crypto(e)),
                }
            }
            _ => {
                log::warn!("Unsupported enc type: {enc_type}");
                return;
            }
        };

        match result {
            Ok(plaintext) => {
                // The decryption functions in `cbc::decrypt` already handle the unpadding.
                // Calling unpad again is incorrect and causes failures.

                log::info!(
                    "Successfully decrypted message from {}: {} bytes (type: {})",
                    info.source.sender,
                    plaintext.len(),
                    enc_type
                );

                match wa::Message::decode(plaintext.as_slice()) {
                    Ok(original_msg) => {
                        let mut msg_ref: &wa::Message = &original_msg;
                        if let Some(dsm) = original_msg.device_sent_message.as_ref()
                            && let Some(inner) = dsm.message.as_ref()
                        {
                            msg_ref = inner;
                        }

                        let mut is_protocol_msg = false;

                        if let Some(skdm) = &msg_ref.sender_key_distribution_message {
                            self.handle_sender_key_distribution_message(
                                &info.source.chat,
                                &info.source.sender,
                                skdm,
                            )
                            .await;
                            is_protocol_msg = true;
                        }

                        if let Some(protocol_msg) = &msg_ref.protocol_message {
                            if protocol_msg.r#type()
                                == wa::message::protocol_message::Type::AppStateSyncKeyShare
                            {
                                if let Some(key_share) =
                                    protocol_msg.app_state_sync_key_share.as_ref()
                                {
                                    log::info!(
                                        "Found AppStateSyncKeyShare with {} keys. Storing them now.",
                                        key_share.keys.len()
                                    );
                                    let self_clone = self.clone();
                                    let key_share_clone = key_share.clone();
                                    tokio::spawn(async move {
                                        self_clone
                                            .handle_app_state_sync_key_share(&key_share_clone)
                                            .await;
                                        // Do not re-trigger syncs here. This was causing an infinite loop.
                                        // The sync that requested the keys will be re-triggered by the
                                        // server with a new 'dirty' or 'server_sync' notification.
                                    });
                                }
                            } else {
                                log::warn!(
                                    "Received unhandled protocol message of type: {:?}",
                                    protocol_msg.r#type()
                                );
                            }
                            is_protocol_msg = true;
                        }

                        if !is_protocol_msg {
                            let base_msg = original_msg.get_base_message();
                            log::debug!(
                                target: "Client/Recv",
                                "Decrypted message content: {base_msg:?}"
                            );
                            let _ = self
                                .dispatch_event(Event::Message(
                                    Box::new(original_msg),
                                    info.clone(),
                                ))
                                .await;
                        }
                    }
                    Err(e) => {
                        log::warn!("Failed to unmarshal decrypted plaintext into wa::Message: {e}");
                    }
                }

                // Mark message as processed after successful decryption and handling
                self.mark_message_as_processed(message_key.clone()).await;
            }
            Err(DecryptionError::Crypto(e)) => {
                log::error!(
                    "Failed to decrypt message (type: {}) from {}: {:?}",
                    enc_type,
                    info.source.sender,
                    e
                );
                // Mark as processed even if decryption failed to prevent repeated attempts
                self.mark_message_as_processed(message_key.clone()).await;
            }
        }
    }

    pub async fn parse_message_info(&self, node: &Node) -> Result<MessageInfo, anyhow::Error> {
        let mut attrs = node.attrs();
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot.id.clone().unwrap_or_default();
        // drop(device_snapshot); // Not needed
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

    pub async fn handle_app_state_sync_key_share(&self, keys: &wa::message::AppStateSyncKeyShare) {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let key_store = device_snapshot.backend.clone(); // This is Arc<dyn Backend>
        // drop(device_snapshot); // Not needed

        for key in &keys.keys {
            if let Some(key_id_proto) = &key.key_id
                && let Some(key_id) = &key_id_proto.key_id
                && let Some(key_data) = &key.key_data
                && let Some(fingerprint) = &key_data.fingerprint
                && let Some(data) = &key_data.key_data
            {
                let fingerprint_bytes = fingerprint.encode_to_vec();
                let new_key = crate::store::traits::AppStateSyncKey {
                    key_data: data.clone(),
                    fingerprint: fingerprint_bytes,
                    timestamp: key_data.timestamp(),
                };

                if let Err(e) = key_store.set_app_state_sync_key(key_id, new_key).await {
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

impl Client {
    pub async fn decrypt_dm_ciphertext(
        &self,
        info: &MessageInfo,
        enc_type: &str,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        use crate::signal::protocol::{Ciphertext, PreKeySignalMessage, SignalMessage};

        let signal_address = SignalAddress::new(
            info.source.sender.user.clone(),
            info.source.sender.device as u32,
        );
        let device_store = self.persistence_manager.get_device_arc().await;
        let device_store_wrapper = crate::store::signal::DeviceStore::new(device_store);

        if enc_type == "pkmsg" {
            let pkmsg = PreKeySignalMessage::deserialize(ciphertext).map_err(|e| {
                DecryptionError::Crypto(anyhow::anyhow!("Failed to deserialize pkmsg: {e:?}"))
            })?;

            let cipher = SessionCipher::new(device_store_wrapper, signal_address);
            return cipher
                .decrypt(Ciphertext::PreKey(pkmsg))
                .await
                .map_err(|e| DecryptionError::Crypto(anyhow::Error::msg(format!("{e:?}"))));
        }

        // Standard "msg" handling
        let whisper_msg = SignalMessage::deserialize(ciphertext).map_err(|e| {
            DecryptionError::Crypto(anyhow::anyhow!("Failed to deserialize msg: {e:?}"))
        })?;

        let cipher = SessionCipher::new(device_store_wrapper, signal_address);
        cipher
            .decrypt(Ciphertext::Whisper(whisper_msg))
            .await
            .map_err(|e| DecryptionError::Crypto(anyhow::Error::msg(format!("{e:?}"))))
    }

    async fn handle_sender_key_distribution_message(
        &self,
        group_jid: &crate::types::jid::Jid,
        sender_jid: &crate::types::jid::Jid,
        skdm: &wa::message::SenderKeyDistributionMessage,
    ) {
        use crate::signal::groups::builder::GroupSessionBuilder;

        let axolotl_bytes = match &skdm.axolotl_sender_key_distribution_message {
            Some(b) => b,
            None => {
                log::warn!(
                    "SenderKeyDistributionMessage missing axolotl_sender_key_distribution_message field"
                );
                return;
            }
        };

        // The key distribution message is a protobuf, but it might be wrapped with a version byte
        // like other signal messages. We try decoding it raw first, and if that fails,
        // we try again skipping the first byte, assuming it's a version prefix.
        let dist_msg_result = SenderKeyDistributionMessage::decode(axolotl_bytes.as_slice())
            .or_else(|e| {
                if !axolotl_bytes.is_empty() {
                    log::warn!("Failed to decode raw SenderKeyDistributionMessage, trying with version byte stripped: {e:?}");
                    SenderKeyDistributionMessage::decode(&axolotl_bytes[1..])
                } else {
                    Err(e)
                }
            });

        let dist_msg = match dist_msg_result {
            Ok(msg) => msg,
            Err(e) => {
                log::error!("Failed to decode Signal SenderKeyDistributionMessage: {e:?}");
                return;
            }
        };

        let sender_address = SignalAddress::new(sender_jid.user.clone(), sender_jid.device as u32);
        let sender_key_name = SenderKeyName::new(group_jid.to_string(), sender_address.to_string());

        // Use Arc<Mutex<Device>> as the store for GroupSessionBuilder
        let device_store_for_builder = self.persistence_manager.get_device_arc().await;
        let device_store_wrapper = crate::store::signal::DeviceStore::new(device_store_for_builder);
        let builder = GroupSessionBuilder::new(device_store_wrapper);

        match builder.process(&sender_key_name, &dist_msg).await {
            Ok(_) => {
                log::info!(
                    "Successfully processed sender key distribution message from {sender_jid} for group {group_jid}"
                );
            }
            Err(e) => {
                log::error!("Failed to process sender key distribution message: {e:?}");
            }
        }
    }
}
