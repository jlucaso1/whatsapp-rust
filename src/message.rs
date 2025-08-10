use crate::binary::node::Node;
use crate::client::Client;
use crate::client::RecentMessageKey;
use crate::error::decryption::DecryptionError;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use libsignal_protocol::SenderKeyDistributionMessage;
use libsignal_protocol::group_decrypt;
use libsignal_protocol::process_sender_key_distribution_message;
use libsignal_protocol::{
    PreKeySignalMessage, ProtocolAddress, SignalMessage, SignalProtocolError, UsePQRatchet,
    message_decrypt,
};
use log::warn;
use prost::Message as ProtoMessage;
use rand::TryRngCore;
use std::sync::Arc;
use wacore::signal::store::SessionStore as _;
use wacore::types::jid::Jid;
use wacore::types::jid::JidExt;
use waproto::whatsapp::{self as wa};

fn unpad_message_ref(plaintext: &[u8], version: u8) -> Result<&[u8], anyhow::Error> {
    if version == 3 {
        return Ok(plaintext);
    }
    if plaintext.is_empty() {
        return Err(anyhow::anyhow!("plaintext is empty, cannot unpad"));
    }
    let pad_len = plaintext[plaintext.len() - 1] as usize;
    if pad_len == 0 || pad_len > plaintext.len() {
        return Err(anyhow::anyhow!("invalid padding length: {}", pad_len));
    }
    let (data, padding) = plaintext.split_at(plaintext.len() - pad_len);
    for &byte in padding {
        if byte != pad_len as u8 {
            return Err(anyhow::anyhow!("invalid padding bytes"));
        }
    }
    Ok(data)
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

        let message_key = RecentMessageKey {
            to: info.source.chat.clone(),
            id: info.id.clone(),
        };

        if self.has_message_been_processed(&message_key).await {
            log::debug!(target: "Client/Recv", "Ignoring message: already processed (to: {}, id: {})", message_key.to, message_key.id);
            return;
        }

        let mut all_enc_nodes = Vec::new();

        let direct_enc_nodes = node.get_children_by_tag("enc");
        all_enc_nodes.extend(direct_enc_nodes);

        let participants = node.get_optional_child_by_tag(&["participants"]);
        if let Some(participants_node) = participants {
            let to_nodes = participants_node.get_children_by_tag("to");
            for to_node in to_nodes {
                let to_jid = to_node.attrs().string("jid");
                let own_jid = self.get_jid().await;

                if let Some(our_jid) = own_jid
                    && to_jid == our_jid.to_string()
                {
                    let enc_children = to_node.get_children_by_tag("enc");
                    all_enc_nodes.extend(enc_children);
                }
            }
        }

        if all_enc_nodes.is_empty() {
            log::warn!("Received message without <enc> child: {}", node.tag);
            return;
        }

        let mut session_enc_nodes = Vec::new();
        let mut group_content_enc_nodes = Vec::new();

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

        log::debug!(
            "Starting PASS 1: Processing {} session establishment messages (pkmsg/msg)",
            session_enc_nodes.len()
        );
        for enc_node in session_enc_nodes {
            let _ = self
                .clone()
                .process_enc_node(enc_node, &info, &message_key)
                .await;
        }

        log::debug!(
            "Starting PASS 2: Processing {} group content messages (skmsg)",
            group_content_enc_nodes.len()
        );
        for enc_node in group_content_enc_nodes {
            let _ = self
                .clone()
                .process_enc_node(enc_node, &info, &message_key)
                .await;
        }
    }

    async fn process_enc_node(
        self: Arc<Self>,
        enc_node: &crate::binary::node::Node,
        info: &MessageInfo,
        message_key: &RecentMessageKey,
    ) -> Result<(), DecryptionError> {
        let ciphertext = match &enc_node.content {
            Some(crate::binary::node::NodeContent::Bytes(b)) => b.clone(),
            _ => {
                log::warn!("Enc node has no byte content");
                return Err(DecryptionError::Crypto(anyhow::anyhow!(
                    "Enc node has no byte content"
                )));
            }
        };

        let enc_type = enc_node.attrs().string("type");
        let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;

        let result = match enc_type.as_str() {
            "pkmsg" | "msg" => {
                self.decrypt_dm_ciphertext(info, &enc_type, &ciphertext)
                    .await
            }
            "skmsg" => self.decrypt_group_ciphertext(info, &ciphertext).await,
            _ => {
                log::warn!("Unsupported enc type: {enc_type}");
                return Err(DecryptionError::Crypto(anyhow::anyhow!(
                    "Unsupported enc type"
                )));
            }
        };

        match result {
            Ok(padded_plaintext) => {
                let plaintext = unpad_message_ref(&padded_plaintext, padding_version)?.to_vec();

                log::info!(
                    "Successfully decrypted message from {}: {} bytes (type: {})",
                    info.source.sender,
                    plaintext.len(),
                    enc_type
                );

                if enc_type == "skmsg" {
                    match wa::Message::decode(plaintext.as_slice()) {
                        Ok(group_msg) => {
                            self.core
                                .event_bus
                                .dispatch(&Event::Message(Box::new(group_msg), info.clone()));
                        }
                        Err(e) => log::warn!("Failed to unmarshal decrypted skmsg plaintext: {e}"),
                    }
                } else {
                    match wa::Message::decode(plaintext.as_slice()) {
                        Ok(original_msg) => {
                            if let Some(skdm) = &original_msg.sender_key_distribution_message
                                && let Some(axolotl_bytes) =
                                    &skdm.axolotl_sender_key_distribution_message
                            {
                                self.handle_sender_key_distribution_message(
                                    &info.source.chat,
                                    &info.source.sender,
                                    axolotl_bytes,
                                )
                                .await;
                            }

                            if let Some(protocol_msg) = &original_msg.protocol_message
                                && let Some(keys) = &protocol_msg.app_state_sync_key_share
                            {
                                self.handle_app_state_sync_key_share(keys).await;
                            }

                            // Handle HistorySyncNotification
                            if let Some(protocol_msg) = &original_msg.protocol_message
                                && let Some(history_sync) = &protocol_msg.history_sync_notification
                            {
                                log::info!(
                                    "Received HistorySyncNotification, dispatching for download and processing."
                                );
                                let client_clone = self.clone();
                                let history_sync_clone = history_sync.clone();
                                let msg_id = info.id.clone();
                                tokio::task::spawn_local(async move {
                                    client_clone
                                        .handle_history_sync(msg_id, history_sync_clone)
                                        .await;
                                });
                            }

                            self.core
                                .event_bus
                                .dispatch(&Event::Message(Box::new(original_msg), info.clone()));
                        }
                        Err(e) => {
                            log::warn!("Failed to unmarshal decrypted pkmsg/msg plaintext: {e}")
                        }
                    }
                }

                self.mark_message_as_processed(message_key.clone()).await;
                Ok(())
            }
            Err(DecryptionError::NoSenderKeyState) => {
                warn!(
                    "No sender key state for message from {}, sending retry receipt.",
                    info.source.sender
                );
                let client_clone = self.clone();
                let info_clone = info.clone();
                tokio::task::spawn_local(async move {
                    if let Err(e) = client_clone.send_retry_receipt(&info_clone).await {
                        log::error!("Failed to send retry receipt: {:?}", e);
                    }
                });

                self.mark_message_as_processed(message_key.clone()).await;
                Ok(())
            }
            Err(DecryptionError::Crypto(e)) => {
                log::error!(
                    "Failed to decrypt message (type: {}) from {}: {:?}",
                    enc_type,
                    info.source.sender,
                    e
                );
                self.mark_message_as_processed(message_key.clone()).await;
                Err(DecryptionError::Crypto(e))
            }
        }
    }

    pub async fn parse_message_info(&self, node: &Node) -> Result<MessageInfo, anyhow::Error> {
        let mut attrs = node.attrs();
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot.id.clone().unwrap_or_default();
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
        let key_store = device_snapshot.backend.clone();

        let mut stored_count = 0;
        let mut failed_count = 0;

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
                    failed_count += 1;
                } else {
                    stored_count += 1;
                }
            }
        }

        if stored_count > 0 || failed_count > 0 {
            log::info!(
                target: "Client/AppState",
                "Processed app state key share: {} stored, {} failed.",
                stored_count,
                failed_count
            );
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
        let device_id = (info.source.sender.device as u32).into();
        let signal_address = ProtocolAddress::new(info.source.sender.user.clone(), device_id);

        let mut adapter =
            SignalProtocolStoreAdapter::new(self.persistence_manager.get_device_arc().await);

        let parsed_message = if enc_type == "pkmsg" {
            libsignal_protocol::CiphertextMessage::PreKeySignalMessage(
                PreKeySignalMessage::try_from(ciphertext)
                    .map_err(|e| DecryptionError::Crypto(anyhow::anyhow!(e)))?,
            )
        } else {
            libsignal_protocol::CiphertextMessage::SignalMessage(
                SignalMessage::try_from(ciphertext)
                    .map_err(|e| DecryptionError::Crypto(anyhow::anyhow!(e)))?,
            )
        };

        let rng = rand::rngs::OsRng;

        message_decrypt(
            &parsed_message,
            &signal_address,
            &mut adapter.session_store,
            &mut adapter.identity_store,
            &mut adapter.pre_key_store,
            &adapter.signed_pre_key_store,
            &mut adapter.kyber_pre_key_store,
            &mut rng.unwrap_err(),
            UsePQRatchet::Yes,
        )
        .await
        .map_err(|e| {
            DecryptionError::Crypto(anyhow::anyhow!("libsignal decryption failed: {:?}", e))
        })
    }

    async fn decrypt_group_ciphertext(
        &self,
        info: &MessageInfo,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, DecryptionError> {
        let sender_address = ProtocolAddress::new(
            info.source.sender.user.clone(),
            (info.source.sender.device as u32).into(),
        );
        let group_sender_address = ProtocolAddress::new(
            format!("{}\n{}", info.source.chat, sender_address),
            0.into(),
        );

        let device_arc = self.persistence_manager.get_device_arc().await;
        let mut device_guard = device_arc.lock().await;

        group_decrypt(ciphertext, &mut *device_guard, &group_sender_address)
            .await
            .map_err(|e| {
                if let SignalProtocolError::NoSenderKeyState = e {
                    DecryptionError::NoSenderKeyState
                } else {
                    log::error!(
                        "Group decryption failed for sender {}: {:?}",
                        group_sender_address,
                        e
                    );
                    DecryptionError::Crypto(anyhow::anyhow!(e))
                }
            })
    }

    async fn handle_sender_key_distribution_message(
        self: &Arc<Self>,
        group_jid: &Jid,
        sender_jid: &Jid,
        axolotl_bytes: &[u8],
    ) {
        let skdm = match SenderKeyDistributionMessage::try_from(axolotl_bytes) {
            Ok(msg) => msg,
            Err(e) => {
                log::error!(
                    "Failed to parse SenderKeyDistributionMessage from {}: {:?}",
                    sender_jid,
                    e
                );
                return;
            }
        };

        let device_arc = self.persistence_manager.get_device_arc().await;
        let mut device_guard = device_arc.lock().await;

        let sender_address =
            ProtocolAddress::new(sender_jid.user.clone(), (sender_jid.device as u32).into());
        let group_sender_address =
            ProtocolAddress::new(format!("{}\n{}", group_jid, sender_address), 0.into());

        if let Err(e) = process_sender_key_distribution_message(
            &group_sender_address,
            &skdm,
            &mut *device_guard,
        )
        .await
        {
            log::error!(
                "Failed to process SenderKeyDistributionMessage from {}: {:?}",
                sender_jid,
                e
            );
        } else {
            log::info!(
                "Successfully processed sender key distribution for group {} from {}",
                group_jid,
                sender_jid
            );
        }
    }
}
