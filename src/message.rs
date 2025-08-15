use crate::binary::node::Node;
use crate::client::Client;
use crate::client::RecentMessageKey;
use crate::error::decryption::DecryptionError;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use log::warn;
use prost::Message as ProtoMessage;
use rand::TryRngCore;
use std::sync::Arc;
use wacore::libsignal::protocol::SenderKeyDistributionMessage;
use wacore::libsignal::protocol::group_decrypt;
use wacore::libsignal::protocol::process_sender_key_distribution_message;
use wacore::libsignal::protocol::{
    PreKeySignalMessage, ProtocolAddress, SignalMessage, SignalProtocolError, UsePQRatchet,
    message_decrypt,
};
use wacore::libsignal::protocol::{
    PublicKey as SignalPublicKey, SENDERKEY_MESSAGE_CURRENT_VERSION,
};
use wacore::signal::SkdmFields;
use wacore::signal::sender_key_name::SenderKeyName;
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
    pub async fn handle_encrypted_message(self: Arc<Self>, node: Arc<Node>) {
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

        for &enc_node in &all_enc_nodes {
            let enc_type = enc_node.attrs().string("type");
            match enc_type.as_str() {
                "pkmsg" | "msg" => session_enc_nodes.push(enc_node),
                "skmsg" => group_content_enc_nodes.push(enc_node),
                _ => log::warn!("Unknown enc type: {enc_type}"),
            }
        }

        log::debug!(
            "Starting PASS 1: Processing {} session establishment messages (pkmsg/msg)",
            session_enc_nodes.len()
        );
        if let Err(e) = self
            .clone()
            .process_session_enc_batch(&session_enc_nodes, &info, &message_key)
            .await
        {
            log::warn!("Batch session decrypt encountered error (continuing): {e:?}");
        }

        log::debug!(
            "Starting PASS 2: Processing {} group content messages (skmsg)",
            group_content_enc_nodes.len()
        );
        if let Err(e) = self
            .clone()
            .process_group_enc_batch(&group_content_enc_nodes, &info, &message_key)
            .await
        {
            log::warn!("Batch group decrypt encountered error (continuing): {e:?}");
        }
    }

    async fn process_session_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&crate::binary::node::Node],
        info: &MessageInfo,
        message_key: &RecentMessageKey,
    ) -> Result<(), DecryptionError> {
        use wacore::libsignal::protocol::CiphertextMessage;
        if enc_nodes.is_empty() {
            return Ok(());
        }

        let mut adapter =
            SignalProtocolStoreAdapter::new(self.persistence_manager.get_device_arc().await);
        let rng = rand::rngs::OsRng;

        for enc_node in enc_nodes {
            let ciphertext = match &enc_node.content {
                Some(crate::binary::node::NodeContent::Bytes(b)) => b.clone(),
                _ => {
                    log::warn!("Enc node has no byte content (batch session)");
                    continue;
                }
            };
            let enc_type = enc_node.attrs().string("type");
            let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;

            let parsed_message = if enc_type == "pkmsg" {
                match PreKeySignalMessage::try_from(ciphertext.as_slice()) {
                    Ok(m) => CiphertextMessage::PreKeySignalMessage(m),
                    Err(e) => {
                        log::error!("Failed to parse PreKeySignalMessage: {e:?}");
                        continue;
                    }
                }
            } else {
                match SignalMessage::try_from(ciphertext.as_slice()) {
                    Ok(m) => CiphertextMessage::SignalMessage(m),
                    Err(e) => {
                        log::error!("Failed to parse SignalMessage: {e:?}");
                        continue;
                    }
                }
            };

            let signal_address = info.source.sender.to_protocol_address();

            let decrypt_res = message_decrypt(
                &parsed_message,
                &signal_address,
                &mut adapter.session_store,
                &mut adapter.identity_store,
                &mut adapter.pre_key_store,
                &adapter.signed_pre_key_store,
                &mut rng.unwrap_err(),
                UsePQRatchet::No,
            )
            .await;

            match decrypt_res {
                Ok(padded_plaintext) => {
                    if let Err(e) = self
                        .clone()
                        .handle_decrypted_plaintext(
                            &enc_type,
                            &padded_plaintext,
                            padding_version,
                            info,
                            message_key,
                        )
                        .await
                    {
                        log::warn!("Failed processing plaintext (batch session): {e:?}");
                    }
                }
                Err(e) => {
                    log::error!("Batch session decrypt failed (type: {}): {:?}", enc_type, e);
                    self.mark_message_as_processed(message_key.clone()).await;
                }
            }
        }
        Ok(())
    }

    async fn process_group_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&crate::binary::node::Node],
        info: &MessageInfo,
        message_key: &RecentMessageKey,
    ) -> Result<(), DecryptionError> {
        if enc_nodes.is_empty() {
            return Ok(());
        }
        let device_arc = self.persistence_manager.get_device_arc().await;

        for enc_node in enc_nodes {
            let ciphertext = match &enc_node.content {
                Some(crate::binary::node::NodeContent::Bytes(b)) => b.clone(),
                _ => {
                    log::warn!("Enc node has no byte content (batch group)");
                    continue;
                }
            };
            let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;

            let sender_address = info.source.sender.to_protocol_address();
            let sender_key_name =
                SenderKeyName::new(info.source.chat.to_string(), sender_address.to_string());
            let group_sender_address = sender_key_name.to_protocol_address();

            let decrypt_result = {
                let mut device_guard = device_arc.write().await;
                group_decrypt(
                    ciphertext.as_slice(),
                    &mut *device_guard,
                    &group_sender_address,
                )
                .await
            };

            match decrypt_result {
                Ok(padded_plaintext) => {
                    if let Err(e) = self
                        .clone()
                        .handle_decrypted_plaintext(
                            "skmsg",
                            &padded_plaintext,
                            padding_version,
                            info,
                            message_key,
                        )
                        .await
                    {
                        log::warn!("Failed processing group plaintext (batch): {e:?}");
                    }
                }
                Err(SignalProtocolError::NoSenderKeyState) => {
                    warn!(
                        "No sender key state for batched group message from {}, sending retry receipt.",
                        info.source.sender
                    );
                    let client_clone = self.clone();
                    let info_clone = info.clone();
                    tokio::task::spawn_local(async move {
                        if let Err(e) = client_clone.send_retry_receipt(&info_clone).await {
                            log::error!("Failed to send retry receipt (batch): {:?}", e);
                        }
                    });
                    self.mark_message_as_processed(message_key.clone()).await;
                }
                Err(e) => {
                    log::error!(
                        "Group batch decrypt failed for sender {}: {:?}",
                        group_sender_address,
                        e
                    );
                    self.mark_message_as_processed(message_key.clone()).await;
                }
            }
        }
        Ok(())
    }

    async fn handle_decrypted_plaintext(
        self: Arc<Self>,
        enc_type: &str,
        padded_plaintext: &[u8],
        padding_version: u8,
        info: &MessageInfo,
        message_key: &RecentMessageKey,
    ) -> Result<(), anyhow::Error> {
        let plaintext_slice = unpad_message_ref(padded_plaintext, padding_version)?;
        log::info!(
            "Successfully decrypted message from {}: {} bytes (type: {}) [batch path]",
            info.source.sender,
            plaintext_slice.len(),
            enc_type
        );

        if enc_type == "skmsg" {
            match wa::Message::decode(plaintext_slice) {
                Ok(group_msg) => {
                    self.core
                        .event_bus
                        .dispatch(&Event::Message(Box::new(group_msg), info.clone()));
                }
                Err(e) => log::warn!("Failed to unmarshal decrypted skmsg plaintext: {e}"),
            }
        } else {
            match wa::Message::decode(plaintext_slice) {
                Ok(original_msg) => {
                    if let Some(skdm) = &original_msg.sender_key_distribution_message
                        && let Some(axolotl_bytes) = &skdm.axolotl_sender_key_distribution_message
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
                Err(e) => log::warn!("Failed to unmarshal decrypted pkmsg/msg plaintext: {e}"),
            }
        }
        self.mark_message_as_processed(message_key.clone()).await;
        Ok(())
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
                is_from_me: sender.is_same_user_as(&own_jid),
                is_group: true,
                ..Default::default()
            }
        } else if from.is_same_user_as(&own_jid) {
            crate::types::message::MessageSource {
                chat: attrs.non_ad_jid("recipient"),
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

    async fn handle_sender_key_distribution_message(
        self: &Arc<Self>,
        group_jid: &Jid,
        sender_jid: &Jid,
        axolotl_bytes: &[u8],
    ) {
        let skdm = match SkdmFields::parse_zero_copy(axolotl_bytes) {
            Ok(fields) => {
                if let (Some(id), Some(iteration), Some(chain_key), Some(signing_key)) = (
                    fields.id,
                    fields.iteration,
                    fields.chain_key,
                    fields.signing_key,
                ) {
                    match SignalPublicKey::from_djb_public_key_bytes(signing_key) {
                        Ok(pub_key) => {
                            match SenderKeyDistributionMessage::new(
                                SENDERKEY_MESSAGE_CURRENT_VERSION,
                                id,
                                iteration,
                                chain_key.to_vec(),
                                pub_key,
                            ) {
                                Ok(skdm) => skdm,
                                Err(e) => {
                                    log::error!(
                                        "Failed to construct SKDM from fast-parsed fields for {}: {:?}",
                                        sender_jid,
                                        e
                                    );
                                    return;
                                }
                            }
                        }
                        Err(e) => {
                            log::error!(
                                "Failed to parse public key from fast-parsed SKDM for {}: {:?}",
                                sender_jid,
                                e
                            );
                            return;
                        }
                    }
                } else {
                    log::error!(
                        "Incomplete SKDM fields from fast parser for {}: id={:?}, iteration={:?}, chain_key={}, signing_key={}",
                        sender_jid,
                        fields.id,
                        fields.iteration,
                        fields.chain_key.is_some(),
                        fields.signing_key.is_some()
                    );
                    return;
                }
            }
            Err(_) => match SenderKeyDistributionMessage::try_from(axolotl_bytes) {
                Ok(msg) => msg,
                Err(e1) => match wa::SenderKeyDistributionMessage::decode(axolotl_bytes) {
                    Ok(go_msg) => {
                        match SignalPublicKey::from_djb_public_key_bytes(
                            &go_msg.signing_key.unwrap(),
                        ) {
                            Ok(pub_key) => {
                                match SenderKeyDistributionMessage::new(
                                    SENDERKEY_MESSAGE_CURRENT_VERSION,
                                    go_msg.id.unwrap(),
                                    go_msg.iteration.unwrap(),
                                    go_msg.chain_key.unwrap(),
                                    pub_key,
                                ) {
                                    Ok(skdm) => skdm,
                                    Err(e) => {
                                        log::error!(
                                            "Failed to construct SKDM from Go format from {}: {:?} (original parse error: {:?})",
                                            sender_jid,
                                            e,
                                            e1
                                        );
                                        return;
                                    }
                                }
                            }
                            Err(e) => {
                                log::error!(
                                    "Failed to parse public key from Go SKDM for {}: {:?} (original parse error: {:?})",
                                    sender_jid,
                                    e,
                                    e1
                                );
                                return;
                            }
                        }
                    }
                    Err(e2) => {
                        log::error!(
                            "Failed to parse SenderKeyDistributionMessage (standard and Go fallback) from {}: primary: {:?}, fallback: {:?}",
                            sender_jid,
                            e1,
                            e2
                        );
                        return;
                    }
                },
            },
        };

        let device_arc = self.persistence_manager.get_device_arc().await;
        let mut device_guard = device_arc.write().await;

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
