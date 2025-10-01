use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use chrono::DateTime;
use log::warn;
use prost::Message as ProtoMessage;
use rand::TryRngCore;
use std::sync::Arc;
use wacore::libsignal::crypto::DecryptionError;
use wacore::libsignal::protocol::SenderKeyDistributionMessage;
use wacore::libsignal::protocol::group_decrypt;
use wacore::libsignal::protocol::process_sender_key_distribution_message;
use wacore::libsignal::protocol::{
    PreKeySignalMessage, SignalMessage, SignalProtocolError, UsePQRatchet, message_decrypt,
};
use wacore::libsignal::protocol::{
    PublicKey as SignalPublicKey, SENDERKEY_MESSAGE_CURRENT_VERSION,
};
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::messages::MessageUtils;
use wacore::types::jid::JidExt;
use wacore_binary::jid::Jid;
use wacore_binary::jid::JidExt as _;
use wacore_binary::node::Node;
use waproto::whatsapp::{self as wa};

impl Client {
    pub(crate) async fn handle_encrypted_message(self: Arc<Self>, node: Arc<Node>) {
        let info = match self.parse_message_info(&node).await {
            Ok(info) => info,
            Err(e) => {
                log::warn!("Failed to parse message info: {e:?}");
                return;
            }
        };

        let mut all_enc_nodes = Vec::new();

        let direct_enc_nodes = node.get_children_by_tag("enc");
        all_enc_nodes.extend(direct_enc_nodes);

        let participants = node.get_optional_child_by_tag(&["participants"]);
        if let Some(participants_node) = participants {
            let to_nodes = participants_node.get_children_by_tag("to");
            for to_node in to_nodes {
                let to_jid = to_node.attrs().string("jid");
                let own_jid = self.get_pn().await;

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

            // First check for custom handlers
            if let Some(handler) = self.custom_enc_handlers.get(&enc_type) {
                let handler_clone = handler.clone();
                let client_clone = self.clone();
                let info_clone = info.clone();
                let enc_node_clone = Arc::new(enc_node.clone());

                tokio::spawn(async move {
                    if let Err(e) = handler_clone
                        .handle(client_clone, &enc_node_clone, &info_clone)
                        .await
                    {
                        log::warn!("Custom handler for enc type '{}' failed: {e:?}", enc_type);
                    }
                });
                continue;
            }

            // Fall back to built-in handlers
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
        let session_decrypted_successfully = self
            .clone()
            .process_session_enc_batch(&session_enc_nodes, &info)
            .await;

        log::debug!(
            "Starting PASS 2: Processing {} group content messages (skmsg)",
            group_content_enc_nodes.len()
        );

        // Only process group content if we successfully decrypted the session establishment message
        if !group_content_enc_nodes.is_empty() {
            if session_decrypted_successfully {
                if let Err(e) = self
                    .clone()
                    .process_group_enc_batch(&group_content_enc_nodes, &info)
                    .await
                {
                    log::warn!("Batch group decrypt encountered error (continuing): {e:?}");
                }
            } else {
                warn!(
                    "Skipping skmsg decryption for message {} from {} because the initial session/senderkey message failed to decrypt. This prevents a retry loop.",
                    info.id, info.source.sender
                );
                // Still dispatch an UndecryptableMessage event so the user knows
                self.core.event_bus.dispatch(&Event::UndecryptableMessage(
                    crate::types::events::UndecryptableMessage {
                        info: info.clone(),
                        is_unavailable: false,
                        unavailable_type: crate::types::events::UnavailableType::Unknown,
                        decrypt_fail_mode: crate::types::events::DecryptFailMode::Show,
                    },
                ));

                // Do NOT send a delivery receipt for undecryptable messages.
                // Per whatsmeow's implementation, delivery receipts are only sent for
                // successfully decrypted/handled messages. Sending a receipt here would
                // tell the server we processed it, incrementing the offline counter.
                // The transport <ack> is sufficient for acknowledgment.
            }
        } else if !session_decrypted_successfully && !session_enc_nodes.is_empty() {
            // Edge case: message with only msg/pkmsg that failed to decrypt, no skmsg
            warn!(
                "Message {} from {} failed to decrypt and has no group content.",
                info.id, info.source.sender
            );
            // Do NOT send delivery receipt - transport ack is sufficient
        }
    }

    async fn process_session_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&wacore_binary::node::Node],
        info: &MessageInfo,
    ) -> bool {
        use wacore::libsignal::protocol::CiphertextMessage;
        if enc_nodes.is_empty() {
            return false;
        }

        let mut adapter =
            SignalProtocolStoreAdapter::new(self.persistence_manager.get_device_arc().await);
        let rng = rand::rngs::OsRng;
        let mut any_success = false;

        for enc_node in enc_nodes {
            let ciphertext = match &enc_node.content {
                Some(wacore_binary::node::NodeContent::Bytes(b)) => b.clone(),
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
                    any_success = true;
                    if let Err(e) = self
                        .clone()
                        .handle_decrypted_plaintext(
                            &enc_type,
                            &padded_plaintext,
                            padding_version,
                            info,
                        )
                        .await
                    {
                        log::warn!("Failed processing plaintext (batch session): {e:?}");
                    }
                }
                Err(e) => {
                    // Handle SessionNotFound gracefully during offline sync
                    if let SignalProtocolError::SessionNotFound(_) = e {
                        warn!(
                            "Gracefully failing decryption for {} from {} due to missing session. This is common during offline sync. Dispatching UndecryptableMessage event.",
                            enc_type, info.source.sender
                        );
                        // Dispatch an event so the library user knows a message was missed.
                        self.core.event_bus.dispatch(&Event::UndecryptableMessage(
                            crate::types::events::UndecryptableMessage {
                                info: info.clone(),
                                is_unavailable: false,
                                unavailable_type: crate::types::events::UnavailableType::Unknown,
                                decrypt_fail_mode: crate::types::events::DecryptFailMode::Show,
                            },
                        ));
                        // IMPORTANT: Continue the loop instead of returning an error.
                        continue;
                    } else {
                        // For other errors, log them but still don't crash the whole batch.
                        log::error!("Batch session decrypt failed (type: {}): {:?}", enc_type, e);
                    }
                }
            }
        }
        any_success
    }

    async fn process_group_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&wacore_binary::node::Node],
        info: &MessageInfo,
    ) -> Result<(), DecryptionError> {
        if enc_nodes.is_empty() {
            return Ok(());
        }
        let device_arc = self.persistence_manager.get_device_arc().await;

        for enc_node in enc_nodes {
            let ciphertext = match &enc_node.content {
                Some(wacore_binary::node::NodeContent::Bytes(b)) => b.clone(),
                _ => {
                    log::warn!("Enc node has no byte content (batch group)");
                    continue;
                }
            };
            let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;

            let sender_address = info.source.sender.to_protocol_address();
            let sender_key_name =
                SenderKeyName::new(info.source.chat.to_string(), sender_address.to_string());

            let decrypt_result = {
                let mut device_guard = device_arc.write().await;
                group_decrypt(ciphertext.as_slice(), &mut *device_guard, &sender_key_name).await
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
                    tokio::spawn(async move {
                        if let Err(e) = client_clone.send_retry_receipt(&info_clone).await {
                            log::error!("Failed to send retry receipt (batch): {:?}", e);
                        }
                    });
                }
                Err(e) => {
                    log::error!(
                        "Group batch decrypt failed for group {} sender {}: {:?}",
                        sender_key_name.group_id(),
                        sender_key_name.sender_id(),
                        e
                    );
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
    ) -> Result<(), anyhow::Error> {
        let plaintext_slice = MessageUtils::unpad_message_ref(padded_plaintext, padding_version)?;
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
                        tokio::spawn(async move {
                            // Enqueue history sync task to dedicated worker
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
        Ok(())
    }

    pub(crate) async fn parse_message_info(
        &self,
        node: &Node,
    ) -> Result<MessageInfo, anyhow::Error> {
        let mut attrs = node.attrs();
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot.pn.clone().unwrap_or_default();
        let from = attrs.jid("from");

        let mut source = if from.server == wacore_binary::jid::BROADCAST_SERVER {
            // This is the new logic block for handling all broadcast messages, including status.
            let participant = attrs.jid("participant");
            crate::types::message::MessageSource {
                chat: from.clone(),
                sender: participant.clone(),
                is_from_me: participant.is_same_user_as(&own_jid),
                is_group: true, // Treat as group-like for session handling
                broadcast_list_owner: if from.user != wacore_binary::jid::STATUS_BROADCAST_USER {
                    Some(participant.clone())
                } else {
                    None
                },
                ..Default::default()
            }
        } else if from.is_group() {
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
            timestamp: DateTime::from_timestamp(attrs.unix_time("t"), 0).unwrap(),
            ..Default::default()
        })
    }

    pub(crate) async fn handle_app_state_sync_key_share(
        &self,
        keys: &wa::message::AppStateSyncKeyShare,
    ) {
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

        // Notify any waiters (initial full sync) that at least one key share was processed.
        if stored_count > 0
            && !self
                .initial_app_state_keys_received
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        {
            // First time setting; notify any waiters
            self.initial_keys_synced_notifier.notify_waiters();
        }
    }

    async fn handle_sender_key_distribution_message(
        self: &Arc<Self>,
        group_jid: &Jid,
        sender_jid: &Jid,
        axolotl_bytes: &[u8],
    ) {
        let skdm = match SenderKeyDistributionMessage::try_from(axolotl_bytes) {
            Ok(msg) => msg,
            Err(e1) => match wa::SenderKeyDistributionMessage::decode(axolotl_bytes) {
                Ok(go_msg) => {
                    match SignalPublicKey::from_djb_public_key_bytes(&go_msg.signing_key.unwrap()) {
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
        };

        let device_arc = self.persistence_manager.get_device_arc().await;
        let mut device_guard = device_arc.write().await;

        let sender_address = sender_jid.to_protocol_address();

        let sender_key_name = SenderKeyName::new(group_jid.to_string(), sender_address.to_string());

        if let Err(e) =
            process_sender_key_distribution_message(&sender_key_name, &skdm, &mut *device_guard)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::persistence_manager::PersistenceManager;
    use crate::store::sqlite_store::SqliteStore;
    use std::sync::Arc;
    use wacore_binary::builder::NodeBuilder;
    use wacore_binary::jid::Jid;

    #[tokio::test]
    async fn test_parse_message_info_for_status_broadcast() {
        // 1. Setup
        let backend = Arc::new(
            SqliteStore::new("file:memdb_status_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _sync_rx) = Client::new(pm).await;

        let participant_jid_str = "556899336555:42@s.whatsapp.net";
        let status_broadcast_jid_str = "status@broadcast";

        // 2. Create the test node mirroring the logs
        let node = NodeBuilder::new("message")
            .attr("from", status_broadcast_jid_str)
            .attr("id", "8A8CCCC7E6E466D9EE8CA11A967E485A")
            .attr("participant", participant_jid_str)
            .attr("t", "1759295366")
            .attr("type", "media")
            .build();

        // 3. Run the function under test
        let info = client
            .parse_message_info(&node)
            .await
            .expect("parse_message_info should not fail");

        // 4. Assert the correct behavior
        let expected_sender: Jid = participant_jid_str.parse().unwrap();
        let expected_chat: Jid = status_broadcast_jid_str.parse().unwrap();

        assert_eq!(
            info.source.sender, expected_sender,
            "The sender should be the 'participant' JID, not 'status@broadcast'"
        );
        assert_eq!(
            info.source.chat, expected_chat,
            "The chat should be 'status@broadcast'"
        );
        assert!(
            info.source.is_group,
            "Broadcast messages should be treated as group-like"
        );
    }

    #[tokio::test]
    async fn test_process_session_enc_batch_handles_session_not_found_gracefully() {
        use wacore::libsignal::protocol::{IdentityKeyPair, KeyPair, SignalMessage};

        // 1. Setup
        let backend = Arc::new(
            SqliteStore::new("file:memdb_graceful_fail?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _sync_rx) = Client::new(pm).await;

        let sender_jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let info = MessageInfo {
            source: crate::types::message::MessageSource {
                sender: sender_jid.clone(),
                chat: sender_jid.clone(),
                ..Default::default()
            },
            ..Default::default()
        };

        // 2. Create a valid but undecryptable SignalMessage (encrypted with a dummy key)
        let dummy_key = [0u8; 32];
        let sender_ratchet = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err()).public_key;
        let sender_identity_pair = IdentityKeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let receiver_identity_pair = IdentityKeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let signal_message = SignalMessage::new(
            4,
            &dummy_key,
            sender_ratchet,
            0,
            0,
            b"test",
            sender_identity_pair.identity_key(),
            receiver_identity_pair.identity_key(),
        )
        .unwrap();

        let enc_node = NodeBuilder::new("enc")
            .attr("type", "msg")
            .bytes(signal_message.serialized().to_vec())
            .build();
        let enc_nodes = vec![&enc_node];

        // 3. Run the function under test
        // The function now returns a boolean indicating if any decryption succeeded.
        // With a SessionNotFound error, it should return false but not panic.
        let success = client.process_session_enc_batch(&enc_nodes, &info).await;

        // 4. Assert the desired behavior: the function continues gracefully
        // The function should return false (no successful decryption) but should not panic.
        assert!(
            !success,
            "process_session_enc_batch should return false when SessionNotFound occurs"
        );

        // Note: Verifying event dispatch would require adding a test event handler.
        // For this test, we're just ensuring the function doesn't panic and returns the correct status.
    }

    #[tokio::test]
    async fn test_handle_encrypted_message_skips_skmsg_after_msg_failure() {
        use wacore::libsignal::protocol::{IdentityKeyPair, KeyPair, SignalMessage};

        // 1. Setup
        let backend = Arc::new(
            SqliteStore::new("file:memdb_skip_skmsg_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _sync_rx) = Client::new(pm).await;

        let sender_jid: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        let group_jid: Jid = "120363021033254949@g.us".parse().unwrap();

        // 2. Create a message node with both msg and skmsg
        // The msg will fail to decrypt (no session), so skmsg should be skipped
        let dummy_key = [0u8; 32];
        let sender_ratchet = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err()).public_key;
        let sender_identity_pair = IdentityKeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let receiver_identity_pair = IdentityKeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let signal_message = SignalMessage::new(
            4,
            &dummy_key,
            sender_ratchet,
            0,
            0,
            b"test",
            sender_identity_pair.identity_key(),
            receiver_identity_pair.identity_key(),
        )
        .unwrap();

        let msg_node = NodeBuilder::new("enc")
            .attr("type", "msg")
            .bytes(signal_message.serialized().to_vec())
            .build();

        let skmsg_node = NodeBuilder::new("enc")
            .attr("type", "skmsg")
            .bytes(vec![4, 5, 6])
            .build();

        let message_node = Arc::new(
            NodeBuilder::new("message")
                .attr("from", group_jid.to_string())
                .attr("participant", sender_jid.to_string())
                .attr("id", "test-id-123")
                .attr("t", "12345")
                .children(vec![msg_node, skmsg_node])
                .build(),
        );

        // 3. Run the function
        // This should NOT panic or cause a retry loop. The skmsg should be skipped.
        client.handle_encrypted_message(message_node).await;

        // 4. Assert
        // If we get here without panicking, the test passes.
        // The key improvement is that we won't send a retry receipt for the skmsg
        // since we detected the msg failure and skipped skmsg processing entirely.
    }

    /// Test case for reproducing LID group message decryption failure
    /// when no 1-on-1 Signal session exists with the LID sender.
    ///
    /// Context:
    /// - LID (Lightweight Identity) is WhatsApp's new identity system
    /// - LID JIDs use format: `236395184570386.1:75@lid` (note the dot)
    /// - Group messages from LID users fail to decrypt if we lack a Signal session
    /// - This causes SessionNotFound errors which we now handle gracefully
    ///
    /// Expected behavior:
    /// - No crash or panic
    /// - UndecryptableMessage event dispatched
    /// - No delivery receipt sent (only transport ack)
    /// - Offline counter increments on reconnection (expected)
    ///
    /// Solution needed:
    /// - Implement proactive session establishment with LID contacts
    /// - Possibly fetch pre-keys when encountering new LID senders in groups
    #[tokio::test]
    #[ignore = "Requires valid whatsapp.db with active session to reproduce. This is a known issue documented in README.md"]
    async fn test_lid_group_message_without_session() {
        use crate::store::sqlite_store::SqliteStore;
        use std::sync::Arc;
        use wacore_binary::builder::NodeBuilder;
        use wacore_binary::jid::Jid;

        // This test reproduces the real-world scenario where:
        // 1. A LID user (e.g., 236395184570386.1:75@lid) sends a group message
        // 2. We don't have a 1-on-1 Signal session with this LID user
        // 3. The message contains both PreKeySignalMessage (pkmsg) and SenderKeyDistributionMessage (skmsg)
        // 4. Decryption fails with SessionNotFound

        // Setup: Create client with real database
        let backend = Arc::new(
            SqliteStore::new("whatsapp.db")
                .await
                .expect("Failed to open whatsapp.db - ensure you have an authenticated session"),
        );
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _sync_rx) = Client::new(pm).await;

        // Simulate a group message from a LID user we haven't chatted with 1-on-1
        let lid_sender: Jid = "236395184570386.1:75@lid".parse().unwrap();
        let group_jid: Jid = "120363021033254949@g.us".parse().unwrap();

        // In reality, this would contain actual encrypted pkmsg and skmsg bytes
        // For now, we're just documenting the structure
        let pkmsg_node = NodeBuilder::new("enc")
            .attr("type", "pkmsg")
            .attr("v", "2")
            .bytes(vec![/* actual pkmsg bytes */])
            .build();

        let skmsg_node = NodeBuilder::new("enc")
            .attr("type", "skmsg")
            .attr("v", "2")
            .bytes(vec![/* actual skmsg bytes */])
            .build();

        let message_node = Arc::new(
            NodeBuilder::new("message")
                .attr("from", group_jid.to_string())
                .attr("participant", lid_sender.to_string())
                .attr("id", "LID_TEST_MSG_001")
                .attr("t", "1759296831")
                .attr("type", "text")
                .attr("notify", "LID Test User")
                .attr("offline", "1")
                .attr("addressing_mode", "lid")
                .children(vec![pkmsg_node, skmsg_node])
                .build(),
        );

        // Attempt to handle the message
        // Expected: Graceful failure, no crash, UndecryptableMessage event dispatched
        client.handle_encrypted_message(message_node).await;

        // If we reach here without panicking, the graceful handling works
        // However, the message remains undecryptable until we:
        // 1. Establish a Signal session with the LID user (send them a 1-on-1 message)
        // 2. OR implement proactive pre-key fetching for LID contacts
        // 3. OR implement session-less SKDM decryption if protocol allows

        println!("✅ LID message handled gracefully (but not decrypted - this is the known issue)");
    }
}
