use std::time::SystemTime;

use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::jid::Jid;
use libsignal_protocol::{
    CiphertextMessage, ProtocolAddress, SessionStore as _, UsePQRatchet, message_encrypt,
    process_prekey_bundle,
};
use log::{debug, info};
use rand::TryRngCore as _;
use wacore::client::MessageUtils;

use waproto::whatsapp as wa;
use waproto::whatsapp::message::DeviceSentMessage;

impl Client {
    /// Sends a text message to the given JID.
    pub async fn send_text_message(&self, to: Jid, text: &str) -> Result<(), anyhow::Error> {
        debug!("send_text_message: Sending '{text}' to {to}");
        let content = wa::Message {
            conversation: Some(text.to_string()),
            ..Default::default()
        };
        // Generate a new ID for a new message and call the internal implementation.
        let request_id = self.generate_message_id().await;
        self.send_message_impl(to, content, request_id, false).await
    }

    /// Encrypts and sends a protobuf message to the given JID.
    /// Multi-device compatible: builds <participants> node and syncs to own devices.
    pub async fn send_message_impl(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
        peer: bool,
    ) -> Result<(), anyhow::Error> {
        if peer {
            self.send_peer_message(to, message, request_id).await
        } else if to.is_group() {
            self.send_group_message(to, message, request_id).await
        } else {
            self.send_dm_message(to, message, request_id).await
        }
    }

    // Moved from send_message: direct message logic
    async fn send_dm_message(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
    ) -> Result<(), anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        use prost::Message as ProtoMessage;

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot
            .id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in"))?;

        self.add_recent_message(to.clone(), request_id.clone(), message.clone())
            .await;

        let padded_message_plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());
        let dsm = wa::Message {
            device_sent_message: Some(Box::new(DeviceSentMessage {
                destination_jid: Some(to.to_string()),
                message: Some(Box::new(message.clone())),
                phash: Some("".to_string()),
            })),
            ..Default::default()
        };
        let padded_dsm_plaintext = MessageUtils::pad_message_v2(dsm.encode_to_vec());

        let participants = vec![to.clone(), own_jid.clone()];
        let all_devices = self.get_user_devices(&participants).await?;

        let mut participant_nodes = Vec::new();
        let mut includes_prekey_message = false;

        let device_store_arc = self.persistence_manager.get_device_arc().await;

        for device_jid in all_devices {
            let is_own_device =
                device_jid.user == own_jid.user && device_jid.device != own_jid.device;
            let plaintext_to_encrypt = if is_own_device {
                &padded_dsm_plaintext
            } else {
                &padded_message_plaintext
            };

            let signal_address =
                ProtocolAddress::new(device_jid.user.clone(), (device_jid.device as u32).into());

            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc.clone());

            // 1. Check if a usable session already exists.
            let session_record = store_adapter
                .session_store
                .load_session(&signal_address)
                .await?;
            let session_exists = match session_record {
                Some(record) => record.has_usable_sender_chain(SystemTime::now())?,
                None => false,
            };

            if !session_exists {
                info!(
                    "No session found for {}, establishing new one.",
                    &signal_address
                );

                // 2. Fetch the pre-key bundle from the server.
                let prekey_bundles = self
                    .fetch_pre_keys(std::slice::from_ref(&device_jid))
                    .await?;
                let bundle = prekey_bundles.get(&device_jid).ok_or_else(|| {
                    anyhow::anyhow!("Failed to fetch pre-key bundle for {}", &signal_address)
                })?;

                // 3. Process the bundle to create and store the session.
                // This is the key function from libsignal-protocol.
                process_prekey_bundle(
                    &signal_address,
                    &mut store_adapter.session_store,
                    &mut store_adapter.identity_store,
                    bundle,
                    SystemTime::now(),
                    &mut rand::rngs::OsRng.unwrap_err(),
                    UsePQRatchet::Yes, // Or No, depending on your desired support for post-quantum crypto
                )
                .await
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to process prekey bundle for {}: {}",
                        &signal_address,
                        e
                    )
                })?;

                info!(
                    "Successfully established new session for {}.",
                    &signal_address
                );
            }

            let encrypted_message = message_encrypt(
                plaintext_to_encrypt,
                &signal_address,
                &mut store_adapter.session_store,
                &mut store_adapter.identity_store,
                std::time::SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await
            .map_err(|e| anyhow::anyhow!("Encryption failed for {}: {}", device_jid, e))?;

            let (enc_type, serialized_bytes) = match encrypted_message {
                CiphertextMessage::PreKeySignalMessage(msg) => {
                    includes_prekey_message = true;
                    ("pkmsg", msg.serialized().to_vec())
                }
                CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
                // This handles the exhaustiveness error
                _ => return Err(anyhow::anyhow!("Unexpected encryption message type")),
            };

            let enc_node = Node {
                tag: "enc".to_string(),
                attrs: [
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), enc_type.to_string()),
                ]
                .into(),
                content: Some(NodeContent::Bytes(serialized_bytes)), // Use the serialized bytes
            };

            participant_nodes.push(Node {
                tag: "to".to_string(),
                attrs: [("jid".to_string(), device_jid.to_string())].into(),
                content: Some(NodeContent::Nodes(vec![enc_node])),
            });
        }

        let mut message_content_nodes = vec![Node {
            tag: "participants".to_string(),
            attrs: Default::default(),
            content: Some(NodeContent::Nodes(participant_nodes)),
        }];

        if includes_prekey_message {
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            if let Some(account) = &device_snapshot.core.account {
                let device_identity_bytes = account.encode_to_vec();
                message_content_nodes.push(Node {
                    tag: "device-identity".to_string(),
                    attrs: Default::default(),
                    content: Some(NodeContent::Bytes(device_identity_bytes)),
                });
            } else if self.test_mode.load(std::sync::atomic::Ordering::Relaxed) {
                // In test mode, skip device identity requirement
                debug!("Skipping device identity check in test mode");
            } else {
                return Err(anyhow::anyhow!(
                    "Cannot send pre-key message: device account identity is missing. Please re-pair."
                ));
            }
        }

        let stanza = Node {
            tag: "message".to_string(),
            attrs: [
                ("to".to_string(), to.to_string()),
                ("id".to_string(), request_id),
                ("type".to_string(), "text".to_string()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(message_content_nodes)),
        };

        info!(
            "send_dm_message: About to call send_node with stanza. Test mode: {}",
            self.test_mode.load(std::sync::atomic::Ordering::Relaxed)
        );

        self.send_node(stanza).await.map_err(|e| e.into())
    }

    // Peer message logic (for protocol messages like AppStateSyncKeyRequest)
    async fn send_peer_message(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
    ) -> Result<(), anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        use prost::Message as ProtoMessage;

        let plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());

        // Only encrypt for the one target device.
        let device_store_arc = self.persistence_manager.get_device_arc().await;
        let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc);

        let signal_address = ProtocolAddress::new(
            to.user.clone(),
            (to.device as u32).into(), // <-- FIX: Cast to u32
        );

        let encrypted_message = message_encrypt(
            &plaintext,
            &signal_address,
            &mut store_adapter.session_store,
            &mut store_adapter.identity_store,
            std::time::SystemTime::now(),
            &mut rand::rngs::OsRng.unwrap_err(),
        )
        .await
        .map_err(|e| anyhow::anyhow!("Failed to encrypt peer message: {}", e))?;

        let (_enc_type, serialized_bytes) = match encrypted_message {
            CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
            // Peer messages should typically not be pkmsgs, but we handle it just in case.
            CiphertextMessage::PreKeySignalMessage(msg) => ("pkmsg", msg.serialized().to_vec()),
            _ => return Err(anyhow::anyhow!("Unexpected peer encryption message type")),
        };

        let enc_node = Node {
            tag: "enc".to_string(),
            attrs: [
                ("v".to_string(), "2".to_string()),
                ("type".to_string(), "msg".to_string()),
            ]
            .into(),
            content: Some(NodeContent::Bytes(serialized_bytes)),
        };

        // Note the `category="peer"` attribute, which is important.
        let stanza = Node {
            tag: "message".to_string(),
            attrs: [
                ("to".to_string(), to.to_string()),
                ("id".to_string(), request_id),
                ("type".to_string(), "text".to_string()),
                ("category".to_string(), "peer".to_string()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(vec![enc_node])),
        };

        self.send_node(stanza).await.map_err(|e| e.into())
    }

    // Group message logic
    async fn send_group_message(
        &self,
        _to: Jid,
        _message: wa::Message,
        _request_id: String,
    ) -> Result<(), anyhow::Error> {
        Err(anyhow::anyhow!("TODO"))
    }
}
