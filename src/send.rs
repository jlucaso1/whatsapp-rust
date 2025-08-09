use std::time::SystemTime;

use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::jid::Jid;
use futures_util::future;
use libsignal_protocol::{
    CiphertextMessage, ProtocolAddress, SessionStore as _, UsePQRatchet,
    create_sender_key_distribution_message, group_encrypt, message_encrypt, process_prekey_bundle,
};
use log::{debug, info};
use prost::Message as ProtoMessage;
use rand::TryRngCore as _;
use wacore::client::MessageUtils;

use wacore::signal::sender_key_name::SenderKeyName;
use wacore::types::jid::JidExt;
use waproto::whatsapp as wa;
use waproto::whatsapp::message::DeviceSentMessage;

impl Client {
    pub async fn send_text_message(&self, to: Jid, text: &str) -> Result<(), anyhow::Error> {
        debug!("send_text_message: Sending '{text}' to {to}");
        let content = wa::Message {
            conversation: Some(text.to_string()),
            ..Default::default()
        };
        let request_id = self.generate_message_id().await;
        self.send_message_impl(to, content, request_id, false).await
    }

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
            message_context_info: message.message_context_info.clone(),
            ..Default::default()
        };
        let padded_dsm_plaintext = MessageUtils::pad_message_v2(dsm.encode_to_vec());

        let participants = vec![to.clone(), own_jid.clone()];
        let all_devices = self.get_user_devices(&participants).await?;

        let mut participant_nodes = Vec::new();
        let mut includes_prekey_message = false;

        let device_store_arc = self.persistence_manager.get_device_arc().await;

        let mut devices_needing_sessions = Vec::new();
        for device_jid in &all_devices {
            let signal_address =
                ProtocolAddress::new(device_jid.user.clone(), (device_jid.device as u32).into());

            let store_adapter = SignalProtocolStoreAdapter::new(device_store_arc.clone());
            let session_record = store_adapter
                .session_store
                .load_session(&signal_address)
                .await?;
            let session_exists = match session_record {
                Some(record) => record.has_usable_sender_chain(SystemTime::now())?,
                None => false,
            };

            if !session_exists {
                devices_needing_sessions.push(device_jid.clone());
            }
        }

        if !devices_needing_sessions.is_empty() {
            info!(
                "Establishing sessions for {} devices in parallel",
                devices_needing_sessions.len()
            );

            let prekey_bundles = self.fetch_pre_keys(&devices_needing_sessions).await?;

            let session_establishment_tasks: Vec<_> = devices_needing_sessions
                .into_iter()
                .map(|device_jid| {
                    let device_store_arc = device_store_arc.clone();
                    let prekey_bundles = &prekey_bundles;
                    async move {
                        let signal_address = ProtocolAddress::new(
                            device_jid.user.clone(),
                            (device_jid.device as u32).into(),
                        );

                        let bundle = prekey_bundles.get(&device_jid).ok_or_else(|| {
                            anyhow::anyhow!(
                                "Failed to fetch pre-key bundle for {}",
                                &signal_address
                            )
                        })?;

                        let mut store_adapter =
                            SignalProtocolStoreAdapter::new(device_store_arc.clone());

                        process_prekey_bundle(
                            &signal_address,
                            &mut store_adapter.session_store,
                            &mut store_adapter.identity_store,
                            bundle,
                            SystemTime::now(),
                            &mut rand::rngs::OsRng.unwrap_err(),
                            UsePQRatchet::Yes,
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
                        Ok::<(), anyhow::Error>(())
                    }
                })
                .collect();

            let results = future::join_all(session_establishment_tasks).await;

            for (i, result) in results.into_iter().enumerate() {
                if let Err(e) = result {
                    debug!("Failed to establish session for device {}: {}", i, e);
                }
            }
        }

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
                _ => return Err(anyhow::anyhow!("Unexpected encryption message type")),
            };

            let enc_node = Node {
                tag: "enc".to_string(),
                attrs: [
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), enc_type.to_string()),
                ]
                .into(),
                content: Some(NodeContent::Bytes(serialized_bytes)),
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

    async fn send_peer_message(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
    ) -> Result<(), anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};
        use prost::Message as ProtoMessage;

        let plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());

        let device_store_arc = self.persistence_manager.get_device_arc().await;
        let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc);

        let signal_address = ProtocolAddress::new(to.user.clone(), (to.device as u32).into());

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

    async fn send_group_message(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
    ) -> Result<(), anyhow::Error> {
        use crate::binary::node::{Node, NodeContent};

        self.add_recent_message(to.clone(), request_id.clone(), message.clone())
            .await;

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        let mut group_info = self.query_group_info(&to).await?;

        let (own_sending_jid, addressing_mode_str) = match group_info.addressing_mode {
            crate::types::message::AddressingMode::Lid => (
                device_snapshot.lid.clone().ok_or_else(|| {
                    anyhow::anyhow!(
                        "Cannot send group message: LID is not set but required by group"
                    )
                })?,
                "lid",
            ),
            crate::types::message::AddressingMode::Pn => (
                device_snapshot
                    .id
                    .clone()
                    .ok_or_else(|| anyhow::anyhow!("Cannot send group message: JID is not set"))?,
                "pn",
            ),
        };

        let own_base_jid = own_sending_jid.to_non_ad();
        if !group_info
            .participants
            .iter()
            .any(|p| p.user == own_base_jid.user)
        {
            group_info.participants.push(own_base_jid);
        }

        let all_devices = self.get_user_devices(&group_info.participants).await?;
        let device_store_arc = self.persistence_manager.get_device_arc().await;

        let (skdm_bytes, sender_key_name) = self
            .create_sender_key_distribution_message_for_group(&to, &own_sending_jid)
            .await?;

        let padded_plaintext = MessageUtils::pad_message_v2(message.encode_to_vec());

        let skmsg_ciphertext = {
            let mut device_guard = device_store_arc.lock().await;
            let group_sender_address =
                ProtocolAddress::new(sender_key_name.group_id().to_string(), 0.into());
            let sender_key_message = group_encrypt(
                &mut *device_guard,
                &group_sender_address,
                &padded_plaintext,
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await?;

            sender_key_message.serialized().to_vec()
        };

        let mut participant_nodes = Vec::new();
        let mut includes_prekey_message = false;

        let phash = MessageUtils::participant_list_hash(&all_devices);

        let recipient_devices: Vec<_> = all_devices
            .iter()
            .filter(|&d| d != &own_sending_jid)
            .cloned()
            .collect();

        let mut devices_needing_sessions = Vec::new();
        for device_jid in &recipient_devices {
            let signal_address =
                ProtocolAddress::new(device_jid.user.clone(), (device_jid.device as u32).into());
            let store_adapter = SignalProtocolStoreAdapter::new(device_store_arc.clone());

            let session_record = store_adapter
                .session_store
                .load_session(&signal_address)
                .await?;

            let session_exists = match &session_record {
                Some(record) => record.has_usable_sender_chain(SystemTime::now())?,
                None => false,
            };

            if !session_exists {
                devices_needing_sessions.push(device_jid.clone());
            }
        }

        if !devices_needing_sessions.is_empty() {
            info!(
                "Establishing sessions for {} group member devices in parallel",
                devices_needing_sessions.len()
            );

            let prekey_bundles = self.fetch_pre_keys(&devices_needing_sessions).await?;

            let session_establishment_tasks: Vec<_> = devices_needing_sessions
                .into_iter()
                .map(|device_jid| {
                    let device_store_arc = device_store_arc.clone();
                    let prekey_bundles = &prekey_bundles;
                    async move {
                        let signal_address = ProtocolAddress::new(
                            device_jid.user.clone(),
                            (device_jid.device as u32).into(),
                        );

                        let bundle = prekey_bundles.get(&device_jid).ok_or_else(|| {
                            anyhow::anyhow!(
                                "Failed to fetch pre-key bundle for {}",
                                &signal_address
                            )
                        })?;

                        let mut store_adapter =
                            SignalProtocolStoreAdapter::new(device_store_arc.clone());

                        process_prekey_bundle(
                            &signal_address,
                            &mut store_adapter.session_store,
                            &mut store_adapter.identity_store,
                            bundle,
                            SystemTime::now(),
                            &mut rand::rngs::OsRng.unwrap_err(),
                            UsePQRatchet::Yes,
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
                            "Successfully established new session for group member {}.",
                            &signal_address
                        );
                        Ok::<(), anyhow::Error>(())
                    }
                })
                .collect();

            let results = future::join_all(session_establishment_tasks).await;

            for (i, result) in results.into_iter().enumerate() {
                if let Err(e) = result {
                    debug!(
                        "Failed to establish session for group member device {}: {}",
                        i, e
                    );
                }
            }
        }

        for device_jid in recipient_devices {
            let plaintext_to_encrypt = &skdm_bytes;

            let signal_address =
                ProtocolAddress::new(device_jid.user.clone(), (device_jid.device as u32).into());
            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc.clone());

            let encrypted_payload = message_encrypt(
                plaintext_to_encrypt,
                &signal_address,
                &mut store_adapter.session_store,
                &mut store_adapter.identity_store,
                SystemTime::now(),
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await?;

            let (enc_type, serialized_bytes) = match encrypted_payload {
                CiphertextMessage::PreKeySignalMessage(msg) => {
                    includes_prekey_message = true;
                    ("pkmsg", msg.serialized().to_vec())
                }
                CiphertextMessage::SignalMessage(msg) => ("msg", msg.serialized().to_vec()),
                _ => continue,
            };

            let enc_node = Node {
                tag: "enc".to_string(),
                attrs: [
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), enc_type.to_string()),
                ]
                .into(),
                content: Some(NodeContent::Bytes(serialized_bytes)),
            };
            participant_nodes.push(Node {
                tag: "to".to_string(),
                attrs: [("jid".to_string(), device_jid.to_string())].into(),
                content: Some(NodeContent::Nodes(vec![enc_node])),
            });
        }

        let mut message_content_nodes = vec![
            Node {
                tag: "participants".to_string(),
                attrs: Default::default(),
                content: Some(NodeContent::Nodes(participant_nodes)),
            },
            Node {
                tag: "enc".to_string(),
                attrs: [
                    ("v".to_string(), "2".to_string()),
                    ("type".to_string(), "skmsg".to_string()),
                ]
                .into(),
                content: Some(NodeContent::Bytes(skmsg_ciphertext)),
            },
        ];

        if includes_prekey_message && let Some(account) = &device_snapshot.core.account {
            message_content_nodes.push(Node {
                tag: "device-identity".to_string(),
                attrs: Default::default(),
                content: Some(NodeContent::Bytes(account.encode_to_vec())),
            });
        }

        let stanza = Node {
            tag: "message".to_string(),
            attrs: [
                ("to".to_string(), to.to_string()),
                ("id".to_string(), request_id),
                ("type".to_string(), "text".to_string()),
                ("participant".to_string(), own_sending_jid.to_string()),
                (
                    "addressing_mode".to_string(),
                    addressing_mode_str.to_string(),
                ),
                ("phash".to_string(), phash),
            ]
            .into(),
            content: Some(NodeContent::Nodes(message_content_nodes)),
        };

        self.send_node(stanza).await.map_err(|e| e.into())
    }

    pub async fn create_sender_key_distribution_message_for_group(
        &self,
        group_jid: &Jid,
        own_lid: &Jid,
    ) -> Result<(Vec<u8>, SenderKeyName), anyhow::Error> {
        let device_store_arc = self.persistence_manager.get_device_arc().await;
        let mut device_guard = device_store_arc.lock().await;

        let sender_address =
            ProtocolAddress::new(own_lid.user.clone(), u32::from(own_lid.device).into());

        let sender_key_name = SenderKeyName::new(group_jid.to_string(), sender_address.to_string());

        let skdm = create_sender_key_distribution_message(
            &ProtocolAddress::new(sender_key_name.group_id().to_string(), 0.into()),
            &mut *device_guard,
            &mut rand::rngs::OsRng.unwrap_err(),
        )
        .await?;

        let skdm_wrapper = wa::Message {
            sender_key_distribution_message: Some(wa::message::SenderKeyDistributionMessage {
                group_id: Some(group_jid.to_string()),
                axolotl_sender_key_distribution_message: Some(skdm.serialized().to_vec()),
            }),
            ..Default::default()
        };

        let padded_skdm = MessageUtils::pad_message_v2(skdm_wrapper.encode_to_vec());
        Ok((padded_skdm, sender_key_name))
    }
}
