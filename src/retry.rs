use crate::binary::node::{Node, NodeContent};
use crate::client::{Client, RecentMessageKey};
use crate::signal::store::PreKeyStore;
use crate::types::events::Receipt;
use crate::types::jid::Jid;
use libsignal_protocol::ProtocolAddress;
use log::{info, warn};
use prost::Message;
use scopeguard;
use std::sync::Arc;
use wacore::client::MessageUtils;
use wacore::signal::store::SessionStore;
use wacore::types::jid::JidExt;
use waproto::whatsapp as wa;

impl Client {
    pub(crate) async fn add_recent_message(&self, to: Jid, id: String, msg: wa::Message) {
        const RECENT_MESSAGES_SIZE: usize = 256;
        let key = RecentMessageKey { to, id };
        let mut map_guard = self.recent_messages_map.lock().await;
        let mut list_guard = self.recent_messages_list.lock().await;

        if list_guard.len() >= RECENT_MESSAGES_SIZE
            && let Some(old_key) = list_guard.pop_front()
        {
            map_guard.remove(&old_key);
        }
        list_guard.push_back(key.clone());
        map_guard.insert(key, msg);
    }

    pub(crate) async fn handle_retry_receipt(
        self: &Arc<Self>,
        receipt: &Receipt,
        node: &crate::binary::node::Node,
    ) -> Result<(), anyhow::Error> {
        let retry_child = node
            .get_optional_child("retry")
            .ok_or_else(|| anyhow::anyhow!("<retry> child missing from receipt"))?;

        let message_id = retry_child.attrs().string("id");

        {
            let mut pending = self.pending_retries.lock().await;
            if pending.contains(&message_id) {
                log::debug!("Ignoring retry for {message_id}: a retry is already in progress.");
                return Ok(());
            }
            pending.insert(message_id.clone());
        }
        let _guard = scopeguard::guard((self.clone(), message_id.clone()), |(client, id)| {
            tokio::task::spawn_local(async move {
                client.pending_retries.lock().await.remove(&id);
            });
        });

        let original_msg = match self
            .take_recent_message(receipt.source.chat.clone(), message_id.clone())
            .await
        {
            Some(msg) => msg,
            None => {
                log::debug!(
                    "Ignoring retry for message {message_id}: already handled or not found in cache."
                );
                return Ok(());
            }
        };

        let participant_jid = receipt.source.sender.clone();

        if receipt.source.chat.is_group() {
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_lid = device_snapshot
                .lid
                .clone()
                .ok_or_else(|| anyhow::anyhow!("LID missing for group retry handling"))?;

            let sender_address =
                ProtocolAddress::new(own_lid.user.clone(), u32::from(own_lid.device).into());
            let sender_key_name = crate::signal::sender_key_name::SenderKeyName::new(
                receipt.source.chat.to_string(),
                sender_address.to_string(),
            );

            let device_store = self.persistence_manager.get_device_arc().await;
            let device_guard = device_store.lock().await;

            if let Err(e) = device_guard
                .backend
                .delete_sender_key(sender_key_name.group_id())
                .await
            {
                log::warn!(
                    "Failed to delete sender key for group {}: {}",
                    receipt.source.chat,
                    e
                );
            } else {
                info!(
                    "Deleted sender key for group {} due to retry receipt from {}",
                    receipt.source.chat, participant_jid
                );
            }

            let signal_address = ProtocolAddress::new(
                participant_jid.user.clone(),
                u32::from(participant_jid.device).into(),
            );

            if let Err(e) = device_store
                .lock()
                .await
                .delete_session(&signal_address)
                .await
            {
                log::warn!("Failed to delete session for {signal_address}: {e}");
            } else {
                info!("Deleted session for {signal_address} due to retry receipt");
            }
        } else {
            let signal_address = ProtocolAddress::new(
                participant_jid.user.clone(),
                u32::from(participant_jid.device).into(),
            );

            let device_store = self.persistence_manager.get_device_arc().await;
            if let Err(e) = device_store
                .lock()
                .await
                .delete_session(&signal_address)
                .await
            {
                log::warn!("Failed to delete session for {signal_address}: {e}");
            } else {
                info!("Deleted session for {signal_address} due to retry receipt");
            }
        }

        if receipt.source.chat.is_group() {
            info!(
                "Handling group message retry for {}. Creating and attaching a new SenderKeyDistributionMessage.",
                message_id
            );

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_sending_jid = device_snapshot
                .lid
                .clone()
                .or(device_snapshot.id.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!("Cannot create SKDM for retry: No local sending JID available")
                })?;

            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let mut device_guard = device_store_arc.lock().await;

            let (skdm_bytes_padded, _sender_key_name) =
                wacore::send::create_sender_key_distribution_message_for_group(
                    &mut *device_guard,
                    &receipt.source.chat,
                    &own_sending_jid,
                )
                .await?;

            let skdm_bytes = MessageUtils::unpad_message(&skdm_bytes_padded, 2).unwrap();
            let skdm_wrapper = wa::Message::decode(skdm_bytes)?;

            let mut resend_msg = original_msg;
            if let Some(skdm) = skdm_wrapper.sender_key_distribution_message {
                resend_msg.sender_key_distribution_message = Some(skdm);
                info!("Attached new SKDM to message {} for retry.", message_id);
            } else {
                warn!(
                    "Failed to extract SKDM from wrapper for retry of message {}.",
                    message_id
                );
            }

            self.send_message_impl(receipt.source.chat.clone(), resend_msg, message_id, false)
                .await?;
        } else {
            self.send_message_impl(receipt.source.chat.clone(), original_msg, message_id, false)
                .await?;
        }

        Ok(())
    }

    pub(crate) async fn send_retry_receipt(
        &self,
        info: &crate::types::message::MessageInfo,
    ) -> Result<(), anyhow::Error> {
        warn!(
            "Sending retry receipt for message {} from {}",
            info.id, info.source.sender
        );

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let device_store = self.persistence_manager.get_device_arc().await;
        let device_guard = device_store.lock().await;

        let new_prekey_id = (rand::random::<u32>() % 16777215) + 1;
        let new_prekey_keypair = wacore::signal::ecc::curve::generate_key_pair();
        let new_prekey_record = wacore::signal::state::record::new_pre_key_record(
            new_prekey_id,
            new_prekey_keypair.clone(),
        );
        if let Err(e) = device_guard
            .store_prekey(new_prekey_id, new_prekey_record)
            .await
        {
            warn!("Failed to store new prekey for retry receipt: {e:?}");
        }
        drop(device_guard);

        let registration_id_bytes = device_snapshot.registration_id.to_be_bytes().to_vec();

        let identity_key_bytes = device_snapshot.identity_key.public_key.to_vec();

        let prekey_id_bytes = new_prekey_id.to_be_bytes()[1..].to_vec();
        let prekey_value_bytes = new_prekey_keypair.public_key.public_key.to_vec();

        let skey_id_bytes = 1u32.to_be_bytes()[1..].to_vec();
        let skey_value_bytes = device_snapshot.signed_pre_key.key_pair.public_key.to_vec();
        let skey_sig_bytes = device_snapshot
            .signed_pre_key
            .signature
            .ok_or_else(|| anyhow::anyhow!("Missing signed prekey signature"))?
            .to_vec();

        let device_identity_bytes = device_snapshot
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing device account info for retry receipt"))?
            .encode_to_vec();

        let retry_node = Node {
            tag: "retry".to_string(),
            attrs: [
                ("v".to_string(), "1".to_string()),
                ("id".to_string(), info.id.clone()),
                ("t".to_string(), info.timestamp.timestamp().to_string()),
                ("count".to_string(), "1".to_string()),
            ]
            .into(),
            content: None,
        };

        let type_bytes = "5".to_string().into_bytes();

        let keys_node = Node {
            tag: "keys".to_string(),
            attrs: Default::default(),
            content: Some(NodeContent::Nodes(vec![
                Node {
                    tag: "type".to_string(),
                    content: Some(NodeContent::Bytes(type_bytes)),
                    ..Default::default()
                },
                Node {
                    tag: "identity".to_string(),
                    content: Some(NodeContent::Bytes(identity_key_bytes)),
                    ..Default::default()
                },
                Node {
                    tag: "key".to_string(),
                    content: Some(NodeContent::Nodes(vec![
                        Node {
                            tag: "id".to_string(),
                            content: Some(NodeContent::Bytes(prekey_id_bytes)),
                            ..Default::default()
                        },
                        Node {
                            tag: "value".to_string(),
                            content: Some(NodeContent::Bytes(prekey_value_bytes)),
                            ..Default::default()
                        },
                    ])),
                    ..Default::default()
                },
                Node {
                    tag: "skey".to_string(),
                    content: Some(NodeContent::Nodes(vec![
                        Node {
                            tag: "id".to_string(),
                            content: Some(NodeContent::Bytes(skey_id_bytes)),
                            ..Default::default()
                        },
                        Node {
                            tag: "value".to_string(),
                            content: Some(NodeContent::Bytes(skey_value_bytes)),
                            ..Default::default()
                        },
                        Node {
                            tag: "signature".to_string(),
                            content: Some(NodeContent::Bytes(skey_sig_bytes)),
                            ..Default::default()
                        },
                    ])),
                    ..Default::default()
                },
                Node {
                    tag: "device-identity".to_string(),
                    content: Some(NodeContent::Bytes(device_identity_bytes)),
                    ..Default::default()
                },
            ])),
        };

        let receipt_to = if info.source.is_group {
            info.source.chat.to_string()
        } else {
            info.source.sender.to_string()
        };

        let receipt_node = Node {
            tag: "receipt".to_string(),
            attrs: [
                ("to".to_string(), receipt_to),
                ("id".to_string(), info.id.clone()),
                ("type".to_string(), "retry".to_string()),
                ("participant".to_string(), info.source.sender.to_string()),
            ]
            .into(),
            content: Some(NodeContent::Nodes(vec![
                retry_node,
                Node {
                    tag: "registration".to_string(),
                    content: Some(NodeContent::Bytes(registration_id_bytes)),
                    ..Default::default()
                },
                keys_node,
            ])),
        };

        self.send_node(receipt_node).await?;
        Ok(())
    }
}
