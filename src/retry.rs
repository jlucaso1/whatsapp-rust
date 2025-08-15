use crate::client::{Client, RecentMessageKey};
use crate::signal::store::PreKeyStore;
use crate::types::events::Receipt;
use log::{info, warn};
use prost::Message;
use rand::TryRngCore;
use scopeguard;
use std::sync::Arc;
use wacore::libsignal::protocol::{KeyPair, ProtocolAddress};
use wacore::signal::store::SessionStore;
use wacore::types::jid::JidExt;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, JidExt as _};
use waproto::whatsapp as wa;

impl Client {
    pub async fn add_recent_message(&self, to: Jid, id: String, msg: Arc<wa::Message>) {
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
        node: &wacore_binary::node::Node,
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

        let original_msg_arc = match self
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
        let original_msg = (*original_msg_arc).clone();

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
            let device_guard = device_store.read().await;

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
        } else {
            let signal_address = participant_jid.to_protocol_address();

            let device_store = self.persistence_manager.get_device_arc().await;
            if let Err(e) = device_store
                .write()
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

            self.send_message_impl(
                receipt.source.chat.clone(),
                original_msg,
                message_id,
                false,
                true,
            )
            .await?;
        } else {
            self.send_message_impl(
                receipt.source.chat.clone(),
                original_msg,
                message_id,
                false,
                true,
            )
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
        let device_guard = device_store.read().await;

        let new_prekey_id = (rand::random::<u32>() % 16777215) + 1;
        let new_prekey_keypair = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
        let new_prekey_record =
            wacore::signal::state::record::new_pre_key_record(new_prekey_id, &new_prekey_keypair);
        // This key is not uploaded to the server pool, so mark as false
        if let Err(e) = device_guard
            .store_prekey(new_prekey_id, new_prekey_record, false)
            .await
        {
            warn!("Failed to store new prekey for retry receipt: {e:?}");
        }
        drop(device_guard);

        let registration_id_bytes = device_snapshot.registration_id.to_be_bytes().to_vec();

        let identity_key_bytes = device_snapshot
            .identity_key
            .public_key
            .public_key_bytes()
            .to_vec();

        let prekey_id_bytes = new_prekey_id.to_be_bytes()[1..].to_vec();
        let prekey_value_bytes = new_prekey_keypair.public_key.public_key_bytes().to_vec();

        let skey_id_bytes = 1u32.to_be_bytes()[1..].to_vec();
        let skey_value_bytes = device_snapshot
            .signed_pre_key
            .public_key
            .public_key_bytes()
            .to_vec();
        let skey_sig_bytes = device_snapshot.signed_pre_key_signature.to_vec();

        let device_identity_bytes = device_snapshot
            .account
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing device account info for retry receipt"))?
            .encode_to_vec();

        let retry_node = NodeBuilder::new("retry")
            .attr("v", "1")
            .attr("id", info.id.clone())
            .attr("t", info.timestamp.timestamp().to_string())
            .attr("count", "1")
            .build();

        let type_bytes = vec![5u8];

        let keys_node = NodeBuilder::new("keys")
            .children([
                NodeBuilder::new("type").bytes(type_bytes).build(),
                NodeBuilder::new("identity")
                    .bytes(identity_key_bytes)
                    .build(),
                NodeBuilder::new("key")
                    .children([
                        NodeBuilder::new("id").bytes(prekey_id_bytes).build(),
                        NodeBuilder::new("value").bytes(prekey_value_bytes).build(),
                    ])
                    .build(),
                NodeBuilder::new("skey")
                    .children([
                        NodeBuilder::new("id").bytes(skey_id_bytes).build(),
                        NodeBuilder::new("value").bytes(skey_value_bytes).build(),
                        NodeBuilder::new("signature").bytes(skey_sig_bytes).build(),
                    ])
                    .build(),
                NodeBuilder::new("device-identity")
                    .bytes(device_identity_bytes)
                    .build(),
            ])
            .build();

        let receipt_to = if info.source.is_group {
            info.source.chat.to_string()
        } else {
            info.source.sender.to_string()
        };

        let registration_node = NodeBuilder::new("registration")
            .bytes(registration_id_bytes)
            .build();

        let receipt_node = NodeBuilder::new("receipt")
            .attr("to", receipt_to)
            .attr("id", info.id.clone())
            .attr("type", "retry")
            .attr("participant", info.source.sender.to_string())
            .children([retry_node, registration_node, keys_node])
            .build();

        self.send_node(receipt_node).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::persistence_manager::PersistenceManager;

    #[tokio::test]
    async fn recent_message_cache_insert_and_take() {
        let _ = env_logger::builder().is_test(true).try_init();

        let pm = Arc::new(PersistenceManager::new(":memory:").await.unwrap());
        let client = Arc::new(Client::new(pm.clone()).await);

        let chat: Jid = "120363021033254949@g.us".parse().unwrap();
        let msg_id = "ABC123".to_string();
        let msg = wa::Message {
            conversation: Some("hello".into()),
            ..Default::default()
        };

        client
            .add_recent_message(chat.clone(), msg_id.clone(), Arc::new(msg.clone()))
            .await;

        // First take should return and remove it from cache
        let taken = client
            .take_recent_message(chat.clone(), msg_id.clone())
            .await;
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().conversation.as_deref(), Some("hello"));

        // Second take should return None
        let taken_again = client.take_recent_message(chat, msg_id).await;
        assert!(taken_again.is_none());
    }
}
