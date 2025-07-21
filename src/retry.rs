use crate::client::{Client, RecentMessageKey};
use crate::signal::address::SignalAddress;
use crate::signal::store::{SenderKeyStore, SessionStore};
use crate::types::events::Receipt;
use crate::types::jid::Jid;
use log::info;
use scopeguard;
use std::sync::Arc;
use waproto::whatsapp as wa;

impl Client {
    /// Add a message to the recent message cache (with eviction)
    pub(crate) async fn add_recent_message(&self, to: Jid, id: String, msg: wa::Message) {
        const RECENT_MESSAGES_SIZE: usize = 256;
        let key = RecentMessageKey { to, id };
        let mut map_guard = self.recent_messages_map.lock().await;
        let mut list_guard = self.recent_messages_list.lock().await;

        if list_guard.len() >= RECENT_MESSAGES_SIZE {
            if let Some(old_key) = list_guard.pop_front() {
                map_guard.remove(&old_key);
            }
        }
        list_guard.push_back(key.clone());
        map_guard.insert(key, msg);
    }

    /// Handle retry receipt: clear session and resend original message
    pub(crate) async fn handle_retry_receipt(
        self: &Arc<Self>,
        receipt: &Receipt,
        node: &crate::binary::node::Node,
    ) -> Result<(), anyhow::Error> {
        let retry_child = node
            .get_optional_child("retry")
            .ok_or_else(|| anyhow::anyhow!("<retry> child missing from receipt"))?;

        let message_id = retry_child.attrs().string("id");

        // Race-proof: Only allow one retry handler per message_id at a time
        {
            let mut pending = self.pending_retries.lock().await;
            if pending.contains(&message_id) {
                log::debug!("Ignoring retry for {message_id}: a retry is already in progress.");
                return Ok(());
            }
            pending.insert(message_id.clone());
        }
        let _guard = scopeguard::guard((self.clone(), message_id.clone()), |(client, id)| {
            tokio::spawn(async move {
                client.pending_retries.lock().await.remove(&id);
            });
        });

        // Try to take the message from the cache. If it's not there, it means we've already
        // processed a retry for this message send, so we can safely ignore this one.
        let original_msg = match self
            .take_recent_message(receipt.source.chat.clone(), message_id.clone())
            .await
        {
            Some(msg) => msg,
            None => {
                log::debug!(
                    "Ignoring retry for message {message_id}: already handled or not found in cache."
                );
                return Ok(()); // Gracefully exit
            }
        };

        let participant_jid = receipt.source.sender.clone();

        // Check if this is a group message
        if receipt.source.chat.is_group() {
            // For group messages, delete the sender key to force generation of a new one
            // This is the key fix to prevent infinite retry loops
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_lid = device_snapshot
                .lid
                .clone()
                .ok_or_else(|| anyhow::anyhow!("LID missing for group retry handling"))?;

            let sender_address = SignalAddress::new(own_lid.user.clone(), own_lid.device as u32);
            let sender_key_name = crate::signal::sender_key_name::SenderKeyName::new(
                receipt.source.chat.to_string(),
                sender_address.to_string(),
            );

            let device_store = self.persistence_manager.get_device_arc().await;

            // Delete the sender key record to force creation of a new one
            if let Err(e) = device_store
                .lock()
                .await
                .delete_sender_key(&sender_key_name)
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

            // Also delete the pairwise session with the participant who sent the retry
            let signal_address = crate::signal::address::SignalAddress::new(
                participant_jid.user.clone(),
                participant_jid.device as u32,
            );

            if let Err(e) = device_store
                .lock()
                .await
                .delete_session(&signal_address)
                .await
            {
                // It's not a critical error if the session file doesn't exist,
                // especially when dealing with the primary device (:0).
                log::warn!("Failed to delete session for {signal_address}: {e}");
            } else {
                info!("Deleted session for {signal_address} due to retry receipt");
            }
        } else {
            // For direct messages, only delete the pairwise session
            let signal_address = crate::signal::address::SignalAddress::new(
                participant_jid.user.clone(),
                participant_jid.device as u32,
            );

            let device_store = self.persistence_manager.get_device_arc().await;
            if let Err(e) = device_store
                .lock()
                .await
                .delete_session(&signal_address)
                .await
            {
                // It's not a critical error if the session file doesn't exist.
                log::warn!("Failed to delete session for {signal_address}: {e}");
            } else {
                info!("Deleted session for {signal_address} due to retry receipt");
            }
        }

        // Resend the original message
        self.send_message_impl(receipt.source.chat.clone(), original_msg, message_id, false)
            .await?; // Use _impl to send with original ID
        Ok(())
    }
}
