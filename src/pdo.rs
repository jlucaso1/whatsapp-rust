//! PDO (Peer Data Operation) support for requesting message content from the primary device.
//!
//! When message decryption fails (e.g., due to session mismatch), instead of only sending
//! a retry receipt to the sender, we can also request the message content from our own
//! primary phone device. This is useful because:
//!
//! 1. The primary phone has already decrypted the message successfully
//! 2. It can share the decrypted content with linked devices via PDO
//! 3. This bypasses session issues entirely since we're asking our own trusted device
//!
//! The flow is:
//! 1. Decryption fails for a message
//! 2. We send a PeerDataOperationRequestMessage with type PLACEHOLDER_MESSAGE_RESEND
//! 3. The phone responds with PeerDataOperationRequestResponseMessage containing the decoded message
//! 4. We emit the message as if we had decrypted it ourselves

use crate::client::Client;
use crate::types::message::MessageInfo;
use log::{debug, info, warn};
use moka::future::Cache;
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use wacore::types::message::{EditAttribute, MessageSource, MsgMetaInfo};
use wacore_binary::jid::{Jid, JidExt};
use waproto::whatsapp as wa;

/// Cache entry for pending PDO requests.
/// Contains the original message info needed to properly dispatch the response.
#[derive(Clone, Debug)]
pub struct PendingPdoRequest {
    pub message_info: MessageInfo,
    pub requested_at: std::time::Instant,
}

/// Creates a new PDO request cache.
/// The cache has a TTL of 30 seconds (phone should respond quickly) and limited capacity.
pub fn new_pdo_cache() -> Cache<String, PendingPdoRequest> {
    Cache::builder()
        .time_to_live(Duration::from_secs(30))
        .max_capacity(500)
        .build()
}

impl Client {
    /// Sends a PDO (Peer Data Operation) request to our own primary phone to get the
    /// decrypted content of a message that we failed to decrypt.
    ///
    /// This is called when decryption fails and we want to ask our phone for the message.
    /// The phone will respond with a PeerDataOperationRequestResponseMessage containing
    /// the full WebMessageInfo which we can then dispatch as a normal message event.
    ///
    /// # Arguments
    /// * `info` - The MessageInfo for the message that failed to decrypt
    ///
    /// # Returns
    /// * `Ok(())` if the request was sent successfully
    /// * `Err` if we couldn't send the request (e.g., not logged in)
    pub async fn send_pdo_placeholder_resend_request(
        self: &Arc<Self>,
        info: &MessageInfo,
    ) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        // We need to send PDO to our PRIMARY PHONE (device 0), not to ourselves (linked device).
        // The primary phone has already decrypted the message and can share the content with us.
        let own_pn = device_snapshot
            .pn
            .clone()
            .ok_or_else(|| anyhow::anyhow!("Not logged in - no phone number available for PDO"))?;

        // Create JID for device 0 (primary phone)
        let primary_phone_jid = own_pn.with_device(0);

        // Resolve JIDs to LID for the MessageKey and cache key, matching WhatsApp Web's behavior.
        // This ensures the cache key matches the JID that the phone will respond with (usually LID).
        let remote_jid = self.resolve_encryption_jid(&info.source.chat).await;
        let participant = if info.source.is_group {
            Some(self.resolve_encryption_jid(&info.source.sender).await)
        } else {
            None
        };

        // Atomically check-and-insert to avoid race conditions where two concurrent
        // calls could both pass a contains_key check before either inserts.
        let cache_key = format!("{}:{}", remote_jid, info.id);
        let pending = PendingPdoRequest {
            message_info: info.clone(),
            requested_at: std::time::Instant::now(),
        };
        let entry = self
            .pdo_pending_requests
            .entry(cache_key.clone())
            .or_insert(pending)
            .await;

        if !entry.is_fresh() {
            debug!(
                "PDO request already pending for message {} from {} (resolved: {})",
                info.id, info.source.sender, remote_jid
            );
            return Ok(());
        }

        // Build the message key for the placeholder resend request
        let message_key = wa::MessageKey {
            remote_jid: Some(remote_jid.to_string()),
            from_me: Some(info.source.is_from_me),
            id: Some(info.id.clone()),
            participant: participant.map(|p| p.to_string()),
        };

        // Build the PDO request message
        let pdo_request = wa::message::PeerDataOperationRequestMessage {
            peer_data_operation_request_type: Some(
                wa::message::PeerDataOperationRequestType::PlaceholderMessageResend as i32,
            ),
            placeholder_message_resend_request: vec![
                wa::message::peer_data_operation_request_message::PlaceholderMessageResendRequest {
                    message_key: Some(message_key),
                },
            ],
            ..Default::default()
        };

        // Wrap it in a protocol message
        let protocol_message = wa::message::ProtocolMessage {
            r#type: Some(
                wa::message::protocol_message::Type::PeerDataOperationRequestMessage as i32,
            ),
            peer_data_operation_request_message: Some(pdo_request),
            ..Default::default()
        };

        let msg = wa::Message {
            protocol_message: Some(Box::new(protocol_message)),
            ..Default::default()
        };

        info!(
            "Sending PDO placeholder resend request for message {} from {} in {} to primary phone {}",
            info.id, info.source.sender, info.source.chat, primary_phone_jid
        );

        // Ensure E2E session exists before sending (matches WhatsApp Web behavior)
        self.ensure_e2e_sessions(vec![primary_phone_jid.clone()])
            .await?;

        // Send the message to our primary phone (device 0)
        match self.send_peer_message(primary_phone_jid, &msg).await {
            Ok(_) => {
                debug!("PDO request sent successfully for message {}", info.id);
                Ok(())
            }
            Err(e) => {
                // Remove from pending cache on failure
                self.pdo_pending_requests.remove(&cache_key).await;
                warn!(
                    "Failed to send PDO request for message {}: {:?}",
                    info.id, e
                );
                Err(e)
            }
        }
    }

    /// Sends a peer message (message to our own devices).
    /// This is used for PDO requests and similar device-to-device communication.
    async fn send_peer_message(
        self: &Arc<Self>,
        to: Jid,
        msg: &wa::Message,
    ) -> Result<String, anyhow::Error> {
        let msg_id = self.generate_message_id().await;

        // Send with peer category and high priority
        self.send_message_impl(
            to,
            msg,
            Some(msg_id.clone()),
            true,  // is_peer_message
            false, // is_retry
            None,
            vec![], // No extra stanza nodes for peer messages
        )
        .await?;

        Ok(msg_id)
    }

    /// Handles a PDO response message from our primary phone.
    /// This is called when we receive a PeerDataOperationRequestResponseMessage.
    ///
    /// # Arguments
    /// * `response` - The PDO response message
    /// * `info` - The MessageInfo for the PDO response message itself
    pub async fn handle_pdo_response(
        self: &Arc<Self>,
        response: &wa::message::PeerDataOperationRequestResponseMessage,
        _pdo_msg_info: &MessageInfo,
    ) {
        debug!(
            "Received PDO response with {} results",
            response.peer_data_operation_result.len()
        );

        for result in &response.peer_data_operation_result {
            if let Some(placeholder_response) = &result.placeholder_message_resend_response {
                self.handle_placeholder_resend_response(placeholder_response)
                    .await;
            }
        }
    }

    /// Handles a single placeholder message resend response from PDO.
    async fn handle_placeholder_resend_response(
        self: &Arc<Self>,
        response: &wa::message::peer_data_operation_request_response_message::peer_data_operation_result::PlaceholderMessageResendResponse,
    ) {
        let Some(web_message_info_bytes) = &response.web_message_info_bytes else {
            warn!("PDO placeholder response missing webMessageInfoBytes");
            return;
        };

        // Decode the WebMessageInfo
        let web_msg_info = match wa::WebMessageInfo::decode(web_message_info_bytes.as_slice()) {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to decode WebMessageInfo from PDO response: {:?}", e);
                return;
            }
        };

        // Extract message key to find the original pending request
        let key = &web_msg_info.key;

        let remote_jid = key.remote_jid.as_deref().unwrap_or("");
        let msg_id = key.id.as_deref().unwrap_or("");
        let cache_key = format!("{}:{}", remote_jid, msg_id);

        // Remove from pending requests
        let pending = self.pdo_pending_requests.remove(&cache_key).await;

        let elapsed = pending
            .as_ref()
            .map(|p| p.requested_at.elapsed().as_millis())
            .unwrap_or(0);

        info!(
            "Received PDO placeholder response for message {} (took {}ms)",
            msg_id, elapsed
        );

        // Build MessageInfo from the WebMessageInfo or use the pending request's info
        let message_info = if let Some(pending) = pending {
            pending.message_info
        } else {
            // Reconstruct MessageInfo from WebMessageInfo if we don't have it cached
            match self.message_info_from_web_message_info(&web_msg_info).await {
                Ok(info) => info,
                Err(e) => {
                    warn!(
                        "Failed to reconstruct MessageInfo from PDO response: {:?}",
                        e
                    );
                    return;
                }
            }
        };

        // Extract the actual message content
        let Some(message) = web_msg_info.message else {
            warn!("PDO response WebMessageInfo missing message content");
            return;
        };

        // Dispatch the message as a normal message event
        info!(
            "Dispatching PDO-recovered message {} from {} via phone",
            message_info.id, message_info.source.sender
        );

        self.core
            .event_bus
            .dispatch(&wacore::types::events::Event::Message(
                Box::new(message),
                message_info,
            ));
    }

    /// Reconstructs a MessageInfo from a WebMessageInfo.
    /// This is used when we receive a PDO response but don't have the original pending request cached.
    async fn message_info_from_web_message_info(
        &self,
        web_msg: &wa::WebMessageInfo,
    ) -> Result<MessageInfo, anyhow::Error> {
        let key = &web_msg.key;

        let remote_jid: Jid = key
            .remote_jid
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("MessageKey missing remoteJid"))?
            .parse()?;

        let is_group = remote_jid.is_group();
        let is_from_me = key.from_me.unwrap_or(false);

        let sender = if is_group {
            key.participant
                .as_ref()
                .map(|p: &String| p.parse())
                .transpose()?
                .unwrap_or_else(|| remote_jid.clone())
        } else if is_from_me {
            self.persistence_manager
                .get_device_snapshot()
                .await
                .pn
                .clone()
                .unwrap_or_else(|| remote_jid.clone())
        } else {
            remote_jid.clone()
        };

        let timestamp = web_msg
            .message_timestamp
            .map(|ts| {
                chrono::DateTime::from_timestamp(ts as i64, 0).unwrap_or_else(chrono::Utc::now)
            })
            .unwrap_or_else(chrono::Utc::now);

        Ok(MessageInfo {
            id: key.id.clone().unwrap_or_default(),
            server_id: 0,
            r#type: String::new(),
            source: MessageSource {
                chat: remote_jid,
                sender,
                sender_alt: None,
                recipient_alt: None,
                is_from_me,
                is_group,
                addressing_mode: None,
                broadcast_list_owner: None,
                recipient: None,
            },
            timestamp,
            push_name: web_msg.push_name.clone().unwrap_or_default(),
            category: String::new(),
            multicast: false,
            media_type: String::new(),
            edit: EditAttribute::default(),
            bot_info: None,
            meta_info: MsgMetaInfo::default(),
            verified_name: None,
            device_sent_meta: None,
        })
    }

    /// Spawns a PDO request for a message that failed to decrypt.
    /// This is called alongside the retry receipt to increase chances of recovery.
    ///
    /// When `immediate` is true, the PDO request is sent without delay.
    /// This is used when we've exhausted retry attempts and need immediate PDO recovery.
    pub(crate) fn spawn_pdo_request_with_options(
        self: &Arc<Self>,
        info: &MessageInfo,
        immediate: bool,
    ) {
        // Don't send PDO for our own messages or status broadcasts
        if info.source.is_from_me {
            return;
        }
        if info.source.chat.server == wacore_binary::jid::BROADCAST_SERVER {
            return;
        }

        let client_clone = Arc::clone(self);
        let info_clone = info.clone();

        tokio::spawn(async move {
            if !immediate {
                // Add a small delay to allow the retry receipt to be processed first
                // This avoids overwhelming the phone with simultaneous requests
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            if let Err(e) = client_clone
                .send_pdo_placeholder_resend_request(&info_clone)
                .await
            {
                warn!(
                    "Failed to send PDO request for message {} from {}: {:?}",
                    info_clone.id, info_clone.source.sender, e
                );
            }
        });
    }

    /// Spawns a PDO request for a message that failed to decrypt.
    /// This is called alongside the retry receipt to increase chances of recovery.
    pub(crate) fn spawn_pdo_request(self: &Arc<Self>, info: &MessageInfo) {
        self.spawn_pdo_request_with_options(info, false);
    }
}

#[cfg(test)]
mod tests {
    use wacore_binary::jid::{DEFAULT_USER_SERVER, Jid, JidExt};

    #[test]
    fn test_pdo_primary_phone_jid_is_device_0() {
        // PDO sends to device 0 (primary phone)
        let own_pn = Jid::pn("559999999999");
        let primary_phone_jid = own_pn.with_device(0);

        assert_eq!(primary_phone_jid.device, 0);
        assert!(!primary_phone_jid.is_ad()); // Device 0 is NOT an additional device
    }

    #[test]
    fn test_pdo_primary_phone_jid_preserves_user() {
        let own_pn = Jid::pn("559999999999");
        let primary_phone_jid = own_pn.with_device(0);

        assert_eq!(primary_phone_jid.user, "559999999999");
        assert_eq!(primary_phone_jid.server, DEFAULT_USER_SERVER);
    }

    #[test]
    fn test_pdo_primary_phone_jid_from_linked_device() {
        // Even if we're device 33, PDO should send to device 0
        let own_pn = Jid::pn_device("559999999999", 33);
        let primary_phone_jid = own_pn.with_device(0);

        assert_eq!(primary_phone_jid.user, "559999999999");
        assert_eq!(primary_phone_jid.device, 0);
    }
}
