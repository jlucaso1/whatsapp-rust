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

use crate::cache::Cache;
use crate::client::Client;
use crate::types::message::MessageInfo;
use log::{debug, info, warn};
use prost::Message;
use std::sync::Arc;
use std::time::Duration;
use wacore::types::message::{
    ChatMessageId, EditAttribute, MessageCategory, MessageSource, MsgMetaInfo,
};
use wacore_binary::{Jid, JidExt};
use waproto::whatsapp as wa;

#[derive(Clone, Debug)]
pub struct PendingPdoRequest {
    pub message_info: Arc<MessageInfo>,
    pub requested_at: wacore::time::Instant,
}

pub fn new_pdo_cache() -> Cache<ChatMessageId, PendingPdoRequest> {
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
        info: &Arc<MessageInfo>,
    ) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        // We need to send PDO to our PRIMARY PHONE (device 0), not to ourselves (linked device).
        // The primary phone has already decrypted the message and can share the content with us.
        let own_pn = device_snapshot
            .pn
            .clone()
            .ok_or_else(|| anyhow::Error::from(crate::client::ClientError::NotLoggedIn))?;

        // Send to bare own JID (no device suffix); server routes to all devices
        // including device 0. Matches whatsmeow's SendPeerMessage(ownID.ToNonAD()).
        let peer_target = own_pn.to_non_ad();

        // Resolve to LID for the MessageKey when LID-migrated, matching WA Web's
        // NonMessageDataRequest.js:412-421 (toUserLid when isLidMigrated).
        // The phone stores messages by LID after migration.
        let resolved_jid = self.resolve_encryption_jid(&info.source.chat).await;
        // WAWebE2EProtoUtils.msgKeyToProtobuf omits participant when fromMe or
        // when the MsgKey has no participant (i.e. a DM, where the chat JID is
        // the sender). Groups and broadcast chats need it so the phone can
        // locate the stored message.
        let participant = if !info.source.is_from_me
            && (info.source.is_group || info.source.chat.server == wacore_binary::Server::Broadcast)
        {
            Some(self.resolve_encryption_jid(&info.source.sender).await)
        } else {
            None
        };

        // Cache key must use PN JID because the phone's response always contains
        // PN JIDs in WebMessageInfo.key. For LID-migrated DMs, info.source.chat
        // can be LID while sender_alt holds the PN — prefer the PN form.
        let cache_chat = if !info.source.is_group && info.source.chat.is_lid() {
            info.source
                .sender_alt
                .as_ref()
                .map(|jid| jid.to_non_ad())
                .unwrap_or_else(|| info.source.chat.clone())
        } else {
            info.source.chat.clone()
        };
        let cache_key = ChatMessageId::new(cache_chat, info.id.clone());

        if self.pdo_pending_requests.get(&cache_key).await.is_some() {
            debug!(
                "PDO request already pending for message {} from {}",
                info.id, info.source.sender
            );
            return Ok(());
        }

        let pending = PendingPdoRequest {
            message_info: Arc::clone(info),
            requested_at: wacore::time::Instant::now(),
        };
        self.pdo_pending_requests
            .insert(cache_key.clone(), pending)
            .await;

        let message_key = wa::MessageKey {
            remote_jid: Some(resolved_jid.to_string()),
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
            "Sending PDO placeholder resend request for message {} from {} in {} to {}",
            info.id, info.source.sender, info.source.chat, peer_target
        );

        if let Err(e) = self
            .ensure_e2e_sessions(std::slice::from_ref(&peer_target))
            .await
        {
            self.pdo_pending_requests.remove(&cache_key).await;
            return Err(e);
        }

        if let Err(e) = self.send_peer_message(peer_target, &msg).await {
            self.pdo_pending_requests.remove(&cache_key).await;
            warn!(
                "Failed to send PDO request for message {}: {:?}",
                info.id, e
            );
            return Err(e);
        }

        debug!("PDO request sent successfully for message {}", info.id);
        Ok(())
    }

    /// Request on-demand message history from the primary phone via PDO.
    pub async fn fetch_message_history(
        self: &Arc<Self>,
        chat_jid: &Jid,
        oldest_msg_id: &str,
        oldest_msg_from_me: bool,
        oldest_msg_timestamp_ms: i64,
        count: i32,
    ) -> Result<String, anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_pn = device_snapshot
            .pn
            .clone()
            .ok_or_else(|| anyhow::Error::from(crate::client::ClientError::NotLoggedIn))?;
        let peer_target = own_pn.to_non_ad();

        let pdo_request = wa::message::PeerDataOperationRequestMessage {
            peer_data_operation_request_type: Some(
                wa::message::PeerDataOperationRequestType::HistorySyncOnDemand as i32,
            ),
            history_sync_on_demand_request: Some(
                wa::message::peer_data_operation_request_message::HistorySyncOnDemandRequest {
                    chat_jid: Some(chat_jid.to_string()),
                    oldest_msg_id: Some(oldest_msg_id.to_string()),
                    oldest_msg_from_me: Some(oldest_msg_from_me),
                    oldest_msg_timestamp_ms: Some(oldest_msg_timestamp_ms),
                    on_demand_msg_count: Some(count),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };

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
            "Sending PDO history sync on-demand request for chat {} (count={}) to {}",
            chat_jid, count, peer_target
        );

        self.ensure_e2e_sessions(std::slice::from_ref(&peer_target))
            .await?;
        self.send_peer_message(peer_target, &msg).await
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
        pdo_msg_info: &MessageInfo,
    ) {
        // Only process PDO responses from device 0 (the primary phone)
        if pdo_msg_info.source.sender.device != 0 {
            debug!(
                "Ignoring PDO response from non-primary device {}",
                pdo_msg_info.source.sender
            );
            return;
        }

        let request_id = response.stanza_id.as_deref().unwrap_or("");
        debug!(
            "Received PDO response (request_id={}) with {} results",
            request_id,
            response.peer_data_operation_result.len()
        );

        for result in &response.peer_data_operation_result {
            if let Some(placeholder_response) = &result.placeholder_message_resend_response {
                self.handle_placeholder_resend_response(placeholder_response, request_id)
                    .await;
            }
        }
    }

    async fn handle_placeholder_resend_response(
        self: &Arc<Self>,
        response: &wa::message::peer_data_operation_request_response_message::peer_data_operation_result::PlaceholderMessageResendResponse,
        request_id: &str,
    ) {
        let Some(web_message_info_bytes) = &response.web_message_info_bytes else {
            warn!("PDO placeholder response missing webMessageInfoBytes");
            return;
        };

        let web_msg_info = match wa::WebMessageInfo::decode(web_message_info_bytes.as_slice()) {
            Ok(info) => info,
            Err(e) => {
                warn!("Failed to decode WebMessageInfo from PDO response: {:?}", e);
                return;
            }
        };

        let key = &web_msg_info.key;
        let remote_jid_str = key.remote_jid.as_deref().unwrap_or("");
        let msg_id = key.id.as_deref().unwrap_or("");

        let cache_key = match remote_jid_str.parse::<Jid>() {
            Ok(jid) => ChatMessageId::new(jid, msg_id.to_owned()),
            Err(_) => {
                warn!(
                    "PDO response has unparseable remote_jid: {}",
                    remote_jid_str
                );
                return;
            }
        };

        let pending = self.pdo_pending_requests.remove(&cache_key).await;

        let elapsed = pending
            .as_ref()
            .map(|p| p.requested_at.elapsed().as_millis())
            .unwrap_or(0);

        info!(
            "Received PDO placeholder response for message {} (took {}ms)",
            msg_id, elapsed
        );

        let mut message_info = if let Some(pending) = pending {
            pending.message_info
        } else {
            match self.message_info_from_web_message_info(&web_msg_info).await {
                Ok(info) => Arc::new(info),
                Err(e) => {
                    warn!(
                        "Failed to reconstruct MessageInfo from PDO response: {:?}",
                        e
                    );
                    return;
                }
            }
        };

        let Some(message) = web_msg_info.message else {
            warn!("PDO response WebMessageInfo missing message content");
            return;
        };

        {
            use wacore::proto_helpers::MessageExt;
            let mi = Arc::make_mut(&mut message_info);
            if mi.ephemeral_expiration.is_none() {
                mi.ephemeral_expiration = message.get_base_message().get_ephemeral_expiration();
            }
            mi.unavailable_request_id = if request_id.is_empty() {
                None
            } else {
                Some(request_id.to_owned())
            };
        }

        info!(
            "Dispatching PDO-recovered message {} from {} via phone (request_id={})",
            message_info.id, message_info.source.sender, request_id
        );

        self.core
            .event_bus
            .dispatch(wacore::types::events::Event::Message(
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

        // `key.participant` is the real author for any chat where the sender
        // differs from the remote_jid — groups AND broadcasts (including
        // status). Falling back to remote_jid for broadcasts would surface
        // `status@broadcast` as the sender and erase the author. Matches the
        // response-handler construction in WAWebNonMessageDataRequestHandlerPlaceholderResend
        // which maps participant to `author` for both broadcast branches.
        let sender = if let Some(p) = key.participant.as_ref() {
            p.parse()?
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
            .map(|ts| wacore::time::from_secs_or_now(ts as i64))
            .unwrap_or_else(wacore::time::now_utc);

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
            category: MessageCategory::default(),
            multicast: false,
            media_type: String::new(),
            edit: EditAttribute::default(),
            bot_info: None,
            meta_info: MsgMetaInfo::default(),
            verified_name: None,
            device_sent_meta: None,
            ephemeral_expiration: None,
            is_offline: false,
            unavailable_request_id: None,
        })
    }

    /// Spawns a PDO request for a message that failed to decrypt.
    /// This is called alongside the retry receipt to increase chances of recovery.
    ///
    /// When `immediate` is true, the PDO request is sent without delay.
    /// This is used when we've exhausted retry attempts and need immediate PDO recovery.
    pub(crate) fn spawn_pdo_request_with_options(
        self: &Arc<Self>,
        info: &Arc<MessageInfo>,
        immediate: bool,
    ) {
        // `fromMe` is NOT excluded here: when the user's other devices send a
        // message and the fanout copy to this client fails to decrypt, PDO is
        // the only recovery path. Matches WAWebNonMessageDataRequestPlaceholderMessageResendUtils.

        // Avoid asking the phone to re-deliver ancient messages during offline
        // sync or long reconnect tails. Matches the
        // `placeholder_message_resend_maximum_days_limit` AB prop (default 14d)
        // enforced by WAWebNonMessageDataRequestPlaceholderMessageResendUtils.
        // Compare in seconds to stay bit-for-bit with WA Web's `age_s > i`
        // check — `num_days()` truncates and would let 14d1h through.
        const PDO_MAX_AGE: chrono::Duration = chrono::Duration::days(14);
        let age = chrono::Utc::now().signed_duration_since(info.timestamp);
        if age > PDO_MAX_AGE {
            debug!(
                "PDO request skipped for message {} (age {}s exceeds {}s limit)",
                info.id,
                age.num_seconds(),
                PDO_MAX_AGE.num_seconds(),
            );
            return;
        }

        let client_clone = Arc::clone(self);
        let info_clone = Arc::clone(info);
        // Per-connection: on disconnect/reconnect the signal fires and we bail
        // before inserting into `pdo_pending_requests`, preventing a 30s TTL
        // strand on an entry that can no longer receive its response.
        let shutdown = self.connection_shutdown_signal();

        self.runtime
            .spawn(Box::pin(async move {
                use futures::FutureExt;

                if !immediate {
                    // Delay lets the retry receipt land before we pile PDO on top.
                    futures::select! {
                        _ = client_clone
                            .runtime
                            .sleep(Duration::from_millis(500))
                            .fuse() => {}
                        _ = wacore::runtime::wait_for_shutdown(&shutdown).fuse() => {
                            return;
                        }
                    }
                }

                if shutdown.is_fired() {
                    return;
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
            }))
            .detach();
    }

    /// Spawns a PDO request for a message that failed to decrypt.
    /// This is called alongside the retry receipt to increase chances of recovery.
    pub(crate) fn spawn_pdo_request(self: &Arc<Self>, info: &Arc<MessageInfo>) {
        self.spawn_pdo_request_with_options(info, false);
    }
}

#[cfg(test)]
mod tests {
    use wacore_binary::{Jid, JidExt, Server};

    #[test]
    fn test_pdo_peer_target_is_device_0() {
        let own_pn = Jid::pn("559999999999");
        let peer_target = own_pn.to_non_ad();

        assert_eq!(peer_target.device, 0);
        assert!(!peer_target.is_ad());
    }

    #[test]
    fn test_pdo_peer_target_preserves_user() {
        let own_pn = Jid::pn("559999999999");
        let peer_target = own_pn.to_non_ad();

        assert_eq!(peer_target.user, "559999999999");
        assert_eq!(peer_target.server, Server::Pn);
    }

    #[test]
    fn test_pdo_peer_target_from_linked_device() {
        let own_pn = Jid::pn_device("559999999999", 33);
        let peer_target = own_pn.to_non_ad();

        assert_eq!(peer_target.user, "559999999999");
        assert_eq!(peer_target.device, 0);
        assert_eq!(peer_target.agent, 0);
    }

    // Reconstruction-path tests share a bare Client wired to mock transport
    // and an in-memory SQLite backend. The only thing they vary is the
    // WebMessageInfo they hand to `message_info_from_web_message_info`.

    async fn setup_reconstruct_client() -> std::sync::Arc<crate::client::Client> {
        use crate::test_utils::{MockHttpClient, create_test_backend};
        use crate::{
            client::Client, runtime_impl::TokioRuntime,
            store::persistence_manager::PersistenceManager, transport::mock::MockTransportFactory,
        };
        use std::sync::Arc;

        let backend = create_test_backend().await;
        let pm = Arc::new(PersistenceManager::new(backend).await.unwrap());
        let (client, _rx) = Client::new(
            Arc::new(TokioRuntime),
            pm,
            Arc::new(MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;
        client
    }

    fn make_web_msg(
        remote_jid: &str,
        from_me: bool,
        id: &str,
        participant: Option<&str>,
    ) -> waproto::whatsapp::WebMessageInfo {
        use waproto::whatsapp as wa;
        wa::WebMessageInfo {
            key: wa::MessageKey {
                remote_jid: Some(remote_jid.into()),
                from_me: Some(from_me),
                id: Some(id.into()),
                participant: participant.map(|p| p.into()),
            },
            ..Default::default()
        }
    }

    /// The reconstruction path preserves the real author for status
    /// broadcasts via `key.participant`. Using `remote_jid` as sender
    /// would surface `status@broadcast` and erase the author.
    #[tokio::test]
    async fn test_reconstruct_prefers_participant_for_status_broadcast() {
        let client = setup_reconstruct_client().await;
        let author_jid = "203040904720543@lid";
        let web_msg = make_web_msg("status@broadcast", false, "STATUS_PDO_1", Some(author_jid));

        let info = client
            .message_info_from_web_message_info(&web_msg)
            .await
            .unwrap();

        assert_eq!(info.source.chat.to_string(), "status@broadcast");
        assert_eq!(info.source.sender.to_string(), author_jid);
    }

    /// DM without participant falls back to remote_jid as the sender,
    /// preserving the pre-fix behaviour for the DM case.
    #[tokio::test]
    async fn test_reconstruct_dm_falls_back_to_remote_jid() {
        let client = setup_reconstruct_client().await;
        let peer = "5511999998888@s.whatsapp.net";
        let web_msg = make_web_msg(peer, false, "DM_PDO_1", None);

        let info = client
            .message_info_from_web_message_info(&web_msg)
            .await
            .unwrap();

        assert_eq!(info.source.chat.to_string(), peer);
        assert_eq!(info.source.sender.to_string(), peer);
    }

    /// LID-migrated 1-on-1 responses carry `remote_jid` in LID form and no
    /// `participant` (WA Web's request side strips it when building the new
    /// MsgKey, and `msgKeyToProtobuf` then omits it). Reconstruction must
    /// still resolve the sender to that LID remote, not to something else.
    #[tokio::test]
    async fn test_reconstruct_lid_migrated_dm_uses_lid_remote() {
        let client = setup_reconstruct_client().await;
        let peer_lid = "236395184570386@lid";
        let web_msg = make_web_msg(peer_lid, false, "LID_DM_PDO_1", None);

        let info = client
            .message_info_from_web_message_info(&web_msg)
            .await
            .unwrap();

        assert_eq!(info.source.chat.to_string(), peer_lid);
        assert_eq!(info.source.sender.to_string(), peer_lid);
        assert!(!info.source.is_group);
        assert!(!info.source.is_from_me);
    }

    /// fromMe LID DM: the response has no participant (WA Web omits it when
    /// fromMe), so the reconstructed sender must come from the device's own
    /// PN, not from the LID remote_jid.
    #[tokio::test]
    async fn test_reconstruct_lid_migrated_dm_from_me_uses_own_pn() {
        let client = setup_reconstruct_client().await;
        let peer_lid = "236395184570386@lid";
        let web_msg = make_web_msg(peer_lid, true, "LID_DM_FROM_ME_1", None);

        let info = client
            .message_info_from_web_message_info(&web_msg)
            .await
            .unwrap();

        // No own PN configured on a fresh test client, so sender falls back
        // to `remote_jid`. The point is that the participant-less fromMe
        // path reconstructs without panic.
        assert_eq!(info.source.chat.to_string(), peer_lid);
        assert!(info.source.is_from_me);
    }
}
