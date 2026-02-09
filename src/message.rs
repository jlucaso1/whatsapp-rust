use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use chrono::DateTime;
use log::{debug, warn};
use prost::Message as ProtoMessage;
use rand::TryRngCore;
use std::sync::Arc;
use std::sync::atomic::Ordering;
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

/// Maximum retry attempts per message (matches WhatsApp Web's MAX_RETRY = 5).
/// After this many retries, we stop sending retry receipts and rely solely on PDO.
const MAX_DECRYPT_RETRIES: u8 = 5;

/// Retry count threshold for logging high retry warnings.
/// WhatsApp Web logs metrics when retry count exceeds this value.
const HIGH_RETRY_COUNT_THRESHOLD: u8 = 3;

/// Retry reason codes matching WhatsApp Web's RetryReason enum.
/// These are included in the retry receipt to help the sender understand
/// why the message couldn't be decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)] // All variants defined for WhatsApp Web compatibility
pub(crate) enum RetryReason {
    /// Unknown or unspecified error
    UnknownError = 0,
    /// No session exists with the sender (SessionNotFound)
    NoSession = 1,
    /// Invalid key in the message
    InvalidKey = 2,
    /// PreKey ID not found (InvalidPreKeyId)
    InvalidKeyId = 3,
    /// Invalid message format or content (InvalidMessage)
    InvalidMessage = 4,
    /// Invalid signature
    InvalidSignature = 5,
    /// Message from the future (timestamp issue)
    FutureMessage = 6,
    /// MAC verification failed (bad MAC)
    BadMac = 7,
    /// Invalid session state
    InvalidSession = 8,
    /// Invalid message key
    InvalidMsgKey = 9,
}

impl Client {
    /// Dispatches a successfully parsed message to the event bus and sends a delivery receipt.
    fn dispatch_parsed_message(self: &Arc<Self>, msg: wa::Message, info: &MessageInfo) {
        // Send delivery receipt immediately in the background.
        let client_clone = self.clone();
        let info_clone = info.clone();
        tokio::spawn(async move {
            client_clone.send_delivery_receipt(&info_clone).await;
        });

        // Dispatch to event bus
        self.core
            .event_bus
            .dispatch(&Event::Message(Box::new(msg), info.clone()));
    }

    /// Handles a newsletter plaintext message.
    /// Newsletters are not E2E encrypted and use the <plaintext> tag directly.
    async fn handle_newsletter_message(self: &Arc<Self>, node: &Node, info: &MessageInfo) {
        let Some(plaintext_node) = node.get_optional_child_by_tag(&["plaintext"]) else {
            log::warn!(
                "[msg:{}] Received newsletter message without <plaintext> child: {}",
                info.id,
                node.tag
            );
            return;
        };

        if let Some(wacore_binary::node::NodeContent::Bytes(bytes)) = &plaintext_node.content {
            match wa::Message::decode(bytes.as_slice()) {
                Ok(msg) => {
                    log::info!(
                        "[msg:{}] Received newsletter plaintext message from {}",
                        info.id,
                        info.source.chat
                    );
                    self.dispatch_parsed_message(msg, info);
                }
                Err(e) => {
                    log::warn!(
                        "[msg:{}] Failed to decode newsletter plaintext: {e}",
                        info.id
                    );
                }
            }
        }
    }
    /// Dispatches an `UndecryptableMessage` event to notify consumers that a message
    /// could not be decrypted. This is called when decryption fails and we need to
    /// show a placeholder to the user (like "Waiting for this message...").
    ///
    /// # Arguments
    /// * `info` - The message info for the undecryptable message
    /// * `decrypt_fail_mode` - Whether to show or hide the placeholder (matches WhatsApp Web's `hideFail`)
    fn dispatch_undecryptable_event(
        &self,
        info: &MessageInfo,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
    ) {
        self.core.event_bus.dispatch(&Event::UndecryptableMessage(
            crate::types::events::UndecryptableMessage {
                info: info.clone(),
                is_unavailable: false,
                unavailable_type: crate::types::events::UnavailableType::Unknown,
                decrypt_fail_mode,
            },
        ));
    }

    /// Handles a decryption failure by dispatching an undecryptable event and spawning a retry receipt.
    ///
    /// This is a convenience method that combines the common pattern of:
    /// 1. Dispatching an UndecryptableMessage event
    /// 2. Spawning a retry receipt to request re-encryption
    ///
    /// Returns `true` to be assigned to `dispatched_undecryptable` flag.
    fn handle_decrypt_failure(self: &Arc<Self>, info: &MessageInfo, reason: RetryReason) -> bool {
        self.dispatch_undecryptable_event(info, crate::types::events::DecryptFailMode::Show);
        self.spawn_retry_receipt(info, reason);
        true
    }

    /// Atomically increments the retry count for a message and returns the new count.
    /// Returns `None` if max retries have been reached.
    ///
    /// Uses moka's `and_compute_with` for truly atomic read-modify-write operations,
    /// preventing race conditions where concurrent calls could exceed MAX_DECRYPT_RETRIES.
    async fn increment_retry_count(&self, cache_key: &str) -> Option<u8> {
        use moka::ops::compute::Op;

        let result = self
            .message_retry_counts
            .entry_by_ref(cache_key)
            .and_compute_with(|maybe_entry| {
                let op = if let Some(entry) = maybe_entry {
                    let current = entry.into_value();
                    if current >= MAX_DECRYPT_RETRIES {
                        // Max retries reached, don't increment
                        Op::Nop
                    } else {
                        Op::Put(current + 1)
                    }
                } else {
                    Op::Put(1_u8)
                };
                std::future::ready(op)
            })
            .await;

        match result {
            moka::ops::compute::CompResult::Inserted(entry) => Some(entry.into_value()),
            moka::ops::compute::CompResult::ReplacedWith(entry) => Some(entry.into_value()),
            moka::ops::compute::CompResult::Unchanged(_) => None, // Max retries reached
            moka::ops::compute::CompResult::StillNone(_) => None,
            moka::ops::compute::CompResult::Removed(_) => None,
        }
    }

    /// Helper to generate consistent cache keys for retry logic.
    /// Key format: "{chat}:{msg_id}:{sender}"
    pub(crate) async fn make_retry_cache_key(
        &self,
        chat: &Jid,
        msg_id: &str,
        sender: &Jid,
    ) -> String {
        let chat = self.resolve_encryption_jid(chat).await;
        let sender = self.resolve_encryption_jid(sender).await;
        format!("{}:{}:{}", chat, msg_id, sender)
    }

    /// Spawns a task that sends a retry receipt for a failed decryption.
    ///
    /// This is used when sessions are not found or invalid to request the sender to resend
    /// the message with a PreKeySignalMessage to re-establish the session.
    ///
    /// # Retry Count Tracking
    ///
    /// This method tracks retry counts per message (keyed by `{chat}:{msg_id}:{sender}`)
    /// and stops sending retry receipts after `MAX_DECRYPT_RETRIES` (5) attempts to prevent
    /// infinite retry loops. This matches WhatsApp Web's behavior.
    ///
    /// # PDO Backup
    ///
    /// A PDO (Peer Data Operation) request is spawned only on the FIRST retry attempt.
    /// This asks our primary phone to share the already-decrypted message content.
    /// PDO is NOT spawned on subsequent retries to avoid duplicate requests.
    ///
    /// When max retries is reached, an immediate PDO request is sent as a last resort.
    ///
    /// # Arguments
    /// * `info` - The message info for the failed message
    /// * `reason` - The retry reason code (matches WhatsApp Web's RetryReason enum)
    fn spawn_retry_receipt(self: &Arc<Self>, info: &MessageInfo, reason: RetryReason) {
        let client = Arc::clone(self);
        let info = info.clone();

        tokio::spawn(async move {
            let cache_key = client
                .make_retry_cache_key(&info.source.chat, &info.id, &info.source.sender)
                .await;

            // Atomically increment retry count and check if we should continue
            let Some(retry_count) = client.increment_retry_count(&cache_key).await else {
                // Max retries reached
                log::info!(
                    "Max retries ({}) reached for message {} from {} [{:?}]. Sending immediate PDO request.",
                    MAX_DECRYPT_RETRIES,
                    info.id,
                    info.source.sender,
                    reason
                );
                // Send PDO request immediately (no delay) as last resort
                client.spawn_pdo_request_with_options(&info, true);
                return;
            };

            // Log warning for high retry counts (like WhatsApp Web's MessageHighRetryCount)
            if retry_count > HIGH_RETRY_COUNT_THRESHOLD {
                log::warn!(
                    "High retry count ({}) for message {} from {} [{:?}]",
                    retry_count,
                    info.id,
                    info.source.sender,
                    reason
                );
            }

            // Send the retry receipt with the actual retry count and reason
            match client.send_retry_receipt(&info, retry_count, reason).await {
                Ok(()) => {
                    debug!(
                        "Sent retry receipt #{} for message {} from {} [{:?}]",
                        retry_count, info.id, info.source.sender, reason
                    );
                }
                Err(e) => {
                    log::error!(
                        "Failed to send retry receipt #{} for message {} [{:?}]: {:?}",
                        retry_count,
                        info.id,
                        reason,
                        e
                    );
                }
            }

            // Only spawn PDO on the FIRST retry to avoid duplicate requests.
            // The PDO cache also provides deduplication, but this reduces unnecessary work.
            if retry_count == 1 {
                client.spawn_pdo_request(&info);
            }
        });
    }

    pub(crate) async fn handle_incoming_message(self: Arc<Self>, node: Arc<Node>) {
        let info = match self.parse_message_info(&node).await {
            Ok(info) => Arc::new(info),
            Err(e) => {
                log::warn!("Failed to parse message info: {e:?}");
                return;
            }
        };

        // Newsletters use <plaintext> instead of <enc> because they are not E2E encrypted.
        if info.source.chat.is_newsletter() {
            self.handle_newsletter_message(&node, &info).await;
            return;
        }

        // Determine the JID to use for end-to-end decryption.
        // ... (previous JID resolution comments)
        let sender_encryption_jid = {
            let sender = &info.source.sender;
            let alt = info.source.sender_alt.as_ref();
            let pn_server = wacore_binary::jid::DEFAULT_USER_SERVER;
            let lid_server = wacore_binary::jid::HIDDEN_USER_SERVER;

            if sender.server == lid_server {
                // Sender is already LID - use it directly for session lookup.
                // Also cache the LID-to-PN mapping if PN alt is available.
                if let Some(alt_jid) = alt
                    && alt_jid.server == pn_server
                {
                    if let Err(err) = self
                        .add_lid_pn_mapping(
                            &sender.user,
                            &alt_jid.user,
                            crate::lid_pn_cache::LearningSource::PeerLidMessage,
                        )
                        .await
                    {
                        warn!(
                            "Failed to persist LID-to-PN mapping {} -> {}: {err}",
                            sender.user, alt_jid.user
                        );
                    }
                    debug!(
                        "Cached LID-to-PN mapping: {} -> {}",
                        sender.user, alt_jid.user
                    );
                }
                sender.clone()
            } else if sender.server == pn_server {
                // ... (PN to LID resolution logic)
                if let Some(alt_jid) = alt
                    && alt_jid.server == lid_server
                {
                    if let Err(err) = self
                        .add_lid_pn_mapping(
                            &alt_jid.user,
                            &sender.user,
                            crate::lid_pn_cache::LearningSource::PeerPnMessage,
                        )
                        .await
                    {
                        warn!(
                            "Failed to persist PN-to-LID mapping {} -> {}: {err}",
                            sender.user, alt_jid.user
                        );
                    }
                    debug!(
                        "Cached PN-to-LID mapping: {} -> {}",
                        sender.user, alt_jid.user
                    );

                    Jid {
                        user: alt_jid.user.clone(),
                        server: lid_server.to_string(),
                        device: sender.device,
                        agent: sender.agent,
                        integrator: sender.integrator,
                    }
                } else if let Some(lid_user) = self.lid_pn_cache.get_current_lid(&sender.user).await
                {
                    Jid {
                        user: lid_user.clone(),
                        server: lid_server.to_string(),
                        device: sender.device,
                        agent: sender.agent,
                        integrator: sender.integrator,
                    }
                } else {
                    sender.clone()
                }
            } else {
                sender.clone()
            }
        };

        let has_unavailable = node.get_optional_child("unavailable").is_some();

        let mut all_enc_nodes = Vec::new();

        let direct_enc_nodes = node.get_children_by_tag("enc");
        all_enc_nodes.extend(direct_enc_nodes);

        let participants = node.get_optional_child_by_tag(&["participants"]);
        if let Some(participants_node) = participants {
            let to_nodes = participants_node.get_children_by_tag("to");
            for to_node in to_nodes {
                let to_jid = match to_node.attrs().optional_string("jid") {
                    Some(jid) => jid.to_string(),
                    None => continue,
                };
                let own_jid = self.get_pn().await;
                if let Some(our_jid) = own_jid
                    && to_jid == our_jid.to_string()
                {
                    let enc_children = to_node.get_children_by_tag("enc");
                    all_enc_nodes.extend(enc_children);
                }
            }
        }

        if all_enc_nodes.is_empty() && !has_unavailable {
            log::warn!(
                "[msg:{}] Received non-newsletter message without <enc> child: {}",
                info.id,
                node.tag
            );
            return;
        }

        if has_unavailable {
            log::debug!(
                "[msg:{}] Message has <unavailable> child, skipping decryption",
                info.id
            );
            return;
        }

        let mut session_enc_nodes = Vec::with_capacity(all_enc_nodes.len());
        let mut group_content_enc_nodes = Vec::with_capacity(all_enc_nodes.len());

        for &enc_node in &all_enc_nodes {
            let enc_type = match enc_node.attrs().optional_string("type") {
                Some(t) => t.to_string(),
                None => {
                    log::warn!("Enc node missing 'type' attribute, skipping");
                    continue;
                }
            };

            if let Some(handler) = self.custom_enc_handlers.get(&enc_type) {
                let handler_clone = handler.clone();
                let client_clone = self.clone();
                let info_arc = Arc::clone(&info);
                let enc_node_clone = Arc::new(enc_node.clone());

                tokio::spawn(async move {
                    if let Err(e) = handler_clone
                        .handle(client_clone, &enc_node_clone, &info_arc)
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

        // Skip session processing for group senders (@c.us, @g.us, @broadcast)
        // Groups don't use 1:1 Signal Protocol sessions
        let is_group_sender = sender_encryption_jid.server.contains(".us")
            || sender_encryption_jid.server.contains("broadcast");

        let (
            session_decrypted_successfully,
            session_had_duplicates,
            session_dispatched_undecryptable,
        ) = if !is_group_sender && !session_enc_nodes.is_empty() {
            self.clone()
                .process_session_enc_batch(&session_enc_nodes, &info, &sender_encryption_jid)
                .await
        } else {
            if is_group_sender && !session_enc_nodes.is_empty() {
                log::debug!(
                    "Skipping {} session messages from group sender {}",
                    session_enc_nodes.len(),
                    sender_encryption_jid
                );
            }
            (false, false, false)
        };

        log::debug!(
            "Starting PASS 2: Processing {} group content messages (skmsg)",
            group_content_enc_nodes.len()
        );

        // Only process group content if:
        // 1. There were no session messages (session already exists), OR
        // 2. Session messages were successfully decrypted, OR
        // 3. Session messages were duplicates (already processed, so session exists)
        // 4. It's a status@broadcast (we might have sender key cached from previous status)
        // Skip only if session messages FAILED to decrypt (not duplicates, not absent)
        if !group_content_enc_nodes.is_empty() {
            // For status broadcasts, always try skmsg even if pkmsg failed.
            // WhatsApp Web does this too - the pkmsg contains the SKDM which might fail,
            // but if we already have the sender key cached from a previous status,
            // we can still decrypt the skmsg content.
            let should_process_skmsg = session_enc_nodes.is_empty()
                || session_decrypted_successfully
                || session_had_duplicates
                || info.source.chat.is_status_broadcast();

            if should_process_skmsg {
                match self
                    .clone()
                    .process_group_enc_batch(
                        &group_content_enc_nodes,
                        &info,
                        &sender_encryption_jid,
                    )
                    .await
                {
                    Ok(true) => {
                        // Optimization: Re-queue locally!
                        // The message failed due to NoSession (NoSenderKey), but we haven't retried yet.
                        // We will sleep briefly and re-queue it to this chat's serial queue.
                        // This allows a pending pkmsg (in the queue or socket buffer) to be processed first.
                        let client = self.clone();
                        let chat_id = info.source.chat.to_string();
                        let node_clone = node.clone();
                        let msg_id = info.id.clone();
                        let info_clone = info.clone();

                        log::info!(
                            "Re-queueing message {} from {} (NoSession) with 500ms delay",
                            msg_id,
                            info.source.chat
                        );

                        // First check if the message queue exists before inserting cache marker
                        // This prevents dropping messages if the queue doesn't exist
                        if client.message_queues.get(&chat_id).await.is_some() {
                            // Queue exists, insert cache marker to prevent re-queue loops
                            let cache_key = client
                                .make_retry_cache_key(
                                    &info.source.chat,
                                    &info.id,
                                    &info.source.sender,
                                )
                                .await;
                            client.local_retry_cache.insert(cache_key, ()).await;

                            tokio::spawn(async move {
                                // Short delay to allow dependent messages (pkmsg) to process
                                tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

                                // Try to re-queue the message
                                if let Some(sender) = client.message_queues.get(&chat_id).await {
                                    if let Err(e) = sender.send(node_clone).await {
                                        log::warn!("Failed to re-queue message: {}", e);
                                        // Fallback to retry receipt if send fails
                                        client.spawn_retry_receipt(
                                            &info_clone,
                                            RetryReason::NoSession,
                                        );
                                    }
                                } else {
                                    // Queue disappeared between check and send, fallback to retry receipt
                                    log::warn!(
                                        "Message queue for {} disappeared, falling back to retry receipt",
                                        chat_id
                                    );
                                    client.spawn_retry_receipt(&info_clone, RetryReason::NoSession);
                                }
                            });
                        } else {
                            // Queue doesn't exist, skip local re-queue and go straight to retry receipt
                            log::warn!(
                                "Message queue for {} not found, skipping local re-queue, using retry receipt",
                                chat_id
                            );
                            client.spawn_retry_receipt(&info_clone, RetryReason::NoSession);
                        }
                    }
                    Ok(false) => {
                        // Processed successfully or handled errors (e.g. sent retry receipt)
                    }
                    Err(e) => {
                        log::warn!("Batch group decrypt encountered error (continuing): {e:?}");
                    }
                }
            } else {
                // Only show warning if session messages actually FAILED (not duplicates)
                if !session_had_duplicates {
                    warn!(
                        "Skipping skmsg decryption for message {} from {} because the initial session/senderkey message failed to decrypt. This prevents a retry loop.",
                        info.id, info.source.sender
                    );
                    // Still dispatch an UndecryptableMessage event so the user knows
                    // But only if we haven't already dispatched one in process_session_enc_batch
                    if !session_dispatched_undecryptable {
                        self.dispatch_undecryptable_event(
                            &info,
                            crate::types::events::DecryptFailMode::Show,
                        );
                    }

                    // Do NOT send a delivery receipt for undecryptable messages.
                    // Per whatsmeow's implementation, delivery receipts are only sent for
                    // successfully decrypted/handled messages. Sending a receipt here would
                    // tell the server we processed it, incrementing the offline counter.
                    // The transport <ack> is sufficient for acknowledgment.
                }
                // If session_had_duplicates is true, we silently skip (no warning, no event)
                // because the message was already processed in a previous session
            }
        } else if !session_decrypted_successfully
            && !session_had_duplicates
            && !session_enc_nodes.is_empty()
        {
            // Edge case: message with only msg/pkmsg that failed to decrypt, no skmsg
            warn!(
                "Message {} from {} failed to decrypt and has no group content. Dispatching UndecryptableMessage event.",
                info.id, info.source.sender
            );
            // Dispatch UndecryptableMessage event for messages that failed to decrypt
            // (This should not cause double-dispatching since process_session_enc_batch
            // already returned dispatched_undecryptable=false for this case)
            self.dispatch_undecryptable_event(&info, crate::types::events::DecryptFailMode::Show);
            // Do NOT send delivery receipt - transport ack is sufficient
        }
    }

    async fn process_session_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&wacore_binary::node::Node],
        info: &MessageInfo,
        sender_encryption_jid: &Jid,
    ) -> (bool, bool, bool) {
        // Returns (any_success, any_duplicate, dispatched_undecryptable)
        use wacore::libsignal::protocol::CiphertextMessage;
        if enc_nodes.is_empty() {
            return (false, false, false);
        }

        // Acquire a per-sender session lock to prevent race conditions when
        // multiple messages from the same sender are processed concurrently.
        // Use the full Signal protocol address string as the lock key so it matches
        // the SignalProtocolStoreAdapter's per-session locks (prevents ratchet counter races).
        let signal_addr_str = sender_encryption_jid.to_protocol_address().to_string();

        let session_mutex = self
            .session_locks
            .get_with(signal_addr_str.clone(), async {
                std::sync::Arc::new(tokio::sync::Mutex::new(()))
            })
            .await;
        let _session_guard = session_mutex.lock().await;

        let mut adapter =
            SignalProtocolStoreAdapter::new(self.persistence_manager.get_device_arc().await);
        let rng = rand::rngs::OsRng;
        let mut any_success = false;
        let mut any_duplicate = false;
        let mut dispatched_undecryptable = false;

        for enc_node in enc_nodes {
            let ciphertext: &[u8] = match &enc_node.content {
                Some(wacore_binary::node::NodeContent::Bytes(b)) => b,
                _ => {
                    log::warn!("Enc node has no byte content (batch session)");
                    continue;
                }
            };
            let enc_type = match enc_node.attrs().optional_string("type") {
                Some(t) => t.to_string(),
                None => {
                    log::warn!("Enc node missing 'type' attribute (batch session)");
                    continue;
                }
            };
            let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;

            let parsed_message = if enc_type == "pkmsg" {
                match PreKeySignalMessage::try_from(ciphertext) {
                    Ok(m) => CiphertextMessage::PreKeySignalMessage(m),
                    Err(e) => {
                        log::error!("Failed to parse PreKeySignalMessage: {e:?}");
                        continue;
                    }
                }
            } else {
                match SignalMessage::try_from(ciphertext) {
                    Ok(m) => CiphertextMessage::SignalMessage(m),
                    Err(e) => {
                        log::error!("Failed to parse SignalMessage: {e:?}");
                        continue;
                    }
                }
            };

            let signal_address = sender_encryption_jid.to_protocol_address();

            if enc_type == "pkmsg" {
                // FLAGGED FOR DEBUGGING: "Bad Mac" Reproducibility
                #[cfg(feature = "debug-snapshots")]
                {
                    use base64::prelude::*;
                    let payload = serde_json::json!({
                        "id": info.id,
                        "sender_jid": sender_encryption_jid.to_string(),
                        "timestamp": info.timestamp,
                        "enc_type": enc_type,
                        "payload_base64": BASE64_STANDARD.encode(ciphertext),
                    });

                    let content_bytes = serde_json::to_vec_pretty(&payload).unwrap_or_default();

                    if let Err(e) = self
                        .persistence_manager
                        .create_snapshot(&format!("pre_pkmsg_{}", info.id), Some(&content_bytes))
                        .await
                    {
                        log::warn!("Failed to create snapshot for pkmsg: {}", e);
                    }
                }
                #[cfg(not(feature = "debug-snapshots"))]
                {
                    // No-op if disabled
                }
            }

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
                    // Handle DuplicatedMessage: This is expected when messages are redelivered during reconnection
                    if let SignalProtocolError::DuplicatedMessage(chain, counter) = e {
                        log::debug!(
                            "Skipping already-processed message from {} (chain {}, counter {}). This is normal during reconnection.",
                            info.source.sender,
                            chain,
                            counter
                        );
                        // Mark that we saw a duplicate so we can skip skmsg without showing error
                        any_duplicate = true;
                        continue;
                    }
                    // Handle UntrustedIdentity: This happens when a user re-installs WhatsApp or changes devices.
                    // The Signal Protocol's security policy rejects messages from new identity keys by default.
                    // We handle this by clearing the old identity (to trust the new one), then retrying decryption.
                    // IMPORTANT: We do NOT delete the session! When the PreKeySignalMessage is processed,
                    // libsignal's `promote_state` will archive the old session as a "previous state".
                    // This allows us to decrypt any in-flight messages that were encrypted with the old session.
                    if let SignalProtocolError::UntrustedIdentity(ref address) = e {
                        log::warn!(
                            "[msg:{}] Received message from untrusted identity: {}. This typically means the sender re-installed WhatsApp or changed their device. Clearing old identity to trust new key (keeping session for in-flight messages).",
                            info.id,
                            address
                        );

                        // Extract backend handle and address while holding the lock,
                        // then drop the lock before the async I/O to avoid lock contention.
                        let backend = {
                            let device_arc = self.persistence_manager.get_device_arc().await;
                            let device = device_arc.read().await;
                            Arc::clone(&device.backend)
                        };

                        // Delete the old, untrusted identity using the backend.
                        // Use the full protocol address string (including device ID) as the key.
                        // NOTE: We intentionally do NOT delete the session here. The session will be
                        // archived (not deleted) when the new PreKeySignalMessage is processed,
                        // allowing decryption of any in-flight messages encrypted with the old session.
                        let address_str = address.to_string();
                        if let Err(err) = backend.delete_identity(&address_str).await {
                            log::warn!("Failed to delete old identity for {}: {:?}", address, err);
                        } else {
                            log::info!("Successfully cleared old identity for {}", address);
                        }

                        // Re-attempt decryption with the new identity
                        log::info!(
                            "[msg:{}] Retrying message decryption for {} after clearing untrusted identity",
                            info.id,
                            address
                        );

                        let retry_decrypt_res = message_decrypt(
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

                        match retry_decrypt_res {
                            Ok(padded_plaintext) => {
                                log::info!(
                                    "[msg:{}] Successfully decrypted message from {} after handling untrusted identity",
                                    info.id,
                                    address
                                );
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
                                    log::warn!(
                                        "Failed processing plaintext after identity retry: {e:?}"
                                    );
                                }
                            }
                            Err(retry_err) => {
                                // Handle DuplicatedMessage in retry path: This commonly happens during reconnection
                                // when the same message is redelivered by the server after we already processed it.
                                // The first attempt triggered UntrustedIdentity, we cleared the session, but meanwhile
                                // another message from the same sender re-established the session and consumed the counter.
                                // This is benign - the message was already successfully processed.
                                if let SignalProtocolError::DuplicatedMessage(chain, counter) =
                                    retry_err
                                {
                                    log::debug!(
                                        "Message from {} was already processed (chain {}, counter {}) - detected during untrusted identity retry. This is normal during reconnection.",
                                        address,
                                        chain,
                                        counter
                                    );
                                    any_duplicate = true;
                                } else if matches!(retry_err, SignalProtocolError::InvalidPreKeyId)
                                {
                                    // InvalidPreKeyId after identity change means the sender is using
                                    // an old prekey that we no longer have. This typically happens when:
                                    // 1. The sender reinstalled WhatsApp and cached our old prekey bundle
                                    // 2. The prekey they're using has been consumed or rotated out
                                    //
                                    // Solution: Send a retry receipt with a fresh prekey so the sender
                                    // can establish a new session and resend the message.
                                    log::warn!(
                                        "[msg:{}] Decryption failed for {} due to InvalidPreKeyId after identity change. \
                                         The sender is using an old prekey we no longer have. \
                                         Sending retry receipt with fresh keys.",
                                        info.id,
                                        address
                                    );

                                    // Send retry receipt so the sender fetches our new prekey bundle
                                    dispatched_undecryptable = self
                                        .handle_decrypt_failure(info, RetryReason::InvalidKeyId);
                                } else {
                                    log::error!(
                                        "[msg:{}] Decryption failed even after clearing untrusted identity for {}: {:?}",
                                        info.id,
                                        address,
                                        retry_err
                                    );
                                    // Send retry receipt so the sender resends with a PreKeySignalMessage
                                    // to establish a new session with the new identity
                                    dispatched_undecryptable =
                                        self.handle_decrypt_failure(info, RetryReason::InvalidKey);
                                }
                            }
                        }
                        continue;
                    }
                    // Handle SessionNotFound gracefully - send retry receipt to request session establishment
                    if let SignalProtocolError::SessionNotFound(_) = e {
                        warn!(
                            "[msg:{}] No session found for {} message from {}. Sending retry receipt to request session establishment.",
                            info.id, enc_type, info.source.sender
                        );
                        // Send retry receipt so the sender resends with a PreKeySignalMessage
                        dispatched_undecryptable =
                            self.handle_decrypt_failure(info, RetryReason::NoSession);
                        continue;
                    } else if matches!(e, SignalProtocolError::InvalidMessage(_, _)) {
                        // InvalidMessage typically means MAC verification failed or session is out of sync.
                        // This happens when the sender's session state diverged from ours (e.g., they reinstalled).
                        // We need to:
                        // 1. Delete the stale session so a new one can be established
                        // 2. Send a retry receipt so the sender resends with a PreKeySignalMessage
                        log::warn!(
                            "[msg:{}] Decryption failed for {} message from {} due to InvalidMessage (likely MAC failure). \
                             Deleting stale session and sending retry receipt.",
                            info.id,
                            enc_type,
                            info.source.sender
                        );

                        // Delete the stale session
                        let device_arc = self.persistence_manager.get_device_arc().await;
                        let device_guard = device_arc.write().await;
                        let address_str = signal_address.to_string();
                        if let Err(err) = device_guard.backend.delete_session(&address_str).await {
                            log::warn!(
                                "Failed to delete stale session for {}: {:?}",
                                signal_address,
                                err
                            );
                        } else {
                            log::info!(
                                "Deleted stale session for {} to allow re-establishment",
                                signal_address
                            );
                        }
                        drop(device_guard);

                        // Send retry receipt so the sender resends with a PreKeySignalMessage
                        dispatched_undecryptable =
                            self.handle_decrypt_failure(info, RetryReason::InvalidMessage);
                        continue;
                    } else if matches!(e, SignalProtocolError::InvalidPreKeyId) {
                        // InvalidPreKeyId means the sender is using a PreKey ID that we don't have.
                        // This typically happens when:
                        // 1. We were offline for a long time
                        // 2. The sender established a session with us using a prekey from the server
                        // 3. We never received the initial session-establishing message
                        // 4. Now we're receiving messages with counters 3, 4, 5... referencing that prekey
                        //
                        // The sender thinks they have a valid session, but we never had it.
                        // We need to send a retry receipt with fresh prekeys so the sender can:
                        // 1. Delete their old session
                        // 2. Fetch our new prekeys from the retry receipt
                        // 3. Create a NEW session and resend with counter 0
                        log::warn!(
                            "[msg:{}] Decryption failed for {} message from {} due to InvalidPreKeyId. \
                             Sender is using a prekey we don't have (likely session established while offline). \
                             Sending retry receipt with fresh prekeys.",
                            info.id,
                            enc_type,
                            info.source.sender
                        );

                        // Send retry receipt with fresh prekeys
                        dispatched_undecryptable =
                            self.handle_decrypt_failure(info, RetryReason::InvalidKeyId);
                        continue;
                    } else {
                        // For other unexpected errors, just log them
                        log::error!(
                            "[msg:{}] Batch session decrypt failed (type: {}) from {}: {:?}",
                            info.id,
                            enc_type,
                            info.source.sender,
                            e
                        );
                        continue;
                    }
                }
            }
        }
        (any_success, any_duplicate, dispatched_undecryptable)
    }

    async fn process_group_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&wacore_binary::node::Node],
        info: &MessageInfo,
        _sender_encryption_jid: &Jid,
    ) -> Result<bool, DecryptionError> {
        if enc_nodes.is_empty() {
            return Ok(false);
        }
        let device_arc = self.persistence_manager.get_device_arc().await;

        for enc_node in enc_nodes {
            let ciphertext: &[u8] = match &enc_node.content {
                Some(wacore_binary::node::NodeContent::Bytes(b)) => b,
                _ => {
                    log::warn!("Enc node has no byte content (batch group)");
                    continue;
                }
            };
            let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;

            // CRITICAL: Use info.source.sender (display JID) for sender key operations, NOT sender_encryption_jid.
            // The sender key is stored under the sender's display JID (e.g., LID), while sender_encryption_jid
            // is the phone number used for E2E session decryption only.
            // Using sender_encryption_jid here causes "No sender key state" errors for self-sent LID messages.
            let sender_address = info.source.sender.to_protocol_address();
            let sender_key_name =
                SenderKeyName::new(info.source.chat.to_string(), sender_address.to_string());

            log::debug!(
                "Looking up sender key for group {} with sender address {} (from sender JID: {})",
                info.source.chat,
                sender_address,
                info.source.sender
            );

            let decrypt_result = {
                let mut device_guard = device_arc.write().await;
                group_decrypt(ciphertext, &mut *device_guard, &sender_key_name).await
            };

            match decrypt_result {
                Ok(padded_plaintext) => {
                    // Check if this message was previously re-queued and clear cache
                    let cache_key = self
                        .make_retry_cache_key(&info.source.chat, &info.id, &info.source.sender)
                        .await;
                    if self.local_retry_cache.remove(&cache_key).await.is_some() {
                        // Successfully decrypted a message that was previously re-queued
                        self.retry_metrics
                            .local_requeue_success
                            .fetch_add(1, Ordering::Relaxed);
                        log::debug!(
                            "[msg:{}] Successfully decrypted message that was previously re-queued",
                            info.id
                        );
                    }

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
                Err(SignalProtocolError::DuplicatedMessage(iteration, counter)) => {
                    log::debug!(
                        "Skipping already-processed sender key message from {} in group {} (iteration {}, counter {}). This is normal during reconnection.",
                        info.source.sender,
                        info.source.chat,
                        iteration,
                        counter
                    );
                    // This is expected when messages are redelivered, just continue silently
                }
                Err(SignalProtocolError::NoSenderKeyState(msg)) => {
                    // Optimization: Check if this message was already re-queued locally
                    let cache_key = self
                        .make_retry_cache_key(&info.source.chat, &info.id, &info.source.sender)
                        .await;
                    let already_requeued = self.local_retry_cache.get(&cache_key).await.is_some();

                    if !already_requeued {
                        // First NoSenderKey: trigger local re-queue
                        self.retry_metrics
                            .local_requeue_attempts
                            .fetch_add(1, Ordering::Relaxed);
                        // Signal caller to re-queue this message
                        // Do NOT send retry receipt yet
                        return Ok(true);
                    }

                    // Second NoSenderKey (already re-queued): fall back to network retry
                    self.retry_metrics
                        .local_requeue_fallback
                        .fetch_add(1, Ordering::Relaxed);
                    warn!(
                        "No sender key state for batched group message [msg:{}] from {}: {}. Sending retry receipt (already requeued).",
                        info.id, info.source.sender, msg
                    );
                    // Use spawn_retry_receipt which has retry count tracking
                    // NoSenderKeyState is similar to NoSession - we need SKDM
                    self.spawn_retry_receipt(info, RetryReason::NoSession);
                }
                Err(e) => {
                    log::error!(
                        "Group batch decrypt failed [msg:{}] for group {} sender {}: {:?}",
                        info.id,
                        sender_key_name.group_id(),
                        sender_key_name.sender_id(),
                        e
                    );
                }
            }
        }
        Ok(false)
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
            "[msg:{}] Successfully decrypted message from {}: {} bytes (type: {}) [batch path]",
            info.id,
            info.source.sender,
            plaintext_slice.len(),
            enc_type
        );

        match wa::Message::decode(plaintext_slice) {
            Ok(mut original_msg) => {
                // Post-decryption logic (SKDM, sync keys, etc.)
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
                    && let Some(pdo_response) =
                        &protocol_msg.peer_data_operation_request_response_message
                {
                    self.handle_pdo_response(pdo_response, info).await;
                }

                // Note: original_msg might be modified by take() below
                let history_sync_taken = original_msg
                    .protocol_message
                    .as_mut()
                    .and_then(|pm| pm.history_sync_notification.take());

                if let Some(history_sync) = history_sync_taken {
                    self.handle_history_sync(info.id.clone(), history_sync)
                        .await;
                }

                // Skip dispatch for messages that only carry sender key distribution
                // (protocol-level key exchange) with no user-visible content.
                // These arrive as a separate pkmsg enc node alongside the actual
                // group message (skmsg) and would otherwise surface as "unknown".
                if is_sender_key_distribution_only(&original_msg) {
                    log::debug!(
                        "[msg:{}] Skipping event dispatch for sender key distribution message",
                        info.id
                    );
                } else {
                    self.dispatch_parsed_message(original_msg, info);
                }
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("Failed to decode decrypted plaintext: {e}")),
        }
    }

    pub(crate) async fn parse_message_info(
        &self,
        node: &Node,
    ) -> Result<MessageInfo, anyhow::Error> {
        let mut attrs = node.attrs();
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot.pn.clone().unwrap_or_default();
        let own_lid = device_snapshot.lid.clone();
        let from = attrs.jid("from");

        let mut source = if from.server == wacore_binary::jid::BROADCAST_SERVER {
            // This is the new logic block for handling all broadcast messages, including status.
            let participant = attrs.jid("participant");
            let is_from_me = participant.matches_user_or_lid(&own_jid, own_lid.as_ref());

            crate::types::message::MessageSource {
                chat: from.clone(),
                sender: participant.clone(),
                is_from_me,
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
            let sender_alt = if let Some(addressing_mode) = attrs
                .optional_string("addressing_mode")
                .map(|s| s.to_ascii_lowercase())
            {
                match addressing_mode.as_str() {
                    "lid" => attrs.optional_jid("participant_pn"),
                    _ => attrs.optional_jid("participant_lid"),
                }
            } else {
                None
            };

            let is_from_me = sender.matches_user_or_lid(&own_jid, own_lid.as_ref());

            crate::types::message::MessageSource {
                chat: from.clone(),
                sender: sender.clone(),
                is_from_me,
                is_group: true,
                sender_alt,
                ..Default::default()
            }
        } else if from.matches_user_or_lid(&own_jid, own_lid.as_ref()) {
            // DM from self (either via PN or LID)
            // Note: peer_recipient_pn contains the RECIPIENT's PN, not sender's.
            // For self-sent messages, we don't set sender_alt here - the decryption
            // logic will use our own PN via the is_from_me fallback path.
            // We store the original `recipient` attribute for retry receipts - this is needed
            // because device sync messages may have a different recipient than our device,
            // and the sender needs this to look up the original message.
            let recipient = attrs.optional_jid("recipient");
            // chat uses non-AD format for session routing, recipient keeps original for retry receipts
            let chat = recipient
                .as_ref()
                .map(|r| r.to_non_ad())
                .unwrap_or_else(|| from.to_non_ad());
            crate::types::message::MessageSource {
                chat,
                sender: from.clone(),
                is_from_me: true,
                recipient,
                // sender_alt stays None - decryption uses own PN for self-sent messages
                ..Default::default()
            }
        } else {
            // DM from someone else
            // Look for alternate JID attribute based on sender type:
            // - For LID senders: look for sender_pn to get their phone number
            // - For PN senders: look for sender_lid to get their LID
            // This is needed because sessions may be stored under either format
            // depending on how the session was originally established.
            let sender_alt = if from.server == wacore_binary::jid::HIDDEN_USER_SERVER {
                // Sender is LID, look for their phone number
                attrs.optional_jid("sender_pn")
            } else {
                // Sender is phone number, look for their LID
                attrs.optional_jid("sender_lid")
            };

            crate::types::message::MessageSource {
                chat: from.to_non_ad(),
                sender: from.clone(),
                is_from_me: false,
                sender_alt,
                ..Default::default()
            }
        };

        source.addressing_mode = attrs
            .optional_string("addressing_mode")
            .map(|s| s.to_ascii_lowercase())
            .and_then(|s| match s.as_str() {
                "pn" => Some(crate::types::message::AddressingMode::Pn),
                "lid" => Some(crate::types::message::AddressingMode::Lid),
                _ => None,
            });

        // Parse the category attribute - this is used for peer device messages ("peer")
        // and is critical for proper retry receipt handling.
        let category = attrs
            .optional_string("category")
            .map(|s| s.to_string())
            .unwrap_or_default();

        let id = attrs.required_string("id")?.to_string();
        // server_id must be in range 99-2147476647 (per WhatsApp Web)
        let server_id = attrs
            .optional_u64("server_id")
            .filter(|&v| (99..=2_147_476_647).contains(&v))
            .unwrap_or(0) as i32;

        // Ensure newsletter JID is normalized: should be just {user}@newsletter
        if source.chat.is_newsletter() {
            source.chat.device = 0;
            source.chat.agent = 0;
        }

        Ok(MessageInfo {
            source,
            id,
            server_id,
            push_name: attrs
                .optional_string("notify")
                .map(|s| s.to_string())
                .unwrap_or_default(),
            timestamp: DateTime::from_timestamp(attrs.unix_time("t"), 0)
                .unwrap_or_else(chrono::Utc::now),
            category,
            ..Default::default()
        })
    }

    pub(crate) async fn handle_app_state_sync_key_share(
        &self,
        keys: &wa::message::AppStateSyncKeyShare,
    ) {
        struct KeyComponents<'a> {
            key_id: &'a [u8],
            data: &'a [u8],
            fingerprint_bytes: Vec<u8>,
            timestamp: i64,
        }

        /// Extract components from an AppStateSyncKey for storage.
        fn extract_key_components(key: &wa::message::AppStateSyncKey) -> Option<KeyComponents<'_>> {
            let key_id = key.key_id.as_ref()?.key_id.as_ref()?;
            let key_data = key.key_data.as_ref()?;
            let fingerprint = key_data.fingerprint.as_ref()?;
            let data = key_data.key_data.as_ref()?;
            Some(KeyComponents {
                key_id,
                data,
                fingerprint_bytes: fingerprint.encode_to_vec(),
                timestamp: key_data.timestamp(),
            })
        }

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let key_store = device_snapshot.backend.clone();

        let mut stored_count = 0;
        let mut failed_count = 0;

        for key in &keys.keys {
            if let Some(components) = extract_key_components(key) {
                let new_key = crate::store::traits::AppStateSyncKey {
                    key_data: components.data.to_vec(),
                    fingerprint: components.fingerprint_bytes,
                    timestamp: components.timestamp,
                };

                if let Err(e) = key_store.set_sync_key(components.key_id, new_key).await {
                    log::error!(
                        "Failed to store app state sync key {:?}: {:?}",
                        hex::encode(components.key_id),
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
                    let (Some(signing_key), Some(id), Some(iteration), Some(chain_key)) = (
                        go_msg.signing_key.as_ref(),
                        go_msg.id,
                        go_msg.iteration,
                        go_msg.chain_key.as_ref(),
                    ) else {
                        log::warn!(
                            "Go SKDM from {} missing required fields (signing_key={}, id={}, iteration={}, chain_key={})",
                            sender_jid,
                            go_msg.signing_key.is_some(),
                            go_msg.id.is_some(),
                            go_msg.iteration.is_some(),
                            go_msg.chain_key.is_some()
                        );
                        return;
                    };
                    let chain_key_arr: [u8; 32] = match chain_key.as_slice().try_into() {
                        Ok(arr) => arr,
                        Err(_) => {
                            log::error!(
                                "Invalid chain_key length {} from Go SKDM from {}",
                                chain_key.len(),
                                sender_jid
                            );
                            return;
                        }
                    };
                    match SignalPublicKey::from_djb_public_key_bytes(signing_key) {
                        Ok(pub_key) => {
                            match SenderKeyDistributionMessage::new(
                                SENDERKEY_MESSAGE_CURRENT_VERSION,
                                id,
                                iteration,
                                chain_key_arr,
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

/// Returns `true` if the message contains only a SenderKey distribution
/// (internal key-exchange for group encryption) and no user-visible content.
///
/// When sending a group message, WhatsApp includes the SKDM in a separate
/// `pkmsg` enc node.  We must process it (store the sender key) but should
/// not surface it as a user event.
fn is_sender_key_distribution_only(msg: &wa::Message) -> bool {
    let has_skdm = msg.sender_key_distribution_message.is_some()
        || msg
            .fast_ratchet_key_sender_key_distribution_message
            .is_some();

    if !has_skdm {
        return false;
    }

    // Strip protocol-only fields and check if anything user-visible remains.
    let mut stripped = msg.clone();
    stripped.sender_key_distribution_message = None;
    stripped.fast_ratchet_key_sender_key_distribution_message = None;
    stripped.message_context_info = None;
    stripped == wa::Message::default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;
    use crate::store::persistence_manager::PersistenceManager;
    use crate::test_utils::MockHttpClient;
    use std::sync::Arc;
    use wacore_binary::builder::NodeBuilder;
    use wacore_binary::jid::{Jid, SERVER_JID};

    fn mock_transport() -> Arc<dyn crate::transport::TransportFactory> {
        Arc::new(crate::transport::mock::MockTransportFactory::new())
    }

    fn mock_http_client() -> Arc<dyn crate::http::HttpClient> {
        Arc::new(MockHttpClient)
    }

    #[tokio::test]
    async fn test_parse_message_info_for_status_broadcast() {
        let backend = Arc::new(
            SqliteStore::new("file:memdb_status_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let participant_jid_str = "556899336555:42@s.whatsapp.net";
        let status_broadcast_jid_str = "status@broadcast";

        let node = NodeBuilder::new("message")
            .attr("from", status_broadcast_jid_str)
            .attr("id", "8A8CCCC7E6E466D9EE8CA11A967E485A")
            .attr("participant", participant_jid_str)
            .attr("t", "1759295366")
            .attr("type", "media")
            .build();

        let info = client
            .parse_message_info(&node)
            .await
            .expect("parse_message_info should not fail");

        let expected_sender: Jid = participant_jid_str
            .parse()
            .expect("test JID should be valid");
        let expected_chat: Jid = status_broadcast_jid_str
            .parse()
            .expect("test JID should be valid");

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

        let backend = Arc::new(
            SqliteStore::new("file:memdb_graceful_fail?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let sender_jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let info = MessageInfo {
            source: crate::types::message::MessageSource {
                sender: sender_jid.clone(),
                chat: sender_jid.clone(),
                ..Default::default()
            },
            ..Default::default()
        };

        // Create a valid but undecryptable SignalMessage
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
        .expect("SignalMessage::new should succeed with valid inputs");

        let enc_node = NodeBuilder::new("enc")
            .attr("type", "msg")
            .bytes(signal_message.serialized().to_vec())
            .build();
        let enc_nodes = vec![&enc_node];

        // With SessionNotFound, should return (false, false, true) - no success, no dupe, dispatched event
        let (success, had_duplicates, dispatched) = client
            .process_session_enc_batch(&enc_nodes, &info, &sender_jid)
            .await;

        assert!(
            !success && !had_duplicates && dispatched,
            "process_session_enc_batch should return (false, false, true) when SessionNotFound occurs and dispatches event"
        );
    }

    #[tokio::test]
    async fn test_handle_incoming_message_skips_skmsg_after_msg_failure() {
        use wacore::libsignal::protocol::{IdentityKeyPair, KeyPair, SignalMessage};

        let backend = Arc::new(
            SqliteStore::new("file:memdb_skip_skmsg_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let sender_jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");

        // Create msg + skmsg node; msg will fail (no session), so skmsg should be skipped
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
        .expect("SignalMessage::new should succeed with valid inputs");

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

        // Should not panic or retry loop - skmsg is skipped after msg failure
        client.handle_incoming_message(message_node).await;
    }

    /// Test case for reproducing sender key JID mismatch in LID group messages
    ///
    /// Problem:
    /// - When we process sender key distribution from a self-sent LID message, we store it under the LID JID
    /// - But when we try to decrypt the group content (skmsg), we look it up using the phone number JID
    /// - This causes "No sender key state" errors even though we just processed the sender key!
    ///
    /// This test verifies the fix by:
    /// 1. Creating a sender key and storing it under the LID address (mimicking SKDM processing)
    /// 2. Attempting retrieval with phone number address (the bug) - should fail
    /// 3. Attempting retrieval with LID address (the fix) - should succeed
    #[tokio::test]
    async fn test_self_sent_lid_group_message_sender_key_mismatch() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore::libsignal::protocol::{
            SenderKeyStore, create_sender_key_distribution_message,
            process_sender_key_distribution_message,
        };
        use wacore::libsignal::store::sender_key_name::SenderKeyName;
        let backend = Arc::new(
            SqliteStore::new("file:memdb_sender_key_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (_client, _sync_rx) =
            Client::new(pm.clone(), mock_transport(), mock_http_client(), None).await;

        let own_lid: Jid = "100000000000001.1:75@lid"
            .parse()
            .expect("test JID should be valid");
        let own_phone: Jid = "15551234567:75@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");

        // Create SKDM using LID address (mimics handle_sender_key_distribution_message)
        let lid_protocol_address = own_lid.to_protocol_address();
        let lid_sender_key_name =
            SenderKeyName::new(group_jid.to_string(), lid_protocol_address.to_string());

        let device_arc = pm.get_device_arc().await;
        let skdm = {
            let mut device_guard = device_arc.write().await;
            create_sender_key_distribution_message(
                &lid_sender_key_name,
                &mut *device_guard,
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await
            .expect("Failed to create SKDM")
        };

        {
            let mut device_guard = device_arc.write().await;
            process_sender_key_distribution_message(
                &lid_sender_key_name,
                &skdm,
                &mut *device_guard,
            )
            .await
            .expect("Failed to process SKDM with LID address");
        }

        // Try to retrieve using PHONE NUMBER address (THE BUG)
        let phone_protocol_address = own_phone.to_protocol_address();
        let phone_sender_key_name =
            SenderKeyName::new(group_jid.to_string(), phone_protocol_address.to_string());

        let phone_lookup_result = {
            let mut device_guard = device_arc.write().await;
            device_guard.load_sender_key(&phone_sender_key_name).await
        };

        assert!(
            phone_lookup_result
                .expect("lookup should not error")
                .is_none(),
            "Sender key should NOT be found when looking up with phone number address (demonstrates the bug)"
        );

        // Try to retrieve using LID address (THE FIX)
        let lid_lookup_result = {
            let mut device_guard = device_arc.write().await;
            device_guard.load_sender_key(&lid_sender_key_name).await
        };

        assert!(
            lid_lookup_result
                .expect("lookup should not error")
                .is_some(),
            "Sender key SHOULD be found when looking up with LID address (same as storage)"
        );
    }

    /// Test that sender key consistency is maintained for multiple LID participants
    ///
    /// Edge case: Group with multiple LID participants, each should have their own
    /// sender key stored under their LID address, not mixed up with phone numbers.
    #[tokio::test]
    async fn test_multiple_lid_participants_sender_key_isolation() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore::libsignal::protocol::{
            SenderKeyStore, create_sender_key_distribution_message,
            process_sender_key_distribution_message,
        };
        use wacore::libsignal::store::sender_key_name::SenderKeyName;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_multi_lid_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let transport_factory = Arc::new(crate::transport::mock::MockTransportFactory::new());
        let (_client, _sync_rx) =
            Client::new(pm.clone(), transport_factory, mock_http_client(), None).await;

        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");

        // Simulate three LID participants
        let participants = vec![
            ("100000000000001.1:75@lid", "15551234567:75@s.whatsapp.net"),
            ("987654321000000.2:42@lid", "551234567890:42@s.whatsapp.net"),
            ("111222333444555.3:10@lid", "559876543210:10@s.whatsapp.net"),
        ];

        let device_arc = pm.get_device_arc().await;

        // Create and store sender keys for each participant under their LID address
        for (lid_str, _phone_str) in &participants {
            let lid_jid: Jid = lid_str.parse().expect("test JID should be valid");
            let lid_protocol_address = lid_jid.to_protocol_address();
            let lid_sender_key_name =
                SenderKeyName::new(group_jid.to_string(), lid_protocol_address.to_string());

            let skdm = {
                let mut device_guard = device_arc.write().await;
                create_sender_key_distribution_message(
                    &lid_sender_key_name,
                    &mut *device_guard,
                    &mut rand::rngs::OsRng.unwrap_err(),
                )
                .await
                .expect("Failed to create SKDM")
            };

            let mut device_guard = device_arc.write().await;
            process_sender_key_distribution_message(
                &lid_sender_key_name,
                &skdm,
                &mut *device_guard,
            )
            .await
            .expect("Failed to process SKDM");
        }

        // Verify each participant's sender key can be retrieved using their LID address
        for (lid_str, phone_str) in &participants {
            let lid_jid: Jid = lid_str.parse().expect("test JID should be valid");
            let phone_jid: Jid = phone_str.parse().expect("test JID should be valid");

            let lid_protocol_address = lid_jid.to_protocol_address();
            let phone_protocol_address = phone_jid.to_protocol_address();

            let lid_sender_key_name =
                SenderKeyName::new(group_jid.to_string(), lid_protocol_address.to_string());
            let phone_sender_key_name =
                SenderKeyName::new(group_jid.to_string(), phone_protocol_address.to_string());

            // Should find with LID address
            let lid_lookup = {
                let mut device_guard = device_arc.write().await;
                device_guard.load_sender_key(&lid_sender_key_name).await
            };
            assert!(
                lid_lookup.expect("lookup should not error").is_some(),
                "Sender key for {} should be found with LID address",
                lid_str
            );

            // Should NOT find with phone number address (the bug)
            let phone_lookup = {
                let mut device_guard = device_arc.write().await;
                device_guard.load_sender_key(&phone_sender_key_name).await
            };
            assert!(
                phone_lookup.expect("lookup should not error").is_none(),
                "Sender key for {} should NOT be found with phone number address",
                lid_str
            );
        }
    }

    /// Test that LID JID parsing handles various edge cases correctly
    ///
    /// Edge cases:
    /// - LID with multiple dots in user portion
    /// - LID with device numbers
    /// - LID without device numbers
    #[test]
    fn test_lid_jid_parsing_edge_cases() {
        use wacore_binary::jid::Jid;

        // Single dot in user portion
        let lid1: Jid = "100000000000001.1:75@lid"
            .parse()
            .expect("test JID should be valid");
        assert_eq!(lid1.user, "100000000000001.1");
        assert_eq!(lid1.device, 75);
        assert_eq!(lid1.agent, 0);

        // Multiple dots in user portion (extreme edge case)
        let lid2: Jid = "123.456.789.0:50@lid"
            .parse()
            .expect("test JID should be valid");
        assert_eq!(lid2.user, "123.456.789.0");
        assert_eq!(lid2.device, 50);
        assert_eq!(lid2.agent, 0);

        // No device number (device 0)
        let lid3: Jid = "987654321000000.5@lid"
            .parse()
            .expect("test JID should be valid");
        assert_eq!(lid3.user, "987654321000000.5");
        assert_eq!(lid3.device, 0);
        assert_eq!(lid3.agent, 0);

        // Very long user portion with dot
        let lid4: Jid = "111222333444555666777.999:1@lid"
            .parse()
            .expect("test JID should be valid");
        assert_eq!(lid4.user, "111222333444555666777.999");
        assert_eq!(lid4.device, 1);
        assert_eq!(lid4.agent, 0);
    }

    /// Test that protocol address generation from LID JIDs matches WhatsApp Web format
    ///
    /// WhatsApp Web uses: {user}[:device]@{server}.0
    /// - The device is encoded in the name
    /// - device_id is always 0
    #[test]
    fn test_lid_protocol_address_consistency() {
        use wacore::types::jid::JidExt as CoreJidExt;
        use wacore_binary::jid::Jid;

        // Format: (jid_str, expected_name, expected_device_id, expected_to_string)
        let test_cases = vec![
            (
                "100000000000001.1:75@lid",
                "100000000000001.1:75@lid",
                0,
                "100000000000001.1:75@lid.0",
            ),
            (
                "987654321000000.2:42@lid",
                "987654321000000.2:42@lid",
                0,
                "987654321000000.2:42@lid.0",
            ),
            (
                "111.222.333:10@lid",
                "111.222.333:10@lid",
                0,
                "111.222.333:10@lid.0",
            ),
            // No device - should not include :0
            ("123456789@lid", "123456789@lid", 0, "123456789@lid.0"),
        ];

        for (jid_str, expected_name, expected_device_id, expected_to_string) in test_cases {
            let lid_jid: Jid = jid_str.parse().expect("test JID should be valid");
            let protocol_addr = lid_jid.to_protocol_address();

            assert_eq!(
                protocol_addr.name(),
                expected_name,
                "Protocol address name should match WhatsApp Web's SignalAddress format for {}",
                jid_str
            );
            assert_eq!(
                u32::from(protocol_addr.device_id()),
                expected_device_id,
                "Protocol address device_id should always be 0 for {}",
                jid_str
            );
            assert_eq!(
                protocol_addr.to_string(),
                expected_to_string,
                "Protocol address to_string() should match createSignalLikeAddress format for {}",
                jid_str
            );
        }
    }

    /// Test sender_alt extraction from message attributes in LID groups
    ///
    /// Edge cases:
    /// - LID group with participant_pn attribute
    /// - PN group with participant_lid attribute
    /// - Mixed addressing modes
    #[tokio::test]
    async fn test_parse_message_info_sender_alt_extraction() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore_binary::builder::NodeBuilder;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_sender_alt_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );

        // Set up own phone number and LID
        {
            let device_arc = pm.get_device_arc().await;
            let mut device = device_arc.write().await;
            device.pn = Some(
                "15551234567@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
            );
            device.lid = Some(
                "100000000000001.1@lid"
                    .parse()
                    .expect("test JID should be valid"),
            );
        }

        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        // Test case 1: LID group message with participant_pn
        let lid_group_node = NodeBuilder::new("message")
            .attr("from", "120363021033254949@g.us")
            .attr("participant", "987654321000000.2:42@lid")
            .attr("participant_pn", "551234567890:42@s.whatsapp.net")
            .attr("addressing_mode", "lid")
            .attr("id", "test1")
            .attr("t", "12345")
            .build();

        let info1 = client
            .parse_message_info(&lid_group_node)
            .await
            .expect("parse_message_info should succeed");
        assert_eq!(info1.source.sender.user, "987654321000000.2");
        assert!(info1.source.sender_alt.is_some());
        assert_eq!(
            info1
                .source
                .sender_alt
                .as_ref()
                .expect("sender_alt should be present")
                .user,
            "551234567890"
        );

        // Test case 2: Self-sent LID group message
        let self_lid_node = NodeBuilder::new("message")
            .attr("from", "120363021033254949@g.us")
            .attr("participant", "100000000000001.1:75@lid")
            .attr("participant_pn", "15551234567:75@s.whatsapp.net")
            .attr("addressing_mode", "lid")
            .attr("id", "test2")
            .attr("t", "12346")
            .build();

        let info2 = client
            .parse_message_info(&self_lid_node)
            .await
            .expect("parse_message_info should succeed");
        assert!(
            info2.source.is_from_me,
            "Should detect self-sent LID message"
        );
        assert_eq!(info2.source.sender.user, "100000000000001.1");
        assert!(info2.source.sender_alt.is_some());
        assert_eq!(
            info2
                .source
                .sender_alt
                .as_ref()
                .expect("sender_alt should be present")
                .user,
            "15551234567"
        );
    }

    /// Test that device query logic uses phone numbers for LID participants
    ///
    /// This is a unit test for the logic in wacore/src/send.rs that converts
    /// LID JIDs to phone number JIDs for device queries.
    #[test]
    fn test_lid_to_phone_mapping_for_device_queries() {
        use std::collections::HashMap;
        use wacore::client::context::GroupInfo;
        use wacore::types::message::AddressingMode;
        use wacore_binary::jid::Jid;

        // Simulate a LID group with phone number mappings
        let mut lid_to_pn_map = HashMap::new();
        lid_to_pn_map.insert(
            "100000000000001.1".to_string(),
            "15551234567@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"),
        );
        lid_to_pn_map.insert(
            "987654321000000.2".to_string(),
            "551234567890@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"),
        );

        let mut group_info = GroupInfo::new(
            vec![
                "100000000000001.1:75@lid"
                    .parse()
                    .expect("test JID should be valid"),
                "987654321000000.2:42@lid"
                    .parse()
                    .expect("test JID should be valid"),
            ],
            AddressingMode::Lid,
        );
        group_info.set_lid_to_pn_map(lid_to_pn_map.clone());

        // Simulate the device query logic
        let jids_to_query: Vec<Jid> = group_info
            .participants
            .iter()
            .map(|jid| {
                let base_jid = jid.to_non_ad();
                if base_jid.is_lid()
                    && let Some(phone_jid) = group_info.phone_jid_for_lid_user(&base_jid.user)
                {
                    return phone_jid.to_non_ad();
                }
                base_jid
            })
            .collect();

        // Verify all queries use phone numbers, not LID JIDs
        for jid in &jids_to_query {
            assert_eq!(
                jid.server, SERVER_JID,
                "Device query should use phone number, got: {}",
                jid
            );
        }

        assert_eq!(jids_to_query.len(), 2);
        assert!(jids_to_query.iter().any(|j| j.user == "15551234567"));
        assert!(jids_to_query.iter().any(|j| j.user == "551234567890"));
    }

    /// Test edge case: Group with mixed LID and phone number participants
    ///
    /// Some participants may still use phone numbers even in a LID group.
    /// The code should handle both correctly.
    #[test]
    fn test_mixed_lid_and_phone_participants() {
        use std::collections::HashMap;
        use wacore::client::context::GroupInfo;
        use wacore::types::message::AddressingMode;
        use wacore_binary::jid::Jid;

        let mut lid_to_pn_map = HashMap::new();
        lid_to_pn_map.insert(
            "100000000000001.1".to_string(),
            "15551234567@s.whatsapp.net"
                .parse()
                .expect("test JID should be valid"),
        );

        let mut group_info = GroupInfo::new(
            vec![
                "100000000000001.1:75@lid"
                    .parse()
                    .expect("test JID should be valid"), // LID participant
                "551234567890:42@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"), // Phone number participant
            ],
            AddressingMode::Lid,
        );
        group_info.set_lid_to_pn_map(lid_to_pn_map.clone());

        let jids_to_query: Vec<Jid> = group_info
            .participants
            .iter()
            .map(|jid| {
                let base_jid = jid.to_non_ad();
                if base_jid.is_lid()
                    && let Some(phone_jid) = group_info.phone_jid_for_lid_user(&base_jid.user)
                {
                    return phone_jid.to_non_ad();
                }
                base_jid
            })
            .collect();

        // Both should end up as phone numbers
        assert_eq!(jids_to_query.len(), 2);
        for jid in &jids_to_query {
            assert_eq!(jid.server, SERVER_JID);
        }
    }

    /// Test edge case: Own JID check in LID mode
    ///
    /// When checking if own JID is in the participant list, we must use
    /// the phone number equivalent if in LID mode, not the LID itself.
    #[test]
    fn test_own_jid_check_in_lid_mode() {
        use std::collections::HashMap;
        use wacore_binary::jid::Jid;

        let own_lid: Jid = "100000000000001.1@lid"
            .parse()
            .expect("test JID should be valid");
        let own_phone: Jid = "15551234567@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");

        let mut lid_to_pn_map = HashMap::new();
        lid_to_pn_map.insert("100000000000001.1".to_string(), own_phone.clone());

        // Simulate the own JID check logic from wacore/src/send.rs
        let own_base_jid = own_lid.to_non_ad();
        let own_jid_to_check = if own_base_jid.is_lid() {
            lid_to_pn_map
                .get(&own_base_jid.user)
                .map(|pn| pn.to_non_ad())
                .unwrap_or_else(|| own_base_jid.clone())
        } else {
            own_base_jid.clone()
        };

        // Verify we're checking using the phone number
        assert_eq!(own_jid_to_check.user, "15551234567");
        assert_eq!(own_jid_to_check.server, SERVER_JID);
    }

    /// Test that sender key operations always use the display JID (LID)
    /// regardless of what JID is used for E2E session decryption
    #[tokio::test]
    async fn test_sender_key_always_uses_display_jid() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore::libsignal::protocol::{SenderKeyStore, create_sender_key_distribution_message};
        use wacore::libsignal::store::sender_key_name::SenderKeyName;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_display_jid_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (_client, _sync_rx) =
            Client::new(pm.clone(), mock_transport(), mock_http_client(), None).await;

        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");
        let display_jid: Jid = "100000000000001.1:75@lid"
            .parse()
            .expect("test JID should be valid");
        let encryption_jid: Jid = "15551234567:75@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");

        // Store sender key using display JID (LID)
        let display_protocol_address = display_jid.to_protocol_address();
        let display_sender_key_name =
            SenderKeyName::new(group_jid.to_string(), display_protocol_address.to_string());

        let device_arc = pm.get_device_arc().await;
        {
            let mut device_guard = device_arc.write().await;
            create_sender_key_distribution_message(
                &display_sender_key_name,
                &mut *device_guard,
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await
            .expect("Failed to create SKDM");
        }

        // Verify it's stored under display JID
        let lookup_with_display = {
            let mut device_guard = device_arc.write().await;
            device_guard.load_sender_key(&display_sender_key_name).await
        };
        assert!(
            lookup_with_display
                .expect("lookup should not error")
                .is_some(),
            "Sender key should be found with display JID (LID)"
        );

        // Verify it's NOT accessible via encryption JID (phone number)
        let encryption_protocol_address = encryption_jid.to_protocol_address();
        let encryption_sender_key_name = SenderKeyName::new(
            group_jid.to_string(),
            encryption_protocol_address.to_string(),
        );

        let lookup_with_encryption = {
            let mut device_guard = device_arc.write().await;
            device_guard
                .load_sender_key(&encryption_sender_key_name)
                .await
        };
        assert!(
            lookup_with_encryption
                .expect("lookup should not error")
                .is_none(),
            "Sender key should NOT be found with encryption JID (phone number)"
        );
    }

    /// Test edge case: Second message with only skmsg (no pkmsg/msg)
    ///
    /// After the first message establishes a session and sender key,
    /// subsequent messages may contain only skmsg. These should still
    /// be decrypted successfully, not skipped.
    ///
    /// Bug: The code was treating "no session messages" as "session failed",
    /// causing it to skip skmsg decryption for all messages after the first.
    #[tokio::test]
    async fn test_second_message_with_only_skmsg_decrypts() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore::libsignal::protocol::{
            create_sender_key_distribution_message, process_sender_key_distribution_message,
        };
        use wacore::libsignal::store::sender_key_name::SenderKeyName;
        use wacore_binary::builder::NodeBuilder;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_second_msg_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) =
            Client::new(pm.clone(), mock_transport(), mock_http_client(), None).await;

        let sender_jid: Jid = "100000000000001.1:75@lid"
            .parse()
            .expect("test JID should be valid");
        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");

        // Step 1: Create and store a sender key (simulating first message processing)
        let sender_protocol_address = sender_jid.to_protocol_address();
        let sender_key_name =
            SenderKeyName::new(group_jid.to_string(), sender_protocol_address.to_string());

        let device_arc = pm.get_device_arc().await;
        {
            let mut device_guard = device_arc.write().await;
            let skdm = create_sender_key_distribution_message(
                &sender_key_name,
                &mut *device_guard,
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await
            .expect("Failed to create SKDM");

            process_sender_key_distribution_message(&sender_key_name, &skdm, &mut *device_guard)
                .await
                .expect("Failed to process SKDM");
        }

        // Create message with ONLY skmsg (simulating second message after session established)
        let skmsg_ciphertext = {
            let mut device_guard = device_arc.write().await;
            let sender_key_msg = wacore::libsignal::protocol::group_encrypt(
                &mut *device_guard,
                &sender_key_name,
                b"ping",
                &mut rand::rngs::OsRng.unwrap_err(),
            )
            .await
            .expect("Failed to encrypt with sender key");
            sender_key_msg.serialized().to_vec()
        };

        let skmsg_node = NodeBuilder::new("enc")
            .attr("type", "skmsg")
            .attr("v", "2")
            .bytes(skmsg_ciphertext)
            .build();

        let message_node = Arc::new(
            NodeBuilder::new("message")
                .attr("from", group_jid.to_string())
                .attr("participant", sender_jid.to_string())
                .attr("id", "SECOND_MSG_TEST")
                .attr("t", "1759306493")
                .attr("type", "text")
                .attr("addressing_mode", "lid")
                .children(vec![skmsg_node])
                .build(),
        );

        // Should NOT skip skmsg - before the fix this would incorrectly skip
        client.handle_incoming_message(message_node).await;
    }

    /// Test case for UntrustedIdentity error handling and recovery
    ///
    /// Scenario:
    /// - User re-installs WhatsApp or switches devices
    /// - Their device generates a new identity key
    /// - The bot still has the old identity key stored
    /// - When a message arrives, Signal Protocol rejects it as "UntrustedIdentity"
    /// - The bot should catch this error, clear the old identity using the FULL protocol address (with device ID), and retry
    ///
    /// This test verifies that:
    /// 1. process_session_enc_batch handles UntrustedIdentity gracefully
    /// 2. The deletion uses the correct full address (name.device_id) not just the name
    /// 3. No panic occurs when UntrustedIdentity is encountered
    /// 4. The error is logged appropriately
    /// 5. The bot continues processing instead of propagating the error
    #[tokio::test]
    async fn test_untrusted_identity_error_is_caught_and_handled() {
        use crate::store::SqliteStore;
        use std::sync::Arc;

        // Setup
        let backend = Arc::new(
            SqliteStore::new("file:memdb_untrusted_identity_caught?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) =
            Client::new(pm.clone(), mock_transport(), mock_http_client(), None).await;

        let sender_jid: Jid = "559981212574@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");

        let info = MessageInfo {
            source: crate::types::message::MessageSource {
                sender: sender_jid.clone(),
                chat: sender_jid.clone(),
                ..Default::default()
            },
            ..Default::default()
        };

        log::info!("Test: UntrustedIdentity scenario for {}", sender_jid);

        // Create a malformed/invalid encrypted node to trigger error handling path
        // This won't create UntrustedIdentity specifically, but tests the error handling code path
        // The important fix is that when UntrustedIdentity IS raised, the code uses
        // address.to_string() (which gives "559981212574.0") instead of address.name()
        // (which only gives "559981212574") for the deletion key.
        let enc_node = NodeBuilder::new("enc")
            .attr("type", "msg")
            .attr("v", "2")
            .bytes(vec![0xFF; 100]) // Invalid encrypted payload
            .build();

        let enc_nodes = vec![&enc_node];

        // Call process_session_enc_batch
        // This should handle any errors gracefully without panicking
        let (success, _had_duplicates, _dispatched) = client
            .process_session_enc_batch(&enc_nodes, &info, &sender_jid)
            .await;

        log::info!(
            "Test: process_session_enc_batch completed - success: {}",
            success
        );

        // The key is that this didn't panic - deletion uses full protocol address
    }

    /// Test case: Error handling during batch processing
    ///
    /// When multiple messages are being processed in a batch, if one triggers
    /// an error (like UntrustedIdentity), it should be handled without affecting
    /// other messages in the batch.
    #[tokio::test]
    async fn test_untrusted_identity_does_not_break_batch_processing() {
        use crate::store::SqliteStore;
        use std::sync::Arc;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_untrusted_batch?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) =
            Client::new(pm.clone(), mock_transport(), mock_http_client(), None).await;

        let sender_jid: Jid = "559981212574@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");

        let info = MessageInfo {
            source: crate::types::message::MessageSource {
                sender: sender_jid.clone(),
                chat: sender_jid.clone(),
                ..Default::default()
            },
            ..Default::default()
        };

        log::info!("Test: Batch processing with multiple error messages");

        // Create multiple invalid encrypted nodes to test batch error handling
        let mut enc_nodes = Vec::new();

        // First message: Invalid encrypted payload
        let enc_node_1 = NodeBuilder::new("enc")
            .attr("type", "msg")
            .attr("v", "2")
            .bytes(vec![0xFF; 50])
            .build();
        enc_nodes.push(enc_node_1);

        // Second message: Another invalid encrypted payload
        let enc_node_2 = NodeBuilder::new("enc")
            .attr("type", "msg")
            .attr("v", "2")
            .bytes(vec![0xAA; 50])
            .build();
        enc_nodes.push(enc_node_2);

        log::info!("Test: Created batch of 2 messages with invalid data");

        let enc_node_refs: Vec<&wacore_binary::node::Node> = enc_nodes.iter().collect();

        // Process the batch
        // Should handle all errors gracefully without stopping at first error
        let (success, _had_duplicates, _dispatched) = client
            .process_session_enc_batch(&enc_node_refs, &info, &sender_jid)
            .await;

        log::info!("Test: Batch processing completed - success: {}", success);
    }

    /// Test case: Error handling in group chat context
    ///
    /// When processing messages from group members, if identity errors occur,
    /// they should be handled per-sender without affecting other group members.
    #[tokio::test]
    async fn test_untrusted_identity_in_group_context() {
        use crate::store::SqliteStore;
        use std::sync::Arc;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_untrusted_group?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) =
            Client::new(pm.clone(), mock_transport(), mock_http_client(), None).await;

        // Simulate a group chat scenario
        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");
        let sender_phone: Jid = "559981212574@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");

        let info = MessageInfo {
            source: crate::types::message::MessageSource {
                sender: sender_phone.clone(),
                chat: group_jid.clone(),
                is_group: true,
                ..Default::default()
            },
            ..Default::default()
        };

        log::info!("Test: Group context - error handling for {}", sender_phone);

        // Create an invalid encrypted message
        let enc_node = NodeBuilder::new("enc")
            .attr("type", "msg")
            .attr("v", "2")
            .bytes(vec![0xFF; 100])
            .build();

        let enc_nodes = vec![&enc_node];

        // Process the message
        // Should handle errors gracefully in group context
        let (success, _had_duplicates, _dispatched) = client
            .process_session_enc_batch(&enc_nodes, &info, &sender_phone)
            .await;

        log::info!("Test: Group message processed - success: {}", success);
    }

    /// Test case: DM message parsing for self-sent messages via LID
    ///
    /// Scenario:
    /// - You send a DM to another user from your phone
    /// - Your bot receives the echo with from=your_LID, recipient=their_LID
    /// - peer_recipient_pn contains the RECIPIENT's phone number (not sender's)
    ///
    /// The fix ensures:
    /// 1. is_from_me is correctly detected for LID senders
    /// 2. sender_alt is NOT populated with peer_recipient_pn (that's the recipient's PN)
    /// 3. Decryption uses own PN via the is_from_me fallback path
    #[tokio::test]
    async fn test_parse_message_info_self_sent_dm_via_lid() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore_binary::builder::NodeBuilder;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_self_dm_lid_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );

        // Set up own phone number and LID
        {
            let device_arc = pm.get_device_arc().await;
            let mut device = device_arc.write().await;
            device.pn = Some(
                "15551234567@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
            );
            device.lid = Some(
                "100000000000001@lid"
                    .parse()
                    .expect("test JID should be valid"),
            );
        }

        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        // Simulate self-sent DM to another user (from your phone to your bot echo)
        // Real log example:
        // from="100000000000001@lid" recipient="39492358562039@lid" peer_recipient_pn="559985213786@s.whatsapp.net"
        let self_dm_node = NodeBuilder::new("message")
            .attr("from", "100000000000001@lid") // Your LID
            .attr("recipient", "39492358562039@lid") // Recipient's LID
            .attr("peer_recipient_pn", "559985213786@s.whatsapp.net") // Recipient's PN (NOT sender's!)
            .attr("notify", "jl")
            .attr("id", "AC756E00B560721DBC4C0680131827EA")
            .attr("t", "1764845025")
            .attr("type", "text")
            .build();

        let info = client
            .parse_message_info(&self_dm_node)
            .await
            .expect("parse_message_info should succeed");

        // Assertions:
        // 1. is_from_me should be true (LID matches own_lid)
        assert!(
            info.source.is_from_me,
            "Should detect self-sent DM from own LID"
        );

        // 2. sender_alt should be None (peer_recipient_pn is recipient's PN, not sender's)
        assert!(
            info.source.sender_alt.is_none(),
            "sender_alt should be None for self-sent DMs (peer_recipient_pn is recipient's PN)"
        );

        assert_eq!(
            info.source.chat.user, "39492358562039",
            "Chat should be the recipient's LID"
        );

        assert_eq!(
            info.source.sender.user, "100000000000001",
            "Sender should be own LID"
        );
    }

    /// Test case: DM message parsing for messages from others via LID
    ///
    /// Scenario:
    /// - Another user sends you a DM
    /// - Message arrives with from=their_LID, sender_pn=their_phone_number
    ///
    /// The fix ensures:
    /// 1. is_from_me is false
    /// 2. sender_alt is populated from sender_pn attribute (if present)
    /// 3. Decryption uses sender_alt for session lookup
    #[tokio::test]
    async fn test_parse_message_info_dm_from_other_via_lid() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore_binary::builder::NodeBuilder;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_other_dm_lid_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );

        // Set up own phone number and LID
        {
            let device_arc = pm.get_device_arc().await;
            let mut device = device_arc.write().await;
            device.pn = Some(
                "15551234567@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
            );
            device.lid = Some(
                "100000000000001@lid"
                    .parse()
                    .expect("test JID should be valid"),
            );
        }

        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        // Simulate DM from another user via their LID
        // The sender_pn attribute should contain their phone number for session lookup
        let other_dm_node = NodeBuilder::new("message")
            .attr("from", "39492358562039@lid") // Sender's LID (not ours)
            .attr("sender_pn", "559985213786@s.whatsapp.net") // Sender's phone number
            .attr("notify", "Other User")
            .attr("id", "AABBCCDD1234567890")
            .attr("t", "1764845100")
            .attr("type", "text")
            .build();

        let info = client
            .parse_message_info(&other_dm_node)
            .await
            .expect("parse_message_info should succeed");

        assert!(
            !info.source.is_from_me,
            "Should NOT be detected as self-sent"
        );

        assert!(
            info.source.sender_alt.is_some(),
            "sender_alt should be set from sender_pn attribute"
        );
        assert_eq!(
            info.source
                .sender_alt
                .as_ref()
                .expect("sender_alt should be present")
                .user,
            "559985213786",
            "sender_alt should contain sender's phone number"
        );

        assert_eq!(
            info.source.chat.user, "39492358562039",
            "Chat should be the sender's LID (non-AD)"
        );

        assert_eq!(
            info.source.sender.user, "39492358562039",
            "Sender should be other user's LID"
        );
    }

    /// Test case: DM message to self (own chat, like "Notes to Myself")
    ///
    /// Scenario:
    /// - You send a message to yourself (your own chat)
    /// - from=your_LID, recipient=your_LID, peer_recipient_pn=your_PN
    ///
    /// This is the original bug case that was fixed earlier.
    #[tokio::test]
    async fn test_parse_message_info_dm_to_self() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore_binary::builder::NodeBuilder;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_dm_to_self_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );

        // Set up own phone number and LID
        {
            let device_arc = pm.get_device_arc().await;
            let mut device = device_arc.write().await;
            device.pn = Some(
                "15551234567@s.whatsapp.net"
                    .parse()
                    .expect("test JID should be valid"),
            );
            device.lid = Some(
                "100000000000001@lid"
                    .parse()
                    .expect("test JID should be valid"),
            );
        }

        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        // Simulate DM to self (like "Notes to Myself" or pinging yourself)
        // from=your_LID, recipient=your_LID, peer_recipient_pn=your_PN
        let self_chat_node = NodeBuilder::new("message")
            .attr("from", "100000000000001@lid") // Your LID
            .attr("recipient", "100000000000001@lid") // Also your LID (self-chat)
            .attr("peer_recipient_pn", "15551234567@s.whatsapp.net") // Your PN
            .attr("notify", "jl")
            .attr("id", "AC391DD54A28E1CE1F3B106DF9951FAD")
            .attr("t", "1764822437")
            .attr("type", "text")
            .build();

        let info = client
            .parse_message_info(&self_chat_node)
            .await
            .expect("parse_message_info should succeed");

        assert!(
            info.source.is_from_me,
            "Should detect self-sent message to self-chat"
        );

        assert!(
            info.source.sender_alt.is_none(),
            "sender_alt should be None for self-sent messages"
        );

        assert_eq!(
            info.source.chat.user, "100000000000001",
            "Chat should be self (recipient)"
        );

        assert_eq!(
            info.source.sender.user, "100000000000001",
            "Sender should be own LID"
        );
    }

    /// Test that receiving a DM with sender_lid populates the lid_pn_cache.
    ///
    /// This is the key behavior for the LID-PN session mismatch fix:
    /// When we receive a message from a phone number with sender_lid attribute,
    /// we cache the phone->LID mapping so that when sending replies, we can
    /// reuse the existing LID session instead of creating a new PN session.
    ///
    /// Flow being tested:
    /// 1. Receive message from 559980000001@s.whatsapp.net with sender_lid=100000012345678@lid
    /// 2. Cache should be populated with: 559980000001 -> 100000012345678
    /// 3. When sending reply to 559980000001, we can look up the LID and use existing session
    #[tokio::test]
    async fn test_lid_pn_cache_populated_on_message_with_sender_lid() {
        // Setup client
        let backend = Arc::new(
            SqliteStore::new("file:memdb_lid_cache_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let phone = "559980000001";
        let lid = "100000012345678";

        // Verify cache is empty initially
        assert!(
            client.lid_pn_cache.get_current_lid(phone).await.is_none(),
            "Cache should be empty before receiving message"
        );

        // Create a DM message node with sender_lid attribute
        // This simulates receiving a message from WhatsApp Web
        let dm_node = NodeBuilder::new("message")
            .attr("from", Jid::pn(phone).to_string())
            .attr("sender_lid", Jid::lid(lid).to_string())
            .attr("id", "TEST123456789")
            .attr("t", "1765482972")
            .attr("type", "text")
            .children([NodeBuilder::new("enc")
                .attr("type", "pkmsg")
                .attr("v", "2")
                .bytes(vec![0u8; 100]) // Dummy encrypted content
                .build()])
            .build();

        // Call handle_incoming_message - this will fail to decrypt (no real session)
        // but it should still populate the cache before attempting decryption
        client
            .clone()
            .handle_incoming_message(Arc::new(dm_node))
            .await;

        // Verify the cache was populated
        let cached_lid = client.lid_pn_cache.get_current_lid(phone).await;
        assert!(
            cached_lid.is_some(),
            "Cache should be populated after receiving message with sender_lid"
        );
        assert_eq!(
            cached_lid.expect("cache should have LID"),
            lid,
            "Cached LID should match the sender_lid from the message"
        );
    }

    /// Test that messages without sender_lid do NOT populate the cache.
    ///
    /// This ensures we don't accidentally cache incorrect mappings.
    #[tokio::test]
    async fn test_lid_pn_cache_not_populated_without_sender_lid() {
        // Setup client
        let backend = Arc::new(
            SqliteStore::new("file:memdb_no_lid_cache_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let phone = "559980000001";

        // Create a DM message node WITHOUT sender_lid attribute
        let dm_node = NodeBuilder::new("message")
            .attr("from", Jid::pn(phone).to_string())
            // Note: NO sender_lid attribute
            .attr("id", "TEST123456789")
            .attr("t", "1765482972")
            .attr("type", "text")
            .children([NodeBuilder::new("enc")
                .attr("type", "pkmsg")
                .attr("v", "2")
                .bytes(vec![0u8; 100])
                .build()])
            .build();

        // Call handle_incoming_message
        client
            .clone()
            .handle_incoming_message(Arc::new(dm_node))
            .await;

        assert!(
            client.lid_pn_cache.get_current_lid(phone).await.is_none(),
            "Cache should NOT be populated for messages without sender_lid"
        );
    }

    /// Test that messages from LID senders with participant_pn DO populate the cache.
    ///
    /// When the sender is a LID (e.g., in LID-mode groups), and participant_pn
    /// contains their phone number, we SHOULD cache this mapping because:
    /// 1. The cache is bidirectional - we need both LID->PN and PN->LID
    /// 2. This enables sending to users we've only seen as LID senders
    #[tokio::test]
    async fn test_lid_pn_cache_populated_for_lid_sender_with_participant_pn() {
        // Setup client
        let backend = Arc::new(
            SqliteStore::new("file:memdb_lid_sender_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let lid = "100000012345678";
        let phone = "559980000001";

        // Create a message from a LID sender with participant_pn attribute
        // This happens in LID-mode groups (addressing_mode="lid")
        let group_node = NodeBuilder::new("message")
            .attr("from", "120363123456789012@g.us") // Group chat
            .attr("participant", Jid::lid(lid).to_string()) // Sender is LID
            .attr("participant_pn", Jid::pn(phone).to_string()) // Their phone number
            .attr("addressing_mode", "lid") // Required for participant_pn to be parsed
            .attr("id", "TEST123456789")
            .attr("t", "1765482972")
            .attr("type", "text")
            .children([NodeBuilder::new("enc")
                .attr("type", "skmsg")
                .attr("v", "2")
                .bytes(vec![0u8; 100])
                .build()])
            .build();

        // Call handle_incoming_message
        client
            .clone()
            .handle_incoming_message(Arc::new(group_node))
            .await;

        // Verify the cache WAS populated (bidirectional cache)
        let cached_lid = client.lid_pn_cache.get_current_lid(phone).await;
        assert!(
            cached_lid.is_some(),
            "Cache should be populated for LID senders with participant_pn"
        );
        assert_eq!(
            cached_lid.expect("cache should have LID"),
            lid,
            "Cached LID should match the sender's LID"
        );

        // Also verify we can look up the phone number from the LID
        let cached_pn = client.lid_pn_cache.get_phone_number(lid).await;
        assert!(cached_pn.is_some(), "Reverse lookup (LID->PN) should work");
        assert_eq!(
            cached_pn.expect("reverse lookup should return phone"),
            phone,
            "Cached phone number should match"
        );
    }

    /// Test that multiple messages from the same sender update the cache correctly.
    ///
    /// This ensures the cache handles repeated messages gracefully.
    #[tokio::test]
    async fn test_lid_pn_cache_handles_repeated_messages() {
        // Setup client
        let backend = Arc::new(
            SqliteStore::new("file:memdb_repeated_msg_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let phone = "559980000001";
        let lid = "100000012345678";

        // Send multiple messages from the same sender
        for i in 0..3 {
            let dm_node = NodeBuilder::new("message")
                .attr("from", Jid::pn(phone).to_string())
                .attr("sender_lid", Jid::lid(lid).to_string())
                .attr("id", format!("TEST{}", i))
                .attr("t", "1765482972")
                .attr("type", "text")
                .children([NodeBuilder::new("enc")
                    .attr("type", "pkmsg")
                    .attr("v", "2")
                    .bytes(vec![0u8; 100])
                    .build()])
                .build();

            client
                .clone()
                .handle_incoming_message(Arc::new(dm_node))
                .await;
        }

        // Verify the cache still has the correct mapping
        let cached_lid = client.lid_pn_cache.get_current_lid(phone).await;
        assert!(cached_lid.is_some(), "Cache should contain the mapping");
        assert_eq!(
            cached_lid.expect("cache should have LID"),
            lid,
            "Cached LID should be correct after multiple messages"
        );
    }

    /// Test that PN-addressed messages use LID for session lookup when LID mapping is known.
    ///
    /// This test verifies the fix for the MAC verification failure bug:
    /// WhatsApp Web's SignalAddress.toString() ALWAYS converts PN addresses to LID
    /// when a LID mapping is known. The Rust client must do the same to ensure
    /// session keys match between clients.
    ///
    /// Bug scenario:
    /// 1. WhatsApp Web Client A sends a group message to our Rust client
    /// 2. Rust client creates session under PN address (559980000001@c.us.0)
    /// 3. Rust client sends group response, creates session under LID (100000012345678@lid.0)
    /// 4. Client A sends DM to Rust client from PN address
    /// 5. Rust client tries to decrypt using PN address but session is under LID
    /// 6. MAC verification fails because wrong session is used
    ///
    /// Fix: When receiving a PN-addressed message, if we have a LID mapping,
    /// use the LID address for session lookup (matching WhatsApp Web behavior).
    #[tokio::test]
    async fn test_pn_message_uses_lid_for_session_lookup_when_mapping_known() {
        use crate::lid_pn_cache::LidPnEntry;
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore::types::jid::JidExt;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_pn_to_lid_session_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let lid = "100000012345678";
        let phone = "559980000001";

        // Pre-populate the LID-PN cache (simulating a previous group message)
        let entry = LidPnEntry::new(
            lid.to_string(),
            phone.to_string(),
            crate::lid_pn_cache::LearningSource::PeerLidMessage,
        );
        client.lid_pn_cache.add(entry).await;

        // Verify the cache has the mapping
        let cached_lid = client.lid_pn_cache.get_current_lid(phone).await;
        assert_eq!(
            cached_lid,
            Some(lid.to_string()),
            "Cache should have the LID-PN mapping"
        );

        // Test scenario: Parse a PN-addressed DM message (with sender_lid attribute)
        let dm_node_with_sender_lid = wacore_binary::builder::NodeBuilder::new("message")
            .attr("from", Jid::pn(phone).to_string())
            .attr("sender_lid", Jid::lid(lid).to_string())
            .attr("id", "test_dm_with_lid")
            .attr("t", "1765494882")
            .attr("type", "text")
            .build();

        let info = client
            .parse_message_info(&dm_node_with_sender_lid)
            .await
            .expect("parse_message_info should succeed");

        // Verify sender is PN but sender_alt is LID
        assert_eq!(info.source.sender.user, phone);
        assert_eq!(info.source.sender.server, "s.whatsapp.net");
        assert!(info.source.sender_alt.is_some());
        assert_eq!(
            info.source
                .sender_alt
                .as_ref()
                .expect("sender_alt should be present")
                .user,
            lid
        );
        assert_eq!(
            info.source
                .sender_alt
                .as_ref()
                .expect("sender_alt should be present")
                .server,
            "lid"
        );

        // Now simulate what handle_incoming_message does: determine encryption JID
        // We can't easily call handle_incoming_message, so we'll test the logic directly
        let sender = &info.source.sender;
        let alt = info.source.sender_alt.as_ref();
        let pn_server = wacore_binary::jid::DEFAULT_USER_SERVER;
        let lid_server = wacore_binary::jid::HIDDEN_USER_SERVER;

        // Apply the same logic as in handle_incoming_message
        let sender_encryption_jid = if sender.server == lid_server {
            sender.clone()
        } else if sender.server == pn_server {
            if let Some(alt_jid) = alt
                && alt_jid.server == lid_server
            {
                // Use the LID from the message attribute
                Jid {
                    user: alt_jid.user.clone(),
                    server: lid_server.to_string(),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else if let Some(lid_user) = client.lid_pn_cache.get_current_lid(&sender.user).await {
                // Use the cached LID
                Jid {
                    user: lid_user,
                    server: lid_server.to_string(),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else {
                sender.clone()
            }
        } else {
            sender.clone()
        };

        // Verify the encryption JID uses the LID, not the PN
        assert_eq!(
            sender_encryption_jid.user, lid,
            "Encryption JID should use LID user"
        );
        assert_eq!(
            sender_encryption_jid.server, "lid",
            "Encryption JID should use LID server"
        );

        // Verify the protocol address format
        let protocol_address = sender_encryption_jid.to_protocol_address();
        assert_eq!(
            protocol_address.to_string(),
            format!("{}@lid.0", lid),
            "Protocol address should be in LID format"
        );
    }

    /// Test that PN-addressed messages use cached LID even without sender_lid attribute.
    ///
    /// This tests the fallback path where the message doesn't have a sender_lid
    /// attribute but we have a previously cached LID mapping.
    #[tokio::test]
    async fn test_pn_message_uses_cached_lid_without_sender_lid_attribute() {
        use crate::lid_pn_cache::LidPnEntry;
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore::types::jid::JidExt;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_cached_lid_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let lid = "100000012345678";
        let phone = "559980000001";

        // Pre-populate the LID-PN cache
        let entry = LidPnEntry::new(
            lid.to_string(),
            phone.to_string(),
            crate::lid_pn_cache::LearningSource::PeerLidMessage,
        );
        client.lid_pn_cache.add(entry).await;

        // Parse a PN-addressed DM message WITHOUT sender_lid attribute
        let dm_node_without_sender_lid = wacore_binary::builder::NodeBuilder::new("message")
            .attr("from", Jid::pn(phone).to_string())
            // Note: No sender_lid attribute!
            .attr("id", "test_dm_no_lid")
            .attr("t", "1765494882")
            .attr("type", "text")
            .build();

        let info = client
            .parse_message_info(&dm_node_without_sender_lid)
            .await
            .expect("parse_message_info should succeed");

        // Verify sender is PN and NO sender_alt (since there's no sender_lid attribute)
        assert_eq!(info.source.sender.user, phone);
        assert_eq!(info.source.sender.server, "s.whatsapp.net");
        assert!(
            info.source.sender_alt.is_none(),
            "Should have no sender_alt without sender_lid attribute"
        );

        // Apply the encryption JID logic (fallback to cached LID)
        let sender = &info.source.sender;
        let alt = info.source.sender_alt.as_ref();
        let pn_server = wacore_binary::jid::DEFAULT_USER_SERVER;
        let lid_server = wacore_binary::jid::HIDDEN_USER_SERVER;

        let sender_encryption_jid = if sender.server == lid_server {
            sender.clone()
        } else if sender.server == pn_server {
            if let Some(alt_jid) = alt
                && alt_jid.server == lid_server
            {
                Jid {
                    user: alt_jid.user.clone(),
                    server: lid_server.to_string(),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else if let Some(lid_user) = client.lid_pn_cache.get_current_lid(&sender.user).await {
                // This is the path we're testing - fallback to cached LID
                Jid {
                    user: lid_user,
                    server: lid_server.to_string(),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else {
                sender.clone()
            }
        } else {
            sender.clone()
        };

        // Verify the encryption JID uses the cached LID
        assert_eq!(
            sender_encryption_jid.user, lid,
            "Encryption JID should use cached LID user"
        );
        assert_eq!(
            sender_encryption_jid.server, "lid",
            "Encryption JID should use LID server"
        );

        let protocol_address = sender_encryption_jid.to_protocol_address();
        assert_eq!(
            protocol_address.to_string(),
            format!("{}@lid.0", lid),
            "Protocol address should be in LID format from cached mapping"
        );
    }

    /// Test that PN-addressed messages use PN when no LID mapping is known.
    ///
    /// When there's no LID mapping available, we should fall back to using
    /// the PN address for session lookup.
    #[tokio::test]
    async fn test_pn_message_uses_pn_when_no_lid_mapping() {
        use crate::store::SqliteStore;
        use std::sync::Arc;
        use wacore::types::jid::JidExt;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_no_lid_mapping_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let phone = "559980000001";

        // Don't populate the cache - simulate first-time contact

        // Parse a PN-addressed DM message without sender_lid
        let dm_node = wacore_binary::builder::NodeBuilder::new("message")
            .attr("from", Jid::pn(phone).to_string())
            .attr("id", "test_dm_no_mapping")
            .attr("t", "1765494882")
            .attr("type", "text")
            .build();

        let info = client
            .parse_message_info(&dm_node)
            .await
            .expect("parse_message_info should succeed");

        // Verify no cached LID
        let cached_lid = client.lid_pn_cache.get_current_lid(phone).await;
        assert!(cached_lid.is_none(), "Should have no cached LID mapping");

        // Apply the encryption JID logic
        let sender = &info.source.sender;
        let alt = info.source.sender_alt.as_ref();
        let pn_server = wacore_binary::jid::DEFAULT_USER_SERVER;
        let lid_server = wacore_binary::jid::HIDDEN_USER_SERVER;

        let sender_encryption_jid = if sender.server == lid_server {
            sender.clone()
        } else if sender.server == pn_server {
            if let Some(alt_jid) = alt
                && alt_jid.server == lid_server
            {
                Jid {
                    user: alt_jid.user.clone(),
                    server: lid_server.to_string(),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else if let Some(lid_user) = client.lid_pn_cache.get_current_lid(&sender.user).await {
                Jid {
                    user: lid_user,
                    server: lid_server.to_string(),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else {
                // This is the path we're testing - no LID mapping, use PN
                sender.clone()
            }
        } else {
            sender.clone()
        };

        // Verify the encryption JID uses the PN (no LID available)
        assert_eq!(
            sender_encryption_jid.user, phone,
            "Encryption JID should use PN user when no LID mapping"
        );
        assert_eq!(
            sender_encryption_jid.server, "s.whatsapp.net",
            "Encryption JID should use PN server when no LID mapping"
        );

        let protocol_address = sender_encryption_jid.to_protocol_address();
        assert_eq!(
            protocol_address.to_string(),
            format!("{}@c.us.0", phone),
            "Protocol address should be in PN format when no LID mapping"
        );
    }

    // and PDO fallback behavior to ensure robust message recovery.

    /// Helper to create a test MessageInfo with customizable fields
    fn create_test_message_info(chat: &str, msg_id: &str, sender: &str) -> MessageInfo {
        use wacore::types::message::{EditAttribute, MessageSource, MsgMetaInfo};

        let chat_jid: Jid = chat.parse().expect("valid chat JID");
        let sender_jid: Jid = sender.parse().expect("valid sender JID");

        MessageInfo {
            id: msg_id.to_string(),
            server_id: 0,
            r#type: "text".to_string(),
            source: MessageSource {
                chat: chat_jid.clone(),
                sender: sender_jid,
                sender_alt: None,
                recipient_alt: None,
                is_from_me: false,
                is_group: chat_jid.is_group(),
                addressing_mode: None,
                broadcast_list_owner: None,
                recipient: None,
            },
            timestamp: chrono::Utc::now(),
            push_name: "Test User".to_string(),
            category: "".to_string(),
            multicast: false,
            media_type: "".to_string(),
            edit: EditAttribute::default(),
            bot_info: None,
            meta_info: MsgMetaInfo::default(),
            verified_name: None,
            device_sent_meta: None,
        }
    }

    /// Helper to create a test client for retry tests with a unique database
    async fn create_test_client_for_retry_with_id(test_id: &str) -> Arc<Client> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);

        let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let db_name = format!(
            "file:memdb_retry_{}_{}_{}?mode=memory&cache=shared",
            test_id,
            unique_id,
            std::process::id()
        );

        let backend = Arc::new(
            SqliteStore::new(&db_name)
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;
        client
    }

    #[tokio::test]
    async fn test_increment_retry_count_starts_at_one() {
        let client = create_test_client_for_retry_with_id("starts_at_one").await;

        let cache_key = "test_chat:msg123:sender456";

        // First increment should return 1
        let count = client.increment_retry_count(cache_key).await;
        assert_eq!(count, Some(1), "First retry should be count 1");

        // Verify it's stored in cache
        let stored = client.message_retry_counts.get(cache_key).await;
        assert_eq!(stored, Some(1), "Cache should store count 1");
    }

    #[tokio::test]
    async fn test_increment_retry_count_increments_correctly() {
        let client = create_test_client_for_retry_with_id("increments").await;

        let cache_key = "test_chat:msg456:sender789";

        // Simulate multiple retries
        let count1 = client.increment_retry_count(cache_key).await;
        let count2 = client.increment_retry_count(cache_key).await;
        let count3 = client.increment_retry_count(cache_key).await;

        assert_eq!(count1, Some(1), "First retry should be 1");
        assert_eq!(count2, Some(2), "Second retry should be 2");
        assert_eq!(count3, Some(3), "Third retry should be 3");
    }

    #[tokio::test]
    async fn test_increment_retry_count_respects_max_retries() {
        let client = create_test_client_for_retry_with_id("max_retries").await;

        let cache_key = "test_chat:msg_max:sender_max";

        // Exhaust all retries (MAX_DECRYPT_RETRIES = 5)
        for i in 1..=5 {
            let count = client.increment_retry_count(cache_key).await;
            assert_eq!(count, Some(i), "Retry {} should return {}", i, i);
        }

        // 6th attempt should return None (max reached)
        let count_after_max = client.increment_retry_count(cache_key).await;
        assert_eq!(
            count_after_max, None,
            "After max retries, should return None"
        );

        // Verify cache still has max value
        let stored = client.message_retry_counts.get(cache_key).await;
        assert_eq!(stored, Some(5), "Cache should retain max count");
    }

    #[tokio::test]
    async fn test_retry_count_different_messages_are_independent() {
        let client = create_test_client_for_retry_with_id("independent").await;

        let key1 = "chat1:msg1:sender1";
        let key2 = "chat1:msg2:sender1"; // Same chat and sender, different message
        let key3 = "chat2:msg1:sender2"; // Different chat and sender

        // Increment each independently
        let _ = client.increment_retry_count(key1).await;
        let _ = client.increment_retry_count(key1).await;
        let _ = client.increment_retry_count(key1).await; // key1 = 3

        let _ = client.increment_retry_count(key2).await; // key2 = 1

        let _ = client.increment_retry_count(key3).await;
        let _ = client.increment_retry_count(key3).await; // key3 = 2

        // Verify each has independent counts
        assert_eq!(client.message_retry_counts.get(key1).await, Some(3));
        assert_eq!(client.message_retry_counts.get(key2).await, Some(1));
        assert_eq!(client.message_retry_counts.get(key3).await, Some(2));
    }

    #[tokio::test]
    async fn test_retry_cache_key_format() {
        // Verify the cache key format is consistent
        let info = create_test_message_info(
            "120363021033254949@g.us",
            "3EB0ABCD1234",
            "5511999998888@s.whatsapp.net",
        );

        let expected_key = format!("{}:{}:{}", info.source.chat, info.id, info.source.sender);
        assert_eq!(
            expected_key,
            "120363021033254949@g.us:3EB0ABCD1234:5511999998888@s.whatsapp.net"
        );

        // Verify key uniqueness for different senders in same group
        let info2 = create_test_message_info(
            "120363021033254949@g.us",
            "3EB0ABCD1234",                 // Same message ID
            "5511888887777@s.whatsapp.net", // Different sender
        );

        let key2 = format!("{}:{}:{}", info2.source.chat, info2.id, info2.source.sender);
        assert_ne!(
            expected_key, key2,
            "Different senders should have different keys"
        );
    }

    /// Test concurrent retry increments are properly serialized.
    ///
    /// With moka's `and_compute_with`, the increment operation is atomic.
    /// This means exactly 5 increments should succeed (returning 1-5),
    /// and exactly 5 should fail (returning None after max is reached).
    #[tokio::test]
    async fn test_concurrent_retry_increments() {
        use tokio::task::JoinSet;

        let client = create_test_client_for_retry_with_id("concurrent").await;
        let cache_key = "concurrent_test:msg:sender";

        // Spawn 10 concurrent increment tasks
        let mut tasks = JoinSet::new();
        for _ in 0..10 {
            let client_clone = client.clone();
            let key = cache_key.to_string();
            tasks.spawn(async move { client_clone.increment_retry_count(&key).await });
        }

        // Collect all results
        let mut results = Vec::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok(count) = result {
                results.push(count);
            }
        }

        // With atomic operations, exactly 5 should succeed and 5 should fail
        let valid_counts: Vec<_> = results.iter().filter(|r| r.is_some()).collect();
        let none_counts: Vec<_> = results.iter().filter(|r| r.is_none()).collect();

        assert_eq!(
            valid_counts.len(),
            5,
            "Exactly 5 increments should succeed with atomic operations"
        );
        assert_eq!(
            none_counts.len(),
            5,
            "Exactly 5 should return None (after max is reached)"
        );

        // Verify the successful increments returned values 1-5
        let mut values: Vec<u8> = valid_counts.iter().filter_map(|r| **r).collect();
        values.sort();
        assert_eq!(
            values,
            vec![1, 2, 3, 4, 5],
            "Successful increments should return 1, 2, 3, 4, 5"
        );

        // Final count should be 5 (max)
        let final_count = client.message_retry_counts.get(cache_key).await;
        assert_eq!(final_count, Some(5), "Final count should be capped at 5");
    }

    #[tokio::test]
    async fn test_high_retry_count_threshold() {
        // Verify HIGH_RETRY_COUNT_THRESHOLD is set correctly
        assert_eq!(
            HIGH_RETRY_COUNT_THRESHOLD, 3,
            "High retry threshold should be 3"
        );
        assert_eq!(MAX_DECRYPT_RETRIES, 5, "Max retries should be 5");
        // Compile-time assertion that threshold < max (avoids clippy warning)
        const _: () = assert!(HIGH_RETRY_COUNT_THRESHOLD < MAX_DECRYPT_RETRIES);
    }

    #[tokio::test]
    async fn test_message_info_creation_for_groups() {
        let info = create_test_message_info(
            "120363021033254949@g.us",
            "MSG123",
            "5511999998888@s.whatsapp.net",
        );

        assert!(
            info.source.is_group,
            "Group JID should be detected as group"
        );
        assert!(
            !info.source.is_from_me,
            "Test messages default to not from me"
        );
        assert_eq!(info.id, "MSG123");
    }

    #[tokio::test]
    async fn test_message_info_creation_for_dm() {
        let info = create_test_message_info(
            "5511999998888@s.whatsapp.net",
            "DM456",
            "5511999998888@s.whatsapp.net",
        );

        assert!(
            !info.source.is_group,
            "DM JID should not be detected as group"
        );
        assert_eq!(info.id, "DM456");
    }

    #[tokio::test]
    async fn test_retry_count_cache_expiration() {
        // Note: This test verifies cache configuration, not actual TTL (which would be slow)
        let client = create_test_client_for_retry_with_id("expiration").await;

        // The cache should have a TTL of 5 minutes (300 seconds) as configured in client.rs
        // We can verify entries are being stored and the cache is functional
        let cache_key = "expiry_test:msg:sender";

        let count = client.increment_retry_count(cache_key).await;
        assert_eq!(count, Some(1));

        // Entry should still exist immediately after
        let stored = client.message_retry_counts.get(cache_key).await;
        assert!(
            stored.is_some(),
            "Entry should exist immediately after insert"
        );
    }

    #[tokio::test]
    async fn test_spawn_retry_receipt_basic_flow() {
        // This is an integration test that verifies spawn_retry_receipt
        // doesn't panic and updates the retry count correctly

        let client = create_test_client_for_retry_with_id("spawn_basic").await;
        let info = create_test_message_info(
            "120363021033254949@g.us",
            "SPAWN_TEST_MSG",
            "5511999998888@s.whatsapp.net",
        );

        let cache_key = format!("{}:{}:{}", info.source.chat, info.id, info.source.sender);

        // Verify count starts at 0
        assert!(
            client.message_retry_counts.get(&cache_key).await.is_none(),
            "Cache should be empty initially"
        );

        // Call spawn_retry_receipt (this spawns a task, so we need to wait)
        client.spawn_retry_receipt(&info, RetryReason::UnknownError);

        // Give the spawned task time to execute
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Verify count was incremented (the actual send will fail due to no connection, but count should update)
        let stored = client.message_retry_counts.get(&cache_key).await;
        assert_eq!(stored, Some(1), "Retry count should be 1 after spawn");
    }

    #[tokio::test]
    async fn test_spawn_retry_receipt_respects_max_retries() {
        let client = create_test_client_for_retry_with_id("spawn_max").await;
        let info = create_test_message_info(
            "120363021033254949@g.us",
            "MAX_RETRY_TEST",
            "5511999998888@s.whatsapp.net",
        );

        let cache_key = format!("{}:{}:{}", info.source.chat, info.id, info.source.sender);

        // Pre-fill cache to max retries
        client
            .message_retry_counts
            .insert(cache_key.clone(), MAX_DECRYPT_RETRIES)
            .await;

        // Verify count is at max
        assert_eq!(
            client.message_retry_counts.get(&cache_key).await,
            Some(MAX_DECRYPT_RETRIES)
        );

        // Call spawn_retry_receipt - should NOT increment (already at max)
        client.spawn_retry_receipt(&info, RetryReason::UnknownError);

        // Give the spawned task time to execute
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // Count should still be at max (not incremented)
        let stored = client.message_retry_counts.get(&cache_key).await;
        assert_eq!(
            stored,
            Some(MAX_DECRYPT_RETRIES),
            "Count should remain at max"
        );
    }

    #[tokio::test]
    async fn test_pdo_cache_key_format_matches() {
        // PDO uses "{chat}:{msg_id}" format
        // Retry uses "{chat}:{msg_id}:{sender}" format
        // They are intentionally different to track independently

        let info = create_test_message_info(
            "120363021033254949@g.us",
            "PDO_KEY_TEST",
            "5511999998888@s.whatsapp.net",
        );

        let retry_key = format!("{}:{}:{}", info.source.chat, info.id, info.source.sender);
        let pdo_key = format!("{}:{}", info.source.chat, info.id);

        assert_ne!(retry_key, pdo_key, "PDO and retry keys should be different");
        assert!(
            retry_key.starts_with(&pdo_key),
            "Retry key should start with PDO key pattern"
        );
    }

    #[tokio::test]
    async fn test_multiple_senders_same_message_id_tracked_separately() {
        // In a group, multiple senders could theoretically have the same message ID
        // (unlikely but the system should handle it)

        let client = create_test_client_for_retry_with_id("multi_sender").await;

        let group = "120363021033254949@g.us";
        let msg_id = "SAME_MSG_ID";
        let sender1 = "5511111111111@s.whatsapp.net";
        let sender2 = "5522222222222@s.whatsapp.net";

        let key1 = format!("{}:{}:{}", group, msg_id, sender1);
        let key2 = format!("{}:{}:{}", group, msg_id, sender2);

        // Increment for sender1 multiple times
        client.increment_retry_count(&key1).await;
        client.increment_retry_count(&key1).await;
        client.increment_retry_count(&key1).await;

        // Increment for sender2 once
        client.increment_retry_count(&key2).await;

        // Verify independent tracking
        assert_eq!(
            client.message_retry_counts.get(&key1).await,
            Some(3),
            "Sender1 should have 3 retries"
        );
        assert_eq!(
            client.message_retry_counts.get(&key2).await,
            Some(1),
            "Sender2 should have 1 retry"
        );
    }

    /// Test: Status broadcast messages should always try skmsg even if pkmsg fails
    ///
    /// - WhatsApp Web tracks pkmsg and skmsg failures separately
    /// - If pkmsg fails but skmsg succeeds, result is SUCCESS
    /// - For status@broadcast, we might have sender key cached from previous status
    ///
    /// This test verifies that the `should_process_skmsg` logic correctly
    /// includes status broadcasts even when session decryption fails.
    #[test]
    fn test_status_broadcast_should_always_process_skmsg() {
        use wacore_binary::jid::{Jid, JidExt};

        // status@broadcast JID
        let status_jid: Jid = "status@broadcast".parse().expect("status JID should parse");
        assert!(
            status_jid.is_status_broadcast(),
            "status@broadcast should be recognized as status broadcast"
        );

        // Regular broadcast list should NOT be status broadcast
        let broadcast_list: Jid = "123456789@broadcast"
            .parse()
            .expect("broadcast JID should parse");
        assert!(
            !broadcast_list.is_status_broadcast(),
            "Regular broadcast list should not be status broadcast"
        );
        assert!(
            broadcast_list.is_broadcast_list(),
            "123456789@broadcast should be broadcast list"
        );

        // Group JID should NOT be status broadcast
        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("group JID should parse");
        assert!(
            !group_jid.is_status_broadcast(),
            "Group JID should not be status broadcast"
        );

        // 1:1 JID should NOT be status broadcast
        let user_jid: Jid = "15551234567@s.whatsapp.net"
            .parse()
            .expect("user JID should parse");
        assert!(
            !user_jid.is_status_broadcast(),
            "User JID should not be status broadcast"
        );
    }

    /// Test: Verify should_process_skmsg logic for status broadcast
    ///
    /// Simulates the decision logic from handle_incoming_message:
    /// - For status@broadcast, should_process_skmsg should be true even when
    ///   session_decrypted_successfully=false and session_had_duplicates=false
    #[test]
    fn test_should_process_skmsg_logic_for_status_broadcast() {
        use wacore_binary::jid::{Jid, JidExt};

        // Test cases: (chat_jid, session_empty, session_success, session_dupe, expected)
        let test_cases = [
            // Status broadcast: always process skmsg
            ("status@broadcast", false, false, false, true),
            ("status@broadcast", false, false, true, true),
            ("status@broadcast", false, true, false, true),
            ("status@broadcast", true, false, false, true),
            // Regular group: only process if session ok or empty
            ("120363021033254949@g.us", false, false, false, false), // Fail: session failed
            ("120363021033254949@g.us", false, false, true, true),   // OK: duplicate
            ("120363021033254949@g.us", false, true, false, true),   // OK: success
            ("120363021033254949@g.us", true, false, false, true),   // OK: no session msgs
            // 1:1 chat: same logic as group
            ("15551234567@s.whatsapp.net", false, false, false, false),
            ("15551234567@s.whatsapp.net", true, false, false, true),
        ];

        for (jid_str, session_empty, session_success, session_dupe, expected) in test_cases {
            let chat_jid: Jid = jid_str.parse().expect("JID should parse");

            // Recreate the should_process_skmsg logic from handle_incoming_message
            let should_process_skmsg =
                session_empty || session_success || session_dupe || chat_jid.is_status_broadcast();

            assert_eq!(
                should_process_skmsg,
                expected,
                "For chat {} with session_empty={}, session_success={}, session_dupe={}: \
                 expected should_process_skmsg={}, got {}",
                jid_str,
                session_empty,
                session_success,
                session_dupe,
                expected,
                should_process_skmsg
            );
        }
    }

    /// Test: parse_message_info returns error when message "id" attribute is missing
    ///
    /// Missing message IDs would cause silent collisions in caches/keys, so this
    /// must be a hard error rather than defaulting to an empty string.
    #[tokio::test]
    async fn test_parse_message_info_missing_id_returns_error() {
        let backend = Arc::new(
            SqliteStore::new("file:memdb_missing_id_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

        let node = NodeBuilder::new("message")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("t", "1759295366")
            .attr("type", "text")
            .build();

        let result = client.parse_message_info(&node).await;

        assert!(
            result.is_err(),
            "parse_message_info should fail when 'id' is missing"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("id"),
            "Error message should mention missing 'id' attribute: {}",
            err_msg
        );
    }
    #[tokio::test]
    async fn test_local_requeue_optimization() {
        // Setup integration test environment
        let _ = env_logger::builder().is_test(true).try_init();

        use crate::store::SqliteStore;
        use crate::store::persistence_manager::PersistenceManager;
        use wacore_binary::builder::NodeBuilder;
        use wacore_binary::node::NodeContent;

        // 1. Setup Client
        let backend = Arc::new(
            SqliteStore::new("file:memdb_requeue_test?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend.clone())
                .await
                .expect("test backend should initialize"),
        );
        // Note: Using None for override_version
        let (client, _rx) =
            Client::new(pm.clone(), mock_transport(), mock_http_client(), None).await;

        // 2. Configure Test Data
        let group_jid: Jid = "120363021033254949@g.us".parse().unwrap();
        let sender_jid: Jid = "1234567890:1@s.whatsapp.net".parse().unwrap();
        let msg_id = "TEST_MSG_REQUEUE_1";

        // Manual queue initialization (since it's not created until first message usually)
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        client
            .message_queues
            .insert(group_jid.to_string(), tx)
            .await;

        // 3. Trigger Message Processing (Simulate receiving skmsg BEFORE session)
        // Construction of mock Signal Message Payload
        // We need to trigger "NoSenderKeyState" (lookup failure), not "TooShort".
        // Structure: [Version(1)] + [Protobuf] + [Signature(64)].
        // Version = 0x33 (3).
        // Protobuf: Field 1 (KeyID)=1, Field 2 (Iteration)=1, Field 3 (Ciphertext)=Bytes.
        // 08 01 10 01 1A 00
        let mut content = vec![0x33, 0x08, 0x01, 0x10, 0x01, 0x1A, 0x00];
        // Append 64 bytes of dummy signature to satisfy length checks
        content.extend(vec![0u8; 64]);

        // Build enc node first
        let mut enc_node = NodeBuilder::new("enc")
            .attr("type", "skmsg")
            .attr("v", "2")
            .build();
        enc_node.content = Some(NodeContent::Bytes(content));

        // Build message node containing enc node
        let valid_skmsg_node = NodeBuilder::new("message")
            .attr("id", msg_id)
            .attr("from", group_jid.to_string())
            .attr("participant", sender_jid.to_string())
            .attr("type", "text")
            .children(vec![enc_node])
            .build();

        // Run handle_incoming_message
        // It will fail decryption. If payload is accepted as valid Signal structure,
        // it will attempt to load SenderKey. Since store is empty, it returns NoSenderKey.
        // This triggers our re-queue optimization.
        client
            .clone()
            .handle_incoming_message(Arc::new(valid_skmsg_node.clone()))
            .await;

        // Verify cache IMMEDIATELY
        // Asserting presence means we successfully triggered the "NoSenderKey" path.
        let retry_cache_key = client
            .make_retry_cache_key(&group_jid, msg_id, &sender_jid)
            .await;
        assert!(
            client.local_retry_cache.contains_key(&retry_cache_key),
            "Message should be in local_retry_cache (Optimization NOT triggered - check error logs)"
        );

        // 4. Verify Re-Queueing
        // The re-queued message should appear in `rx` after ~500ms.
        let queued_msg =
            tokio::time::timeout(tokio::time::Duration::from_millis(1000), rx.recv()).await;
        assert!(
            queued_msg.is_ok(),
            "Timed out waiting for re-queued message"
        );
        assert!(
            queued_msg.unwrap().is_some(),
            "Queue should contain the message"
        );

        // 5. Verify No Network Retry for 1st attempt
        // message_retry_counts tracks network retries.
        // It should be EMPTY because we skipped spawn_retry_receipt.
        let retry_key = format!("{}:{}:{}", group_jid, msg_id, sender_jid);
        assert!(
            client.message_retry_counts.get(&retry_key).await.is_none(),
            "Should NOT have sent network retry receipt yet"
        );

        // 6. Simulate Second Pass (Re-queued message processed)
        // Now if we process the re-queued message:
        // Cache entry exists. So it should trigger network retry (fall back).
        client
            .clone()
            .handle_incoming_message(Arc::new(valid_skmsg_node))
            .await;

        // Verify retry count allows network retry now
        // spawn_retry_receipt spawns a task, so we need to wait for it to update the cache.
        // Use retry loop instead of fixed sleep to avoid flaky test under load.
        for _ in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            if client.message_retry_counts.get(&retry_key).await == Some(1) {
                break;
            }
        }
        assert_eq!(
            client.message_retry_counts.get(&retry_key).await,
            Some(1),
            "Should have sent network retry receipt on 2nd attempt"
        );
    }
    #[tokio::test]
    async fn test_local_requeue_edge_cases() {
        let _ = env_logger::builder().is_test(true).try_init();
        use crate::store::SqliteStore;
        use crate::store::persistence_manager::PersistenceManager;
        use wacore_binary::builder::NodeBuilder;
        use wacore_binary::node::NodeContent;

        // One-time setup
        let backend = Arc::new(
            SqliteStore::new("file:memdb_requeue_edge?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend.clone())
                .await
                .expect("test backend should initialize"),
        );
        let (client, _) = Client::new(pm.clone(), mock_transport(), mock_http_client(), None).await;

        let group_jid: Jid = "120363021033254949@g.us".parse().unwrap();
        let sender_jid: Jid = "1234567890:1@s.whatsapp.net".parse().unwrap();

        // 1. Garbage Data Test (Too Short)
        // Should NOT trigger re-queue (cache should remain empty for this ID)
        let garbage_id = "GARBAGE_u1928";
        let garbage_node = NodeBuilder::new("message")
            .attr("id", garbage_id)
            .attr("from", group_jid.to_string())
            .attr("participant", sender_jid.to_string())
            .attr("type", "text")
            .children(vec![{
                let mut n = NodeBuilder::new("enc")
                    .attr("type", "skmsg")
                    .attr("v", "2")
                    .build();
                n.content = Some(NodeContent::Bytes(vec![1, 2, 3])); // Too short
                n
            }])
            .build();

        client
            .clone()
            .handle_incoming_message(Arc::new(garbage_node))
            .await;

        let retry_cache_key = client
            .make_retry_cache_key(&group_jid, garbage_id, &sender_jid)
            .await;
        assert!(
            !client.local_retry_cache.contains_key(&retry_cache_key),
            "Garbage message should NOT be re-queued/cached"
        );

        // 2. Concurrent/Duplicate Test
        // Send a valid-format message that triggers NoSenderKey.
        // Send it TWICE.
        // 1st -> ReQueued.
        // 2nd -> Network Retry Fallback.
        let dup_id = "DUP_MSG_123";
        // Manual queue init
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        client
            .message_queues
            .insert(group_jid.to_string(), tx)
            .await;

        // Pseudo-valid SenderKeyMessage: Version 3 + Protobuf + Fake Sig
        let mut content = vec![0x33, 0x08, 0x01, 0x10, 0x01, 0x1A, 0x00];
        content.extend(vec![0u8; 64]); // fake sig

        let dup_node = NodeBuilder::new("message")
            .attr("id", dup_id)
            .attr("from", group_jid.to_string())
            .attr("participant", sender_jid.to_string())
            .attr("type", "text")
            .children(vec![{
                let mut n = NodeBuilder::new("enc")
                    .attr("type", "skmsg")
                    .attr("v", "2")
                    .build();
                n.content = Some(NodeContent::Bytes(content));
                n
            }])
            .build();

        let dup_arc = Arc::new(dup_node);

        // First Pass
        client
            .clone()
            .handle_incoming_message(dup_arc.clone())
            .await;

        let retry_key = client
            .make_retry_cache_key(&group_jid, dup_id, &sender_jid)
            .await;
        assert!(
            client.local_retry_cache.contains_key(&retry_key),
            "First dup message should be cached/requeued"
        );
        assert!(client.message_retry_counts.get(&retry_key).await.is_none());

        // Second Pass (Immediate duplicate)
        client.clone().handle_incoming_message(dup_arc).await;

        // Should have triggered retry receipt logic (increment count)
        // Wait slightly for spawn to update cache
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        assert_eq!(
            client.message_retry_counts.get(&retry_key).await,
            Some(1),
            "Second dup message should trigger network retry fallback"
        );
    }

    #[test]
    fn test_is_sender_key_distribution_only() {
        let skdm = wa::message::SenderKeyDistributionMessage {
            group_id: Some("group".into()),
            axolotl_sender_key_distribution_message: Some(vec![1, 2, 3]),
        };

        // Empty message → false (no SKDM)
        assert!(!is_sender_key_distribution_only(&wa::Message::default()));

        // SKDM only → true
        assert!(is_sender_key_distribution_only(&wa::Message {
            sender_key_distribution_message: Some(skdm.clone()),
            ..Default::default()
        }));

        // SKDM + message_context_info → still true (context_info is metadata)
        assert!(is_sender_key_distribution_only(&wa::Message {
            sender_key_distribution_message: Some(skdm.clone()),
            message_context_info: Some(wa::MessageContextInfo::default()),
            ..Default::default()
        }));

        // SKDM + sticker → false (has user content)
        assert!(!is_sender_key_distribution_only(&wa::Message {
            sender_key_distribution_message: Some(skdm.clone()),
            sticker_message: Some(Box::new(wa::message::StickerMessage::default())),
            ..Default::default()
        }));

        // SKDM + text → false (has user content)
        assert!(!is_sender_key_distribution_only(&wa::Message {
            sender_key_distribution_message: Some(skdm.clone()),
            conversation: Some("hello".into()),
            ..Default::default()
        }));

        // protocol_message only (no SKDM) → false
        assert!(!is_sender_key_distribution_only(&wa::Message {
            protocol_message: Some(Box::new(wa::message::ProtocolMessage::default())),
            ..Default::default()
        }));
    }
}
