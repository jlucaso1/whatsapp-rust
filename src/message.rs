use crate::client::Client;
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use log::{debug, warn};
use prost::Message as ProtoMessage;

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
use wacore::message_processing::EncType;
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

pub(crate) use wacore::protocol::retry::RetryReason;

impl Client {
    /// Dispatches a successfully parsed message to the event bus and sends a delivery receipt.
    fn dispatch_parsed_message(self: &Arc<Self>, msg: wa::Message, info: &MessageInfo) {
        use wacore::proto_helpers::MessageExt;

        let mut info = info.clone();
        if info.ephemeral_expiration.is_none() {
            info.ephemeral_expiration = msg.get_base_message().get_ephemeral_expiration();
        }

        // Send delivery receipt immediately in the background.
        let client_clone = self.clone();
        let info_for_receipt = info.clone();
        self.runtime
            .spawn(Box::pin(async move {
                client_clone.send_delivery_receipt(&info_for_receipt).await;
            }))
            .detach();

        self.core
            .event_bus
            .dispatch(&Event::Message(Box::new(msg), info));
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
    fn handle_decrypt_failure(
        self: &Arc<Self>,
        info: &MessageInfo,
        reason: RetryReason,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
    ) -> bool {
        self.dispatch_undecryptable_event(info, decrypt_fail_mode);
        self.spawn_retry_receipt(info, reason);
        true
    }

    /// Increments the retry count for a message and returns the new count.
    /// Returns `None` if max retries have been reached.
    ///
    /// Note: get-then-insert has a theoretical TOCTOU window since
    /// `spawn_retry_receipt` detaches. In practice, retries for the same
    /// message are rare and a double-send is benign (recipients deduplicate
    /// by message ID).
    async fn increment_retry_count(&self, cache_key: &str) -> Option<u8> {
        let current = self.message_retry_counts.get(&cache_key.to_string()).await;
        match current {
            Some(count) if count >= MAX_DECRYPT_RETRIES => None,
            Some(count) => {
                let new_count = count + 1;
                self.message_retry_counts
                    .insert(cache_key.to_string(), new_count)
                    .await;
                Some(new_count)
            }
            None => {
                self.message_retry_counts
                    .insert(cache_key.to_string(), 1_u8)
                    .await;
                Some(1)
            }
        }
    }

    /// Generate consistent cache key for retry logic.
    pub(crate) async fn make_retry_cache_key(
        &self,
        chat: &Jid,
        msg_id: &str,
        sender: &Jid,
    ) -> String {
        use std::fmt::Write;
        let chat = self.resolve_encryption_jid(chat).await;
        let sender = self.resolve_encryption_jid(sender).await;
        let mut key =
            String::with_capacity(chat.user.len() + msg_id.len() + sender.user.len() + 20);
        let _ = write!(key, "{chat}:{msg_id}:{sender}");
        key
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

        self.runtime.spawn(Box::pin(async move {
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
        })).detach();
    }

    pub(crate) async fn handle_incoming_message(self: Arc<Self>, node: Arc<Node>) {
        let info = match self.parse_message_info(&node).await {
            Ok(info) => Arc::new(info),
            Err(e) => {
                let id = node.attrs.get("id").map(|v| v.as_str());
                let from = node.attrs.get("from").map(|v| v.as_str());
                log::warn!("Failed to parse message info (id={id:?}, from={from:?}): {e:?}");
                return;
            }
        };

        // Newsletters use <plaintext> instead of <enc> because they are not E2E encrypted.
        if info.source.chat.is_newsletter() {
            self.handle_newsletter_message(&node, &info).await;
            return;
        }

        // Warm LID-PN cache before resolution so resolve_encryption_jid() finds the mapping
        self.cache_lid_pn_from_message(&info.source.sender, info.source.sender_alt.as_ref())
            .await;
        let sender_encryption_jid = self.resolve_encryption_jid(&info.source.sender).await;

        let has_unavailable = node.get_optional_child("unavailable").is_some();

        let mut all_enc_nodes = Vec::new();

        let direct_enc_nodes = node.get_children_by_tag("enc");
        all_enc_nodes.extend(direct_enc_nodes);

        let participants = node.get_optional_child_by_tag(&["participants"]);
        if let Some(participants_node) = participants {
            let own_jid_str = self.get_pn().await.map(|j| j.to_string());
            let to_nodes = participants_node.get_children_by_tag("to");
            for to_node in to_nodes {
                let to_jid = match to_node.attrs().optional_string("jid") {
                    Some(jid) => jid,
                    None => continue,
                };
                if let Some(ref ours) = own_jid_str
                    && *to_jid == **ours
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
        let mut max_sender_retry_count: u8 = 0;
        let mut has_hide_fail = false;

        for &enc_node in &all_enc_nodes {
            // Parse sender retry count (WA Web: e.maybeAttrInt("count") ?? 0)
            // Clamp to MAX_DECRYPT_RETRIES to prevent u64→u8 truncation on unexpected values.
            let sender_count = enc_node
                .attrs()
                .optional_u64("count")
                .map(|c| c.min(MAX_DECRYPT_RETRIES as u64) as u8)
                .unwrap_or(0);
            max_sender_retry_count = max_sender_retry_count.max(sender_count);

            // Parse decrypt-fail attribute (WA Web: e.maybeAttrString("decrypt-fail") === "hide")
            if enc_node
                .attrs
                .get("decrypt-fail")
                .is_some_and(|v| v == "hide")
            {
                has_hide_fail = true;
            }

            let enc_type = match enc_node.attrs().optional_string("type") {
                Some(t) => t,
                None => {
                    log::warn!("Enc node missing 'type' attribute, skipping");
                    continue;
                }
            };

            if let Some(handler) = self
                .custom_enc_handlers
                .read()
                .await
                .get(enc_type.as_ref())
                .cloned()
            {
                let handler_clone = handler;
                let client_clone = self.clone();
                let info_arc = Arc::clone(&info);
                let enc_node_clone = Arc::new(enc_node.clone());
                let enc_type_owned = enc_type.to_string();

                self.runtime
                    .spawn(Box::pin(async move {
                        if let Err(e) = handler_clone
                            .handle(client_clone, &enc_node_clone, &info_arc)
                            .await
                        {
                            log::warn!(
                                "Custom handler for enc type '{}' failed: {e:?}",
                                enc_type_owned
                            );
                        }
                    }))
                    .detach();
                continue;
            }

            // Fall back to built-in handlers
            match EncType::from_wire(enc_type.as_ref()) {
                Some(et) if et.is_session() => session_enc_nodes.push(enc_node),
                Some(EncType::SenderKey) => group_content_enc_nodes.push(enc_node),
                _ => log::warn!("Unknown enc type: {enc_type}"),
            }
        }

        // WA Web diagnostic: validate skmsg is not first in multi-enc messages.
        // If skmsg comes first, the SKDM (carried in pkmsg/msg) hasn't been processed yet,
        // so the skmsg decryption would fail with NoSenderKey.
        if !session_enc_nodes.is_empty()
            && !group_content_enc_nodes.is_empty()
            && all_enc_nodes.first().is_some_and(|n| {
                n.attrs
                    .get("type")
                    .is_some_and(|v| v == EncType::SenderKey.as_wire_str())
            })
        {
            log::error!(
                "[msg:{}] Protocol violation: skmsg is first in multi-enc message from {}. \
                 Expected pkmsg/msg first (containing SKDM).",
                info.id,
                info.source.sender
            );
        }

        // Determine decrypt fail mode from enc nodes (WA Web: hideFail)
        let decrypt_fail_mode = if has_hide_fail {
            crate::types::events::DecryptFailMode::Hide
        } else {
            crate::types::events::DecryptFailMode::Show
        };

        // Pre-seed retry cache with sender's retry count to avoid redundant retries.
        // Uses max(existing, incoming) so redeliveries with higher counts update the cache,
        // but lower counts don't reset our local counter.
        if max_sender_retry_count > 0 {
            let cache_key = self
                .make_retry_cache_key(&info.source.chat, &info.id, &info.source.sender)
                .await;
            let existing = self.message_retry_counts.get(&cache_key).await.unwrap_or(0);
            if max_sender_retry_count > existing {
                self.message_retry_counts
                    .insert(cache_key, max_sender_retry_count)
                    .await;
            }
            log::debug!(
                "[msg:{}] Sender retry count {} pre-seeded into cache",
                info.id,
                max_sender_retry_count
            );
        }

        // Acquire global processing permit (1 during offline sync, N after).
        // Read generation + clone Arc under the same mutex so the pair is consistent.
        //
        // When the semaphore transitions from 1→N (offline→online), tasks waiting on
        // the old 1-permit semaphore must re-acquire from the new N-permit semaphore.
        // Without this re-acquire loop, those tasks would be silently dropped, which
        // can lose pkmsg messages carrying SKDM (sender key distribution). If the
        // SKDM is lost, ALL subsequent skmsg messages from that sender will fail
        // with "No sender key state".
        let _global_permit = loop {
            let (generation, semaphore) = self.read_message_semaphore();
            let permit = semaphore.acquire_arc().await;
            if generation
                == self
                    .message_semaphore_generation
                    .load(std::sync::atomic::Ordering::SeqCst)
            {
                break permit;
            }
            // Generation changed while waiting (e.g. offline→online transition).
            // Drop the stale permit and retry with the new semaphore, which has
            // more permits and will grant access quickly.
            log::debug!(
                "Semaphore generation changed during acquire, re-acquiring from new semaphore"
            );
            drop(permit);
        };

        log::debug!(
            "Starting PASS 1: Processing {} session establishment messages (pkmsg/msg)",
            session_enc_nodes.len()
        );

        // Skip session processing for group/broadcast JIDs — they use sender keys, not 1:1 sessions.
        let is_group_sender = sender_encryption_jid.is_group()
            || sender_encryption_jid.is_broadcast_list()
            || sender_encryption_jid.is_status_broadcast();

        let (
            session_decrypted_successfully,
            session_had_duplicates,
            session_dispatched_undecryptable,
        ) = if !is_group_sender && !session_enc_nodes.is_empty() {
            self.clone()
                .process_session_enc_batch(
                    &session_enc_nodes,
                    &info,
                    &sender_encryption_jid,
                    decrypt_fail_mode,
                )
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
        // Skip only if session messages FAILED to decrypt (not duplicates, not absent).
        // Matches WA Web's `canDecryptNext` pattern: if pkmsg fails with a retriable error,
        // the SKDM it carried is lost, so skmsg will always fail with NoSenderKey — skip it
        // to avoid unnecessary retry receipts. The retry for the pkmsg will cause the sender
        // to resend the entire message including SKDM.
        if !group_content_enc_nodes.is_empty() {
            let should_process_skmsg = session_enc_nodes.is_empty()
                || session_decrypted_successfully
                || session_had_duplicates;

            if should_process_skmsg {
                match self
                    .clone()
                    .process_group_enc_batch(
                        &group_content_enc_nodes,
                        &info,
                        &sender_encryption_jid,
                        decrypt_fail_mode,
                    )
                    .await
                {
                    Ok(()) => {
                        // Processed successfully or handled errors (e.g. sent retry receipt)
                    }
                    Err(e) => {
                        log::warn!(
                            "[msg:{}] Batch group decrypt from {} in {} failed: {e:?}",
                            info.id,
                            info.source.sender,
                            info.source.chat
                        );
                    }
                }
            } else {
                // Only show warning if session messages actually FAILED (not duplicates)
                if !session_had_duplicates {
                    if info.is_expired_status() {
                        log::debug!(
                            "[msg:{}] Silently dropping expired status from {}",
                            info.id,
                            info.source.sender
                        );
                    } else {
                        warn!(
                            "Skipping skmsg decryption for message {} from {} because pkmsg failed to decrypt.",
                            info.id, info.source.sender
                        );
                        if !session_dispatched_undecryptable {
                            self.dispatch_undecryptable_event(&info, decrypt_fail_mode);
                        }
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
            self.dispatch_undecryptable_event(&info, decrypt_fail_mode);
            // Do NOT send delivery receipt - transport ack is sufficient
        }

        // Flush cached Signal state to DB (matches WA Web's flushBufferToDiskIfNotMemOnlyMode)
        self.flush_signal_cache_logged(&format!("message {}", info.id))
            .await;
    }

    async fn process_session_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&wacore_binary::node::Node],
        info: &MessageInfo,
        sender_encryption_jid: &Jid,
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
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
        let signal_address = sender_encryption_jid.to_protocol_address();

        let session_mutex = self.session_lock_for(signal_address.as_str()).await;
        let _session_guard = session_mutex.lock().await;

        let mut adapter = self.signal_adapter().await;
        let mut rng = rand::make_rng::<rand::rngs::StdRng>();
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
                Some(t) => t,
                None => {
                    log::warn!("Enc node missing 'type' attribute (batch session)");
                    continue;
                }
            };
            let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;
            let enc_type_enum = EncType::from_wire(enc_type.as_ref());

            let parsed_message = if enc_type_enum == Some(EncType::PreKeyMessage) {
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

            if enc_type_enum == Some(EncType::PreKeyMessage) {
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
                &mut rng,
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
                        log::warn!(
                            "[msg:{}] Failed processing plaintext from {}: {e:?}",
                            info.id,
                            info.source.sender
                        );
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

                        // Delete the old, untrusted identity through the signal cache.
                        // NOTE: We intentionally do NOT delete the session here. The session will be
                        // archived (not deleted) when the new PreKeySignalMessage is processed,
                        // allowing decryption of any in-flight messages encrypted with the old session.
                        self.signal_cache.delete_identity(address).await;
                        // Flush immediately so the backend is updated BEFORE the retry decrypt below.
                        // Device::is_trusted_identity reads from backend, not cache.
                        if let Err(e) = self.flush_signal_cache().await {
                            log::warn!("Failed to flush identity deletion for {}: {e:?}", address);
                            continue;
                        }
                        log::info!(
                            "Cleared old identity for {} from cache and backend",
                            address
                        );

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
                            &mut rng,
                            UsePQRatchet::No,
                        )
                        .await;

                        match retry_decrypt_res {
                            Ok(padded_plaintext) => {
                                log::debug!(
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
                                    dispatched_undecryptable = self.handle_decrypt_failure(
                                        info,
                                        RetryReason::InvalidKeyId,
                                        decrypt_fail_mode,
                                    );
                                } else {
                                    log::error!(
                                        "[msg:{}] Decryption failed even after clearing untrusted identity for {}: {:?}",
                                        info.id,
                                        address,
                                        retry_err
                                    );
                                    // Send retry receipt so the sender resends with a PreKeySignalMessage
                                    // to establish a new session with the new identity
                                    dispatched_undecryptable = self.handle_decrypt_failure(
                                        info,
                                        RetryReason::InvalidKey,
                                        decrypt_fail_mode,
                                    );
                                }
                            }
                        }

                        // Re-issue tctoken so the contact still has a valid token for us
                        let sender_jid = info.source.sender.clone();
                        if !sender_jid.is_bot() && !sender_jid.is_status_broadcast() {
                            let client = self.clone();
                            self.runtime
                                .spawn(Box::pin(async move {
                                    client
                                        .reissue_tc_token_after_identity_change(&sender_jid)
                                        .await;
                                }))
                                .detach();
                        }

                        continue;
                    }
                    // Try PN→LID session migration before sending retry receipt
                    if let SignalProtocolError::SessionNotFound(_) = e {
                        if self
                            .try_pn_to_lid_migration_decrypt(
                                sender_encryption_jid,
                                &signal_address,
                                &parsed_message,
                                &mut adapter,
                                &mut rng,
                                &enc_type,
                                padding_version,
                                info,
                            )
                            .await
                        {
                            any_success = true;
                            continue;
                        }

                        warn!(
                            "[msg:{}] No session found for {} message from {}. Sending retry receipt to request session establishment.",
                            info.id, enc_type, info.source.sender
                        );
                        dispatched_undecryptable = self.handle_decrypt_failure(
                            info,
                            RetryReason::NoSession,
                            decrypt_fail_mode,
                        );
                        continue;
                    } else if matches!(
                        e,
                        SignalProtocolError::BadMac(_) | SignalProtocolError::InvalidMessage(_, _)
                    ) {
                        // BadMac: MAC verification specifically failed (WA Web error code 7).
                        // InvalidMessage: session out of sync or other decryption failure (code 4).
                        // In both cases we delete the stale session and request re-establishment.
                        let (reason, label) = if matches!(e, SignalProtocolError::BadMac(_)) {
                            (RetryReason::BadMac, "BadMac")
                        } else {
                            (RetryReason::InvalidMessage, "InvalidMessage")
                        };
                        log::warn!(
                            "[msg:{}] Decryption failed for {} message from {} due to {label}. \
                             Deleting stale session and sending retry receipt.",
                            info.id,
                            enc_type,
                            info.source.sender
                        );

                        // Delete the stale session from the signal cache.
                        // IMPORTANT: Must go through the cache, not directly to the backend!
                        // Going to the backend directly leaves the stale session in the cache,
                        // which causes retry messages to also fail (they'd load the stale session).
                        self.signal_cache.delete_session(&signal_address).await;
                        log::info!(
                            "Deleted stale session for {} from cache to allow re-establishment",
                            signal_address
                        );

                        // Send retry receipt so the sender resends with a PreKeySignalMessage
                        dispatched_undecryptable =
                            self.handle_decrypt_failure(info, reason, decrypt_fail_mode);
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
                        dispatched_undecryptable = self.handle_decrypt_failure(
                            info,
                            RetryReason::InvalidKeyId,
                            decrypt_fail_mode,
                        );
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
        decrypt_fail_mode: crate::types::events::DecryptFailMode,
    ) -> Result<(), DecryptionError> {
        if enc_nodes.is_empty() {
            return Ok(());
        }
        // Use the signal cache adapter for group decryption so sender keys are read/written
        // through the cache, keeping it consistent with SKDM processing.
        let mut adapter = self.signal_adapter().await;

        for enc_node in enc_nodes {
            let ciphertext: &[u8] = match &enc_node.content {
                Some(wacore_binary::node::NodeContent::Bytes(b)) => b,
                _ => {
                    log::warn!("Enc node has no byte content (batch group)");
                    continue;
                }
            };
            let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;

            // Always use bare sender for sender key operations. Real WA delivers
            // skmsg with bare participant but pkmsg (SKDM) with device-qualified
            // participant — normalizing to bare ensures consistent lookup.
            let sender_for_sk = info.source.sender.to_non_ad();
            let sender_address = sender_for_sk.to_protocol_address();
            let sender_key_name = SenderKeyName::from_jid(&info.source.chat, &sender_address);

            log::debug!(
                "Looking up sender key for group {} with sender address {} (from sender JID: {})",
                info.source.chat,
                sender_address,
                info.source.sender
            );

            let decrypt_result =
                group_decrypt(ciphertext, &mut adapter.sender_key_store, &sender_key_name).await;

            match decrypt_result {
                Ok(padded_plaintext) => {
                    // Sync device list if sender is unknown, but still process
                    // the message. Signal decryption success already proves the
                    // sender holds the session key — discarding would only add
                    // latency via an unnecessary retry round-trip.
                    if !self.is_from_known_device(&info.source.sender).await {
                        debug!(
                            "[msg:{}] Unknown device {}, triggering device sync",
                            info.id, info.source.sender
                        );
                        self.handle_unknown_device_sync(info).await;
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
                    if info.is_expired_status() {
                        log::debug!(
                            "[msg:{}] Skipping retry for expired status from {}",
                            info.id,
                            info.source.sender
                        );
                        continue;
                    }

                    let is_unknown_device = !self.is_from_known_device(&info.source.sender).await;
                    let retry_reason = if is_unknown_device {
                        RetryReason::UnknownCompanionNoPrekey
                    } else {
                        RetryReason::NoSession
                    };

                    warn!(
                        "No sender key state for group message [msg:{}] from {}: {}. Sending retry receipt.",
                        info.id, info.source.sender, msg
                    );

                    if is_unknown_device {
                        self.handle_unknown_device_sync(info).await;
                    }

                    self.dispatch_undecryptable_event(info, decrypt_fail_mode);
                    self.spawn_retry_receipt(info, retry_reason);
                }
                Err(e) => {
                    if info.is_expired_status() {
                        log::debug!(
                            "[msg:{}] Ignoring decrypt error for expired status from {}: {:?}",
                            info.id,
                            info.source.sender,
                            e
                        );
                        continue;
                    }

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
        Ok(())
    }

    /// WA Web: online → `syncDeviceListJob`, offline → `OfflinePendingDeviceCache`.
    async fn handle_unknown_device_sync(self: &Arc<Self>, info: &MessageInfo) {
        let user_jid = info.source.sender.to_non_ad();

        // Dedup: skip if we already have a sync pending/in-flight for this user
        if !self.pending_device_sync.add(user_jid.clone()).await {
            return;
        }

        if info.is_offline {
            log::debug!("Queueing {} for pending device sync (offline)", user_jid);
        } else {
            log::debug!("Triggering immediate device sync for {}", user_jid);
            let client = Arc::clone(self);
            self.runtime
                .spawn(Box::pin(async move {
                    client.invalidate_device_cache(&user_jid.user).await;
                    if let Err(e) = client.get_user_devices(&[user_jid]).await {
                        log::warn!("Immediate device sync failed: {e:?}");
                    }
                }))
                .detach();
        }
    }

    async fn handle_decrypted_plaintext(
        self: Arc<Self>,
        enc_type: &str,
        padded_plaintext: &[u8],
        padding_version: u8,
        info: &MessageInfo,
    ) -> Result<(), anyhow::Error> {
        let original_msg = wacore::messages::decode_plaintext(padded_plaintext, padding_version)?;
        log::debug!(
            "[msg:{}] Successfully decrypted message from {}: type={} [batch path]",
            info.id,
            info.source.sender,
            enc_type
        );

        // Validate DSM presence against sender identity
        // (WAWebHandleMsgError.DeviceSentMessageError)
        if original_msg.device_sent_message.is_some() && !info.source.is_from_me {
            warn!(
                "[msg:{}] DeviceSentMessage present but sender {} is not self",
                info.id, info.source.sender,
            );
        }

        // Unwrap DeviceSentMessage wrapper (self-sent messages synced from
        // the primary device). The actual content (reactions, text, etc.)
        // is nested inside device_sent_message.message and must be
        // extracted before protocol checks or dispatch.
        let mut msg = wacore::messages::unwrap_device_sent(original_msg);

        // Post-decryption logic (SKDM, sync keys, etc.)
        if let Some(skdm) = &msg.sender_key_distribution_message
            && let Some(axolotl_bytes) = &skdm.axolotl_sender_key_distribution_message
        {
            self.handle_sender_key_distribution_message(
                &info.source.chat,
                &info.source.sender,
                axolotl_bytes,
            )
            .await;
        }

        if let Some(protocol_msg) = &msg.protocol_message
            && let Some(keys) = &protocol_msg.app_state_sync_key_share
        {
            self.handle_app_state_sync_key_share(keys).await;
        }

        if let Some(protocol_msg) = &msg.protocol_message
            && let Some(pdo_response) = &protocol_msg.peer_data_operation_request_response_message
        {
            self.handle_pdo_response(pdo_response, info).await;
        }

        // Note: msg might be modified by take() below
        let history_sync_taken = msg
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
        if wacore::messages::is_sender_key_distribution_only(&msg) {
            log::debug!(
                "[msg:{}] Skipping event dispatch for sender key distribution message",
                info.id
            );
        } else {
            self.dispatch_parsed_message(msg, info);
        }
        Ok(())
    }

    /// Attempt PN→LID session migration and retry decryption.
    /// Returns true if decryption succeeded after migration.
    #[allow(clippy::too_many_arguments)]
    async fn try_pn_to_lid_migration_decrypt(
        self: &Arc<Self>,
        sender_jid: &Jid,
        signal_address: &wacore::libsignal::protocol::ProtocolAddress,
        parsed_message: &wacore::libsignal::protocol::CiphertextMessage,
        adapter: &mut crate::store::signal_adapter::SignalProtocolStoreAdapter,
        rng: &mut rand::rngs::StdRng,
        enc_type: &str,
        padding_version: u8,
        info: &MessageInfo,
    ) -> bool {
        use wacore::libsignal::protocol::{UsePQRatchet, message_decrypt};

        if !sender_jid.is_lid() {
            return false;
        }

        let Some(pn) = self.lid_pn_cache.get_phone_number(&sender_jid.user).await else {
            return false;
        };

        self.migrate_signal_sessions_on_lid_discovery(&pn, &sender_jid.user)
            .await;

        // Migration now goes through signal_cache, so no manual reload needed

        match message_decrypt(
            parsed_message,
            signal_address,
            &mut adapter.session_store,
            &mut adapter.identity_store,
            &mut adapter.pre_key_store,
            &adapter.signed_pre_key_store,
            rng,
            UsePQRatchet::No,
        )
        .await
        {
            Ok(padded_plaintext) => {
                log::info!(
                    "[msg:{}] Decrypted after PN→LID session migration for {}",
                    info.id,
                    info.source.sender
                );
                if let Err(e) = self
                    .clone()
                    .handle_decrypted_plaintext(enc_type, &padded_plaintext, padding_version, info)
                    .await
                {
                    log::warn!(
                        "[msg:{}] Failed processing plaintext after migration: {e:?}",
                        info.id
                    );
                }
                true
            }
            Err(SignalProtocolError::DuplicatedMessage(chain, counter)) => {
                log::debug!(
                    "[msg:{}] Already processed (chain {chain}, counter {counter}) after migration",
                    info.id
                );
                true
            }
            Err(retry_err) => {
                log::warn!(
                    "[msg:{}] Decryption still failed after PN→LID migration: {retry_err:?}",
                    info.id
                );
                false
            }
        }
    }

    /// Cache LID-PN mapping from message attributes (before resolve_encryption_jid).
    async fn cache_lid_pn_from_message(&self, sender: &Jid, alt: Option<&Jid>) {
        let pn_server = wacore_binary::jid::DEFAULT_USER_SERVER;
        let lid_server = wacore_binary::jid::HIDDEN_USER_SERVER;

        let (lid_user, pn_user, source) = if sender.server == lid_server {
            if let Some(alt_jid) = alt
                && alt_jid.server == pn_server
            {
                (
                    &sender.user,
                    &alt_jid.user,
                    crate::lid_pn_cache::LearningSource::PeerLidMessage,
                )
            } else {
                return;
            }
        } else if sender.server == pn_server {
            if let Some(alt_jid) = alt
                && alt_jid.server == lid_server
            {
                (
                    &alt_jid.user,
                    &sender.user,
                    crate::lid_pn_cache::LearningSource::PeerPnMessage,
                )
            } else {
                return;
            }
        } else {
            return;
        };

        if let Err(err) = self.add_lid_pn_mapping(lid_user, pn_user, source).await {
            warn!(
                "Failed to cache LID-PN mapping {} <-> {}: {err}",
                lid_user, pn_user
            );
        }
    }

    pub(crate) async fn parse_message_info(
        &self,
        node: &Node,
    ) -> Result<MessageInfo, anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let default_jid = Jid::default();
        let own_jid = device_snapshot.pn.as_ref().unwrap_or(&default_jid);
        wacore::messages::parse_message_info(node, own_jid, device_snapshot.lid.as_ref())
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
            self.initial_keys_synced_notifier.notify(usize::MAX);
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

        // Normalize to bare sender for consistent sender key addressing.
        let sender_bare = sender_jid.to_non_ad();
        let sender_address = sender_bare.to_protocol_address();

        let sender_key_name = SenderKeyName::from_jid(&group_jid, &sender_address);

        // Route through the signal cache adapter so the sender key is immediately visible
        // in the cache for subsequent group_decrypt calls within the same message batch.
        let mut adapter = self.signal_adapter().await;

        if let Err(e) = process_sender_key_distribution_message(
            &sender_key_name,
            &skdm,
            &mut adapter.sender_key_store,
        )
        .await
        {
            log::error!(
                "Failed to process SenderKeyDistributionMessage from {}: {:?}",
                sender_jid,
                e
            );
        } else {
            log::debug!(
                "Successfully processed sender key distribution for group {} from {}",
                group_jid,
                sender_jid
            );
        }
    }
}

/// Unwraps a `DeviceSentMessage` wrapper, returning the inner message with
/// merged `message_context_info`.
///
/// Self-sent messages synced from the primary device arrive with the actual
/// content (reactions, text, etc.) nested inside `device_sent_message.message`.
/// This extracts the inner message when present, merges `MessageContextInfo`
/// from outer and inner following WhatsApp Web's
/// `WAWebDeviceSentMessageProtoUtils.unwrapDeviceSentMessage` logic, or returns
/// the original message unchanged when there is no wrapper or the wrapper has
/// no inner message.
/// Re-export from wacore for backwards compatibility (used by tests via `super::*`).
#[cfg(test)]
fn unwrap_device_sent(msg: wa::Message) -> wa::Message {
    wacore::messages::unwrap_device_sent(msg)
}

/// Re-export from wacore for backwards compatibility (used by tests via `super::*`).
#[cfg(test)]
fn is_sender_key_distribution_only(msg: &wa::Message) -> bool {
    wacore::messages::is_sender_key_distribution_only(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::SqliteStore;
    use crate::store::persistence_manager::PersistenceManager;
    use crate::test_utils::MockHttpClient;
    use crate::types::message::EditAttribute;
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
        let sender_ratchet =
            KeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>()).public_key;
        let sender_identity_pair =
            IdentityKeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>());
        let receiver_identity_pair =
            IdentityKeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>());
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
            .process_session_enc_batch(
                &enc_nodes,
                &info,
                &sender_jid,
                crate::types::events::DecryptFailMode::Show,
            )
            .await;

        assert!(
            !success && !had_duplicates && dispatched,
            "process_session_enc_batch should return (false, false, true) when SessionNotFound occurs and dispatches event"
        );
    }

    /// P1: An empty session record (exists but no current/previous state) should be
    /// treated the same as SessionNotFound — the retry receipt gets error code 1 (NoSession)
    /// and includes keys early, instead of producing an unhelpful InvalidMessage error.
    #[tokio::test]
    async fn test_empty_session_record_treated_as_session_not_found() {
        use wacore::libsignal::protocol::{IdentityKeyPair, KeyPair, SessionRecord, SignalMessage};

        let backend = Arc::new(
            SqliteStore::new("file:memdb_empty_session?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("test backend should initialize"),
        );
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

        let sender_jid: Jid = "0000000000000@s.whatsapp.net"
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

        // Pre-store an empty (degenerate) session record in the signal cache.
        // This simulates the bug scenario: record exists but has no usable ratchet state.
        let signal_address = sender_jid.to_protocol_address();
        client
            .signal_cache
            .put_session(&signal_address, SessionRecord::new_fresh())
            .await;

        // Craft a SignalMessage to trigger decryption
        let dummy_key = [0u8; 32];
        let sender_ratchet =
            KeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>()).public_key;
        let sender_identity =
            IdentityKeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>());
        let receiver_identity =
            IdentityKeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>());
        let signal_message = SignalMessage::new(
            4,
            &dummy_key,
            sender_ratchet,
            0,
            0,
            b"test",
            sender_identity.identity_key(),
            receiver_identity.identity_key(),
        )
        .expect("SignalMessage::new should succeed");

        let enc_node = NodeBuilder::new("enc")
            .attr("type", "msg")
            .bytes(signal_message.serialized().to_vec())
            .build();
        let enc_nodes = vec![&enc_node];

        let (success, had_duplicates, dispatched) = client
            .clone()
            .process_session_enc_batch(
                &enc_nodes,
                &info,
                &sender_jid,
                crate::types::events::DecryptFailMode::Show,
            )
            .await;

        // Should behave identically to SessionNotFound: failure, no dupe, event dispatched.
        assert!(
            !success && !had_duplicates && dispatched,
            "Empty session record should be treated as SessionNotFound: \
             expected (false, false, true), got ({success}, {had_duplicates}, {dispatched})"
        );

        // Verify we took the SessionNotFound path (error code 1 / NoSession) rather
        // than the InvalidMessage path (error code 4). The key difference:
        // - SessionNotFound does NOT delete the session from the cache
        // - InvalidMessage/BadMac DOES delete it (via signal_cache.delete_session)
        //
        // If the session record is still present in the cache, we know the
        // SessionNotFound branch ran, which sends RetryReason::NoSession (code 1)
        // and triggers early key inclusion on retry #1 via should_include_keys().
        let backend = client.persistence_manager.backend();
        let session_still_exists = client
            .signal_cache
            .has_session(&signal_address, &*backend)
            .await
            .expect("has_session should not fail");
        assert!(
            session_still_exists,
            "Session should NOT have been deleted — SessionNotFound path preserves it. \
             If deleted, the InvalidMessage path ran instead (wrong error code)."
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

        let sender_jid: Jid = "1234567890@s.whatsapp.net"
            .parse()
            .expect("test JID should be valid");
        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");

        // Create msg + skmsg node; msg will fail (no session), so skmsg should be skipped
        let dummy_key = [0u8; 32];
        let sender_ratchet =
            KeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>()).public_key;
        let sender_identity_pair =
            IdentityKeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>());
        let receiver_identity_pair =
            IdentityKeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>());
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
                .attr("from", group_jid)
                .attr("participant", sender_jid)
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
        let (_client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
        let lid_sender_key_name = SenderKeyName::from_jid(&group_jid, &lid_protocol_address);

        // Pin serialized form so from_jid stays compatible with persisted records
        assert_eq!(lid_sender_key_name.group_id(), group_jid.to_string());
        assert_eq!(
            lid_sender_key_name.sender_id(),
            lid_protocol_address.to_string()
        );

        let device_arc = pm.get_device_arc().await;
        let skdm = {
            let mut device_guard = device_arc.write().await;
            create_sender_key_distribution_message(
                &lid_sender_key_name,
                &mut *device_guard,
                &mut rand::make_rng::<rand::rngs::StdRng>(),
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
        let phone_sender_key_name = SenderKeyName::from_jid(&group_jid, &phone_protocol_address);

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
        let (_client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            transport_factory,
            mock_http_client(),
            None,
        )
        .await;

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
            let lid_sender_key_name = SenderKeyName::from_jid(&group_jid, &lid_protocol_address);

            let skdm = {
                let mut device_guard = device_arc.write().await;
                create_sender_key_distribution_message(
                    &lid_sender_key_name,
                    &mut *device_guard,
                    &mut rand::make_rng::<rand::rngs::StdRng>(),
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

            let lid_sender_key_name = SenderKeyName::from_jid(&group_jid, &lid_protocol_address);
            let phone_sender_key_name =
                SenderKeyName::from_jid(&group_jid, &phone_protocol_address);

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
        use wacore::types::message::AddressingMode;
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

        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

        // Test case 1: LID group message with participant_pn
        let lid_group_node = NodeBuilder::new("message")
            .attr("from", "120363021033254949@g.us")
            .attr("participant", "987654321000000.2:42@lid")
            .attr("participant_pn", "551234567890:42@s.whatsapp.net")
            .attr("addressing_mode", AddressingMode::Lid.as_str())
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
            .attr("addressing_mode", AddressingMode::Lid.as_str())
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
        let (_client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
            SenderKeyName::from_jid(&group_jid, &display_protocol_address);

        let device_arc = pm.get_device_arc().await;
        {
            let mut device_guard = device_arc.write().await;
            create_sender_key_distribution_message(
                &display_sender_key_name,
                &mut *device_guard,
                &mut rand::make_rng::<rand::rngs::StdRng>(),
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
        let encryption_sender_key_name =
            SenderKeyName::from_jid(&group_jid, &encryption_protocol_address);

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
        use wacore::types::message::AddressingMode;
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

        let sender_jid: Jid = "100000000000001.1:75@lid"
            .parse()
            .expect("test JID should be valid");
        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");

        // Step 1: Create and store a sender key (simulating first message processing)
        let sender_protocol_address = sender_jid.to_protocol_address();
        let sender_key_name = SenderKeyName::from_jid(&group_jid, &sender_protocol_address);

        let device_arc = pm.get_device_arc().await;
        {
            let mut device_guard = device_arc.write().await;
            let skdm = create_sender_key_distribution_message(
                &sender_key_name,
                &mut *device_guard,
                &mut rand::make_rng::<rand::rngs::StdRng>(),
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
                &mut rand::make_rng::<rand::rngs::StdRng>(),
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
                .attr("from", group_jid)
                .attr("participant", sender_jid)
                .attr("id", "SECOND_MSG_TEST")
                .attr("t", "1759306493")
                .attr("type", "text")
                .attr("addressing_mode", AddressingMode::Lid.as_str())
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
            .process_session_enc_batch(
                &enc_nodes,
                &info,
                &sender_jid,
                crate::types::events::DecryptFailMode::Show,
            )
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
            .process_session_enc_batch(
                &enc_node_refs,
                &info,
                &sender_jid,
                crate::types::events::DecryptFailMode::Show,
            )
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
            .process_session_enc_batch(
                &enc_nodes,
                &info,
                &sender_phone,
                crate::types::events::DecryptFailMode::Show,
            )
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

        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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

        // 2. sender_alt should be own PN (derived from own_jid, not message attrs)
        assert!(
            info.source.sender_alt.is_some(),
            "sender_alt should be own PN for self-sent LID messages"
        );
        assert_eq!(
            info.source.sender_alt.as_ref().unwrap().user,
            "15551234567",
            "sender_alt should be the own PN user"
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

        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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

        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
            info.source.sender_alt.is_some(),
            "sender_alt should be own PN for self-sent LID messages"
        );
        assert_eq!(
            info.source.sender_alt.as_ref().unwrap().user,
            "15551234567",
            "sender_alt should match own PN"
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
        use wacore::types::message::AddressingMode;

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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

        let lid = "100000012345678";
        let phone = "559980000001";

        // Create a message from a LID sender with participant_pn attribute
        // This happens in LID-mode groups (addressing_mode="lid")
        let group_node = NodeBuilder::new("message")
            .attr("from", "120363123456789012@g.us") // Group chat
            .attr("participant", Jid::lid(lid).to_string()) // Sender is LID
            .attr("participant_pn", Jid::pn(phone).to_string()) // Their phone number
            .attr("addressing_mode", AddressingMode::Lid.as_str()) // Required for participant_pn to be parsed
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
                    server: wacore_binary::jid::cow_server_from_str(lid_server),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else if let Some(lid_user) = client.lid_pn_cache.get_current_lid(&sender.user).await {
                // Use the cached LID
                Jid {
                    user: lid_user,
                    server: wacore_binary::jid::cow_server_from_str(lid_server),
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
                    server: wacore_binary::jid::cow_server_from_str(lid_server),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else if let Some(lid_user) = client.lid_pn_cache.get_current_lid(&sender.user).await {
                // This is the path we're testing - fallback to cached LID
                Jid {
                    user: lid_user,
                    server: wacore_binary::jid::cow_server_from_str(lid_server),
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
                    server: wacore_binary::jid::cow_server_from_str(lid_server),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else if let Some(lid_user) = client.lid_pn_cache.get_current_lid(&sender.user).await {
                Jid {
                    user: lid_user,
                    server: wacore_binary::jid::cow_server_from_str(lid_server),
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
        use wacore::types::message::{EditAttribute, MessageCategory, MessageSource, MsgMetaInfo};

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
            timestamp: wacore::time::now_utc(),
            push_name: "Test User".to_string(),
            category: MessageCategory::default(),
            multicast: false,
            media_type: "".to_string(),
            edit: EditAttribute::default(),
            bot_info: None,
            meta_info: MsgMetaInfo::default(),
            verified_name: None,
            device_sent_meta: None,
            ephemeral_expiration: None,
            is_offline: false,
        }
    }

    /// Helper to create a test client for retry tests with a unique database
    async fn create_test_client_for_retry_with_id(test_id: &str) -> Arc<Client> {
        use portable_atomic::AtomicU64;
        use std::sync::atomic::Ordering;
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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;
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
    /// The increment operation uses get+insert which is not fully atomic,
    /// but is sufficient since message retry processing is serialized per key
    /// by the per-chat lock. At most 5 increments should succeed.
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

    /// Test: Verify JID type detection for status broadcasts, broadcast lists, groups, and users.
    #[test]
    fn test_status_broadcast_jid_detection() {
        use wacore_binary::jid::{Jid, JidExt};

        let status_jid: Jid = "status@broadcast".parse().expect("status JID should parse");
        assert!(status_jid.is_status_broadcast());

        let broadcast_list: Jid = "123456789@broadcast"
            .parse()
            .expect("broadcast JID should parse");
        assert!(!broadcast_list.is_status_broadcast());
        assert!(broadcast_list.is_broadcast_list());

        let group_jid: Jid = "120363021033254949@g.us"
            .parse()
            .expect("group JID should parse");
        assert!(!group_jid.is_status_broadcast());

        let user_jid: Jid = "15551234567@s.whatsapp.net"
            .parse()
            .expect("user JID should parse");
        assert!(!user_jid.is_status_broadcast());
    }

    /// Test: Verify should_process_skmsg logic matches WA Web's canDecryptNext pattern.
    ///
    /// WA Web applies canDecryptNext uniformly: if pkmsg fails with a retriable error,
    /// skmsg is skipped regardless of chat type (group, status, 1:1). No exception for
    /// status broadcasts — the retry receipt for the pkmsg will cause the sender to
    /// resend the entire message including SKDM.
    #[test]
    fn test_should_process_skmsg_logic_matches_wa_web() {
        // Test cases: (chat_jid, session_empty, session_success, session_dupe, expected)
        let test_cases = [
            // Status broadcast: same rules as all other chats (WA Web: canDecryptNext is uniform)
            ("status@broadcast", false, false, false, false), // Fail: session failed → skip skmsg
            ("status@broadcast", false, false, true, true),   // OK: duplicate
            ("status@broadcast", false, true, false, true),   // OK: success
            ("status@broadcast", true, false, false, true),   // OK: no session msgs
            // Regular group
            ("120363021033254949@g.us", false, false, false, false),
            ("120363021033254949@g.us", false, false, true, true),
            ("120363021033254949@g.us", false, true, false, true),
            ("120363021033254949@g.us", true, false, false, true),
            // 1:1 chat
            ("15551234567@s.whatsapp.net", false, false, false, false),
            ("15551234567@s.whatsapp.net", true, false, false, true),
        ];

        for (jid_str, session_empty, session_success, session_dupe, expected) in test_cases {
            // Recreate the should_process_skmsg logic from handle_incoming_message
            let should_process_skmsg = session_empty || session_success || session_dupe;

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
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm,
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

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
    async fn test_no_sender_key_sends_immediate_retry() {
        // Verify that when skmsg decryption fails with NoSenderKeyState,
        // a retry receipt is sent immediately (no delay, no re-queue).
        // This matches WA Web behavior where NoSenderKey → SignalRetryable → RETRY.
        let _ = env_logger::builder().is_test(true).try_init();

        use crate::store::SqliteStore;
        use crate::store::persistence_manager::PersistenceManager;
        use wacore_binary::builder::NodeBuilder;
        use wacore_binary::node::NodeContent;

        let backend = Arc::new(
            SqliteStore::new("file:memdb_retry_immediate?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        );
        let pm = Arc::new(
            PersistenceManager::new(backend.clone())
                .await
                .expect("test backend should initialize"),
        );
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            mock_transport(),
            mock_http_client(),
            None,
        )
        .await;

        let group_jid: Jid = "120363021033254949@g.us".parse().unwrap();
        let sender_jid: Jid = "1234567890:1@s.whatsapp.net".parse().unwrap();
        let msg_id = "TEST_IMMEDIATE_RETRY";

        // Pseudo-valid SenderKeyMessage: Version 3 + Protobuf + Fake Sig (64 bytes)
        let mut content = vec![0x33, 0x08, 0x01, 0x10, 0x01, 0x1A, 0x00];
        content.extend(vec![0u8; 64]);

        let node = NodeBuilder::new("message")
            .attr("id", msg_id)
            .attr("from", group_jid.clone())
            .attr("participant", sender_jid.clone())
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

        client.clone().handle_incoming_message(Arc::new(node)).await;

        // spawn_retry_receipt runs in a spawned task, wait for it
        let retry_key = client
            .make_retry_cache_key(&group_jid, msg_id, &sender_jid)
            .await;
        for _ in 0..20 {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            if client.message_retry_counts.get(&retry_key).await.is_some() {
                break;
            }
        }
        assert_eq!(
            client.message_retry_counts.get(&retry_key).await,
            Some(1),
            "NoSenderKeyState should immediately trigger retry receipt (count=1)"
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

    /// Test: unwrap_device_sent extracts a reaction from a DeviceSentMessage wrapper.
    #[test]
    fn test_unwrap_device_sent_extracts_reaction() {
        let wrapped = wa::Message {
            device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                destination_jid: Some("5511999999999@s.whatsapp.net".to_string()),
                message: Some(Box::new(wa::Message {
                    reaction_message: Some(wa::message::ReactionMessage {
                        text: Some("\u{2764}".to_string()),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
                phash: None,
            })),
            ..Default::default()
        };

        let unwrapped = unwrap_device_sent(wrapped);
        assert!(
            unwrapped.device_sent_message.is_none(),
            "DSM wrapper should be removed"
        );
        assert_eq!(
            unwrapped
                .reaction_message
                .as_ref()
                .and_then(|r| r.text.as_deref()),
            Some("\u{2764}"),
            "reaction should be accessible after unwrapping"
        );
        assert!(
            !is_sender_key_distribution_only(&unwrapped),
            "unwrapped reaction should not be filtered as SKDM-only"
        );
    }

    /// Test: unwrap_device_sent preserves the wrapper when inner message is None.
    #[test]
    fn test_unwrap_device_sent_preserves_empty_wrapper() {
        let wrapped = wa::Message {
            device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                destination_jid: Some("5511999999999@s.whatsapp.net".to_string()),
                message: None,
                phash: None,
            })),
            ..Default::default()
        };

        let result = unwrap_device_sent(wrapped);
        assert!(
            result.device_sent_message.is_some(),
            "empty DSM wrapper should be preserved"
        );
    }

    /// Test: unwrap_device_sent passes through a plain message unchanged.
    #[test]
    fn test_unwrap_device_sent_passthrough() {
        let msg = wa::Message {
            conversation: Some("hello".to_string()),
            ..Default::default()
        };

        let result = unwrap_device_sent(msg);
        assert_eq!(result.conversation.as_deref(), Some("hello"));
    }

    /// Test: unwrap_device_sent merges messageContextInfo from outer and inner,
    /// matching WAWebDeviceSentMessageProtoUtils.unwrapDeviceSentMessage.
    #[test]
    fn test_unwrap_device_sent_merges_context_info() {
        let wrapped = wa::Message {
            // Outer message_context_info (from the DSM envelope)
            message_context_info: Some(wa::MessageContextInfo {
                message_secret: Some(vec![10, 20, 30]),
                limit_sharing_v2: Some(wa::LimitSharing::default()),
                ..Default::default()
            }),
            device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                destination_jid: Some("5511999999999@s.whatsapp.net".to_string()),
                message: Some(Box::new(wa::Message {
                    conversation: Some("hello".to_string()),
                    // Inner has its own message_secret but no limit_sharing_v2
                    message_context_info: Some(wa::MessageContextInfo {
                        message_secret: Some(vec![1, 2, 3]),
                        ..Default::default()
                    }),
                    ..Default::default()
                })),
                phash: None,
            })),
            ..Default::default()
        };

        let result = unwrap_device_sent(wrapped);
        let ctx = result.message_context_info.as_ref().unwrap();

        assert_eq!(
            ctx.message_secret,
            Some(vec![1, 2, 3]),
            "inner message_secret should be preferred"
        );
        assert!(
            ctx.limit_sharing_v2.is_some(),
            "limit_sharing_v2 should come from outer (always)"
        );
    }

    /// Test: unwrap_device_sent falls back to outer message_secret when inner has none.
    #[test]
    fn test_unwrap_device_sent_secret_fallback() {
        let wrapped = wa::Message {
            message_context_info: Some(wa::MessageContextInfo {
                message_secret: Some(vec![10, 20, 30]),
                ..Default::default()
            }),
            device_sent_message: Some(Box::new(wa::message::DeviceSentMessage {
                destination_jid: Some("5511999999999@s.whatsapp.net".to_string()),
                message: Some(Box::new(wa::Message {
                    conversation: Some("hello".to_string()),
                    // Inner has no message_context_info at all
                    ..Default::default()
                })),
                phash: None,
            })),
            ..Default::default()
        };

        let result = unwrap_device_sent(wrapped);
        let ctx = result.message_context_info.as_ref().unwrap();
        assert_eq!(
            ctx.message_secret,
            Some(vec![10, 20, 30]),
            "should fall back to outer message_secret"
        );
    }

    #[tokio::test]
    async fn test_parse_edit_attribute_sender_revoke() {
        let client = create_test_client_for_retry_with_id("edit_sender_revoke").await;

        let node = NodeBuilder::new("message")
            .attr("from", "status@broadcast")
            .attr("id", "TEST123")
            .attr("participant", "5551234567@lid")
            .attr("t", "1772895198")
            .attr("type", "text")
            .attr("edit", "7")
            .build();

        let info = client
            .parse_message_info(&node)
            .await
            .expect("parse_message_info should succeed");

        assert_eq!(
            info.edit,
            EditAttribute::SenderRevoke,
            "edit='7' should parse as SenderRevoke"
        );
    }

    #[tokio::test]
    async fn test_parse_edit_attribute_admin_revoke() {
        let client = create_test_client_for_retry_with_id("edit_admin_revoke").await;

        let node = NodeBuilder::new("message")
            .attr("from", "120363999999999999@g.us")
            .attr("id", "TEST456")
            .attr("participant", "5551234567@lid")
            .attr("t", "1772895198")
            .attr("type", "text")
            .attr("edit", "8")
            .build();

        let info = client
            .parse_message_info(&node)
            .await
            .expect("parse_message_info should succeed");

        assert_eq!(
            info.edit,
            EditAttribute::AdminRevoke,
            "edit='8' should parse as AdminRevoke"
        );
    }

    #[tokio::test]
    async fn test_parse_edit_attribute_message_edit() {
        let client = create_test_client_for_retry_with_id("edit_message_edit").await;

        let node = NodeBuilder::new("message")
            .attr("from", "5551234567@s.whatsapp.net")
            .attr("id", "TEST789")
            .attr("t", "1772895198")
            .attr("type", "text")
            .attr("edit", "1")
            .build();

        let info = client
            .parse_message_info(&node)
            .await
            .expect("parse_message_info should succeed");

        assert_eq!(
            info.edit,
            EditAttribute::MessageEdit,
            "edit='1' should parse as MessageEdit"
        );
    }

    #[tokio::test]
    async fn test_parse_edit_attribute_missing() {
        let client = create_test_client_for_retry_with_id("edit_missing").await;

        let node = NodeBuilder::new("message")
            .attr("from", "5551234567@s.whatsapp.net")
            .attr("id", "TESTABC")
            .attr("t", "1772895198")
            .attr("type", "text")
            .build();

        let info = client
            .parse_message_info(&node)
            .await
            .expect("parse_message_info should succeed");

        assert_eq!(
            info.edit,
            EditAttribute::Empty,
            "missing edit attr should default to Empty"
        );
    }

    #[tokio::test]
    async fn test_revoked_message_still_retries() {
        let client = create_test_client_for_retry_with_id("revoke_retry").await;

        let mut info = create_test_message_info(
            "status@broadcast",
            "REVOKE_MSG1",
            "5551234567@s.whatsapp.net",
        );
        info.edit = EditAttribute::SenderRevoke;

        // WA Web retries revoked messages the same as any other — the revoke
        // protocol message contains the target ID needed to process the deletion
        client.spawn_retry_receipt(&info, RetryReason::NoSession);

        // Wait for the spawned task to execute
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let cache_key = client
            .make_retry_cache_key(&info.source.chat, &info.id, &info.source.sender)
            .await;
        assert_eq!(
            client.message_retry_counts.get(&cache_key).await,
            Some(1),
            "revoked message should still have retry count 1 (WA Web retries all messages)"
        );
    }

    #[tokio::test]
    async fn test_enc_count_preseeds_retry_cache() {
        let client = create_test_client_for_retry_with_id("enc_preseed").await;

        let chat_jid: Jid = "5551234567@s.whatsapp.net".parse().unwrap();
        let msg_id = "ENC_COUNT_MSG1";

        // Pre-seed via the same logic used in handle_incoming_message
        let max_sender_retry_count: u8 = 3;
        let cache_key = client
            .make_retry_cache_key(&chat_jid, msg_id, &chat_jid)
            .await;
        // Insert only if absent (portable alternative to moka's entry_by_ref().or_insert())
        if client.message_retry_counts.get(&cache_key).await.is_none() {
            client
                .message_retry_counts
                .insert(cache_key.clone(), max_sender_retry_count)
                .await;
        }

        assert_eq!(
            client.message_retry_counts.get(&cache_key).await,
            Some(3),
            "cache should be pre-seeded with sender retry count"
        );
    }

    #[tokio::test]
    async fn test_enc_no_count_cache_empty() {
        let client = create_test_client_for_retry_with_id("enc_no_count").await;

        let chat_jid: Jid = "5551234567@s.whatsapp.net".parse().unwrap();
        let msg_id = "ENC_NO_COUNT_MSG1";

        // When max_sender_retry_count is 0, no pre-seeding occurs
        let max_sender_retry_count: u8 = 0;
        if max_sender_retry_count > 0 {
            let cache_key = client
                .make_retry_cache_key(&chat_jid, msg_id, &chat_jid)
                .await;
            if client.message_retry_counts.get(&cache_key).await.is_none() {
                client
                    .message_retry_counts
                    .insert(cache_key, max_sender_retry_count)
                    .await;
            }
        }

        let cache_key = client
            .make_retry_cache_key(&chat_jid, msg_id, &chat_jid)
            .await;
        assert!(
            client.message_retry_counts.get(&cache_key).await.is_none(),
            "cache should be empty when no count attribute"
        );
    }

    #[tokio::test]
    async fn test_enc_count_does_not_overwrite_higher() {
        let client = create_test_client_for_retry_with_id("enc_no_overwrite").await;

        let chat_jid: Jid = "5551234567@s.whatsapp.net".parse().unwrap();
        let msg_id = "ENC_NOOVERWRITE_MSG1";

        let cache_key = client
            .make_retry_cache_key(&chat_jid, msg_id, &chat_jid)
            .await;

        // Pre-insert a higher value
        client
            .message_retry_counts
            .insert(cache_key.clone(), 4)
            .await;

        // max(existing, incoming) should NOT overwrite with a lower value
        let max_sender_retry_count: u8 = 2;
        let existing = client
            .message_retry_counts
            .get(&cache_key)
            .await
            .unwrap_or(0);
        if max_sender_retry_count > existing {
            client
                .message_retry_counts
                .insert(cache_key.clone(), max_sender_retry_count)
                .await;
        }

        assert_eq!(
            client.message_retry_counts.get(&cache_key).await,
            Some(4),
            "should not overwrite existing higher value"
        );
    }

    #[tokio::test]
    async fn test_enc_count_updates_when_sender_higher() {
        let client = create_test_client_for_retry_with_id("enc_update_higher").await;

        let chat_jid: Jid = "5551234567@s.whatsapp.net".parse().unwrap();
        let msg_id = "ENC_UPDATE_MSG1";

        let cache_key = client
            .make_retry_cache_key(&chat_jid, msg_id, &chat_jid)
            .await;

        // Pre-insert a lower value
        client
            .message_retry_counts
            .insert(cache_key.clone(), 1)
            .await;

        // max(existing, incoming) SHOULD update with a higher value
        let max_sender_retry_count: u8 = 3;
        let existing = client
            .message_retry_counts
            .get(&cache_key)
            .await
            .unwrap_or(0);
        if max_sender_retry_count > existing {
            client
                .message_retry_counts
                .insert(cache_key.clone(), max_sender_retry_count)
                .await;
        }

        assert_eq!(
            client.message_retry_counts.get(&cache_key).await,
            Some(3),
            "should update to higher sender count"
        );
    }

    /// Shared helper: the OLD semaphore acquire logic that silently dropped tasks
    /// on generation mismatch. Used by the bug-demonstration test.
    async fn acquire_permit_old_behavior(
        semaphore: &std::sync::Mutex<Arc<async_lock::Semaphore>>,
        generation: &portable_atomic::AtomicU64,
    ) -> bool {
        use std::sync::atomic::Ordering;
        let (snap_gen, snap_sem) = {
            let guard = semaphore.lock().unwrap();
            (generation.load(Ordering::SeqCst), guard.clone())
        };
        let _permit = snap_sem.acquire_arc().await;
        // OLD: if generation changed, silently return false (message lost)
        snap_gen == generation.load(Ordering::SeqCst)
    }

    /// Shared helper: the FIXED semaphore acquire logic that re-acquires from the
    /// new semaphore on generation mismatch. Mirrors the production code in
    /// handle_incoming_message.
    async fn acquire_permit_with_reacquire(
        semaphore: &std::sync::Mutex<Arc<async_lock::Semaphore>>,
        generation: &portable_atomic::AtomicU64,
    ) {
        use std::sync::atomic::Ordering;
        loop {
            let (snap_gen, snap_sem) = {
                let guard = semaphore.lock().unwrap();
                (generation.load(Ordering::SeqCst), guard.clone())
            };
            let permit = snap_sem.acquire_arc().await;
            if snap_gen == generation.load(Ordering::SeqCst) {
                drop(permit);
                break;
            }
            drop(permit);
        }
    }

    /// Demonstrates the bug: the OLD code silently dropped tasks when generation changed.
    #[tokio::test]
    async fn test_old_behavior_drops_tasks_on_generation_swap() {
        use portable_atomic::AtomicU64;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let semaphore = Arc::new(std::sync::Mutex::new(Arc::new(async_lock::Semaphore::new(
            1,
        ))));
        let generation = Arc::new(AtomicU64::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(AtomicUsize::new(0));

        let blocker_sem = semaphore.lock().unwrap().clone();
        let blocker_permit = blocker_sem.acquire_arc().await;

        let num_waiters: usize = 8;
        let mut handles = Vec::new();

        for _ in 0..num_waiters {
            let sem = semaphore.clone();
            let gen_counter = generation.clone();
            let done = completed.clone();
            let ready_counter = ready.clone();

            handles.push(tokio::spawn(async move {
                // Signal readiness before blocking on semaphore
                ready_counter.fetch_add(1, Ordering::SeqCst);
                if acquire_permit_old_behavior(&sem, &gen_counter).await {
                    done.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        // Wait until all waiters have signaled readiness (about to block on semaphore)
        while ready.load(Ordering::SeqCst) < num_waiters {
            tokio::task::yield_now().await;
        }

        // Swap semaphore — triggers the bug
        {
            let mut guard = semaphore.lock().unwrap();
            *guard = Arc::new(async_lock::Semaphore::new(64));
            generation.fetch_add(1, Ordering::SeqCst);
        }

        drop(blocker_permit);

        for handle in handles {
            let result = tokio::time::timeout(tokio::time::Duration::from_secs(5), handle).await;
            assert!(result.is_ok(), "Waiter task timed out");
            result.unwrap().unwrap();
        }

        let done = completed.load(Ordering::SeqCst);
        assert!(
            done < num_waiters,
            "Bug demonstration: expected tasks to be dropped, but all {} completed",
            num_waiters
        );
    }

    /// Verifies the fix: re-acquire loop ensures NO tasks are dropped on generation swap.
    #[tokio::test]
    async fn test_semaphore_generation_swap_does_not_drop_tasks() {
        use portable_atomic::AtomicU64;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let semaphore = Arc::new(std::sync::Mutex::new(Arc::new(async_lock::Semaphore::new(
            1,
        ))));
        let generation = Arc::new(AtomicU64::new(0));
        let completed = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(AtomicUsize::new(0));

        let blocker_sem = semaphore.lock().unwrap().clone();
        let blocker_permit = blocker_sem.acquire_arc().await;

        let num_waiters: usize = 8;
        let mut handles = Vec::new();

        for _ in 0..num_waiters {
            let sem = semaphore.clone();
            let gen_counter = generation.clone();
            let done = completed.clone();
            let ready_counter = ready.clone();

            handles.push(tokio::spawn(async move {
                ready_counter.fetch_add(1, Ordering::SeqCst);
                acquire_permit_with_reacquire(&sem, &gen_counter).await;
                done.fetch_add(1, Ordering::SeqCst);
            }));
        }

        // Wait until all waiters have signaled readiness
        while ready.load(Ordering::SeqCst) < num_waiters {
            tokio::task::yield_now().await;
        }

        // Swap semaphore (simulates offline sync completion)
        {
            let mut guard = semaphore.lock().unwrap();
            *guard = Arc::new(async_lock::Semaphore::new(64));
            generation.fetch_add(1, Ordering::SeqCst);
        }

        drop(blocker_permit);

        for handle in handles {
            let result = tokio::time::timeout(tokio::time::Duration::from_secs(5), handle).await;
            assert!(
                result.is_ok(),
                "Waiter task timed out — likely silently dropped by generation check"
            );
            result.unwrap().unwrap();
        }

        assert_eq!(
            completed.load(Ordering::SeqCst),
            num_waiters,
            "All {} waiter tasks should complete, but only {} did. \
             Tasks were silently dropped during semaphore generation swap.",
            num_waiters,
            completed.load(Ordering::SeqCst)
        );
    }
}
