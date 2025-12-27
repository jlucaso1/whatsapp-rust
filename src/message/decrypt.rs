//! Message decryption handlers for Signal Protocol encrypted messages.
//!
//! This module handles the decryption of incoming WhatsApp messages using
//! the Signal Protocol. It processes both:
//! - Session messages (pkmsg/msg) - 1:1 encrypted messages
//! - Group messages (skmsg) - Sender key encrypted group messages

use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::events::Event;
use crate::types::message::MessageInfo;
use log::warn;
use prost::Message as ProtoMessage;
use rand::TryRngCore;
use std::sync::Arc;
use wacore::libsignal::crypto::DecryptionError;
use wacore::libsignal::protocol::{
    PreKeySignalMessage, SignalMessage, SignalProtocolError, UsePQRatchet, group_decrypt,
    message_decrypt,
};
use wacore::libsignal::store::sender_key_name::SenderKeyName;
use wacore::messages::MessageUtils;
use wacore::types::jid::JidExt;
use wacore::types::message::RetryReason;
use wacore_binary::jid::{Jid, JidExt as BinaryJidExt};
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

impl Client {
    /// Main entry point for handling encrypted messages.
    ///
    /// This method:
    /// 1. Parses the message info from the incoming node
    /// 2. Determines the correct JID to use for Signal session lookup
    /// 3. Routes encrypted content to appropriate handlers (session vs group)
    /// 4. Manages the LID-PN cache for session consistency
    pub(crate) async fn handle_encrypted_message(self: Arc<Self>, node: Arc<Node>) {
        let info = match self.parse_message_info(&node).await {
            Ok(info) => Arc::new(info),
            Err(e) => {
                log::warn!("Failed to parse message info: {e:?}");
                return;
            }
        };

        // Determine the JID to use for end-to-end decryption.
        //
        // CRITICAL: WhatsApp Web ALWAYS uses LID-based addresses for Signal sessions when
        // a LID mapping is known. This is implemented in WAWebSignalAddress.toString():
        //
        //   var n = o("WAWebWidFactory").asUserWidOrThrow(this.wid);
        //   var a = !n.isLid() && n.isUser();  // true if PN
        //   var i = a ? o("WAWebApiContact").getCurrentLid(n) : n;  // Get LID if PN
        //   if (i == null) {
        //     return [this.wid.user, t, "@c.us"].join("");  // No LID, use PN
        //   } else {
        //     return [i.user, t, "@lid"].join("");  // Use LID
        //   }
        //
        // This means sessions are stored under the LID address, not the PN address.
        // When we receive a PN-addressed message, we must look up the session using
        // the LID address (if a LID mapping is known) to match WhatsApp Web's behavior.
        let sender_encryption_jid = self.resolve_sender_encryption_jid(&info).await;

        log::debug!(
            "Message from {} (sender: {}, encryption JID: {}, is_from_me: {})",
            info.source.chat,
            info.source.sender,
            sender_encryption_jid,
            info.source.is_from_me
        );

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

        let mut session_enc_nodes = Vec::with_capacity(all_enc_nodes.len());
        let mut group_content_enc_nodes = Vec::with_capacity(all_enc_nodes.len());

        for &enc_node in &all_enc_nodes {
            let enc_type = enc_node.attrs().string("type");

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
                if let Err(e) = self
                    .clone()
                    .process_group_enc_batch(
                        &group_content_enc_nodes,
                        &info,
                        &sender_encryption_jid,
                    )
                    .await
                {
                    log::warn!("Batch group decrypt encountered error (continuing): {e:?}");
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

    /// Resolves the JID to use for Signal session lookup based on LID-PN mappings.
    async fn resolve_sender_encryption_jid(&self, info: &MessageInfo) -> Jid {
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
                log::debug!(
                    "Cached LID-to-PN mapping: {} -> {}",
                    sender.user,
                    alt_jid.user
                );
            }
            sender.clone()
        } else if sender.server == pn_server {
            // Sender is PN - check if we have a LID mapping.
            // WhatsApp Web uses LID for sessions when available.

            // First, cache/update the mapping if sender_lid attribute is present
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
                log::debug!(
                    "Cached PN-to-LID mapping: {} -> {}",
                    sender.user,
                    alt_jid.user
                );

                // Use the LID from the message attribute for session lookup
                Jid {
                    user: alt_jid.user.clone(),
                    server: lid_server.to_string(),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else if let Some(lid_user) = self.lid_pn_cache.get_current_lid(&sender.user).await {
                // No sender_lid attribute, but we have a cached LID mapping
                log::debug!(
                    "Using cached LID {} for session lookup (sender was PN {})",
                    lid_user,
                    sender
                );
                Jid {
                    user: lid_user,
                    server: lid_server.to_string(),
                    device: sender.device,
                    agent: sender.agent,
                    integrator: sender.integrator,
                }
            } else {
                // No LID mapping known - use PN address
                log::debug!("No LID mapping for {}, using PN for session lookup", sender);
                sender.clone()
            }
        } else {
            // Other server type (bot, hosted, group, broadcast, etc.) - use as-is
            // Note: Group senders will be handled specially below (skipped for session processing)
            sender.clone()
        }
    }

    /// Processes a batch of session-encrypted messages (pkmsg/msg).
    ///
    /// Returns a tuple of (any_success, any_duplicate, dispatched_undecryptable)
    pub(crate) async fn process_session_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&wacore_binary::node::Node],
        info: &MessageInfo,
        sender_encryption_jid: &Jid,
    ) -> (bool, bool, bool) {
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
            let enc_type = enc_node.attrs().string("type");
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
                    // Handle decryption errors
                    let result = self
                        .handle_session_decrypt_error(
                            e,
                            &parsed_message,
                            &signal_address,
                            &mut adapter,
                            &rng,
                            &enc_type,
                            padding_version,
                            info,
                            &mut any_success,
                            &mut any_duplicate,
                        )
                        .await;

                    if let Some(dispatched) = result {
                        dispatched_undecryptable = dispatched;
                    }
                }
            }
        }
        (any_success, any_duplicate, dispatched_undecryptable)
    }

    /// Handles decryption errors for session messages.
    ///
    /// Returns Some(true) if an undecryptable event was dispatched, Some(false) if not,
    /// or None if no action was needed (e.g., duplicate message).
    #[allow(clippy::too_many_arguments)]
    async fn handle_session_decrypt_error(
        self: &Arc<Self>,
        e: SignalProtocolError,
        parsed_message: &wacore::libsignal::protocol::CiphertextMessage,
        signal_address: &wacore::libsignal::protocol::ProtocolAddress,
        adapter: &mut SignalProtocolStoreAdapter,
        rng: &rand::rngs::OsRng,
        enc_type: &str,
        padding_version: u8,
        info: &MessageInfo,
        any_success: &mut bool,
        any_duplicate: &mut bool,
    ) -> Option<bool> {
        // Handle DuplicatedMessage: This is expected when messages are redelivered during reconnection
        if let SignalProtocolError::DuplicatedMessage(chain, counter) = e {
            log::debug!(
                "Skipping already-processed message from {} (chain {}, counter {}). This is normal during reconnection.",
                info.source.sender,
                chain,
                counter
            );
            *any_duplicate = true;
            return None;
        }

        // Handle UntrustedIdentity: This happens when a user re-installs WhatsApp or changes devices.
        if let SignalProtocolError::UntrustedIdentity(ref address) = e {
            return Some(
                self.handle_untrusted_identity(
                    address,
                    parsed_message,
                    signal_address,
                    adapter,
                    rng,
                    enc_type,
                    padding_version,
                    info,
                    any_success,
                    any_duplicate,
                )
                .await,
            );
        }

        // Handle SessionNotFound gracefully - send retry receipt to request session establishment
        if let SignalProtocolError::SessionNotFound(_) = e {
            warn!(
                "[msg:{}] No session found for {} message from {}. Sending retry receipt to request session establishment.",
                info.id, enc_type, info.source.sender
            );
            return Some(self.handle_decrypt_failure(info, RetryReason::NoSession));
        }

        if matches!(e, SignalProtocolError::InvalidMessage(_, _)) {
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

            return Some(self.handle_decrypt_failure(info, RetryReason::InvalidMessage));
        }

        if matches!(e, SignalProtocolError::InvalidPreKeyId) {
            log::warn!(
                "[msg:{}] Decryption failed for {} message from {} due to InvalidPreKeyId. \
                 Sender is using a prekey we don't have (likely session established while offline). \
                 Sending retry receipt with fresh prekeys.",
                info.id,
                enc_type,
                info.source.sender
            );
            return Some(self.handle_decrypt_failure(info, RetryReason::InvalidKeyId));
        }

        // For other unexpected errors, just log them
        log::error!(
            "[msg:{}] Batch session decrypt failed (type: {}) from {}: {:?}",
            info.id,
            enc_type,
            info.source.sender,
            e
        );
        None
    }

    /// Handles UntrustedIdentity errors by clearing the old identity and retrying.
    #[allow(clippy::too_many_arguments)]
    async fn handle_untrusted_identity(
        self: &Arc<Self>,
        address: &wacore::libsignal::protocol::ProtocolAddress,
        parsed_message: &wacore::libsignal::protocol::CiphertextMessage,
        signal_address: &wacore::libsignal::protocol::ProtocolAddress,
        adapter: &mut SignalProtocolStoreAdapter,
        rng: &rand::rngs::OsRng,
        enc_type: &str,
        padding_version: u8,
        info: &MessageInfo,
        any_success: &mut bool,
        any_duplicate: &mut bool,
    ) -> bool {
        log::warn!(
            "[msg:{}] Received message from untrusted identity: {}. This typically means the sender re-installed WhatsApp or changed their device. Clearing old identity to trust new key (keeping session for in-flight messages).",
            info.id,
            address
        );

        // Extract backend handle
        let backend = {
            let device_arc = self.persistence_manager.get_device_arc().await;
            let device = device_arc.read().await;
            Arc::clone(&device.backend)
        };

        // Delete the old, untrusted identity
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
            parsed_message,
            signal_address,
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
                *any_success = true;
                if let Err(e) = self
                    .clone()
                    .handle_decrypted_plaintext(enc_type, &padded_plaintext, padding_version, info)
                    .await
                {
                    log::warn!("Failed processing plaintext after identity retry: {e:?}");
                }
                false
            }
            Err(retry_err) => {
                if let SignalProtocolError::DuplicatedMessage(chain, counter) = retry_err {
                    log::debug!(
                        "Message from {} was already processed (chain {}, counter {}) - detected during untrusted identity retry. This is normal during reconnection.",
                        address,
                        chain,
                        counter
                    );
                    *any_duplicate = true;
                    false
                } else if matches!(retry_err, SignalProtocolError::InvalidPreKeyId) {
                    log::warn!(
                        "[msg:{}] Decryption failed for {} due to InvalidPreKeyId after identity change. \
                         The sender is using an old prekey we no longer have. \
                         Sending retry receipt with fresh keys.",
                        info.id,
                        address
                    );
                    self.handle_decrypt_failure(info, RetryReason::InvalidKeyId)
                } else {
                    log::error!(
                        "[msg:{}] Decryption failed even after clearing untrusted identity for {}: {:?}",
                        info.id,
                        address,
                        retry_err
                    );
                    self.handle_decrypt_failure(info, RetryReason::InvalidKey)
                }
            }
        }
    }

    /// Processes a batch of group-encrypted messages (skmsg).
    pub(crate) async fn process_group_enc_batch(
        self: Arc<Self>,
        enc_nodes: &[&wacore_binary::node::Node],
        info: &MessageInfo,
        _sender_encryption_jid: &Jid,
    ) -> Result<(), DecryptionError> {
        if enc_nodes.is_empty() {
            return Ok(());
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
                    warn!(
                        "No sender key state for batched group message from {}: {}. Sending retry receipt.",
                        info.source.sender, msg
                    );
                    // Use spawn_retry_receipt which has retry count tracking
                    // NoSenderKeyState is similar to NoSession - we need the SKDM
                    self.spawn_retry_receipt(info, RetryReason::NoSession);
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

    /// Handles successfully decrypted plaintext by dispatching events and processing special messages.
    pub(crate) async fn handle_decrypted_plaintext(
        self: Arc<Self>,
        enc_type: &str,
        padded_plaintext: &[u8],
        padding_version: u8,
        info: &MessageInfo,
    ) -> Result<(), anyhow::Error> {
        // Send delivery receipt immediately in the background.
        // This should not block further message processing.
        let client_clone = self.clone();
        let info_clone = info.clone();
        tokio::spawn(async move {
            client_clone.send_delivery_receipt(&info_clone).await;
        });

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
                Ok(mut original_msg) => {
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

                    // Handle PDO (Peer Data Operation) responses from our primary phone
                    if let Some(protocol_msg) = &original_msg.protocol_message
                        && let Some(pdo_response) =
                            &protocol_msg.peer_data_operation_request_response_message
                    {
                        self.handle_pdo_response(pdo_response, info).await;
                    }

                    // Take ownership of history_sync_notification to avoid cloning large inline payload
                    let history_sync_taken = original_msg
                        .protocol_message
                        .as_mut()
                        .and_then(|pm| pm.history_sync_notification.take());

                    if let Some(history_sync) = history_sync_taken {
                        log::info!(
                            "Received HistorySyncNotification, dispatching for download and processing."
                        );
                        let client_clone = self.clone();
                        let msg_id = info.id.clone();
                        tokio::spawn(async move {
                            // Enqueue history sync task to dedicated worker
                            // history_sync is moved, not cloned - avoids copying large inline payload
                            client_clone.handle_history_sync(msg_id, history_sync).await;
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

    /// Handles app state sync key share messages.
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
}
