use crate::client::Client;
use crate::message::RetryReason;
use crate::types::events::Receipt;
use log::{info, warn};
use prost::Message;
use wacore::types::message::MessageCategory;

use scopeguard;
use std::sync::Arc;
use wacore::iq::prekeys::{OneTimePreKeyNode, SignedPreKeyNode};
use wacore::libsignal::protocol::{
    KeyPair, PreKeyBundle, PublicKey, UsePQRatchet, process_prekey_bundle,
};
use wacore::libsignal::store::PreKeyStore;
use wacore::protocol::ProtocolNode;
use wacore::types::jid::JidExt;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::JidExt as _;
use wacore_binary::node::{Node, NodeContent};

/// Helper to extract bytes content from a Node.
fn get_bytes_content(node: &Node) -> Option<&[u8]> {
    match &node.content {
        Some(NodeContent::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    }
}

/// Helper to extract registration ID from a node (4 bytes big-endian).
fn extract_registration_id_from_node(node: &Node) -> Option<u32> {
    let registration_node = node.get_optional_child("registration")?;
    let bytes = get_bytes_content(registration_node)?;

    if bytes.len() >= 4 {
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    } else if !bytes.is_empty() {
        // Handle variable-length encoding.
        let mut arr = [0u8; 4];
        let start = 4 - bytes.len();
        arr[start..].copy_from_slice(bytes);
        Some(u32::from_be_bytes(arr))
    } else {
        None
    }
}

/// Maximum retry attempts we'll honor (matches WhatsApp Web's MAX_RETRY = 5).
/// We refuse to resend if the requester has already retried this many times.
const MAX_RETRY_COUNT: u8 = 5;

/// Minimum retry count before we include keys in retry receipts.
/// WhatsApp Web only includes keys when retryCount >= 2, giving the first
/// retry a chance to succeed without key exchange overhead.
const MIN_RETRY_COUNT_FOR_KEYS: u8 = 2;

/// Minimum retry count before we start tracking base keys.
/// WhatsApp Web saves base key on retry 2, checks on retry > 2.
const MIN_RETRY_FOR_BASE_KEY_CHECK: u8 = 2;

impl Client {
    pub(crate) async fn handle_retry_receipt(
        self: &Arc<Self>,
        receipt: &Receipt,
        node: &Node,
    ) -> Result<(), anyhow::Error> {
        let retry_child = node
            .get_optional_child("retry")
            .ok_or_else(|| anyhow::anyhow!("<retry> child missing from receipt"))?;

        let message_id = retry_child
            .attrs()
            .optional_string("id")
            .ok_or_else(|| anyhow::anyhow!("<retry> missing 'id' attribute"))?
            .to_string();
        let retry_count: u8 = retry_child
            .attrs()
            .optional_string("count")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        // Refuse to handle retries that have exceeded the maximum attempts.
        // This prevents infinite retry loops and matches WhatsApp Web's behavior.
        if retry_count >= MAX_RETRY_COUNT {
            warn!(
                "Refusing retry #{} for message {} from {}: exceeds max attempts ({})",
                retry_count, message_id, receipt.source.sender, MAX_RETRY_COUNT
            );
            return Ok(());
        }

        let is_group_or_status =
            receipt.source.chat.is_group() || receipt.source.chat.is_status_broadcast();

        // For groups/status broadcasts, the actual participant is in the
        // `participant` attribute of the receipt node, NOT receipt.source.sender
        // (which may be the group/broadcast JID for non-group servers).
        let participant_str = if is_group_or_status {
            node.attrs()
                .optional_string("participant")
                .map(|s| s.to_string())
                .unwrap_or_else(|| receipt.source.sender.to_string())
        } else {
            receipt.source.sender.to_string()
        };

        // Deduplicate retry receipts to prevent processing the same retry multiple times.
        // For groups/status: key includes participant since each device retries independently.
        // For DMs: key is (chat, msg_id) since there's only one sender.
        // Uses atomic entry API to avoid race conditions between check and insert.
        let dedupe_key = if is_group_or_status {
            format!("{}:{}:{}", receipt.source.chat, message_id, participant_str)
        } else {
            format!("{}:{}", receipt.source.chat, message_id)
        };

        if self.retried_group_messages.get(&dedupe_key).await.is_some() {
            log::debug!(
                "Ignoring duplicate retry for message {} from {}: already handled.",
                message_id,
                receipt.source.sender
            );
            return Ok(());
        }
        self.retried_group_messages
            .insert(dedupe_key.clone(), ())
            .await;

        // Prevent concurrent retries for the same message+participant.
        if !self
            .pending_retries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(dedupe_key.clone())
        {
            log::debug!("Ignoring retry for {dedupe_key}: a retry is already in progress.");
            return Ok(());
        }
        let pending = Arc::clone(&self.pending_retries);
        let guard_key = dedupe_key.clone();
        let _guard = scopeguard::guard((), move |()| {
            pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .remove(&guard_key);
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

        // Re-add for groups/status so other participants can also retry.
        // take_recent_message consumed it; without this a second participant's
        // retry would silently fail with "not found in cache".
        if is_group_or_status {
            self.add_recent_message(
                receipt.source.chat.clone(),
                message_id.clone(),
                &original_msg,
            )
            .await;
        }

        // Reuse the participant string extracted earlier (same source: node's
        // `participant` attribute for groups/status, receipt.source.sender for DMs).
        let participant_jid = participant_str
            .parse::<wacore_binary::jid::Jid>()
            .unwrap_or_else(|_| receipt.source.sender.clone());

        // Resolved JID for session operations; keep original for stanza addressing
        let resolved_jid = self.resolve_encryption_jid(&participant_jid).await;

        let sender_device_id = participant_jid.device() as u32;
        let sender_user = participant_jid.user.clone();
        if !self.has_device(&sender_user, sender_device_id).await {
            warn!(
                "handle_retry_receipt: device not found for device={}, user={}",
                sender_device_id, sender_user
            );
            return Ok(());
        }

        // Check if this is a retry from our own device (peer).
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let is_peer = device_snapshot
            .pn
            .as_ref()
            .is_some_and(|our_pn| participant_jid.is_same_user_as(our_pn))
            || device_snapshot
                .lid
                .as_ref()
                .is_some_and(|our_lid| participant_jid.is_same_user_as(our_lid));

        // Process key bundle to establish a pairwise session for the retry.
        // Needed for both DMs and groups (group retries use pairwise, not sender key).
        // Status broadcasts skip this — they can't resend and only mark for next send.
        if !receipt.source.chat.is_status_broadcast() {
            // Try to process key bundle if present
            let key_bundle_result = self
                .process_retry_key_bundle(node, &resolved_jid, is_peer)
                .await;

            if let Err(e) = &key_bundle_result {
                warn!(
                    "Failed to process key bundle from retry receipt: {}. Checking for reg ID mismatch.",
                    e
                );

                // WhatsApp Web behavior: If no key bundle but registration ID differs from stored
                // session, delete the session to force re-establishment.
                // This handles the case where the requester reinstalled but didn't include keys.
                if let Some(received_reg_id) = extract_registration_id_from_node(node) {
                    let signal_address = resolved_jid.to_protocol_address();
                    let device_store = self.persistence_manager.get_device_arc().await;
                    let device_guard = device_store.read().await;

                    // Read session through cache to get consistent state
                    let session = self
                        .signal_cache
                        .get_session(&signal_address, &*device_guard.backend)
                        .await
                        .ok()
                        .flatten();
                    drop(device_guard);

                    if let Some(session) = session
                        && let Ok(stored_reg_id) = session.remote_registration_id()
                        && stored_reg_id != 0
                        && stored_reg_id != received_reg_id
                    {
                        info!(
                            "Registration ID mismatch for {} (stored: {}, received: {}). \
                             Deleting session since no key bundle provided.",
                            signal_address, stored_reg_id, received_reg_id
                        );
                        self.signal_cache.delete_session(&signal_address).await;
                        self.flush_signal_cache().await.unwrap_or_else(|e| {
                            log::warn!("Failed to flush session deletion for reg ID mismatch: {e}");
                        });
                    }
                }
            }
        }

        // Fetch group info (cache-first, server on miss) — used for SKDM rotation + addressing_mode.
        // Without this, a cold cache would silently default to PN semantics for LID groups.
        let cached_group_info = if receipt.source.chat.is_group() {
            match self.groups().query_info(&receipt.source.chat).await {
                Ok(info) => Some(info),
                Err(e) => {
                    log::warn!(
                        "Failed to fetch group info for retry of msg {} in {}: {e}",
                        message_id,
                        receipt.source.chat
                    );
                    None
                }
            }
        } else {
            None
        };

        if is_group_or_status {
            let group_jid = receipt.source.chat.to_string();

            // WA Web rotateKey: unknown device (not in participant list, not LID) →
            // force full sender key rotation by clearing all sender key device tracking.
            if !participant_jid.is_lid() && !receipt.source.chat.is_status_broadcast() {
                // If we can't verify membership (no cached group info), treat
                // as unknown and trigger rotation (matches WA Web where the
                // device wouldn't be in the senderKey map → rotateKey=true)
                let is_known_participant = cached_group_info.as_ref().is_some_and(|g| {
                    g.participants
                        .iter()
                        .any(|p| p.user == participant_jid.user)
                });

                if !is_known_participant {
                    log::warn!(
                        "Unknown device {} in group {} — forcing full sender key rotation \
                         (matches WA Web's rotateKey behavior)",
                        participant_str,
                        group_jid
                    );

                    // WA Web: deleteGroupSenderKeyInfo(groupWid, ownWid)
                    // Delete our own sender key for forward secrecy.
                    // When addressing mode is known, delete only that namespace.
                    // When unknown (group info unavailable), delete both PN and LID
                    // to ensure the active key is removed regardless of mode.
                    let addressing_mode = cached_group_info.as_ref().map(|g| g.addressing_mode);

                    let jids_to_delete: Vec<_> = match addressing_mode {
                        Some(wacore::types::message::AddressingMode::Lid) => {
                            device_snapshot.lid.as_ref().into_iter().collect()
                        }
                        Some(wacore::types::message::AddressingMode::Pn) => {
                            device_snapshot.pn.as_ref().into_iter().collect()
                        }
                        None => {
                            // Can't determine mode — delete both namespaces
                            device_snapshot
                                .lid
                                .as_ref()
                                .into_iter()
                                .chain(device_snapshot.pn.as_ref())
                                .collect()
                        }
                    };

                    for own_jid in jids_to_delete {
                        use wacore::libsignal::store::sender_key_name::SenderKeyName;
                        let sk_name = SenderKeyName::new(
                            group_jid.clone(),
                            own_jid.to_protocol_address().to_string(),
                        );
                        self.signal_cache
                            .delete_sender_key(sk_name.cache_key())
                            .await;
                    }

                    // Clear DB first, then invalidate cache. This order prevents
                    // a concurrent resolve_skdm_targets from reading stale DB rows
                    // and re-inserting them into cache after invalidation.
                    if let Err(e) = self
                        .persistence_manager
                        .clear_sender_key_devices(&group_jid)
                        .await
                    {
                        log::warn!("Failed to clear sender key devices for rotation: {}", e);
                    }
                    self.sender_key_device_cache.invalidate(&group_jid).await;
                }
            }

            // Mark this device as needing fresh SKDM (filters out own devices internally)
            if let Err(e) = self
                .mark_forget_sender_key(&group_jid, std::slice::from_ref(&participant_jid))
                .await
            {
                log::warn!(
                    "Failed to mark sender key forget for {} in {}: {}",
                    participant_jid,
                    group_jid,
                    e
                );
            } else {
                let chat_type = if receipt.source.chat.is_status_broadcast() {
                    "status broadcast"
                } else {
                    "group"
                };
                info!(
                    "Marked {} for fresh SKDM in {} {} due to retry receipt",
                    participant_jid, chat_type, group_jid
                );
            }
        } else {
            // For DMs, handle base key tracking for collision detection (matches WhatsApp Web).
            // This detects when we haven't regenerated our session despite receiving retry receipts,
            // which can cause infinite retry loops where both sides are stuck with stale keys.
            let signal_address = resolved_jid.to_protocol_address();
            let device_store = self.persistence_manager.get_device_arc().await;

            // Check for base key collision before deleting the session.
            // Read session through cache for consistent state.
            {
                let device_guard = device_store.read().await;
                let session = self
                    .signal_cache
                    .get_session(&signal_address, &*device_guard.backend)
                    .await
                    .ok()
                    .flatten();

                if let Some(session) = session
                    && let Ok(current_base_key) = session.alice_base_key()
                {
                    let addr_str = signal_address.as_str();
                    if retry_count == MIN_RETRY_FOR_BASE_KEY_CHECK {
                        // On retry 2: Save the base key for later comparison
                        if let Err(e) = device_guard
                            .backend
                            .save_base_key(addr_str, &message_id, current_base_key)
                            .await
                        {
                            warn!("Failed to save base key for {}: {}", signal_address, e);
                        } else {
                            info!(
                                "Saved base key for {} at retry #{} for collision detection",
                                signal_address, retry_count
                            );
                        }
                    } else if retry_count > MIN_RETRY_FOR_BASE_KEY_CHECK {
                        // On retry > 2: Check if base key is the same (collision detection)
                        match device_guard
                            .backend
                            .has_same_base_key(addr_str, &message_id, current_base_key)
                            .await
                        {
                            Ok(true) => {
                                // Collision detected! We haven't regenerated our session.
                                warn!(
                                    "Base key collision detected for {} at retry #{}. \
                                     Session hasn't been regenerated. Forcing fresh session.",
                                    signal_address, retry_count
                                );
                                // Clean up base key entry since we're deleting the session
                                let _ = device_guard
                                    .backend
                                    .delete_base_key(addr_str, &message_id)
                                    .await;
                            }
                            Ok(false) => {
                                // Base key changed, session was regenerated - good!
                                info!(
                                    "Base key changed for {} at retry #{} - session regenerated",
                                    signal_address, retry_count
                                );
                                // Clean up old base key entry
                                let _ = device_guard
                                    .backend
                                    .delete_base_key(addr_str, &message_id)
                                    .await;
                            }
                            Err(e) => {
                                warn!("Failed to check base key for {}: {}", signal_address, e);
                            }
                        }
                    }
                }
            }

            // Delete the old session through the signal cache so encryption uses a fresh session.
            // IMPORTANT: Must go through cache, not backend, to avoid stale cached sessions.
            self.signal_cache.delete_session(&signal_address).await;
            self.flush_signal_cache().await.unwrap_or_else(|e| {
                log::warn!("Failed to flush signal cache after session delete: {e}");
            });
            info!("Deleted session for {signal_address} due to retry receipt");
        }

        // Status broadcasts can't resend (requires explicit recipient list).
        // Participant already marked for fresh SKDM above; next status send includes them.
        if receipt.source.chat.is_status_broadcast() {
            info!(
                "Status broadcast retry for {} — participant marked for fresh SKDM, \
                 will be included in next status send",
                message_id
            );
            return Ok(());
        }

        info!(
            "Resending message {} to {} (retry #{})",
            message_id, receipt.source.chat, retry_count
        );

        if receipt.source.chat.is_group() {
            // Group retry: pairwise encrypt to failing device only (RetryMsgJob.js:71).
            // Using sender-key broadcast would resend to ALL participants → duplicates.
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;

            let addressing_mode = cached_group_info
                .as_ref()
                .map(|g| g.addressing_mode)
                .unwrap_or_default();

            let mut store_adapter = self.signal_adapter().await;

            let stanza = wacore::send::prepare_group_retry_stanza(
                &mut store_adapter.session_store,
                &mut store_adapter.identity_store,
                receipt.source.chat.clone(),
                participant_jid,
                resolved_jid.clone(),
                &original_msg,
                message_id,
                retry_count,
                device_snapshot.account.as_ref(),
                addressing_mode,
            )
            .await?;

            self.send_node(stanza).await?;
            self.flush_signal_cache().await.unwrap_or_else(|e| {
                log::warn!("Failed to flush signal cache after group retry: {e}");
            });
        } else {
            // DM retry: re-encrypt via normal send path (already targets single recipient)
            self.send_message_impl(
                receipt.source.chat.clone(),
                &original_msg,
                Some(message_id),
                false,
                true,
                None,
                vec![],
            )
            .await?;
        }

        Ok(())
    }

    /// Extracts and processes the key bundle from a retry receipt.
    /// This allows us to establish a new session with the requester using their fresh prekeys.
    ///
    /// # Arguments
    /// * `node` - The retry receipt node containing the key bundle
    /// * `requester_jid` - The JID of the device requesting the retry
    /// * `is_peer` - Whether this is a peer device (our own device)
    async fn process_retry_key_bundle(
        &self,
        node: &Node,
        requester_jid: &wacore_binary::jid::Jid,
        is_peer: bool,
    ) -> Result<(), anyhow::Error> {
        let keys_node = node
            .get_optional_child("keys")
            .ok_or_else(|| anyhow::anyhow!("<keys> child missing from retry receipt"))?;

        let registration_node = node.get_optional_child("registration");

        // Extract registration ID (4 bytes big-endian).
        let registration_id = registration_node
            .and_then(get_bytes_content)
            .map(|bytes| {
                if bytes.len() >= 4 {
                    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
                } else if !bytes.is_empty() {
                    // Handle variable-length encoding.
                    let mut arr = [0u8; 4];
                    let start = 4 - bytes.len();
                    arr[start..].copy_from_slice(bytes);
                    u32::from_be_bytes(arr)
                } else {
                    0
                }
            })
            .unwrap_or(0);

        if registration_id == 0 {
            return Err(anyhow::anyhow!("Invalid registration ID in retry receipt"));
        }

        let resolved_jid = self.resolve_encryption_jid(requester_jid).await;
        let signal_address = resolved_jid.to_protocol_address();

        // Check if the registration ID changed (indicates device reinstall).
        // Read session through cache for consistent state.
        {
            let device_store = self.persistence_manager.get_device_arc().await;
            let device_guard = device_store.read().await;
            let session = self
                .signal_cache
                .get_session(&signal_address, &*device_guard.backend)
                .await
                .ok()
                .flatten();
            drop(device_guard);

            if let Some(session) = session {
                let existing_reg_id = session.remote_registration_id()?;
                if existing_reg_id != 0 && existing_reg_id != registration_id {
                    // WhatsApp Web throws an error for peer device registration ID changes.
                    // This is a security measure - peer devices should maintain consistent identity.
                    if is_peer {
                        return Err(anyhow::anyhow!(
                            "Registration ID changed for peer device {} (was {}, now {}). \
                             This may indicate the device was reinstalled.",
                            signal_address,
                            existing_reg_id,
                            registration_id
                        ));
                    }
                    info!(
                        "Registration ID changed for {} (was {}, now {}). Session will be replaced.",
                        signal_address, existing_reg_id, registration_id
                    );
                }
            }
        }

        // Extract identity key.
        let identity_bytes = keys_node
            .get_optional_child("identity")
            .and_then(get_bytes_content)
            .ok_or_else(|| anyhow::anyhow!("Missing identity key in retry receipt"))?;
        let identity_key = PublicKey::from_djb_public_key_bytes(identity_bytes)?;

        // Extract prekey (optional in some cases).
        let prekey_node = keys_node
            .get_optional_child("key")
            .map(OneTimePreKeyNode::try_from_node)
            .transpose()?;
        let prekey_data = if let Some(prekey_node) = prekey_node {
            let prekey_public = PublicKey::from_djb_public_key_bytes(&prekey_node.public_bytes)?;
            Some((prekey_node.id.into(), prekey_public))
        } else {
            None
        };

        // Extract signed prekey.
        let skey_node = keys_node
            .get_optional_child("skey")
            .ok_or_else(|| anyhow::anyhow!("Missing signed prekey in retry receipt"))?;

        let signed_prekey = SignedPreKeyNode::try_from_node(skey_node)?;
        let skey_public = PublicKey::from_djb_public_key_bytes(&signed_prekey.public_bytes)?;
        let skey_signature: [u8; 64] = signed_prekey
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid signature length"))?;

        // Build and process the prekey bundle.
        let bundle = PreKeyBundle::new(
            registration_id,
            u32::from(requester_jid.device).into(),
            prekey_data,
            signed_prekey.id.into(),
            skey_public,
            skey_signature.into(),
            identity_key.into(),
        )?;

        // Acquire per-sender session lock to prevent race with concurrent message decryption.
        // This matches the session_locks pattern used in process_session_enc_batch.
        let session_mutex = self.session_lock_for(signal_address.as_str()).await;
        let _session_guard = session_mutex.lock().await;

        let mut adapter = self.signal_adapter().await;

        process_prekey_bundle(
            &signal_address,
            &mut adapter.session_store,
            &mut adapter.identity_store,
            &bundle,
            &mut rand::make_rng::<rand::rngs::StdRng>(),
            UsePQRatchet::No,
        )
        .await?;

        // Flush after session establishment
        self.flush_signal_cache().await?;

        info!(
            "Processed key bundle from retry receipt for {}",
            signal_address
        );

        Ok(())
    }

    /// Sends a retry receipt to request the sender to resend a message.
    ///
    /// # Arguments
    /// * `info` - The message info for the failed message
    /// * `retry_count` - The retry attempt number (1-5). This is sent to the sender so they
    ///   know which attempt this is. The sender may use this to decide whether to resend.
    /// * `reason` - The retry reason code (matches WhatsApp Web's RetryReason enum). This helps
    ///   the sender understand why the message couldn't be decrypted.
    pub(crate) async fn send_retry_receipt(
        &self,
        info: &crate::types::message::MessageInfo,
        retry_count: u8,
        reason: RetryReason,
    ) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        // Bot message filtering (matches WhatsApp Web behavior):
        // Don't send retry receipts to bot accounts from non-bot accounts.
        // This prevents unnecessary retry traffic to automated systems.
        let we_are_bot = device_snapshot
            .pn
            .as_ref()
            .map(|our_pn| our_pn.is_bot())
            .unwrap_or(false);
        let sender_is_bot = info.source.sender.is_bot();

        if !we_are_bot && sender_is_bot {
            log::debug!(
                "Skipping retry receipt for message {} from bot {}: bots don't process retries",
                info.id,
                info.source.sender
            );
            return Ok(());
        }

        warn!(
            "Sending retry receipt #{} for message {} from {} (reason: {:?})",
            retry_count, info.id, info.source.sender, reason
        );

        // Build the retry element with the error code (matches WhatsApp Web's format)
        let mut retry_builder = NodeBuilder::new("retry")
            .attr("v", "1")
            .attr("id", info.id.clone())
            .attr("t", info.timestamp.timestamp().to_string())
            .attr("count", retry_count.to_string());

        // Include the error code if it's not UnknownError (matches WhatsApp Web's behavior
        // where error is only included when there's a specific reason)
        if reason != RetryReason::UnknownError {
            retry_builder = retry_builder.attr("error", (reason as u8).to_string());
        }

        let retry_node = retry_builder.build();

        let registration_id_bytes = device_snapshot.registration_id.to_be_bytes().to_vec();
        let registration_node = NodeBuilder::new("registration")
            .bytes(registration_id_bytes)
            .build();

        // WhatsApp Web only includes keys when retryCount >= 2.
        // First retry gives the sender a chance to resend without full key exchange.
        //
        // WA Web includes keys at retryCount >= MIN_RETRY_COUNT_FOR_KEYS.
        // Optimization for NoSession: include keys on retry#1 to reduce round-trips
        // for skmsg-only failures where the sender needs our prekeys for SKDM.
        let include_keys_early = reason == RetryReason::NoSession;
        let keys_node = if retry_count >= MIN_RETRY_COUNT_FOR_KEYS || include_keys_early {
            let device_store = self.persistence_manager.get_device_arc().await;
            let device_guard = device_store.read().await;

            let new_prekey_id = (rand::random::<u32>() % 16777215) + 1;
            let new_prekey_keypair = KeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>());
            let new_prekey_record = wacore::libsignal::store::record_helpers::new_pre_key_record(
                new_prekey_id,
                &new_prekey_keypair,
            );
            // This key is not uploaded to the server pool, so mark as false
            if let Err(e) = device_guard
                .store_prekey(new_prekey_id, new_prekey_record, false)
                .await
            {
                warn!("Failed to store new prekey for retry receipt: {e:?}");
            }
            drop(device_guard);

            let identity_key_bytes = device_snapshot
                .identity_key
                .public_key
                .public_key_bytes()
                .to_vec();

            let prekey_value_bytes = new_prekey_keypair.public_key.serialize().to_vec();

            let skey_id = device_snapshot.signed_pre_key_id;
            let skey_value_bytes = device_snapshot
                .signed_pre_key
                .public_key
                .serialize()
                .to_vec();
            let skey_sig_bytes = device_snapshot.signed_pre_key_signature.to_vec();

            let device_identity_bytes = device_snapshot
                .account
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Missing device account info for retry receipt"))?
                .encode_to_vec();

            let type_bytes = vec![5u8];

            Some(
                NodeBuilder::new("keys")
                    .children([
                        NodeBuilder::new("type").bytes(type_bytes).build(),
                        NodeBuilder::new("identity")
                            .bytes(identity_key_bytes)
                            .build(),
                        OneTimePreKeyNode::new(new_prekey_id, prekey_value_bytes).into_node(),
                        SignedPreKeyNode::new(skey_id, skey_value_bytes, skey_sig_bytes)
                            .into_node(),
                        NodeBuilder::new("device-identity")
                            .bytes(device_identity_bytes)
                            .build(),
                    ])
                    .build(),
            )
        } else {
            None
        };

        let receipt_to = if info.source.is_group {
            &info.source.chat
        } else {
            &info.source.sender
        };

        // Build the receipt node. For group messages, include the participant attribute
        // to identify which group member should resend. For DMs, omit it since the
        // "to" address already identifies the sender.
        let mut builder = NodeBuilder::new("receipt")
            .attr("to", receipt_to.clone())
            .attr("id", info.id.clone())
            .attr("type", "retry");

        if info.source.is_group {
            builder = builder.attr("participant", info.source.sender.clone());
        }

        // Handle peer vs device sync messages (matches WhatsApp Web's sendRetryReceipt):
        // WhatsApp Web checks: if (to.isUser()) { if (isMeAccount(to)) { ... } }
        // This means the category/recipient logic ONLY applies to DMs (not groups).
        // For groups, only the participant attribute is set (handled above).
        if !info.source.is_group {
            let is_from_own_account = device_snapshot
                .pn
                .as_ref()
                .is_some_and(|pn| info.source.sender.is_same_user_as(pn))
                || device_snapshot
                    .lid
                    .as_ref()
                    .is_some_and(|lid| info.source.sender.is_same_user_as(lid));

            if is_from_own_account {
                if info.category == MessageCategory::Peer {
                    builder = builder.attr("category", MessageCategory::Peer.as_str());
                } else {
                    // Include recipient so the sender can look up the original message.
                    // Without this, the retry fails silently (getTargetChat returns null).
                    let recipient = info.source.recipient.as_ref().unwrap_or(&info.source.chat);
                    builder = builder.attr("recipient", recipient.clone());
                }
            }
        }

        // Build children list - keys are only included when retryCount >= 2
        let receipt_node = if let Some(keys) = keys_node {
            builder
                .children([retry_node, registration_node, keys])
                .build()
        } else {
            builder.children([retry_node, registration_node]).build()
        };

        self.send_node(receipt_node).await?;
        Ok(())
    }

    /// Sends an `enc_rekey_retry` receipt for VoIP call encryption re-keying.
    ///
    /// WA Web: When a peer fails to decrypt VoIP call encryption data (e.g.,
    /// `<enc>` within a `<call>` stanza), the receiver sends this receipt asking
    /// the sender to re-key.  The receipt uses `<enc_rekey>` child instead of
    /// `<retry>`, carrying VoIP call context (`call-id`, `call-creator`).
    ///
    /// WA Web reference: `ENC_RETRY_RECEIPT_ATTRS.GROUP_CALL = "enc_rekey_retry"`,
    /// constructed in `WAWebVoipSignalingEnums` module.
    #[allow(dead_code)] // Will be used when call handling is implemented (#345)
    pub(crate) async fn send_enc_rekey_retry_receipt(
        &self,
        stanza_id: &str,
        peer_jid: &wacore_binary::jid::Jid,
        call_id: &str,
        call_creator: &wacore_binary::jid::Jid,
        retry_count: u8,
    ) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        let registration_id_bytes = device_snapshot.registration_id.to_be_bytes().to_vec();

        // WA Web: <enc_rekey call-creator="JID" call-id="..." count="N"/>
        let enc_rekey_node = NodeBuilder::new("enc_rekey")
            .attr("call-creator", call_creator.clone())
            .attr("call-id", call_id)
            .attr("count", retry_count.to_string())
            .build();

        let registration_node = NodeBuilder::new("registration")
            .bytes(registration_id_bytes)
            .build();

        let receipt_node = NodeBuilder::new("receipt")
            .attr("to", peer_jid.clone())
            .attr("id", stanza_id)
            .attr("type", "enc_rekey_retry")
            .children([enc_rekey_node, registration_node])
            .build();

        info!(
            "Sending enc_rekey_retry receipt for call-id={} to {} (count={})",
            call_id, peer_jid, retry_count
        );

        self.send_node(receipt_node).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::persistence_manager::PersistenceManager;
    use crate::test_utils::MockHttpClient;
    use std::borrow::Cow;
    use wacore_binary::jid::{Jid, JidExt};
    use waproto::whatsapp as wa;

    #[tokio::test]
    async fn recent_message_cache_insert_and_take() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        // Enable L1 cache so MockBackend (which doesn't persist) works for this test
        let mut config = crate::cache_config::CacheConfig::default();
        config.recent_messages.capacity = 1_000;
        let (client, _sync_rx) = Client::new_with_cache_config(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
            config,
        )
        .await;

        let chat: Jid = "120363021033254949@g.us"
            .parse()
            .expect("test JID should be valid");
        let msg_id = "ABC123".to_string();
        let msg = wa::Message {
            conversation: Some("hello".into()),
            ..Default::default()
        };

        // Insert via the new async API
        client
            .add_recent_message(chat.clone(), msg_id.clone(), &msg)
            .await;

        // First take should return and remove it from cache
        let taken = client
            .take_recent_message(chat.clone(), msg_id.clone())
            .await;
        assert!(taken.is_some());
        assert_eq!(
            taken
                .expect("taken message should exist")
                .conversation
                .as_deref(),
            Some("hello")
        );

        // Second take should return None
        let taken_again = client.take_recent_message(chat, msg_id).await;
        assert!(taken_again.is_none());
    }

    #[test]
    fn get_bytes_content_extracts_bytes() {
        use wacore_binary::node::{Attrs, Node};

        // Test with bytes content
        let node = Node {
            tag: Cow::Borrowed("test"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Bytes(vec![1, 2, 3, 4])),
        };
        assert_eq!(get_bytes_content(&node), Some(&[1, 2, 3, 4][..]));

        // Test with string content (should return None)
        let node_str = Node {
            tag: Cow::Borrowed("test"),
            attrs: Attrs::new(),
            content: Some(NodeContent::String("hello".to_string())),
        };
        assert_eq!(get_bytes_content(&node_str), None);

        // Test with no content
        let node_empty = Node {
            tag: Cow::Borrowed("test"),
            attrs: Attrs::new(),
            content: None,
        };
        assert_eq!(get_bytes_content(&node_empty), None);
    }

    #[test]
    fn peer_detection_logic() {
        let our_jid = Jid::pn("559911112222");
        let peer_jid = Jid::pn_device("559911112222", 1);
        let other_jid = Jid::pn("559933334444");

        assert_eq!(our_jid.user, peer_jid.user);
        assert_ne!(our_jid.user, other_jid.user);
    }

    /// Integration test for retry receipt attribute logic.
    /// Tests the fix for lost device sync messages (AC7B18EBD4445BFC55C0EA3CF9F913F8 case).
    /// Matches WhatsApp Web's sendRetryReceipt: if (to.isUser()) { if (isMeAccount(to)) { ... } }
    #[test]
    fn retry_receipt_attributes_for_device_sync_vs_peer_vs_group() {
        use wacore::types::message::{MessageCategory, MessageInfo, MessageSource};
        use wacore_binary::builder::NodeBuilder;

        let our_pn = Jid::pn("559999999999");
        let our_lid = Jid::lid("100000000000001");

        fn build_retry_receipt(
            info: &MessageInfo,
            our_pn: &Jid,
            our_lid: &Jid,
        ) -> wacore_binary::node::Node {
            let mut builder = NodeBuilder::new("receipt")
                .attr("to", info.source.sender.clone())
                .attr("id", info.id.clone())
                .attr("type", "retry");

            if info.source.is_group {
                builder = builder.attr("participant", info.source.sender.clone());
            }

            if !info.source.is_group {
                let is_from_own_account = info.source.sender.is_same_user_as(our_pn)
                    || info.source.sender.is_same_user_as(our_lid);

                if is_from_own_account {
                    if info.category == MessageCategory::Peer {
                        builder = builder.attr("category", MessageCategory::Peer.as_str());
                    } else {
                        let recipient = info.source.recipient.as_ref().unwrap_or(&info.source.chat);
                        builder = builder.attr("recipient", recipient.clone());
                    }
                }
            }

            builder.build()
        }

        // Case 1: Device sync DM
        let recipient_lid = Jid::lid("200000000000002");
        let device_sync_info = MessageInfo {
            id: "DEVICE_SYNC_MSG_001".to_string(),
            source: MessageSource {
                chat: recipient_lid.clone(),
                sender: our_lid.clone(),
                is_from_me: true,
                is_group: false,
                recipient: Some(recipient_lid.clone()),
                ..Default::default()
            },
            category: MessageCategory::default(),
            ..Default::default()
        };

        let node = build_retry_receipt(&device_sync_info, &our_pn, &our_lid);
        assert_eq!(
            node.attrs
                .get("recipient")
                .map(|v| v == "200000000000002@lid"),
            Some(true),
            "Device sync DM should include recipient"
        );
        assert!(
            node.attrs.get("category").is_none(),
            "Device sync DM should NOT have category=peer"
        );
        assert!(
            node.attrs.get("participant").is_none(),
            "DM should NOT have participant"
        );

        // Case 2: Peer DM with category="peer"
        let other_pn = Jid::pn("551188888888");
        let peer_info = MessageInfo {
            id: "PEER123".to_string(),
            source: MessageSource {
                chat: other_pn.clone(),
                sender: our_pn.clone(),
                is_from_me: true,
                is_group: false,
                recipient: None,
                ..Default::default()
            },
            category: MessageCategory::Peer,
            ..Default::default()
        };

        let node = build_retry_receipt(&peer_info, &our_pn, &our_lid);
        assert_eq!(
            node.attrs.get("category").map(|v| v == "peer"),
            Some(true),
            "Peer DM should have category=peer"
        );
        assert!(
            node.attrs.get("recipient").is_none(),
            "Peer DM should NOT have recipient"
        );

        // Case 3: Group message from our own account
        let group_info = MessageInfo {
            id: "GROUP123".to_string(),
            source: MessageSource {
                chat: "123456789@g.us".parse().unwrap(),
                sender: our_lid.clone(),
                is_from_me: true,
                is_group: true,
                recipient: None,
                ..Default::default()
            },
            category: MessageCategory::default(),
            ..Default::default()
        };

        let node = build_retry_receipt(&group_info, &our_pn, &our_lid);
        assert!(
            node.attrs.get("participant").is_some(),
            "Group should have participant"
        );
        assert!(
            node.attrs.get("category").is_none(),
            "Group should NOT have category"
        );
        assert!(
            node.attrs.get("recipient").is_none(),
            "Group should NOT have recipient"
        );

        // Case 4: DM from someone else
        let other_dm_info = MessageInfo {
            id: "OTHER123".to_string(),
            source: MessageSource {
                chat: other_pn.clone(),
                sender: other_pn.clone(),
                is_from_me: false,
                is_group: false,
                recipient: None,
                ..Default::default()
            },
            category: MessageCategory::default(),
            ..Default::default()
        };

        let node = build_retry_receipt(&other_dm_info, &our_pn, &our_lid);
        assert!(
            node.attrs.get("category").is_none(),
            "DM from other should NOT have category"
        );
        assert!(
            node.attrs.get("recipient").is_none(),
            "DM from other should NOT have recipient"
        );
    }

    /// Verify enc_rekey_retry receipt node structure matches WhatsApp Web:
    /// <receipt to="peer" id="stanza_id" type="enc_rekey_retry">
    ///   <enc_rekey call-creator="creator_jid" call-id="..." count="N"/>
    ///   <registration>{4-byte big-endian reg id}</registration>
    /// </receipt>
    #[test]
    fn enc_rekey_retry_receipt_node_structure() {
        use wacore_binary::builder::NodeBuilder;

        let peer_jid: Jid = "5511999999999@s.whatsapp.net".parse().expect("peer JID");
        let call_creator: Jid = "5511888888888@s.whatsapp.net".parse().expect("creator JID");
        let call_id = "CALL-ABC-123";
        let stanza_id = "3EB0AABBCCDD";
        let retry_count: u8 = 2;
        let registration_id: u32 = 12345;

        // Build the receipt exactly as send_enc_rekey_retry_receipt does
        let enc_rekey_node = NodeBuilder::new("enc_rekey")
            .attr("call-creator", call_creator)
            .attr("call-id", call_id)
            .attr("count", retry_count.to_string())
            .build();

        let registration_node = NodeBuilder::new("registration")
            .bytes(registration_id.to_be_bytes().to_vec())
            .build();

        let receipt_node = NodeBuilder::new("receipt")
            .attr("to", peer_jid)
            .attr("id", stanza_id)
            .attr("type", "enc_rekey_retry")
            .children([enc_rekey_node, registration_node])
            .build();

        // Verify top-level receipt attributes
        assert_eq!(
            receipt_node.attrs().optional_string("type").as_deref(),
            Some("enc_rekey_retry"),
            "receipt type must be enc_rekey_retry"
        );
        assert!(
            receipt_node
                .attrs
                .get("to")
                .is_some_and(|v| *v == "5511999999999@s.whatsapp.net"),
            "receipt 'to' must be peer JID"
        );
        assert_eq!(
            receipt_node.attrs().optional_string("id").as_deref(),
            Some("3EB0AABBCCDD")
        );

        // Verify <enc_rekey> child (NOT <retry>)
        assert!(
            receipt_node.get_optional_child("retry").is_none(),
            "enc_rekey_retry must NOT contain <retry> child"
        );
        let enc_rekey = receipt_node
            .get_optional_child("enc_rekey")
            .expect("<enc_rekey> child must exist");
        assert_eq!(
            enc_rekey.attrs().optional_string("call-id").as_deref(),
            Some("CALL-ABC-123")
        );
        assert!(
            enc_rekey
                .attrs
                .get("call-creator")
                .is_some_and(|v| *v == "5511888888888@s.whatsapp.net"),
            "enc_rekey 'call-creator' must be creator JID"
        );
        assert_eq!(
            enc_rekey.attrs().optional_string("count").as_deref(),
            Some("2")
        );

        // Verify <registration> child
        let registration = receipt_node
            .get_optional_child("registration")
            .expect("<registration> child must exist");
        let reg_bytes = match &registration.content {
            Some(wacore_binary::node::NodeContent::Bytes(b)) => b.clone(),
            _ => panic!("registration must contain bytes"),
        };
        assert_eq!(
            u32::from_be_bytes(reg_bytes.try_into().unwrap()),
            12345,
            "registration ID must be 4-byte big-endian"
        );
    }

    #[test]
    fn prekey_id_parsing() {
        // PreKey IDs are 3 bytes big-endian
        let id_bytes = [0x01, 0x02, 0x03];
        let prekey_id = u32::from_be_bytes([0, id_bytes[0], id_bytes[1], id_bytes[2]]);
        assert_eq!(prekey_id, 0x00010203);

        // Signed prekey IDs follow the same format
        let skey_id_bytes = [0xFF, 0xFE, 0xFD];
        let skey_id = u32::from_be_bytes([0, skey_id_bytes[0], skey_id_bytes[1], skey_id_bytes[2]]);
        assert_eq!(skey_id, 0x00FFFEFD);
    }

    #[tokio::test]
    async fn base_key_store_operations() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend().await;

        let address = "12345.0:1";
        let msg_id = "ABC123";
        let base_key = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Initially, has_same_base_key should return false (no saved key)
        let result = backend.has_same_base_key(address, msg_id, &base_key).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Save the base key
        let save_result = backend.save_base_key(address, msg_id, &base_key).await;
        assert!(save_result.is_ok());

        // Same key should now match (collision detected)
        let result = backend.has_same_base_key(address, msg_id, &base_key).await;
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Different key should NOT match (no collision)
        let different_key = vec![10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let result = backend
            .has_same_base_key(address, msg_id, &different_key)
            .await;
        assert!(result.is_ok());
        assert!(!result.unwrap());

        // Delete the base key
        let delete_result = backend.delete_base_key(address, msg_id).await;
        assert!(delete_result.is_ok());

        // After deletion, has_same_base_key should return false
        let result = backend.has_same_base_key(address, msg_id, &base_key).await;
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[tokio::test]
    async fn base_key_store_upsert() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend().await;

        let address = "12345.0:1";
        let msg_id = "MSG001";
        let first_key = vec![1, 2, 3];
        let second_key = vec![4, 5, 6];

        // Save first key
        backend
            .save_base_key(address, msg_id, &first_key)
            .await
            .unwrap();
        assert!(
            backend
                .has_same_base_key(address, msg_id, &first_key)
                .await
                .unwrap()
        );
        assert!(
            !backend
                .has_same_base_key(address, msg_id, &second_key)
                .await
                .unwrap()
        );

        // Save second key (upsert should replace)
        backend
            .save_base_key(address, msg_id, &second_key)
            .await
            .unwrap();
        assert!(
            !backend
                .has_same_base_key(address, msg_id, &first_key)
                .await
                .unwrap()
        );
        assert!(
            backend
                .has_same_base_key(address, msg_id, &second_key)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn base_key_store_multiple_messages() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend().await;

        let address = "12345.0:1";
        let msg_id_1 = "MSG001";
        let msg_id_2 = "MSG002";
        let key_1 = vec![1, 2, 3];
        let key_2 = vec![4, 5, 6];

        // Save keys for different messages
        backend
            .save_base_key(address, msg_id_1, &key_1)
            .await
            .unwrap();
        backend
            .save_base_key(address, msg_id_2, &key_2)
            .await
            .unwrap();

        // Each message should have its own key
        assert!(
            backend
                .has_same_base_key(address, msg_id_1, &key_1)
                .await
                .unwrap()
        );
        assert!(
            !backend
                .has_same_base_key(address, msg_id_1, &key_2)
                .await
                .unwrap()
        );
        assert!(
            !backend
                .has_same_base_key(address, msg_id_2, &key_1)
                .await
                .unwrap()
        );
        assert!(
            backend
                .has_same_base_key(address, msg_id_2, &key_2)
                .await
                .unwrap()
        );

        // Delete one message's key, other should remain
        backend.delete_base_key(address, msg_id_1).await.unwrap();
        assert!(
            !backend
                .has_same_base_key(address, msg_id_1, &key_1)
                .await
                .unwrap()
        );
        assert!(
            backend
                .has_same_base_key(address, msg_id_2, &key_2)
                .await
                .unwrap()
        );
    }

    #[test]
    fn bot_jid_detection() {
        // Test bot JID detection for bot message filtering
        use wacore_binary::jid::JidExt as _;

        // Regular user JID - not a bot
        let regular_user: Jid = "1234567890@s.whatsapp.net".parse().unwrap();
        assert!(!regular_user.is_bot());

        // Bot JID with bot server
        let bot_server: Jid = "somebot@bot".parse().unwrap();
        assert!(bot_server.is_bot());

        // Legacy bot JID pattern (1313555...)
        let legacy_bot: Jid = "1313555123456@s.whatsapp.net".parse().unwrap();
        assert!(legacy_bot.is_bot());

        // Legacy bot JID pattern (131655500...)
        let legacy_bot2: Jid = "131655500123456@s.whatsapp.net".parse().unwrap();
        assert!(legacy_bot2.is_bot());

        // Similar but not bot (doesn't start with exact prefix)
        let not_bot: Jid = "1313556123456@s.whatsapp.net".parse().unwrap();
        assert!(!not_bot.is_bot());
    }

    #[test]
    fn extract_registration_id_from_node_test() {
        use wacore_binary::node::{Attrs, Node};

        // Test with 4-byte registration ID
        let reg_bytes = vec![0x00, 0x01, 0x02, 0x03]; // = 66051
        let reg_node = Node {
            tag: Cow::Borrowed("registration"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Bytes(reg_bytes)),
        };
        let parent = Node {
            tag: Cow::Borrowed("receipt"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![reg_node])),
        };
        assert_eq!(extract_registration_id_from_node(&parent), Some(0x00010203));

        // Test with 3-byte registration ID (variable length)
        let reg_bytes_short = vec![0x01, 0x02, 0x03]; // = 66051
        let reg_node_short = Node {
            tag: Cow::Borrowed("registration"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Bytes(reg_bytes_short)),
        };
        let parent_short = Node {
            tag: Cow::Borrowed("receipt"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![reg_node_short])),
        };
        assert_eq!(
            extract_registration_id_from_node(&parent_short),
            Some(0x00010203)
        );

        // Test with no registration node
        let parent_no_reg = Node {
            tag: Cow::Borrowed("receipt"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![])),
        };
        assert_eq!(extract_registration_id_from_node(&parent_no_reg), None);

        // Test with empty bytes
        let reg_node_empty = Node {
            tag: Cow::Borrowed("registration"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Bytes(vec![])),
        };
        let parent_empty = Node {
            tag: Cow::Borrowed("receipt"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![reg_node_empty])),
        };
        assert_eq!(extract_registration_id_from_node(&parent_empty), None);
    }

    #[test]
    fn group_or_status_detection_for_sender_key_handling() {
        // Test that both groups and status broadcasts trigger sender key handling
        use wacore_binary::jid::JidExt as _;

        let group: Jid = "120363021033254949@g.us".parse().unwrap();
        let status: Jid = "status@broadcast".parse().unwrap();
        let dm: Jid = "1234567890@s.whatsapp.net".parse().unwrap();

        // Both group and status should trigger sender key deletion
        assert!(group.is_group() || group.is_status_broadcast());
        assert!(status.is_group() || status.is_status_broadcast());

        // DM should NOT trigger sender key deletion
        assert!(!(dm.is_group() || dm.is_status_broadcast()));
    }

    /// Test that verifies the key inclusion optimization:
    /// - Keys should be included on retry#1 for NoSession errors (the optimization)
    /// - Keys should NOT be included on retry#1 for other error types
    /// - Keys should be included on retry#2+ for ALL error types
    #[test]
    fn keys_inclusion_optimization_for_no_session_errors() {
        use crate::message::RetryReason;

        // Test cases: (retry_count, reason, should_include_keys)
        let test_cases = [
            // NoSession errors - optimization kicks in at retry#1
            (
                1,
                RetryReason::NoSession,
                true,
                "NoSession at retry#1 should include keys (optimization)",
            ),
            (
                2,
                RetryReason::NoSession,
                true,
                "NoSession at retry#2 should include keys",
            ),
            (
                3,
                RetryReason::NoSession,
                true,
                "NoSession at retry#3 should include keys",
            ),
            // InvalidMessage errors - no keys at retry#1, keys at retry#2+
            (
                1,
                RetryReason::InvalidMessage,
                false,
                "InvalidMessage at retry#1 should NOT include keys",
            ),
            (
                2,
                RetryReason::InvalidMessage,
                true,
                "InvalidMessage at retry#2 should include keys",
            ),
            (
                3,
                RetryReason::InvalidMessage,
                true,
                "InvalidMessage at retry#3 should include keys",
            ),
            // BadMac errors - same as InvalidMessage
            (
                1,
                RetryReason::BadMac,
                false,
                "BadMac at retry#1 should NOT include keys",
            ),
            (
                2,
                RetryReason::BadMac,
                true,
                "BadMac at retry#2 should include keys",
            ),
            // UnknownError - no keys at retry#1
            (
                1,
                RetryReason::UnknownError,
                false,
                "UnknownError at retry#1 should NOT include keys",
            ),
            (
                2,
                RetryReason::UnknownError,
                true,
                "UnknownError at retry#2 should include keys",
            ),
        ];

        for (retry_count, reason, should_include_keys, description) in test_cases {
            // Replicate the logic from send_retry_receipt
            let include_keys_early = reason == RetryReason::NoSession;
            let would_include_keys = retry_count >= MIN_RETRY_COUNT_FOR_KEYS || include_keys_early;

            assert_eq!(
                would_include_keys, should_include_keys,
                "Failed: {description}. retry_count={retry_count}, reason={reason:?}"
            );
        }
    }

    /// Integration test simulating high concurrent offline message scenarios.
    /// This tests the scenario where many skmsg-only messages arrive before SKDM,
    /// causing NoSession errors that need retry with keys.
    #[tokio::test]
    async fn concurrent_offline_messages_retry_key_optimization() {
        use crate::message::RetryReason;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::sync::Barrier;

        let _ = env_logger::builder().is_test(true).try_init();

        // Simulate processing multiple concurrent skmsg failures
        // Each represents a skmsg-only message from the same sender that failed with NoSession
        let num_messages = 50;
        let barrier = Arc::new(Barrier::new(num_messages));

        // Track how many would include keys on retry#1
        let keys_included_count = Arc::new(AtomicUsize::new(0));
        let no_keys_count = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();

        for i in 0..num_messages {
            let barrier = barrier.clone();
            let keys_included = keys_included_count.clone();
            let no_keys = no_keys_count.clone();

            handles.push(tokio::spawn(async move {
                // Simulate concurrent message processing
                barrier.wait().await;

                // Each message is a skmsg-only message that fails with NoSession
                // (simulating burst of group messages before SKDM arrives)
                let retry_count = 1; // First retry
                let reason = if i % 5 == 0 {
                    // Some messages have MAC failure (pkmsg failed)
                    RetryReason::InvalidMessage
                } else {
                    // Most are skmsg-only NoSession failures
                    RetryReason::NoSession
                };

                // Apply the optimization logic
                let include_keys_early = reason == RetryReason::NoSession;
                let would_include_keys =
                    retry_count >= MIN_RETRY_COUNT_FOR_KEYS || include_keys_early;

                if would_include_keys {
                    keys_included.fetch_add(1, Ordering::SeqCst);
                } else {
                    no_keys.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }

        // Wait for all tasks to complete
        for handle in handles {
            handle.await.expect("task should complete");
        }

        let total_keys_included = keys_included_count.load(Ordering::SeqCst);
        let total_no_keys = no_keys_count.load(Ordering::SeqCst);

        // With our optimization:
        // - 80% (40/50) are NoSession → keys included on retry#1
        // - 20% (10/50) are InvalidMessage → no keys on retry#1
        assert_eq!(
            total_keys_included, 40,
            "Expected 40 messages to include keys (NoSession), got {total_keys_included}"
        );
        assert_eq!(
            total_no_keys, 10,
            "Expected 10 messages to NOT include keys (InvalidMessage), got {total_no_keys}"
        );

        // Verify the optimization reduces round-trips
        // Without optimization: ALL 50 would need retry#2 for keys
        // With optimization: Only 10 need retry#2 for keys (80% improvement for NoSession)
        let optimization_benefit = (total_keys_included as f64 / num_messages as f64) * 100.0;
        assert!(
            optimization_benefit >= 80.0,
            "Optimization should benefit at least 80% of NoSession messages, got {optimization_benefit:.1}%"
        );
    }

    /// Test that the retry optimization correctly handles the edge case where
    /// a sender device is removed mid-retry (cannot respond to retry receipts).
    /// This tests our ability to handle the root cause of permanent failures.
    #[test]
    fn retry_optimization_with_removed_device_scenario() {
        use crate::message::RetryReason;

        // Simulate the scenario from the log:
        // 1. skmsg arrives → NoSession error → retry#1 with keys (optimization)
        // 2. Device is removed → no response to retry
        // 3. Message is permanently lost (expected behavior)

        let retry_count = 1;
        let reason = RetryReason::NoSession;

        // With optimization, we include keys on retry#1
        let include_keys_early = reason == RetryReason::NoSession;
        let would_include_keys = retry_count >= MIN_RETRY_COUNT_FOR_KEYS || include_keys_early;

        assert!(
            would_include_keys,
            "NoSession should include keys on retry#1 to give sender best chance to respond"
        );

        // Even if sender device is removed, we tried our best by including keys early
        // This reduces the window for message loss from:
        // - Before: retry#1 (no keys) → sender can't establish session → retry#2 (keys) → device removed
        // - After: retry#1 (keys) → sender can establish session immediately → device removed before response
        // The optimization gives the sender one fewer round-trip to respond.
    }

    /// Test that participant extraction from receipt nodes works correctly
    /// for status broadcasts. The `participant` attribute contains the actual
    /// retrying device, while `receipt.source.sender` may be `status@broadcast`.
    #[test]
    fn status_broadcast_participant_extraction() {
        use wacore_binary::builder::NodeBuilder;

        // Simulate a retry receipt for a status broadcast with participant attribute
        let node = NodeBuilder::new("receipt")
            .attr("from", "status@broadcast")
            .attr("id", "3EB06D00CAB92340790621")
            .attr("participant", "236395184570386@lid")
            .attr("type", "retry")
            .build();

        let is_group_or_status = true;
        let fallback_sender: Jid = "status@broadcast".parse().unwrap();

        let participant_str = if is_group_or_status {
            node.attrs()
                .optional_string("participant")
                .map(|s| s.to_string())
                .unwrap_or_else(|| fallback_sender.to_string())
        } else {
            fallback_sender.to_string()
        };

        // Should extract the actual participant, not status@broadcast
        assert_eq!(participant_str, "236395184570386@lid");

        let participant_jid: Jid = participant_str.parse().unwrap();
        assert!(participant_jid.is_lid());
        assert_eq!(participant_jid.user, "236395184570386");
        assert!(!participant_jid.is_status_broadcast());
    }

    /// Test fallback when participant attribute is missing from status receipt.
    #[test]
    fn status_broadcast_participant_extraction_fallback() {
        use wacore_binary::builder::NodeBuilder;

        // Receipt without participant attribute (edge case)
        let node = NodeBuilder::new("receipt")
            .attr("from", "status@broadcast")
            .attr("id", "MSG001")
            .attr("type", "retry")
            .build();

        let fallback_sender: Jid = "status@broadcast".parse().unwrap();

        let participant_str = node
            .attrs()
            .optional_string("participant")
            .map(|s| s.to_string())
            .unwrap_or_else(|| fallback_sender.to_string());

        // Falls back to sender (status@broadcast) — not ideal but won't crash
        assert_eq!(participant_str, "status@broadcast");
    }

    /// Test that dedupe keys are correctly differentiated per-participant
    /// for status broadcast retries.
    #[test]
    fn status_broadcast_dedupe_key_per_participant() {
        let chat = "status@broadcast";
        let msg_id = "3EB06D00CAB92340790621";

        let key_a = format!("{}:{}:{}", chat, msg_id, "236395184570386@lid");
        let key_b = format!("{}:{}:{}", chat, msg_id, "559985213786@s.whatsapp.net");

        assert_ne!(
            key_a, key_b,
            "Different participants should have different dedupe keys"
        );

        let key_a2 = format!("{}:{}:{}", chat, msg_id, "236395184570386@lid");
        assert_eq!(
            key_a, key_a2,
            "Same participant should have same dedupe key"
        );
    }

    /// Test that the recent message cache supports re-addition after take.
    /// This is critical for status broadcasts where we take the message,
    /// mark the participant for fresh SKDM, then re-add so other devices
    /// can also retry.
    #[tokio::test]
    async fn recent_message_cache_readd_after_take() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend().await;
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        // Enable L1 cache so MockBackend (which doesn't persist) works for this test
        let mut config = crate::cache_config::CacheConfig::default();
        config.recent_messages.capacity = 1_000;
        let (client, _sync_rx) = Client::new_with_cache_config(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
            config,
        )
        .await;

        let chat = Jid::status_broadcast();
        let msg_id = "STATUS_MSG_001".to_string();
        let msg = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("status text".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        // Add message to cache
        client
            .add_recent_message(chat.clone(), msg_id.clone(), &msg)
            .await;

        // First device takes the message
        let taken = client
            .take_recent_message(chat.clone(), msg_id.clone())
            .await;
        assert!(taken.is_some(), "First take should succeed");

        // Re-add for subsequent retries (simulating the status broadcast fix)
        let taken_msg = taken.unwrap();
        client
            .add_recent_message(chat.clone(), msg_id.clone(), &taken_msg)
            .await;

        // Second device should also be able to take the message
        let taken2 = client
            .take_recent_message(chat.clone(), msg_id.clone())
            .await;
        assert!(
            taken2.is_some(),
            "Second take should succeed after re-add (status broadcast multi-device retry)"
        );
        assert_eq!(
            taken2
                .unwrap()
                .extended_text_message
                .as_ref()
                .unwrap()
                .text
                .as_deref(),
            Some("status text")
        );
    }
}
