use crate::client::Client;
use crate::message::RetryReason;
use crate::types::events::Receipt;
use log::{debug, info, warn};
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
use wacore_binary::JidExt as _;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{Jid, OwnedNodeRef};
#[cfg(test)]
use wacore_binary::{Node, NodeContent};
use wacore_binary::{NodeContentRef, NodeRef};

/// Helper to extract bytes content from a Node (used in tests).
#[cfg(test)]
fn get_bytes_content(node: &Node) -> Option<&[u8]> {
    match &node.content {
        Some(NodeContent::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    }
}

/// Helper to extract bytes content from a NodeRef.
fn get_bytes_content_ref<'a>(node: &'a NodeRef<'_>) -> Option<&'a [u8]> {
    match node.content.as_deref() {
        Some(NodeContentRef::Bytes(b)) => Some(b.as_ref()),
        _ => None,
    }
}

/// Helper to extract registration ID from a Node (used in tests).
#[cfg(test)]
fn extract_registration_id_from_node(node: &Node) -> Option<u32> {
    let registration_node = node.get_optional_child("registration")?;
    let bytes = get_bytes_content(registration_node)?;

    if bytes.len() >= 4 {
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    } else if !bytes.is_empty() {
        let mut arr = [0u8; 4];
        let start = 4 - bytes.len();
        arr[start..].copy_from_slice(bytes);
        Some(u32::from_be_bytes(arr))
    } else {
        None
    }
}

/// Helper to extract registration ID from a NodeRef (4 bytes big-endian).
fn extract_registration_id_from_node_ref(node: &NodeRef<'_>) -> Option<u32> {
    let registration_node = node.get_optional_child("registration")?;
    let bytes = get_bytes_content_ref(registration_node)?;

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

/// Minimum retry count before we start tracking base keys.
/// WhatsApp Web saves base key on retry 2, checks on retry > 2.
const MIN_RETRY_FOR_BASE_KEY_CHECK: u8 = 2;

/// Separated chat and requester JIDs for retry receipt handling.
/// Mirrors WAWebHandleRetryRequest `getActualChatInfo` + `getTargetChat`.
struct RetryChatInfo {
    /// Bare chat JID (no device suffix) for message lookup.
    chat: Jid,
    /// Device-specific JID of the requesting device, for session management.
    requester: Jid,
    /// Raw `from` JID from the receipt, for stanza `to` attribute.
    /// WA Web preserves the original `from` (variable `m`) for the retry stanza.
    original_from: Jid,
    /// True if the requester is a bot JID (skip namespace normalization).
    is_bot: bool,
}

/// Resolve the chat and requester JIDs from a retry receipt, separating
/// message-lookup concerns from session-management concerns.
/// Mirrors WAWebHandleRetryRequest `getActualChatInfo` + `getTargetChat`.
fn resolve_retry_chat_info(
    receipt: &Receipt,
    node: &NodeRef<'_>,
    own_pn: Option<&Jid>,
    own_lid: Option<&Jid>,
) -> RetryChatInfo {
    let from = &receipt.source.chat;

    if from.is_group() || from.is_status_broadcast() {
        // Groups/status: chat is already the group/broadcast JID.
        // Requester is the participant attr (the actual retrying device).
        let requester = node
            .attrs()
            .optional_jid("participant")
            .unwrap_or_else(|| receipt.source.sender.clone());
        RetryChatInfo {
            chat: from.clone(),
            requester,
            original_from: from.clone(),
            is_bot: false,
        }
    } else {
        // DM: resolve chat target via getTargetChat logic.
        let recipient = node.attrs().optional_jid("recipient");
        let is_bot = from.is_bot();

        // WA Web getTargetChat (RetryRequest.js:339-371):
        // 1. Bot + recipient → chat = recipient
        // 2. Peer device + recipient → chat = recipient
        // 3. Peer device without recipient → abort (return null)
        // 4. Normal user → chat = asUserWidOrThrow(from) = from.to_non_ad()
        let is_peer = own_pn.is_some_and(|pn| from.is_same_user_as(pn))
            || own_lid.is_some_and(|lid| from.is_same_user_as(lid));

        let chat = if is_bot && recipient.is_some() {
            recipient.clone().unwrap().to_non_ad()
        } else if is_peer {
            match &recipient {
                Some(r) => r.to_non_ad(),
                // No recipient on peer retry — chat will be our own JID,
                // message lookup will likely fail. WA Web returns null here.
                None => {
                    log::warn!(
                        "Peer device retry without recipient attr — message lookup may fail"
                    );
                    from.to_non_ad()
                }
            }
        } else {
            from.to_non_ad()
        };

        let requester = if from.device() == 0 && from.agent == 0 {
            chat.clone()
        } else {
            from.clone()
        };

        RetryChatInfo {
            chat,
            requester,
            original_from: from.clone(),
            is_bot,
        }
    }
}

fn build_retry_dedupe_key(chat: &Jid, message_id: &str, participant_jid: &Jid) -> String {
    let mut key = String::with_capacity(message_id.len() + 64);
    chat.push_to(&mut key);
    key.push(':');
    key.push_str(message_id);
    key.push(':');
    participant_jid.push_to(&mut key);
    key
}

impl Client {
    pub(crate) async fn handle_retry_receipt(
        self: &Arc<Self>,
        receipt: &Receipt,
        node: &Arc<OwnedNodeRef>,
    ) -> Result<(), anyhow::Error> {
        let nr = node.get();
        let retry_child = nr
            .get_optional_child("retry")
            .ok_or_else(|| anyhow::anyhow!("<retry> child missing from receipt"))?;

        let message_id = retry_child
            .get_attr("id")
            .map(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("<retry> missing 'id' attribute"))?
            .into_owned();
        let retry_count: u8 = retry_child
            .get_attr("count")
            .map(|v| v.as_str())
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

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let mut info = resolve_retry_chat_info(
            receipt,
            nr,
            device_snapshot.pn.as_ref(),
            device_snapshot.lid.as_ref(),
        );
        let is_group_or_status = info.chat.is_group() || info.chat.is_status_broadcast();

        // Deduplicate retry receipts per requesting device.
        // DMs can also receive retries from multiple companion devices.
        let dedupe_key = build_retry_dedupe_key(&info.chat, &message_id, &info.requester);

        if self.retried_group_messages.get(&dedupe_key).await.is_some() {
            log::debug!(
                "Ignoring duplicate retry for message {} from {}: already handled.",
                message_id,
                info.requester
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

        let (original_msg, alt_chat) = match self.take_recent_message(&info.chat, &message_id).await
        {
            Some(result) => result,
            None => {
                log::debug!(
                    "Ignoring retry for message {message_id}: already handled or not found in cache."
                );
                return Ok(());
            }
        };

        // take_recent_message consumes the cached message; re-add it so other
        // devices for the same chat can still request a retry.
        self.add_recent_message(&info.chat, &message_id, &original_msg)
            .await;

        // When message was found via alternate PN<->LID key, the Signal session
        // lives in the stored message's namespace (not the receipt's). Build the
        // encryption JID from that namespace + requester's device, skipping
        // resolve_encryption_jid (which would map back to the primary namespace).
        // WA Web: `e.from.isBot() ? (p = e.from) : (p = d.isLid() ? toLid(e.from) : toPn(e.from))`
        // Bots skip namespace normalization (WAWebHandleRetryRequest:311-312).
        let resolved_jid = if let Some(alt_chat) = alt_chat
            && !is_group_or_status
            && !info.is_bot
        {
            let requester = &info.requester;
            info.requester = Jid {
                user: alt_chat.user,
                server: alt_chat.server,
                device: requester.device,
                agent: requester.agent,
                integrator: requester.integrator,
            };
            info.requester.clone()
        } else {
            self.resolve_encryption_jid(&info.requester).await
        };

        let sender_device_id = info.requester.device() as u32;
        let sender_user = info.requester.user.clone();
        if !self.has_device(&sender_user, sender_device_id).await {
            warn!(
                "handle_retry_receipt: device not found for device={}, user={}",
                sender_device_id, sender_user
            );
            return Ok(());
        }

        // Check if this is a retry from our own device (peer).
        let is_peer = device_snapshot
            .pn
            .as_ref()
            .is_some_and(|our_pn| info.requester.is_same_user_as(our_pn))
            || device_snapshot
                .lid
                .as_ref()
                .is_some_and(|our_lid| info.requester.is_same_user_as(our_lid));

        // Process key bundle to establish a pairwise session for the retry.
        // Needed for both DMs and groups (group retries use pairwise, not sender key).
        // Status broadcasts skip this — they can't resend and only mark for next send.
        if !info.chat.is_status_broadcast() {
            // Try to process key bundle if present
            let key_bundle_result = self
                .process_retry_key_bundle(nr, &resolved_jid, is_peer)
                .await;

            if let Err(e) = &key_bundle_result {
                warn!(
                    "Failed to process key bundle from retry receipt: {}. Checking for reg ID mismatch.",
                    e
                );

                // WhatsApp Web behavior: If no key bundle but registration ID differs from stored
                // session, delete the session to force re-establishment.
                // This handles the case where the requester reinstalled but didn't include keys.
                if let Some(received_reg_id) = extract_registration_id_from_node_ref(nr) {
                    let signal_address = resolved_jid.to_protocol_address();
                    let device_store = self.persistence_manager.get_device_arc().await;
                    let device_guard = device_store.read().await;

                    // Read session through cache to get consistent state
                    let session = self
                        .signal_cache
                        .peek_session(&signal_address, &*device_guard.backend)
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
                        let lock = self.session_lock_for(signal_address.as_str()).await;
                        let _guard = lock.lock().await;
                        self.signal_cache.delete_session(&signal_address).await;
                        drop(_guard);
                        self.flush_signal_cache_logged("reg ID mismatch session deletion", None)
                            .await;
                    }
                }
            }
        }

        // Fetch group info (cache-first, server on miss) — used for SKDM rotation + addressing_mode.
        // Without this, a cold cache would silently default to PN semantics for LID groups.
        let cached_group_info = if info.chat.is_group() {
            match self.groups().query_info(&info.chat).await {
                Ok(gi) => Some(gi),
                Err(e) => {
                    log::warn!(
                        "Failed to fetch group info for retry of msg {} in {}: {e}",
                        message_id,
                        info.chat
                    );
                    None
                }
            }
        } else {
            None
        };

        if is_group_or_status {
            let group_jid = info.chat.to_string();

            // WA Web rotateKey: unknown device (not in participant list, not LID) →
            // force full sender key rotation by clearing all sender key device tracking.
            if !info.requester.is_lid() && !info.chat.is_status_broadcast() {
                // If we can't verify membership (no cached group info), treat
                // as unknown and trigger rotation (matches WA Web where the
                // device wouldn't be in the senderKey map → rotateKey=true)
                let is_known_participant = cached_group_info
                    .as_ref()
                    .is_some_and(|g| g.participants.iter().any(|p| p.user == info.requester.user));

                if !is_known_participant {
                    log::warn!(
                        "Unknown device {} in group {} — forcing full sender key rotation \
                         (matches WA Web's rotateKey behavior)",
                        info.requester,
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
                        let sk_name = SenderKeyName::from_parts(
                            &group_jid,
                            own_jid.to_protocol_address().as_str(),
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
                .mark_forget_sender_key(&group_jid, std::slice::from_ref(&info.requester))
                .await
            {
                log::warn!(
                    "Failed to mark sender key forget for {} in {}: {}",
                    info.requester,
                    group_jid,
                    e
                );
            } else {
                let chat_type = if info.chat.is_status_broadcast() {
                    "status broadcast"
                } else {
                    "group"
                };
                info!(
                    "Marked {} for fresh SKDM in {} {} due to retry receipt",
                    info.requester, chat_type, group_jid
                );
            }
        } else {
            self.delete_dm_retry_session_target(&resolved_jid, &message_id, retry_count)
                .await?;
        }

        // Status broadcasts can't resend (requires explicit recipient list).
        // Participant already marked for fresh SKDM above; next status send includes them.
        if info.chat.is_status_broadcast() {
            info!(
                "Status broadcast retry for {} — participant marked for fresh SKDM, \
                 will be included in next status send",
                message_id
            );
            return Ok(());
        }

        info!(
            "Resending message {} to {} (retry #{})",
            message_id, info.chat, retry_count
        );

        if info.chat.is_group() {
            // Group retry: pairwise encrypt to failing device only (RetryMsgJob.js:71).
            // Using sender-key broadcast would resend to ALL participants → duplicates.
            let device_snapshot = self.persistence_manager.get_device_snapshot().await;

            let addressing_mode = cached_group_info
                .as_ref()
                .map(|g| g.addressing_mode)
                .unwrap_or_default();

            let signal_address = resolved_jid.to_protocol_address();
            let session_mutex = self.session_lock_for(signal_address.as_str()).await;
            let _session_guard = session_mutex.lock().await;
            let mut store_adapter = self.signal_adapter().await;

            let stanza = wacore::send::prepare_group_retry_stanza(
                &mut store_adapter.session_store,
                &mut store_adapter.identity_store,
                info.chat,
                info.requester,
                resolved_jid.clone(),
                &original_msg,
                message_id,
                retry_count,
                device_snapshot.account.as_ref(),
                addressing_mode,
            )
            .await?;

            self.send_node(stanza).await?;
            self.flush_signal_cache().await?;
        } else {
            // DM retry: pairwise resend to the requesting device only.
            // Use _resolved variant: resolved_jid is already in the correct
            // namespace (including alternate PN/LID normalization).
            // WA Web's ensureE2ESessions also uses already-normalized JIDs.
            self.ensure_e2e_sessions_resolved(std::slice::from_ref(&resolved_jid))
                .await?;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let signal_address = resolved_jid.to_protocol_address();
            let session_mutex = self.session_lock_for(signal_address.as_str()).await;
            let _session_guard = session_mutex.lock().await;
            let mut store_adapter = self.signal_adapter().await;

            let stanza = wacore::send::prepare_dm_retry_stanza(
                &mut store_adapter.session_store,
                &mut store_adapter.identity_store,
                info.original_from,
                info.requester,
                resolved_jid.clone(),
                &original_msg,
                message_id,
                retry_count,
                device_snapshot.account.as_ref(),
            )
            .await?;

            self.send_node(stanza).await?;
            self.flush_signal_cache().await?;
        }

        Ok(())
    }

    async fn delete_dm_retry_session_target(
        &self,
        device_jid: &Jid,
        message_id: &str,
        retry_count: u8,
    ) -> Result<(), anyhow::Error> {
        // Base key collision detection prevents stale-session retry loops.
        let signal_address = device_jid.to_protocol_address();
        let device_store = self.persistence_manager.get_device_arc().await;

        // Check for base key collision before deleting the session.
        // Read session through cache for consistent state.
        {
            let device_guard = device_store.read().await;
            let session = self
                .signal_cache
                .peek_session(&signal_address, &*device_guard.backend)
                .await
                .ok()
                .flatten();

            if let Some(session) = session
                && let Ok(current_base_key) = session.alice_base_key()
            {
                let addr_str = signal_address.as_str();
                if retry_count == MIN_RETRY_FOR_BASE_KEY_CHECK {
                    // Save retry #2's base key so later retries can prove regeneration happened.
                    if let Err(e) = device_guard
                        .backend
                        .save_base_key(addr_str, message_id, current_base_key)
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
                    // An unchanged base key means we never rebuilt the session.
                    match device_guard
                        .backend
                        .has_same_base_key(addr_str, message_id, current_base_key)
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
                                .delete_base_key(addr_str, message_id)
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
                                .delete_base_key(addr_str, message_id)
                                .await;
                        }
                        Err(e) => {
                            warn!("Failed to check base key for {}: {}", signal_address, e);
                        }
                    }
                }
            }
        }

        // Delete through the cache so resend can't revive a stale in-memory session.
        // The retry path flushes once after the resend so the session transition
        // stays visible through the cache for the whole targeted rebuild.
        self.signal_cache.delete_session(&signal_address).await;
        info!("Deleted session for {signal_address} due to retry receipt");
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
        node: &NodeRef<'_>,
        requester_jid: &wacore_binary::Jid,
        is_peer: bool,
    ) -> Result<(), anyhow::Error> {
        let keys_node = node
            .get_optional_child("keys")
            .ok_or_else(|| anyhow::anyhow!("<keys> child missing from retry receipt"))?;

        let registration_node = node.get_optional_child("registration");

        // Extract registration ID (4 bytes big-endian).
        let registration_id = registration_node
            .and_then(get_bytes_content_ref)
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

        // Use requester_jid directly — the caller already resolved the correct
        // namespace (including alternate PN/LID normalization). Re-resolving
        // here would undo that normalization.
        let signal_address = requester_jid.to_protocol_address();

        // Check if the registration ID changed (indicates device reinstall).
        // Read session through cache for consistent state.
        {
            let device_store = self.persistence_manager.get_device_arc().await;
            let device_guard = device_store.read().await;
            let session = self
                .signal_cache
                .peek_session(&signal_address, &*device_guard.backend)
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
            .and_then(get_bytes_content_ref)
            .ok_or_else(|| anyhow::anyhow!("Missing identity key in retry receipt"))?;
        let identity_key = PublicKey::from_djb_public_key_bytes(identity_bytes)?;

        // Extract prekey (optional in some cases).
        let prekey_data = if let Some(key_ref) = keys_node.get_optional_child("key") {
            let prekey_node = OneTimePreKeyNode::try_from_node_ref(key_ref)?;
            let prekey_public = PublicKey::from_djb_public_key_bytes(&prekey_node.public_bytes)?;
            Some((prekey_node.id.into(), prekey_public))
        } else {
            None
        };

        // Extract signed prekey.
        let skey_ref = keys_node
            .get_optional_child("skey")
            .ok_or_else(|| anyhow::anyhow!("Missing signed prekey in retry receipt"))?;

        let signed_prekey = SignedPreKeyNode::try_from_node_ref(skey_ref)?;
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

        debug!(
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

        let keys_node = if wacore::protocol::retry::should_include_keys(retry_count, reason) {
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
            .attr("to", receipt_to)
            .attr("id", info.id.clone())
            .attr("type", "retry");

        if info.source.is_group {
            builder = builder.attr("participant", &info.source.sender);
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
                    builder = builder.attr("recipient", recipient);
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
        peer_jid: &wacore_binary::Jid,
        call_id: &str,
        call_creator: &wacore_binary::Jid,
        retry_count: u8,
    ) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;

        let registration_id_bytes = device_snapshot.registration_id.to_be_bytes().to_vec();

        // WA Web: <enc_rekey call-creator="JID" call-id="..." count="N"/>
        let enc_rekey_node = NodeBuilder::new("enc_rekey")
            .attr("call-creator", call_creator)
            .attr("call-id", call_id)
            .attr("count", retry_count.to_string())
            .build();

        let registration_node = NodeBuilder::new("registration")
            .bytes(registration_id_bytes)
            .build();

        let receipt_node = NodeBuilder::new("receipt")
            .attr("to", peer_jid)
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
    use std::sync::Arc;
    use wacore::types::jid::JidExt as _;
    use wacore_binary::{Jid, JidExt};
    use waproto::whatsapp as wa;

    #[tokio::test]
    async fn recent_message_cache_insert_and_take() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend();
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
        client.add_recent_message(&chat, &msg_id, &msg).await;

        // First take should return and remove it from cache
        let taken = client.take_recent_message(&chat, &msg_id).await;
        assert!(taken.is_some());
        let (msg, alt_chat) = taken.unwrap();
        assert!(alt_chat.is_none(), "primary key should match");
        assert_eq!(msg.conversation.as_deref(), Some("hello"));

        // Second take should return None
        let taken_again = client.take_recent_message(&chat, &msg_id).await;
        assert!(taken_again.is_none());
    }

    #[test]
    fn get_bytes_content_extracts_bytes() {
        use wacore_binary::{Attrs, Node};

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
            content: Some(NodeContent::String("hello".into())),
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
        ) -> wacore_binary::Node {
            // Mirror production routing: groups → chat JID, DMs → sender JID
            let receipt_to = if info.source.is_group {
                &info.source.chat
            } else {
                &info.source.sender
            };
            let mut builder = NodeBuilder::new("receipt")
                .attr("to", receipt_to)
                .attr("id", info.id.clone())
                .attr("type", "retry");

            if info.source.is_group {
                builder = builder.attr("participant", &info.source.sender);
            }

            if !info.source.is_group {
                let is_from_own_account = info.source.sender.is_same_user_as(our_pn)
                    || info.source.sender.is_same_user_as(our_lid);

                if is_from_own_account {
                    if info.category == MessageCategory::Peer {
                        builder = builder.attr("category", MessageCategory::Peer.as_str());
                    } else {
                        let recipient = info.source.recipient.as_ref().unwrap_or(&info.source.chat);
                        builder = builder.attr("recipient", recipient);
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
            Some(wacore_binary::NodeContent::Bytes(b)) => b.clone(),
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

        let backend = crate::test_utils::create_test_backend();

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

        let backend = crate::test_utils::create_test_backend();

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

        let backend = crate::test_utils::create_test_backend();

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

    #[tokio::test]
    async fn dm_retry_deletes_only_requested_session() {
        let client = crate::test_utils::create_test_client_with_failing_http().await;
        let user = "100000000000088".to_string();
        let resolved_jid = Jid::lid_device(user.clone(), 33);

        let backend = client.persistence_manager.backend();
        let device_0 = Jid::lid_device(user.clone(), 0).to_protocol_address();
        let device_33 = Jid::lid_device(user, 33).to_protocol_address();

        backend
            .put_session(device_0.as_str(), b"invalid-session")
            .await
            .unwrap();
        backend
            .put_session(device_33.as_str(), b"invalid-session")
            .await
            .unwrap();

        client
            .delete_dm_retry_session_target(&resolved_jid, "MSG-ONE-DEVICE", 1)
            .await
            .unwrap();
        client.flush_signal_cache().await.unwrap();

        assert!(
            backend
                .get_session(device_0.as_str())
                .await
                .unwrap()
                .is_some(),
            "non-requesting device session should be preserved"
        );
        assert!(
            backend
                .get_session(device_33.as_str())
                .await
                .unwrap()
                .is_none(),
            "requesting device session should be deleted"
        );
    }

    #[tokio::test]
    async fn dm_retry_deletes_resolved_session_without_registry_devices() {
        let client = crate::test_utils::create_test_client_with_failing_http().await;
        let resolved_jid = Jid::lid("100000000000099");
        let signal_address = resolved_jid.to_protocol_address();
        let backend = client.persistence_manager.backend();

        backend
            .put_session(signal_address.as_str(), b"invalid-session")
            .await
            .unwrap();

        client
            .delete_dm_retry_session_target(&resolved_jid, "MSG-FALLBACK", 1)
            .await
            .unwrap();
        client.flush_signal_cache().await.unwrap();

        assert!(
            backend
                .get_session(signal_address.as_str())
                .await
                .unwrap()
                .is_none(),
            "resolved session should be deleted when registry has no device list"
        );
    }

    #[test]
    fn bot_jid_detection() {
        // Test bot JID detection for bot message filtering
        use wacore_binary::JidExt as _;

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
        use wacore_binary::{Attrs, Node};

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
        use wacore_binary::JidExt as _;

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
            let would_include_keys =
                wacore::protocol::retry::should_include_keys(retry_count, reason);

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

                let would_include_keys =
                    wacore::protocol::retry::should_include_keys(retry_count, reason);

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
        let would_include_keys = wacore::protocol::retry::should_include_keys(retry_count, reason);

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

    /// Helper to build a DM Receipt for testing resolve_retry_chat_info.
    fn make_test_receipt(from: &str) -> Receipt {
        Receipt {
            source: crate::types::message::MessageSource {
                chat: from.parse().unwrap(),
                sender: from.parse().unwrap(),
                ..Default::default()
            },
            message_ids: vec!["MSG001".to_string()],
            timestamp: wacore::time::now_utc(),
            r#type: crate::types::presence::ReceiptType::Retry,
        }
    }

    #[test]
    fn resolve_retry_chat_info_dm_with_device() {
        use wacore_binary::builder::NodeBuilder;

        // Node attrs are unused in the DM branch (no participant lookup)
        let node = NodeBuilder::new("receipt").build();
        let receipt = make_test_receipt("5511999999999:33@s.whatsapp.net");
        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        // chat should be bare (device stripped)
        assert_eq!(info.chat.device(), 0);
        assert_eq!(info.chat.user, "5511999999999");
        assert!(info.chat.is_pn());

        // requester should preserve device 33
        assert_eq!(info.requester.device(), 33);
        assert_eq!(info.requester.user, "5511999999999");
    }

    #[test]
    fn resolve_retry_chat_info_lid_dm_with_device() {
        use wacore_binary::builder::NodeBuilder;

        let node = NodeBuilder::new("receipt").build();
        let receipt = make_test_receipt("236395184570386:5@lid");
        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        // chat should be bare LID (device stripped)
        assert_eq!(info.chat.device(), 0);
        assert_eq!(info.chat.user, "236395184570386");
        assert!(info.chat.is_lid());

        // requester should preserve device 5
        assert_eq!(info.requester.device(), 5);
        assert_eq!(info.requester.user, "236395184570386");
        assert!(info.requester.is_lid());
    }

    #[test]
    fn resolve_retry_chat_info_dm_bare() {
        use wacore_binary::builder::NodeBuilder;

        let node = NodeBuilder::new("receipt").build();
        let receipt = make_test_receipt("5511999999999@s.whatsapp.net");
        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        assert_eq!(info.chat.device(), 0);
        assert_eq!(info.requester.device(), 0);
        assert_eq!(info.chat, info.requester);
    }

    #[test]
    fn resolve_retry_chat_info_group() {
        use wacore_binary::builder::NodeBuilder;

        let node = NodeBuilder::new("receipt")
            .attr("from", "120363021033254949@g.us")
            .attr("id", "MSG001")
            .attr("participant", "236395184570386:33@lid")
            .attr("type", "retry")
            .build();
        let receipt = Receipt {
            source: crate::types::message::MessageSource {
                chat: "120363021033254949@g.us".parse().unwrap(),
                sender: "236395184570386:33@lid".parse().unwrap(),
                ..Default::default()
            },
            message_ids: vec!["MSG001".to_string()],
            timestamp: wacore::time::now_utc(),
            r#type: crate::types::presence::ReceiptType::Retry,
        };
        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        assert!(info.chat.is_group());
        assert_eq!(info.chat.user, "120363021033254949");
        assert!(info.requester.is_lid());
        assert_eq!(info.requester.device(), 33);
    }

    #[test]
    fn resolve_retry_chat_info_status_broadcast() {
        use wacore_binary::builder::NodeBuilder;

        let node = NodeBuilder::new("receipt")
            .attr("from", "status@broadcast")
            .attr("id", "3EB06D00CAB92340790621")
            .attr("participant", "236395184570386@lid")
            .attr("type", "retry")
            .build();
        let receipt = make_test_receipt("status@broadcast");
        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        assert!(info.chat.is_status_broadcast());
        // requester should be the participant, not status@broadcast
        assert!(info.requester.is_lid());
        assert_eq!(info.requester.user, "236395184570386");
    }

    #[test]
    fn resolve_retry_chat_info_status_broadcast_no_participant() {
        use wacore_binary::builder::NodeBuilder;

        // Missing participant attr (edge case) — falls back to sender
        let node = NodeBuilder::new("receipt")
            .attr("from", "status@broadcast")
            .attr("id", "MSG001")
            .attr("type", "retry")
            .build();
        let receipt = make_test_receipt("status@broadcast");
        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        assert!(info.chat.is_status_broadcast());
        assert!(info.requester.is_status_broadcast());
    }

    /// Test that retry dedupe keys are differentiated per requesting device,
    /// including DMs where multiple companion devices can retry the same message.
    #[test]
    fn retry_dedupe_key_per_participant() {
        let msg_id = "3EB06D00CAB92340790621";

        let status_chat = Jid::status_broadcast();
        let status_participant_a: Jid = "236395184570386@lid".parse().unwrap();
        let status_participant_b: Jid = "559985213786@s.whatsapp.net".parse().unwrap();
        let status_key_a = build_retry_dedupe_key(&status_chat, msg_id, &status_participant_a);
        let status_key_b = build_retry_dedupe_key(&status_chat, msg_id, &status_participant_b);
        assert_ne!(
            status_key_a, status_key_b,
            "Different status participants should have different dedupe keys"
        );
        assert_eq!(
            status_key_a,
            build_retry_dedupe_key(&status_chat, msg_id, &status_participant_a),
            "Same status participant should have the same dedupe key"
        );

        let dm_chat = Jid::pn("559911112222");
        let dm_device_a = Jid::pn_device("559922223333", 1);
        let dm_device_b = Jid::pn_device("559922223333", 2);
        let dm_key_a = build_retry_dedupe_key(&dm_chat, msg_id, &dm_device_a);
        let dm_key_b = build_retry_dedupe_key(&dm_chat, msg_id, &dm_device_b);
        assert_ne!(
            dm_key_a, dm_key_b,
            "Different DM requester devices should have different dedupe keys"
        );
        assert_eq!(
            dm_key_a,
            build_retry_dedupe_key(&dm_chat, msg_id, &dm_device_a),
            "Same DM requester device should have the same dedupe key"
        );
    }

    /// Test that the recent message cache supports re-addition after take.
    /// This is critical for multi-device retries where another device can
    /// ask for the same message after the first retry already consumed it.
    #[tokio::test]
    async fn recent_message_cache_readd_after_take() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend();
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

        let msg = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("status text".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        for (chat, msg_id) in [
            (Jid::status_broadcast(), "STATUS_MSG_001".to_string()),
            (Jid::pn("559911112222"), "DM_MSG_001".to_string()),
        ] {
            client.add_recent_message(&chat, &msg_id, &msg).await;

            let taken = client.take_recent_message(&chat, &msg_id).await;
            assert!(taken.is_some(), "First take should succeed for {chat}");

            let (taken_msg, _) = taken.unwrap();
            client.add_recent_message(&chat, &msg_id, &taken_msg).await;

            let taken2 = client.take_recent_message(&chat, &msg_id).await;
            assert!(
                taken2.is_some(),
                "Second take should succeed after re-add for {chat}"
            );
            assert_eq!(
                taken2
                    .unwrap()
                    .0
                    .extended_text_message
                    .as_ref()
                    .unwrap()
                    .text
                    .as_deref(),
                Some("status text")
            );
        }
    }

    /// Message stored under bare JID should be found when looking up via bare
    /// JID (the path resolve_retry_chat_info now provides for DMs).
    #[tokio::test]
    async fn dm_retry_message_lookup_uses_bare_jid() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend();
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
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

        let bare_jid: Jid = "5511999999999@s.whatsapp.net".parse().unwrap();
        let msg_id = "RETRY_MSG_001";
        let msg = wa::Message {
            conversation: Some("test dm".into()),
            ..Default::default()
        };

        // Store under bare JID (how send_message stores it)
        client.add_recent_message(&bare_jid, msg_id, &msg).await;

        // Lookup via bare JID should succeed (this is what info.chat provides)
        let taken = client.take_recent_message(&bare_jid, msg_id).await;
        assert!(taken.is_some(), "Lookup via bare JID should succeed");
        let (msg_out, alt_chat) = taken.unwrap();
        assert!(alt_chat.is_none(), "primary key should match for bare JID");

        // Re-add under bare JID
        client.add_recent_message(&bare_jid, msg_id, &msg_out).await;

        // Second take should also work
        let taken2 = client.take_recent_message(&bare_jid, msg_id).await;
        assert!(
            taken2.is_some(),
            "Second lookup via bare JID should succeed after re-add"
        );
    }

    /// Alternate PN/LID key lookup: a message stored under PN should be found
    /// when the primary lookup resolves to LID (because a mapping was added
    /// between send time and retry time).
    #[tokio::test]
    async fn alternate_key_lookup_pn_to_lid() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend();
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
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

        let pn_jid: Jid = "5511999999999@s.whatsapp.net".parse().unwrap();
        let lid_jid: Jid = "236395184570386@lid".parse().unwrap();
        let msg_id = "RETRY_ALT_001";
        let msg = wa::Message {
            conversation: Some("alternate key test".into()),
            ..Default::default()
        };

        // Store under PN (no LID mapping existed at send time)
        client.add_recent_message(&pn_jid, msg_id, &msg).await;

        // Now add a LID mapping (simulates mapping arriving between send and retry)
        client
            .lid_pn_cache
            .add(wacore::types::lid_pn::LidPnEntry {
                lid: lid_jid.user.to_string(),
                phone_number: pn_jid.user.to_string(),
                created_at: 0,
                learning_source: wacore::types::lid_pn::LearningSource::Usync,
            })
            .await;

        // Lookup via LID: primary key resolves to LID (miss),
        // alternate key falls back to PN (hit)
        let taken = client.take_recent_message(&lid_jid, msg_id).await;
        assert!(
            taken.is_some(),
            "Alternate PN key lookup should find message stored under PN"
        );
        let (msg_out, alt_chat) = taken.unwrap();
        let alt_chat = alt_chat.expect("should be found via alternate key");
        assert!(alt_chat.is_pn(), "alternate chat should be PN");
        assert_eq!(alt_chat.user, pn_jid.user);
        assert_eq!(msg_out.conversation.as_deref(), Some("alternate key test"));
    }

    /// swap_pn_lid_namespace should swap between PN and LID while preserving
    /// device/agent — this is the shared helper used for both alternate key
    /// computation and requester normalization after an alternate hit.
    #[tokio::test]
    async fn swap_pn_lid_namespace_preserves_device() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend();
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
        let (client, _sync_rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            pm.clone(),
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        let pn_jid: Jid = "5511999999999@s.whatsapp.net".parse().unwrap();
        let lid_jid: Jid = "236395184570386@lid".parse().unwrap();

        client
            .lid_pn_cache
            .add(wacore::types::lid_pn::LidPnEntry {
                lid: lid_jid.user.to_string(),
                phone_number: pn_jid.user.to_string(),
                created_at: 0,
                learning_source: wacore::types::lid_pn::LearningSource::Usync,
            })
            .await;

        // LID:5 → PN:5
        let lid_with_device: Jid = "236395184570386:5@lid".parse().unwrap();
        let swapped = client.swap_pn_lid_namespace(&lid_with_device).await;
        let swapped = swapped.expect("should resolve LID→PN");
        assert!(swapped.is_pn());
        assert_eq!(swapped.user, "5511999999999");
        assert_eq!(swapped.device(), 5);

        // PN:3 → LID:3
        let pn_with_device: Jid = "5511999999999:3@s.whatsapp.net".parse().unwrap();
        let swapped = client.swap_pn_lid_namespace(&pn_with_device).await;
        let swapped = swapped.expect("should resolve PN→LID");
        assert!(swapped.is_lid());
        assert_eq!(swapped.user, "236395184570386");
        assert_eq!(swapped.device(), 3);

        // Group JID → None
        let group: Jid = "120363021033254949@g.us".parse().unwrap();
        assert!(client.swap_pn_lid_namespace(&group).await.is_none());
    }

    /// Alternate key lookup via PN input: message stored under PN, LID mapping
    /// added later, lookup via PN. Exercises the `server != server` optimization
    /// where `to` is used directly as alternate (no cache round-trip).
    #[tokio::test]
    async fn alternate_key_lookup_pn_input_server_changed() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend();
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
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

        let pn_jid: Jid = "5511999999999@s.whatsapp.net".parse().unwrap();
        let lid_jid: Jid = "236395184570386@lid".parse().unwrap();
        let msg_id = "RETRY_ALT_PN";
        let msg = wa::Message {
            conversation: Some("pn input alternate".into()),
            ..Default::default()
        };

        // Store under PN (no mapping at send time)
        client.add_recent_message(&pn_jid, msg_id, &msg).await;

        // Add LID mapping
        client
            .lid_pn_cache
            .add(wacore::types::lid_pn::LidPnEntry {
                lid: lid_jid.user.to_string(),
                phone_number: pn_jid.user.to_string(),
                created_at: 0,
                learning_source: wacore::types::lid_pn::LearningSource::Usync,
            })
            .await;

        // Lookup via PN: resolve_encryption_jid maps to LID (primary),
        // primary misses, server changed (Lid != Pn) → uses `to` directly
        let taken = client.take_recent_message(&pn_jid, msg_id).await;
        assert!(
            taken.is_some(),
            "Should find message via server-changed path"
        );
        let (msg_out, alt_chat) = taken.unwrap();
        let alt_chat = alt_chat.expect("should be alternate hit");
        assert!(
            alt_chat.is_pn(),
            "alternate chat should be PN (the original input)"
        );
        assert_eq!(alt_chat.user, pn_jid.user);
        assert_eq!(msg_out.conversation.as_deref(), Some("pn input alternate"));
    }

    /// When no PN/LID mapping exists, no alternate is tried and take returns None.
    #[tokio::test]
    async fn no_alternate_without_mapping() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend();
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
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

        let lid_jid: Jid = "236395184570386@lid".parse().unwrap();
        let msg_id = "RETRY_NO_ALT";
        let msg = wa::Message {
            conversation: Some("no alternate".into()),
            ..Default::default()
        };

        // Store under LID, no PN mapping exists
        client.add_recent_message(&lid_jid, msg_id, &msg).await;

        // Lookup via LID: primary hits directly (same namespace)
        let taken = client.take_recent_message(&lid_jid, msg_id).await;
        assert!(taken.is_some());
        let (_, alt_chat) = taken.unwrap();
        assert!(alt_chat.is_none(), "primary hit should have no alt_chat");

        // Now try looking up a message that doesn't exist at all
        let missing = client.take_recent_message(&lid_jid, "NONEXISTENT").await;
        assert!(missing.is_none(), "non-existent message should return None");
    }

    /// When both primary and alternate miss, take returns None.
    #[tokio::test]
    async fn alternate_key_both_miss() {
        let _ = env_logger::builder().is_test(true).try_init();

        let backend = crate::test_utils::create_test_backend();
        let pm = Arc::new(
            PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );
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

        let pn_jid: Jid = "5511999999999@s.whatsapp.net".parse().unwrap();
        let lid_jid: Jid = "236395184570386@lid".parse().unwrap();

        // Add mapping but don't store any message
        client
            .lid_pn_cache
            .add(wacore::types::lid_pn::LidPnEntry {
                lid: lid_jid.user.to_string(),
                phone_number: pn_jid.user.to_string(),
                created_at: 0,
                learning_source: wacore::types::lid_pn::LearningSource::Usync,
            })
            .await;

        // Lookup via PN: primary (LID) misses, alternate (PN) also misses
        let taken = client.take_recent_message(&pn_jid, "MISSING").await;
        assert!(taken.is_none(), "both primary and alternate miss → None");
    }

    // --- Peer device / bot / original_from tests ---

    #[test]
    fn resolve_retry_chat_info_peer_device_with_recipient() {
        use wacore_binary::builder::NodeBuilder;

        // Peer retry: from=our own JID, recipient=the actual chat partner
        let our_pn: Jid = "5511999999999@s.whatsapp.net".parse().unwrap();
        let recipient: Jid = "5522888888888@s.whatsapp.net".parse().unwrap();

        let node = NodeBuilder::new("receipt")
            .attr("recipient", "5522888888888@s.whatsapp.net")
            .build();
        let receipt = make_test_receipt("5511999999999:2@s.whatsapp.net");

        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), Some(&our_pn), None);

        // Chat should be the recipient (the actual conversation partner)
        assert_eq!(info.chat.user, recipient.user);
        assert_eq!(info.chat.device(), 0, "chat should be bare");
        // Requester is still our device
        assert_eq!(info.requester.user, our_pn.user);
        assert_eq!(info.requester.device(), 2);
    }

    #[test]
    fn resolve_retry_chat_info_peer_device_without_recipient() {
        use wacore_binary::builder::NodeBuilder;

        // Peer retry without recipient attr — should fall back to from
        let our_pn: Jid = "5511999999999@s.whatsapp.net".parse().unwrap();
        let node = NodeBuilder::new("receipt").build();
        let receipt = make_test_receipt("5511999999999:2@s.whatsapp.net");

        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), Some(&our_pn), None);

        // Falls back to from.to_non_ad() (our own bare JID)
        assert_eq!(info.chat.user, our_pn.user);
        assert_eq!(info.chat.device(), 0);
    }

    #[test]
    fn resolve_retry_chat_info_bot_with_recipient() {
        use wacore_binary::builder::NodeBuilder;

        // Bot retry: from=bot JID, recipient=actual chat
        let node = NodeBuilder::new("receipt")
            .attr("recipient", "5522888888888@s.whatsapp.net")
            .build();
        let receipt = make_test_receipt("131355500001@s.whatsapp.net");

        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        assert!(info.is_bot, "bot JID should be detected");
        // Chat should be the recipient
        assert_eq!(info.chat.user, "5522888888888");
        assert_eq!(info.chat.device(), 0);
    }

    #[test]
    fn resolve_retry_chat_info_bot_without_recipient() {
        use wacore_binary::builder::NodeBuilder;

        // Bot retry without recipient — falls through to normal DM path
        let node = NodeBuilder::new("receipt").build();
        let receipt = make_test_receipt("131355500001@s.whatsapp.net");

        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        assert!(info.is_bot);
        // Without recipient, falls to from.to_non_ad()
        assert_eq!(info.chat.user, "131355500001");
    }

    #[test]
    fn resolve_retry_chat_info_preserves_original_from() {
        use wacore_binary::builder::NodeBuilder;

        // DM with device suffix — original_from preserves the raw receipt from
        // (WA Web: variable m = e.from, used as-is for stanza to)
        let node = NodeBuilder::new("receipt").build();
        let receipt = make_test_receipt("5511999999999:33@s.whatsapp.net");

        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, None);

        // original_from keeps the full JID including device
        assert_eq!(info.original_from.device(), 33);
        assert_eq!(info.original_from.user, "5511999999999");

        // chat is bare
        assert_eq!(info.chat.device(), 0);
        assert_eq!(info.chat.user, "5511999999999");
    }

    #[test]
    fn resolve_retry_chat_info_peer_via_lid() {
        use wacore_binary::builder::NodeBuilder;

        // Peer retry detected via LID (not PN)
        let our_lid: Jid = "236395184570386@lid".parse().unwrap();
        let recipient: Jid = "5522888888888@s.whatsapp.net".parse().unwrap();

        let node = NodeBuilder::new("receipt")
            .attr("recipient", "5522888888888@s.whatsapp.net")
            .build();
        let receipt = make_test_receipt("236395184570386:5@lid");

        let info = resolve_retry_chat_info(&receipt, &node.as_node_ref(), None, Some(&our_lid));

        assert_eq!(info.chat.user, recipient.user);
        assert_eq!(info.chat.device(), 0);
        assert_eq!(info.requester.device(), 5);
    }
}
