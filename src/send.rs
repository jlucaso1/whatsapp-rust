use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::message::EditAttribute;
use anyhow::anyhow;
use log::debug;
use wacore::client::context::SendContextResolver;
use wacore::libsignal::protocol::SignalProtocolError;
use wacore::types::jid::JidExt;
use wacore::types::message::AddressingMode;
use wacore_binary::builder::NodeBuilder;
#[cfg(test)]
use wacore_binary::jid::DeviceKey;
use wacore_binary::jid::{Jid, JidExt as _};
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

/// Options for [`Client::send_message_with_options`].
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Override the auto-generated message ID.
    /// Useful for resending a failed message with the same ID or idempotency.
    pub message_id: Option<String>,
    /// Extra XML child nodes on the message stanza.
    pub extra_stanza_nodes: Vec<Node>,
    /// Ephemeral duration in seconds. Sets `contextInfo.expiration` on the
    /// message (WA Web `EProtoGenerator.js:183` parity).
    /// Common values: 86400 (24h), 604800 (7d), 7776000 (90d).
    pub ephemeral_expiration: Option<u32>,
}

/// Result of a successfully sent message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendResult {
    pub message_id: String,
    pub to: Jid,
}

impl SendResult {
    /// `participant` is `None` -- only valid for the sender's own messages.
    pub fn message_key(&self) -> wa::MessageKey {
        wa::MessageKey {
            remote_jid: Some(self.to.to_string()),
            from_me: Some(true),
            id: Some(self.message_id.clone()),
            participant: None,
        }
    }
}

/// Duration for pinned messages. Default is 7 days (matches WA Web).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum PinDuration {
    Hours24,
    #[default]
    Days7,
    Days30,
}

impl PinDuration {
    fn as_secs(self) -> u32 {
        match self {
            Self::Hours24 => 86_400,
            Self::Days7 => 604_800,
            Self::Days30 => 2_592_000,
        }
    }
}

/// Specifies who is revoking (deleting) the message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum RevokeType {
    /// The message sender deleting their own message.
    #[default]
    Sender,
    /// A group admin deleting another user's message.
    /// `original_sender` is the JID of the user who sent the message being deleted.
    Admin { original_sender: Jid },
}

/// Derive stanza-level edit attribute and meta node from message content.
fn infer_stanza_metadata(msg: &wa::Message) -> (Option<EditAttribute>, Option<Node>) {
    if msg.pin_in_chat_message.is_some() {
        return (Some(EditAttribute::PinInChat), None);
    }

    // Poll messages
    if msg.poll_creation_message.is_some()
        || msg.poll_creation_message_v2.is_some()
        || msg.poll_creation_message_v3.is_some()
    {
        return (None, Some(meta_node("polltype", "creation")));
    }
    if let Some(ref poll_update) = msg.poll_update_message
        && poll_update.vote.is_some()
    {
        return (None, Some(meta_node("polltype", "vote")));
    }
    // TODO: polltype="result_snapshot" for poll_result_snapshot_message (gated behind AB flag)

    // Event messages
    if msg.event_message.is_some() {
        return (None, Some(meta_node("event_type", "creation")));
    }
    if msg.enc_event_response_message.is_some() {
        return (None, Some(meta_node("event_type", "response")));
    }
    if let Some(ref sec) = msg.secret_encrypted_message
        && sec.secret_enc_type
            == Some(wa::message::secret_encrypted_message::SecretEncType::EventEdit as i32)
    {
        return (None, Some(meta_node("event_type", "edit")));
    }

    (None, None)
}

fn meta_node(key: &'static str, value: &'static str) -> Node {
    NodeBuilder::new("meta").attr(key, value).build()
}

/// Derive the `<biz>` stanza child for native-flow interactive messages.
/// All native flow types use the same nested structure (confirmed via protocol capture).
fn infer_biz_node(msg: &wa::Message) -> Option<Node> {
    let interactive = extract_interactive_message(msg)?;
    let wa::message::interactive_message::InteractiveMessage::NativeFlowMessage(nf) =
        interactive.interactive_message.as_ref()?
    else {
        return None;
    };

    let first_button_name = nf.buttons.first()?.name.as_deref()?;
    let flow_name = button_name_to_flow_name(first_button_name);

    Some(
        NodeBuilder::new("biz")
            .children([NodeBuilder::new("interactive")
                .attr("type", "native_flow")
                .attr("v", "1")
                .children([NodeBuilder::new("native_flow")
                    .attr("name", flow_name)
                    .build()])
                .build()])
            .build(),
    )
}

fn extract_interactive_message(msg: &wa::Message) -> Option<&wa::message::InteractiveMessage> {
    // Only checks documentWithCaptionMessage wrapper (for media headers) and direct field.
    // Does not use unwrap_message() since we need the InteractiveMessage specifically.
    if let Some(ref doc) = msg.document_with_caption_message
        && let Some(ref inner) = doc.message
        && let Some(ref im) = inner.interactive_message
    {
        return Some(im);
    }
    msg.interactive_message.as_deref()
}

fn button_name_to_flow_name(button_name: &str) -> &str {
    match button_name {
        "review_and_pay" => "order_details",
        "payment_info" => "payment_info",
        "review_order" | "order_status" => "order_status",
        "payment_status" => "payment_status",
        "payment_method" => "payment_method",
        "payment_reminder" => "payment_reminder",
        "open_webview" => "message_with_link",
        "message_with_link_status" => "message_with_link_status",
        "cta_url" => "cta_url",
        "cta_call" => "cta_call",
        "cta_copy" => "cta_copy",
        "cta_catalog" => "cta_catalog",
        "catalog_message" => "catalog_message",
        "quick_reply" => "quick_reply",
        "galaxy_message" => "galaxy_message",
        "booking_confirmation" => "booking_confirmation",
        "call_permission_request" => "call_permission_request",
        other => other,
    }
}

impl Client {
    /// Send a message to a user, group, or newsletter.
    ///
    /// Newsletter messages are sent as plaintext (no E2E encryption).
    /// For status/story updates use [`Client::status()`] instead.
    pub async fn send_message(
        &self,
        to: Jid,
        message: wa::Message,
    ) -> Result<SendResult, anyhow::Error> {
        self.send_message_with_options(to, message, SendOptions::default())
            .await
    }

    /// Send a message with additional options.
    pub async fn send_message_with_options(
        &self,
        to: Jid,
        mut message: wa::Message,
        options: SendOptions,
    ) -> Result<SendResult, anyhow::Error> {
        if let Some(exp) = options.ephemeral_expiration
            && exp > 0
        {
            use wacore::proto_helpers::MessageExt;
            if !message.set_ephemeral_expiration(exp) {
                // Bare `conversation` messages have no contextInfo field.
                log::warn!("Could not set contextInfo.expiration on this message type");
            }
        }

        let request_id = match options.message_id {
            Some(id) => id,
            None => self.generate_message_id().await,
        };
        // Both paths below consume `to` and `request_id`, so save copies for the result.
        let result = SendResult {
            message_id: request_id.clone(),
            to: to.clone(),
        };

        // Newsletters are not E2E encrypted — send as plaintext via SMAX stanza.
        // Matches WA Web's OutMessagePublishNewsletterRequest + ContentType mixins.
        if to.is_newsletter() {
            use prost::Message as _;
            let stanza_type = wacore::send::stanza_type_from_message(&message);
            let (_, meta_node) = infer_stanza_metadata(&message);
            let mut plaintext_builder = NodeBuilder::new("plaintext");
            if let Some(mt) = wacore::send::media_type_from_message(&message) {
                plaintext_builder = plaintext_builder.attr("mediatype", mt);
            }
            let mut children = vec![plaintext_builder.bytes(message.encode_to_vec()).build()];
            children.extend(meta_node);
            children.extend(options.extra_stanza_nodes);
            let stanza = NodeBuilder::new("message")
                .attr("to", to)
                .attr("type", stanza_type)
                .attr("id", &request_id)
                .children(children)
                .build();
            self.send_node(stanza).await?;
            return Ok(result);
        }

        let (edit, inferred_meta) = infer_stanza_metadata(&message);
        let inferred_biz = infer_biz_node(&message);

        let extra_nodes = if inferred_meta.is_none() && inferred_biz.is_none() {
            options.extra_stanza_nodes
        } else {
            let mut nodes = Vec::with_capacity(2 + options.extra_stanza_nodes.len());
            nodes.extend(inferred_meta);
            nodes.extend(inferred_biz);
            nodes.extend(options.extra_stanza_nodes);
            nodes
        };
        self.send_message_impl(
            to,
            &message,
            Some(request_id),
            false,
            false,
            edit,
            extra_nodes,
        )
        .await?;
        Ok(result)
    }

    /// Send a status/story update to the given recipients using sender key encryption.
    ///
    /// This builds a `GroupInfo` from the provided recipients (always PN addressing mode),
    /// then reuses the group encryption pipeline with `to = status@broadcast`.
    pub(crate) async fn send_status_message(
        &self,
        message: wa::Message,
        recipients: &[Jid],
        options: crate::features::status::StatusSendOptions,
    ) -> Result<SendResult, anyhow::Error> {
        use wacore::client::context::GroupInfo;
        use wacore_binary::builder::NodeBuilder;

        if recipients.is_empty() {
            return Err(anyhow!("Cannot send status with no recipients"));
        }

        let to = Jid::status_broadcast();
        let request_id = self.generate_message_id().await;

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let own_jid = device_snapshot
            .pn
            .clone()
            .ok_or(crate::client::ClientError::NotLoggedIn)?;
        // Status always uses PN addressing, so own_lid is only needed as a
        // fallback parameter for prepare_group_stanza (unused in PN mode).
        let own_lid = device_snapshot
            .lid
            .clone()
            .unwrap_or_else(|| own_jid.clone());
        let account_info = device_snapshot.account.clone();

        // Status always uses PN addressing. Resolve any LID recipients to their
        // phone numbers so we don't end up with duplicate PN+LID entries for the
        // same user (which causes server error 400).
        // Reject non-user JIDs (groups, broadcasts, etc.) to prevent invalid
        // <participants> entries that cause server errors.
        let mut resolved_recipients = Vec::with_capacity(recipients.len());
        for jid in recipients {
            if jid.is_group() || jid.is_status_broadcast() || jid.is_broadcast_list() {
                return Err(anyhow!(
                    "Invalid status recipient {}: must be a user JID, not a group/broadcast",
                    jid
                ));
            }
            if jid.is_lid() {
                if let Some(pn) = self.lid_pn_cache.get_phone_number(&jid.user).await {
                    resolved_recipients
                        .push(Jid::new(&pn, wacore_binary::jid::DEFAULT_USER_SERVER));
                } else {
                    return Err(anyhow!(
                        "No PN mapping for LID {}. Ensure the recipient has been \
                         contacted previously.",
                        jid
                    ));
                }
            } else {
                resolved_recipients.push(jid.clone());
            }
        }

        if resolved_recipients.is_empty() {
            return Err(anyhow!("No valid PN recipients after LID resolution"));
        }

        // Deduplicate by user (in case both LID and PN were provided for the same user)
        let mut seen_users = std::collections::HashSet::new();
        resolved_recipients.retain(|jid| seen_users.insert(jid.user.clone()));

        let mut group_info = GroupInfo::new(resolved_recipients, AddressingMode::Pn);

        // Ensure we're in the participant list
        let own_base = own_jid.to_non_ad();
        if !group_info
            .participants
            .iter()
            .any(|p| p.is_same_user_as(&own_base))
        {
            group_info.participants.push(own_base);
        }

        self.add_recent_message(to.clone(), request_id.clone(), &message)
            .await;

        let device_store_arc = self.persistence_manager.get_device_arc().await;
        let to_str = to.to_string();

        let force_skdm = {
            use wacore::libsignal::store::sender_key_name::SenderKeyName;
            let sender_address = own_jid.to_protocol_address();
            let sender_key_name = SenderKeyName::new(to_str.clone(), sender_address.to_string());

            let device_guard = device_store_arc.read().await;
            let key_exists = self
                .signal_cache
                .get_sender_key(&sender_key_name, &*device_guard.backend)
                .await?
                .is_some();

            !key_exists
        };

        let mut store_adapter =
            SignalProtocolStoreAdapter::new(device_store_arc.clone(), self.signal_cache.clone());
        let mut stores = wacore::send::SignalStores {
            session_store: &mut store_adapter.session_store,
            identity_store: &mut store_adapter.identity_store,
            prekey_store: &mut store_adapter.pre_key_store,
            signed_prekey_store: &store_adapter.signed_pre_key_store,
            sender_key_store: &mut store_adapter.sender_key_store,
        };

        // Determine which devices need SKDM using the unified per-device map
        let skdm_target_devices: Option<Vec<Jid>> = if force_skdm {
            None
        } else {
            self.resolve_skdm_targets(&to_str, &group_info.participants, &own_jid)
                .await
        };

        // WhatsApp Web includes <meta status_setting="..."/> on non-revoke status messages.
        // Revoke messages omit this node.
        let is_revoke = message.protocol_message.as_ref().is_some_and(|pm| {
            pm.r#type == Some(wa::message::protocol_message::Type::Revoke as i32)
        });
        let extra_stanza_nodes = if is_revoke {
            vec![]
        } else {
            vec![
                NodeBuilder::new("meta")
                    .attr("status_setting", options.privacy.as_str())
                    .build(),
            ]
        };

        let prepared = match wacore::send::prepare_group_stanza(
            &mut stores,
            self,
            &mut group_info,
            &own_jid,
            &own_lid,
            account_info.as_ref(),
            to.clone(),
            &message,
            request_id.clone(),
            force_skdm,
            skdm_target_devices,
            None,
            &extra_stanza_nodes,
        )
        .await
        {
            Ok(prepared) => prepared,
            Err(e) => {
                if let Some(SignalProtocolError::NoSenderKeyState(_)) =
                    e.downcast_ref::<SignalProtocolError>()
                {
                    log::warn!("No sender key for status broadcast, forcing distribution.");

                    if let Err(e) = self
                        .persistence_manager
                        .clear_sender_key_devices(&to_str)
                        .await
                    {
                        log::warn!(
                            "Failed to clear status SKDM recipients for {}: {:?}",
                            to_str,
                            e
                        );
                    }
                    self.sender_key_device_cache.invalidate(&to_str).await;

                    let mut store_adapter_retry = SignalProtocolStoreAdapter::new(
                        device_store_arc.clone(),
                        self.signal_cache.clone(),
                    );
                    let mut stores_retry = wacore::send::SignalStores {
                        session_store: &mut store_adapter_retry.session_store,
                        identity_store: &mut store_adapter_retry.identity_store,
                        prekey_store: &mut store_adapter_retry.pre_key_store,
                        signed_prekey_store: &store_adapter_retry.signed_pre_key_store,
                        sender_key_store: &mut store_adapter_retry.sender_key_store,
                    };

                    wacore::send::prepare_group_stanza(
                        &mut stores_retry,
                        self,
                        &mut group_info,
                        &own_jid,
                        &own_lid,
                        account_info.as_ref(),
                        to.clone(),
                        &message,
                        request_id.clone(),
                        true,
                        None,
                        None,
                        &extra_stanza_nodes,
                    )
                    .await?
                } else {
                    return Err(e);
                }
            }
        };

        let stanza = self
            .ensure_status_participants(prepared.node, &group_info)
            .await?;

        self.send_node(stanza).await?;

        self.update_sender_key_devices(&to_str, &prepared.skdm_devices)
            .await;

        // Invalidate device registry for users whose devices returned 406
        for user in &prepared.stale_device_users {
            self.invalidate_device_cache(user).await;
        }

        // Flush cached Signal state to DB after encryption
        if let Err(e) = self.flush_signal_cache().await {
            log::error!("Failed to flush signal cache after send_status_message: {e:?}");
        }

        Ok(SendResult {
            message_id: request_id,
            to,
        })
    }

    /// Resolve which devices need SKDM by reading the per-device sender key map.
    ///
    /// Returns `None` for full distribution (no map data or all unknown), or
    /// `Some(devices)` listing only the devices that need fresh SKDM.
    /// Uses `Jid::device_key()` for O(1) lookups — no string allocations in the hot path.
    async fn resolve_skdm_targets(
        &self,
        group_jid: &str,
        participants: &[Jid],
        own_sending_jid: &Jid,
    ) -> Option<Vec<Jid>> {
        use crate::sender_key_device_cache::SenderKeyDeviceMap;

        // Atomic get-or-init: if another task invalidated the cache during our
        // DB read, get_or_init's single-flight guarantee means the stale data
        // won't be inserted — the invalidation wins and the next caller re-inits.
        let pm = self.persistence_manager.clone();
        let cached_map = self
            .sender_key_device_cache
            .get_or_init(group_jid, async {
                let db_rows = pm
                    .get_sender_key_devices(group_jid)
                    .await
                    .unwrap_or_else(|e| {
                        log::warn!(
                            "Failed to read sender key devices for {}: {:?}",
                            group_jid,
                            e
                        );
                        vec![]
                    });
                std::sync::Arc::new(SenderKeyDeviceMap::from_db_rows(&db_rows))
            })
            .await;

        if cached_map.is_empty() {
            return None;
        }

        let jids_to_resolve: Vec<Jid> = participants.iter().map(|jid| jid.to_non_ad()).collect();

        match SendContextResolver::resolve_devices(self, &jids_to_resolve).await {
            Ok(all_devices) => {
                let needs_skdm: Vec<Jid> = all_devices
                    .into_iter()
                    .filter(|device| {
                        if device.is_hosted() {
                            return false;
                        }
                        if device.user == own_sending_jid.user
                            && device.device == own_sending_jid.device
                        {
                            return false;
                        }
                        // O(1) lookups into pre-indexed cache
                        !cached_map
                            .device_has_key(&device.user, device.device)
                            .unwrap_or(false)
                            || cached_map.is_user_forgotten(&device.user)
                    })
                    .collect();

                if needs_skdm.is_empty() {
                    Some(vec![])
                } else {
                    log::debug!(
                        "Found {} devices needing SKDM for {}",
                        needs_skdm.len(),
                        group_jid
                    );
                    Some(needs_skdm)
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to resolve devices for SKDM check in {}: {:?}",
                    group_jid,
                    e
                );
                None
            }
        }
    }

    /// Update sender key device tracking after a successful group/status send.
    ///
    /// Called AFTER `send_node()` succeeds (WA Web: `markHasSenderKey` after server ACK).
    /// On full distribution, clears old state and marks the provided device list.
    /// On partial, marks only the specific SKDM recipients.
    ///
    /// The `all_resolved_devices` parameter carries the exact device list resolved
    /// for the stanza, avoiding a redundant `resolve_devices` call and preventing
    /// the clear-then-fail race where a transient resolver failure leaves the map empty.
    /// Mark devices as `has_key=true` after successful SKDM distribution.
    async fn update_sender_key_devices(&self, group_jid: &str, devices: &[Jid]) {
        if devices.is_empty() {
            return;
        }

        // Write to DB first, then invalidate cache. Next read reloads from
        // DB with the authoritative state. This avoids the clone+modify race
        // where concurrent writers can overwrite each other's mutations.
        let strs: Vec<String> = devices.iter().map(|j| j.to_string()).collect();
        let entries: Vec<(&str, bool)> = strs.iter().map(|s| (s.as_str(), true)).collect();
        if let Err(e) = self
            .persistence_manager
            .set_sender_key_status(group_jid, &entries)
            .await
        {
            log::warn!(
                "Failed to update sender key devices for {}: {:?}",
                group_jid,
                e
            );
        }
        self.sender_key_device_cache.invalidate(group_jid).await;
    }

    /// Ensure the status stanza has a <participants> node listing all recipient
    /// user JIDs. WhatsApp Web's `participantList` uses bare USER JIDs (not
    /// device JIDs) — `<to jid="user@s.whatsapp.net"/>` — to tell the server
    /// which users should receive the skmsg. The SKDM distribution list
    /// (already in <participants>) uses device JIDs with <enc> children.
    async fn ensure_status_participants(
        &self,
        stanza: wacore_binary::Node,
        group_info: &wacore::client::context::GroupInfo,
    ) -> Result<wacore_binary::Node, anyhow::Error> {
        Ok(wacore::send::ensure_status_participants(stanza, group_info))
    }

    /// Delete a message for everyone in the chat (revoke).
    ///
    /// This sends a revoke protocol message that removes the message for all participants.
    /// The message will show as "This message was deleted" for recipients.
    ///
    /// # Arguments
    /// * `to` - The chat JID (DM or group)
    /// * `message_id` - The ID of the message to delete
    /// * `revoke_type` - Use `RevokeType::Sender` to delete your own message,
    ///   or `RevokeType::Admin { original_sender }` to delete another user's message as group admin
    pub async fn revoke_message(
        &self,
        to: Jid,
        message_id: impl Into<String>,
        revoke_type: RevokeType,
    ) -> Result<(), anyhow::Error> {
        let message_id = message_id.into();
        self.require_pn().await?;

        let (from_me, participant, edit_attr) = match &revoke_type {
            RevokeType::Sender => {
                // For sender revoke, participant is NOT set (from_me=true identifies it)
                // This matches whatsmeow's BuildMessageKey behavior
                (
                    true,
                    None,
                    crate::types::message::EditAttribute::SenderRevoke,
                )
            }
            RevokeType::Admin { original_sender } => {
                // Admin revoke requires group context
                if !to.is_group() {
                    return Err(anyhow!("Admin revoke is only valid for group chats"));
                }
                // The protocolMessageKey.participant should match the original message's key exactly
                // Do NOT convert LID to PN - pass through unchanged like WhatsApp Web does
                let participant_str = original_sender.to_non_ad().to_string();
                log::debug!(
                    "Admin revoke: using participant {} for MessageKey",
                    participant_str
                );
                (
                    false,
                    Some(participant_str),
                    crate::types::message::EditAttribute::AdminRevoke,
                )
            }
        };

        let revoke_message = wa::Message {
            protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                key: Some(wa::MessageKey {
                    remote_jid: Some(to.to_string()),
                    from_me: Some(from_me),
                    id: Some(message_id.clone()),
                    participant,
                }),
                r#type: Some(wa::message::protocol_message::Type::Revoke as i32),
                ..Default::default()
            })),
            ..Default::default()
        };

        // The revoke message stanza needs a NEW unique ID, not the message ID being revoked
        // The message_id being revoked is already in protocolMessage.key.id
        // Passing None generates a fresh stanza ID
        //
        // For admin revokes, force SKDM distribution to get the proper message structure
        // with phash, <participants>, and <device-identity> that WhatsApp Web uses
        let force_skdm = matches!(revoke_type, RevokeType::Admin { .. });
        self.send_message_impl(
            to,
            &revoke_message,
            None,
            false,
            force_skdm,
            Some(edit_attr),
            vec![],
        )
        .await
    }

    /// Pin a message in a chat for all participants.
    pub async fn pin_message(
        &self,
        chat: Jid,
        key: wa::MessageKey,
        duration: PinDuration,
    ) -> Result<(), anyhow::Error> {
        self.send_pin(
            chat,
            key,
            wa::message::pin_in_chat_message::Type::PinForAll,
            duration.as_secs(),
        )
        .await
    }

    /// Unpin a previously pinned message.
    pub async fn unpin_message(&self, chat: Jid, key: wa::MessageKey) -> Result<(), anyhow::Error> {
        self.send_pin(
            chat,
            key,
            wa::message::pin_in_chat_message::Type::UnpinForAll,
            0,
        )
        .await
    }

    async fn send_pin(
        &self,
        chat: Jid,
        key: wa::MessageKey,
        pin_type: wa::message::pin_in_chat_message::Type,
        duration_secs: u32,
    ) -> Result<(), anyhow::Error> {
        let message = wa::Message {
            pin_in_chat_message: Some(wa::message::PinInChatMessage {
                key: Some(key),
                r#type: Some(pin_type as i32),
                sender_timestamp_ms: Some(wacore::time::now_millis()),
            }),
            message_context_info: Some(wa::MessageContextInfo {
                message_add_on_duration_in_secs: Some(duration_secs),
                ..Default::default()
            }),
            ..Default::default()
        };

        self.send_message_impl(
            chat,
            &message,
            None,
            false,
            false,
            Some(crate::types::message::EditAttribute::PinInChat),
            vec![],
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_message_impl(
        &self,
        to: Jid,
        message: &wa::Message,
        request_id_override: Option<String>,
        peer: bool,
        force_key_distribution: bool,
        edit: Option<crate::types::message::EditAttribute>,
        extra_stanza_nodes: Vec<Node>,
    ) -> Result<(), anyhow::Error> {
        // Status broadcasts must go through send_status_message() which provides recipients
        if to.is_status_broadcast() {
            return Err(anyhow!(
                "Use send_status_message() or client.status() API for status@broadcast"
            ));
        }

        // Generate request ID early (doesn't need lock)
        let request_id = match request_id_override {
            Some(id) => id,
            None => self.generate_message_id().await,
        };

        // SKDM update data — only populated for group sends, deferred until after send_node().
        // This matches WhatsApp Web which only calls markHasSenderKey() after server ACK.
        struct SkdmUpdate {
            to_str: String,
            devices: Vec<Jid>,
            stale_users: Vec<String>,
        }
        let mut skdm_update: Option<SkdmUpdate> = None;
        let mut should_issue_tc_token_after_send = false;
        let mut used_cached_tc_token_key: Option<String> = None;
        let tc_issue_target = to.clone();

        let stanza_to_send: wacore_binary::Node = if peer && !to.is_group() {
            // Peer messages are only valid for individual users, not groups
            // Resolve encryption JID and acquire lock ONLY for encryption
            let encryption_jid = self.resolve_encryption_jid(&to).await;
            let signal_addr_str = encryption_jid.to_protocol_address_string();

            let session_mutex = self
                .session_locks
                .get_with_by_ref(&signal_addr_str, async {
                    std::sync::Arc::new(async_lock::Mutex::new(()))
                })
                .await;
            let _session_guard = session_mutex.lock().await;

            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let mut store_adapter =
                SignalProtocolStoreAdapter::new(device_store_arc, self.signal_cache.clone());

            wacore::send::prepare_peer_stanza(
                &mut store_adapter.session_store,
                &mut store_adapter.identity_store,
                to,
                encryption_jid,
                message,
                request_id,
            )
            .await?
        } else if to.is_group() {
            // Group messages: No client-level lock needed.
            // Each participant device is encrypted separately with its own per-device lock
            // inside prepare_group_stanza, so we don't need to serialize entire group sends.

            // Preparation work (no lock needed)
            let mut group_info = self.groups().query_info(&to).await?;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_jid = device_snapshot
                .pn
                .clone()
                .ok_or(crate::client::ClientError::NotLoggedIn)?;
            let own_lid = device_snapshot
                .lid
                .clone()
                .ok_or_else(|| anyhow!("LID not set, cannot send to group"))?;
            let account_info = device_snapshot.account.clone();

            // Store serialized message bytes for retry (lightweight)
            self.add_recent_message(to.clone(), request_id.clone(), message)
                .await;

            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let to_str = to.to_string();

            let (own_sending_jid, _) = match group_info.addressing_mode {
                crate::types::message::AddressingMode::Lid => (own_lid.clone(), "lid"),
                crate::types::message::AddressingMode::Pn => (own_jid.clone(), "pn"),
            };

            if !group_info
                .participants
                .iter()
                .any(|participant| participant.is_same_user_as(&own_sending_jid))
            {
                group_info.participants.push(own_sending_jid.to_non_ad());
            }

            let force_skdm = {
                use wacore::libsignal::store::sender_key_name::SenderKeyName;
                let sender_address = own_sending_jid.to_protocol_address();
                let sender_key_name =
                    SenderKeyName::new(to_str.clone(), sender_address.to_string());

                let device_guard = device_store_arc.read().await;
                let key_exists = self
                    .signal_cache
                    .get_sender_key(&sender_key_name, &*device_guard.backend)
                    .await?
                    .is_some();

                force_key_distribution || !key_exists
            };

            let mut store_adapter = SignalProtocolStoreAdapter::new(
                device_store_arc.clone(),
                self.signal_cache.clone(),
            );

            let mut stores = wacore::send::SignalStores {
                session_store: &mut store_adapter.session_store,
                identity_store: &mut store_adapter.identity_store,
                prekey_store: &mut store_adapter.pre_key_store,
                signed_prekey_store: &store_adapter.signed_pre_key_store,
                sender_key_store: &mut store_adapter.sender_key_store,
            };

            // Determine which devices need SKDM distribution using the unified
            // per-device sender key map (matches WA Web's participant.senderKey Map).
            let skdm_target_devices: Option<Vec<Jid>> = if force_skdm {
                None
            } else {
                self.resolve_skdm_targets(&to_str, &group_info.participants, &own_sending_jid)
                    .await
            };

            match wacore::send::prepare_group_stanza(
                &mut stores,
                self,
                &mut group_info,
                &own_jid,
                &own_lid,
                account_info.as_ref(),
                to.clone(),
                message,
                request_id.clone(),
                force_skdm,
                skdm_target_devices,
                edit.clone(),
                &extra_stanza_nodes,
            )
            .await
            {
                Ok(prepared) => {
                    skdm_update = Some(SkdmUpdate {
                        to_str: to_str.clone(),
                        devices: prepared.skdm_devices,
                        stale_users: prepared.stale_device_users,
                    });
                    prepared.node
                }
                Err(e) => {
                    if let Some(SignalProtocolError::NoSenderKeyState(_)) =
                        e.downcast_ref::<SignalProtocolError>()
                    {
                        log::warn!("No sender key for group {}, forcing distribution.", to);

                        if let Err(e) = self
                            .persistence_manager
                            .clear_sender_key_devices(&to_str)
                            .await
                        {
                            log::warn!("Failed to clear SKDM recipients: {:?}", e);
                        }
                        self.sender_key_device_cache.invalidate(&to_str).await;

                        let mut store_adapter_retry = SignalProtocolStoreAdapter::new(
                            device_store_arc.clone(),
                            self.signal_cache.clone(),
                        );
                        let mut stores_retry = wacore::send::SignalStores {
                            session_store: &mut store_adapter_retry.session_store,
                            identity_store: &mut store_adapter_retry.identity_store,
                            prekey_store: &mut store_adapter_retry.pre_key_store,
                            signed_prekey_store: &store_adapter_retry.signed_pre_key_store,
                            sender_key_store: &mut store_adapter_retry.sender_key_store,
                        };

                        let retry_prepared = wacore::send::prepare_group_stanza(
                            &mut stores_retry,
                            self,
                            &mut group_info,
                            &own_jid,
                            &own_lid,
                            account_info.as_ref(),
                            to,
                            message,
                            request_id,
                            true,
                            None,
                            edit.clone(),
                            &extra_stanza_nodes,
                        )
                        .await?;

                        skdm_update = Some(SkdmUpdate {
                            to_str,
                            devices: retry_prepared.skdm_devices,
                            stale_users: retry_prepared.stale_device_users,
                        });
                        retry_prepared.node
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            // Per-device locking to match decrypt path (message.rs:684),
            // preventing ratchet desync on concurrent send/receive.

            self.add_recent_message(to.clone(), request_id.clone(), message)
                .await;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_jid = device_snapshot
                .pn
                .as_ref()
                .ok_or(crate::client::ClientError::NotLoggedIn)?;

            // PN→LID mapping (WA Web: ManagePhoneNumberMappingJob)
            if to.is_pn() && self.lid_pn_cache.get_current_lid(&to.user).await.is_none() {
                let sid = self.generate_request_id();
                let spec = wacore::iq::usync::LidQuerySpec::new(vec![to.to_non_ad()], sid);
                // Best-effort: WA Web also catches and warns on failure
                match self.execute(spec).await {
                    Ok(resp) => {
                        for mapping in &resp.lid_mappings {
                            if let Err(e) = self
                                .add_lid_pn_mapping(
                                    &mapping.lid,
                                    &mapping.phone_number,
                                    crate::lid_pn_cache::LearningSource::Usync,
                                )
                                .await
                            {
                                log::warn!(
                                    "Failed to persist LID mapping {} -> {}: {e:?}",
                                    mapping.phone_number,
                                    mapping.lid
                                );
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("LID query failed for {}, falling back to PN: {e:?}", to);
                    }
                }
            }

            // Bare recipient (WA Web: MsgCreateFanoutStanza)
            let recipient_bare = self.resolve_encryption_jid(&to).await.to_non_ad();

            // Populate device registry for retry handling
            let _ = self.get_user_devices(std::slice::from_ref(&to)).await;
            let own_devices = self.get_user_devices(std::slice::from_ref(own_jid)).await?;

            let mut all_dm_jids = Vec::with_capacity(1 + own_devices.len());
            all_dm_jids.push(recipient_bare);
            all_dm_jids.extend(own_devices);

            self.ensure_e2e_sessions(&all_dm_jids).await?;

            let mut extra_stanza_nodes = extra_stanza_nodes;
            if !to.is_group() && !to.is_newsletter() {
                let (should_issue_after_send, cached_token_key) = self
                    .maybe_include_tc_token(&to, &mut extra_stanza_nodes)
                    .await;
                should_issue_tc_token_after_send = should_issue_after_send;
                if should_issue_after_send {
                    used_cached_tc_token_key = cached_token_key;
                }
            }
            if should_issue_tc_token_after_send {
                debug!(target: "Client/TcToken", "Scheduled tc token issuance after send for {}", to);
            }

            let lock_keys = self.build_session_lock_keys(&all_dm_jids).await;

            let mut _session_mutexes = Vec::with_capacity(lock_keys.len());
            for key in &lock_keys {
                _session_mutexes.push(
                    self.session_locks
                        .get_with_by_ref(key, async {
                            std::sync::Arc::new(async_lock::Mutex::new(()))
                        })
                        .await,
                );
            }
            let mut _session_guards = Vec::with_capacity(_session_mutexes.len());
            for mutex in &_session_mutexes {
                _session_guards.push(mutex.lock().await);
            }

            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let mut store_adapter =
                SignalProtocolStoreAdapter::new(device_store_arc, self.signal_cache.clone());

            let mut stores = wacore::send::SignalStores {
                session_store: &mut store_adapter.session_store,
                identity_store: &mut store_adapter.identity_store,
                prekey_store: &mut store_adapter.pre_key_store,
                signed_prekey_store: &store_adapter.signed_pre_key_store,
                sender_key_store: &mut store_adapter.sender_key_store,
            };

            wacore::send::prepare_dm_stanza(
                &mut stores,
                self,
                own_jid,
                device_snapshot.lid.as_ref(),
                device_snapshot.account.as_ref(),
                to,
                message,
                request_id,
                edit,
                &extra_stanza_nodes,
                all_dm_jids,
            )
            .await?
        };

        self.send_node(stanza_to_send).await?;

        // Update SKDM recipient cache AFTER server ACK (matches WhatsApp Web behavior).
        // WA Web only calls markHasSenderKey() after the server confirms receipt.
        if let Some(update) = skdm_update {
            self.update_sender_key_devices(&update.to_str, &update.devices)
                .await;
            // Invalidate device registry for users whose devices returned 406
            // so the next send re-fetches from server (without stale devices)
            for user in &update.stale_users {
                self.invalidate_device_cache(user).await;
            }
        }

        // Flush cached Signal state to DB after encryption
        if let Err(e) = self.flush_signal_cache().await {
            log::error!("Failed to flush signal cache after send_message_impl: {e:?}");
        }

        // Issue new tc token after send if a bucket boundary was crossed.
        // Fire-and-forget so send_message returns without waiting for the IQ
        if should_issue_tc_token_after_send {
            if let Some(client) = self.self_weak.get().and_then(|w| w.upgrade()) {
                let target = tc_issue_target;
                let cached_key = used_cached_tc_token_key;
                self.runtime
                    .spawn(Box::pin(async move {
                        let issued_ok = client.issue_tc_token_after_send(&target).await;
                        if issued_ok && let Some(token_key) = cached_key {
                            client.mark_tc_token_used_after_send(&token_key).await;
                        }
                    }))
                    .detach();
            } else {
                log::debug!(target: "Client/TcToken", "Skipping fire-and-forget issuance: client dropped");
            }
        }

        Ok(())
    }

    /// Look up and include a privacy token in outgoing 1:1 message stanza nodes.
    ///
    /// Follows WA Web's fallback chain (MsgCreateFanoutStanza.js):
    ///   1. tctoken — from stored trusted contact token (if valid, non-expired)
    ///   2. cstoken — HMAC-SHA256(nct_salt, recipient_lid) fallback for first-contact
    ///   3. No token — message sent without token (server may return 463)
    ///
    /// Returns whether we should issue a new tc token after send, and the cache key
    /// of the attached valid tc token when that token should be marked as used.
    async fn maybe_include_tc_token(
        &self,
        to: &Jid,
        extra_nodes: &mut Vec<Node>,
    ) -> (bool, Option<String>) {
        use wacore::iq::props::config_codes;
        use wacore::iq::tctoken::{
            build_cs_token_node, build_tc_token_node, compute_cs_token, is_tc_token_expired_with,
            should_send_new_tc_token_with,
        };

        // Skip for own JID — no need to send privacy token to ourselves
        let snapshot = self.persistence_manager.get_device_snapshot().await;
        let is_self = snapshot
            .pn
            .as_ref()
            .is_some_and(|pn| pn.is_same_user_as(to))
            || snapshot
                .lid
                .as_ref()
                .is_some_and(|lid| lid.is_same_user_as(to));
        if is_self {
            return (false, None);
        }

        // Bots and status broadcast don't participate in the privacy token system
        if to.is_bot() || to.is_status_broadcast() {
            return (false, None);
        }

        // Resolve the destination to a LID user string once — reused for
        // tctoken lookup, issuance, and cstoken HMAC input.
        let resolved_lid_user = if to.is_lid() {
            Some(to.user.clone())
        } else {
            self.lid_pn_cache.get_current_lid(&to.user).await
        };
        let token_jid = resolved_lid_user.as_deref().unwrap_or(&to.user).to_string();

        let backend = self.persistence_manager.backend();
        let tc_config = self.tc_token_config().await;

        // Look up existing tctoken
        let existing = match backend.get_tc_token(&token_jid).await {
            Ok(entry) => entry,
            Err(e) => {
                log::warn!(target: "Client/TcToken", "Failed to get tc_token for {}: {e}", token_jid);
                None
            }
        };

        // Issuance scheduling is independent of the AB prop — WA Web's sendTcToken
        // in MsgJob.js fires regardless of whether a token was attached to the stanza
        let should_issue_after_send = should_send_new_tc_token_with(
            existing.as_ref().and_then(|entry| entry.sender_timestamp),
            &tc_config,
        );

        // AB prop gates stanza inclusion only (not issuance scheduling)
        let token_send_enabled = self
            .ab_props
            .is_enabled_or(config_codes::PRIVACY_TOKEN_ON_ALL_1_ON_1_MESSAGES, false)
            .await;

        if token_send_enabled {
            match existing {
                Some(ref entry)
                    if !is_tc_token_expired_with(entry.token_timestamp, &tc_config)
                        && !entry.token.is_empty() =>
                {
                    extra_nodes.push(build_tc_token_node(&entry.token));
                    return (should_issue_after_send, Some(token_jid));
                }
                _ => {
                    // cstoken fallback — gated by wa_nct_token_send_enabled
                    let nct_send_enabled = self
                        .ab_props
                        .is_enabled_or(config_codes::NCT_TOKEN_SEND_ENABLED, false)
                        .await;

                    if nct_send_enabled
                        && let Some(salt) = &snapshot.nct_salt
                        && let Some(lid_user) = &resolved_lid_user
                    {
                        // HMAC input is "user@lid" (account LID without device suffix),
                        // matching WA Web's accountLid.toString()
                        let recipient_lid =
                            wacore_binary::jid::Jid::new(lid_user, "lid").to_string();
                        let cs_token = compute_cs_token(salt, &recipient_lid);
                        extra_nodes.push(build_cs_token_node(&cs_token));
                        log::debug!(target: "Client/CsToken", "Attached cstoken for {} (NCT fallback)", to);
                    } else {
                        log::debug!(target: "Client/CsToken", "No tctoken or NCT salt/LID available for {}", to);
                    }
                }
            }
        }

        (should_issue_after_send, None)
    }

    /// Returns `true` if the issuance IQ succeeded.
    async fn issue_tc_token_after_send(&self, to: &Jid) -> bool {
        use wacore::iq::tctoken::IssuePrivacyTokensSpec;

        // Bots and status broadcast don't participate in the privacy token system
        if to.is_bot() || to.is_status_broadcast() {
            return false;
        }

        let issuance_jid = self.resolve_issuance_jid(to).await;
        let Ok(response) = self
            .execute(IssuePrivacyTokensSpec::new(std::slice::from_ref(
                &issuance_jid,
            )))
            .await
        else {
            log::debug!(target: "Client/TcToken", "Failed to issue tc_token for {}", issuance_jid);
            return false;
        };

        self.store_issued_tc_tokens(&response.tokens).await
    }

    /// Returns true if at least one token was persisted.
    async fn store_issued_tc_tokens(
        &self,
        tokens: &[wacore::iq::tctoken::ReceivedTcToken],
    ) -> bool {
        use wacore::store::traits::TcTokenEntry;

        if tokens.is_empty() {
            return false;
        }

        let backend = self.persistence_manager.backend();
        let now = wacore::time::now_secs();
        let mut any_stored = false;
        for received in tokens {
            if received.token.is_empty() {
                log::warn!(target: "Client/TcToken", "Server returned empty tc_token for {}, skipping", received.jid);
                continue;
            }

            let entry = TcTokenEntry {
                token: received.token.clone(),
                token_timestamp: received.timestamp,
                sender_timestamp: Some(now),
            };

            if let Err(e) = backend.put_tc_token(&received.jid.user, &entry).await {
                log::warn!(target: "Client/TcToken", "Failed to store issued tc_token: {e}");
            } else {
                any_stored = true;
            }
        }
        any_stored
    }

    /// Variant of [`store_issued_tc_tokens`] that preserves the original
    /// sender_timestamp for identity-change re-issuance (bucket continuity).
    async fn store_issued_tc_tokens_with_sender_ts(
        &self,
        tokens: &[wacore::iq::tctoken::ReceivedTcToken],
        sender_ts: i64,
    ) {
        use wacore::store::traits::TcTokenEntry;

        let backend = self.persistence_manager.backend();
        for received in tokens {
            if received.token.is_empty() {
                continue;
            }
            let entry = TcTokenEntry {
                token: received.token.clone(),
                token_timestamp: received.timestamp,
                sender_timestamp: Some(sender_ts),
            };
            if let Err(e) = backend.put_tc_token(&received.jid.user, &entry).await {
                log::warn!(target: "Client/TcToken", "Failed to store re-issued tc_token: {e}");
            }
        }
    }

    async fn mark_tc_token_used_after_send(&self, token_key: &str) {
        use wacore::store::traits::TcTokenEntry;

        let backend = self.persistence_manager.backend();
        let existing = match backend.get_tc_token(token_key).await {
            Ok(entry) => entry,
            Err(e) => {
                log::warn!(target: "Client/TcToken", "Failed to reload tc_token for {}: {e}", token_key);
                return;
            }
        };

        let Some(entry) = existing else {
            return;
        };
        if entry.token.is_empty() {
            return;
        }

        let updated_entry = TcTokenEntry {
            sender_timestamp: Some(wacore::time::now_secs()),
            ..entry
        };
        if let Err(e) = backend.put_tc_token(token_key, &updated_entry).await {
            log::warn!(target: "Client/TcToken", "Failed to update sender_timestamp for {}: {e}", token_key);
        }
    }

    /// Re-issue tctoken after a contact's device identity changes.
    /// Only re-issues if we previously sent a token (sender_timestamp valid).
    /// Uses session_locks to deduplicate concurrent spawns for the same sender.
    pub(crate) async fn reissue_tc_token_after_identity_change(&self, sender: &Jid) {
        use wacore::iq::tctoken::{IssuePrivacyTokensSpec, is_sender_tc_token_expired};

        // Dedup via session_locks — bare JID won't collide with protocol addresses ("user:device")
        let bare = sender.to_non_ad().to_string();
        let mutex = self
            .session_locks
            .get_with_by_ref(bare.as_str(), async {
                std::sync::Arc::new(async_lock::Mutex::new(()))
            })
            .await;
        let Some(_guard) = mutex.try_lock() else {
            return;
        };

        let token_jid = if sender.is_lid() {
            sender.user.clone()
        } else {
            match self.lid_pn_cache.get_current_lid(&sender.user).await {
                Some(lid) => lid,
                None => sender.user.clone(),
            }
        };

        let backend = self.persistence_manager.backend();
        let entry = match backend.get_tc_token(&token_jid).await {
            Ok(Some(e)) => e,
            _ => return,
        };

        let Some(sender_ts) = entry.sender_timestamp else {
            return;
        };

        // Sender-side expiration (may use different bucket config than receiver)
        let tc_config = self.tc_token_config().await;
        if is_sender_tc_token_expired(sender_ts, &tc_config) {
            return;
        }

        // Use stored sender_ts so the bucket window isn't advanced
        let issuance_jid = self.resolve_issuance_jid(sender).await;
        match self
            .execute(IssuePrivacyTokensSpec::with_timestamp(
                std::slice::from_ref(&issuance_jid),
                sender_ts,
            ))
            .await
        {
            Ok(response) => {
                // Keep original sender_ts so the bucket window isn't advanced
                self.store_issued_tc_tokens_with_sender_ts(&response.tokens, sender_ts)
                    .await;
                log::debug!(
                    target: "Client/TcToken",
                    "Re-issued tctoken after identity change for {}",
                    sender
                );
            }
            Err(e) => {
                log::debug!(
                    target: "Client/TcToken",
                    "Failed to re-issue tctoken after identity change for {}: {e}",
                    sender
                );
            }
        }
    }

    /// Look up a valid (non-expired) tctoken for a JID. Returns the raw token bytes if found.
    ///
    /// Used by profile picture, presence subscribe, and other features that need tctoken gating.
    pub(crate) async fn lookup_tc_token_for_jid(&self, jid: &Jid) -> Option<Vec<u8>> {
        use wacore::iq::tctoken::is_tc_token_expired_with;

        let token_jid = if jid.is_lid() {
            jid.user.clone()
        } else {
            match self.lid_pn_cache.get_current_lid(&jid.user).await {
                Some(lid) => lid,
                None => jid.user.clone(),
            }
        };

        let tc_config = self.tc_token_config().await;
        let backend = self.persistence_manager.backend();
        match backend.get_tc_token(&token_jid).await {
            Ok(Some(entry))
                if !entry.token.is_empty()
                    && !is_tc_token_expired_with(entry.token_timestamp, &tc_config) =>
            {
                Some(entry.token)
            }
            Ok(_) => None,
            Err(e) => {
                log::warn!(target: "Client/TcToken", "Failed to get tc_token for {}: {e}", token_jid);
                None
            }
        }
    }

    /// Build sorted, deduplicated per-device session lock keys for a set of device JIDs.
    /// Keys match the decrypt path's format (message.rs:684) so send and receive
    /// serialize on the same device's Signal session.
    pub(crate) async fn build_session_lock_keys(&self, device_jids: &[Jid]) -> Vec<String> {
        let mut keys = Vec::with_capacity(device_jids.len());
        for jid in device_jids {
            let enc_jid = self.resolve_encryption_jid(jid).await;
            keys.push(enc_jid.to_protocol_address_string());
        }
        keys.sort_unstable();
        keys.dedup();
        keys
    }

    /// Build tctoken timing config from AB props, falling back to defaults.
    pub(crate) async fn tc_token_config(&self) -> wacore::iq::tctoken::TcTokenConfig {
        use wacore::iq::props::config_codes;
        use wacore::iq::tctoken::{TC_TOKEN_BUCKET_DURATION, TC_TOKEN_NUM_BUCKETS, TcTokenConfig};

        TcTokenConfig {
            bucket_duration: self
                .ab_props
                .get_int(config_codes::TCTOKEN_DURATION, TC_TOKEN_BUCKET_DURATION)
                .await,
            num_buckets: self
                .ab_props
                .get_int(config_codes::TCTOKEN_NUM_BUCKETS, TC_TOKEN_NUM_BUCKETS)
                .await,
            sender_bucket_duration: self
                .ab_props
                .get_int(
                    config_codes::TCTOKEN_DURATION_SENDER,
                    TC_TOKEN_BUCKET_DURATION,
                )
                .await,
            sender_num_buckets: self
                .ab_props
                .get_int(
                    config_codes::TCTOKEN_NUM_BUCKETS_SENDER,
                    TC_TOKEN_NUM_BUCKETS,
                )
                .await,
        }
        .clamped()
    }

    /// Resolve a JID to its LID form for tc_token storage.
    async fn resolve_to_lid_jid(&self, jid: &Jid) -> Jid {
        if jid.is_lid() {
            return jid.to_non_ad();
        }

        if let Some(lid_user) = self.lid_pn_cache.get_current_lid(&jid.user).await {
            Jid::new(&lid_user, "lid")
        } else {
            jid.to_non_ad()
        }
    }

    /// Resolve the target JID for privacy token issuance.
    /// Gated by `lid_trusted_token_issue_to_lid` — LID when true, PN when false.
    async fn resolve_issuance_jid(&self, jid: &Jid) -> Jid {
        use wacore::iq::props::config_codes;

        // Default true: issue to LID by default (safer — server accepts both)
        let issue_to_lid = self
            .ab_props
            .is_enabled_or(config_codes::LID_TRUSTED_TOKEN_ISSUE_TO_LID, true)
            .await;

        let resolved = if issue_to_lid {
            self.resolve_to_lid_jid(jid).await
        } else if jid.is_lid() {
            if let Some(pn) = self.lid_pn_cache.get_phone_number(&jid.user).await {
                Jid::new(&pn, "s.whatsapp.net")
            } else {
                jid.to_non_ad()
            }
        } else {
            jid.to_non_ad()
        };
        // Issuance targets bare account JIDs, not device-scoped ones
        resolved.to_non_ad()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_revoke_type_default_is_sender() {
        // RevokeType::Sender is the default (for deleting own messages)
        let revoke_type = RevokeType::default();
        assert_eq!(revoke_type, RevokeType::Sender);
    }

    #[test]
    fn test_force_skdm_only_for_admin_revoke() {
        // Admin revokes require force_skdm=true to get proper message structure
        // with phash, <participants>, and <device-identity> that WhatsApp Web uses.
        // Without this, the server returns error 479.
        let sender_jid = Jid::from_str("123456@s.whatsapp.net").unwrap();

        let sender_revoke = RevokeType::Sender;
        let admin_revoke = RevokeType::Admin {
            original_sender: sender_jid,
        };

        // This matches the logic in revoke_message()
        let force_skdm_sender = matches!(sender_revoke, RevokeType::Admin { .. });
        let force_skdm_admin = matches!(admin_revoke, RevokeType::Admin { .. });

        assert!(!force_skdm_sender, "Sender revoke should NOT force SKDM");
        assert!(force_skdm_admin, "Admin revoke MUST force SKDM");
    }

    #[test]
    fn test_sender_revoke_message_key_structure() {
        // Sender revoke (edit="7"): from_me=true, participant=None
        // The sender is identified by from_me=true, no participant field needed
        let to = Jid::from_str("120363040237990503@g.us").unwrap();
        let message_id = "3EB0ABC123".to_string();

        let (from_me, participant, edit_attr) = match RevokeType::Sender {
            RevokeType::Sender => (
                true,
                None,
                crate::types::message::EditAttribute::SenderRevoke,
            ),
            RevokeType::Admin { original_sender } => (
                false,
                Some(original_sender.to_non_ad().to_string()),
                crate::types::message::EditAttribute::AdminRevoke,
            ),
        };

        assert!(from_me, "Sender revoke must have from_me=true");
        assert!(
            participant.is_none(),
            "Sender revoke must NOT set participant"
        );
        assert_eq!(edit_attr.to_string_val(), "7");

        let revoke_message = wa::Message {
            protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                key: Some(wa::MessageKey {
                    remote_jid: Some(to.to_string()),
                    from_me: Some(from_me),
                    id: Some(message_id.clone()),
                    participant,
                }),
                r#type: Some(wa::message::protocol_message::Type::Revoke as i32),
                ..Default::default()
            })),
            ..Default::default()
        };

        let proto_msg = revoke_message.protocol_message.unwrap();
        let key = proto_msg.key.unwrap();
        assert_eq!(key.from_me, Some(true));
        assert_eq!(key.participant, None);
        assert_eq!(key.id, Some(message_id));
    }

    #[test]
    fn test_admin_revoke_message_key_structure() {
        // Admin revoke (edit="8"): from_me=false, participant=original_sender
        // The participant field identifies whose message is being deleted
        let to = Jid::from_str("120363040237990503@g.us").unwrap();
        let message_id = "3EB0ABC123".to_string();
        let original_sender = Jid::from_str("236395184570386:22@lid").unwrap();

        let revoke_type = RevokeType::Admin {
            original_sender: original_sender.clone(),
        };
        let (from_me, participant, edit_attr) = match revoke_type {
            RevokeType::Sender => (
                true,
                None,
                crate::types::message::EditAttribute::SenderRevoke,
            ),
            RevokeType::Admin { original_sender } => (
                false,
                Some(original_sender.to_non_ad().to_string()),
                crate::types::message::EditAttribute::AdminRevoke,
            ),
        };

        assert!(!from_me, "Admin revoke must have from_me=false");
        assert!(
            participant.is_some(),
            "Admin revoke MUST set participant to original sender"
        );
        assert_eq!(edit_attr.to_string_val(), "8");

        let revoke_message = wa::Message {
            protocol_message: Some(Box::new(wa::message::ProtocolMessage {
                key: Some(wa::MessageKey {
                    remote_jid: Some(to.to_string()),
                    from_me: Some(from_me),
                    id: Some(message_id.clone()),
                    participant: participant.clone(),
                }),
                r#type: Some(wa::message::protocol_message::Type::Revoke as i32),
                ..Default::default()
            })),
            ..Default::default()
        };

        let proto_msg = revoke_message.protocol_message.unwrap();
        let key = proto_msg.key.unwrap();
        assert_eq!(key.from_me, Some(false));
        // Participant should be the original sender with device number stripped
        assert_eq!(key.participant, Some("236395184570386@lid".to_string()));
        assert_eq!(key.id, Some(message_id));
    }

    #[test]
    fn test_admin_revoke_preserves_lid_format() {
        // LID JIDs must NOT be converted to PN (phone number) format.
        // This was a bug that caused error 479 - the participant field must
        // preserve the original JID format exactly (with device stripped).
        let lid_sender = Jid::from_str("236395184570386:22@lid").unwrap();
        let participant_str = lid_sender.to_non_ad().to_string();

        // Must preserve @lid suffix, device number stripped
        assert_eq!(participant_str, "236395184570386@lid");
        assert!(
            participant_str.ends_with("@lid"),
            "LID participant must preserve @lid suffix"
        );
    }

    // SKDM Recipient Filtering Tests - validates DeviceKey-based filtering

    #[test]
    fn test_skdm_recipient_filtering_basic() {
        use std::collections::HashSet;

        let known_recipients: Vec<Jid> = [
            "1234567890:0@s.whatsapp.net",
            "1234567890:5@s.whatsapp.net",
            "9876543210:0@s.whatsapp.net",
        ]
        .into_iter()
        .map(|s| Jid::from_str(s).unwrap())
        .collect();

        let all_devices: Vec<Jid> = [
            "1234567890:0@s.whatsapp.net",
            "1234567890:5@s.whatsapp.net",
            "9876543210:0@s.whatsapp.net",
            "5555555555:0@s.whatsapp.net", // new
        ]
        .into_iter()
        .map(|s| Jid::from_str(s).unwrap())
        .collect();

        let known_set: HashSet<DeviceKey<'_>> =
            known_recipients.iter().map(|j| j.device_key()).collect();

        let new_devices: Vec<Jid> = all_devices
            .into_iter()
            .filter(|device| !known_set.contains(&device.device_key()))
            .collect();

        assert_eq!(new_devices.len(), 1);
        assert_eq!(new_devices[0].user, "5555555555");
    }

    #[test]
    fn test_skdm_recipient_filtering_lid_jids() {
        use std::collections::HashSet;

        let known_recipients: Vec<Jid> = [
            "236395184570386:91@lid",
            "129171292463295:0@lid",
            "45857667830004:14@lid",
        ]
        .into_iter()
        .map(|s| Jid::from_str(s).unwrap())
        .collect();

        let all_devices: Vec<Jid> = [
            "236395184570386:91@lid",
            "129171292463295:0@lid",
            "45857667830004:14@lid",
            "45857667830004:15@lid", // new
        ]
        .into_iter()
        .map(|s| Jid::from_str(s).unwrap())
        .collect();

        let known_set: HashSet<DeviceKey<'_>> =
            known_recipients.iter().map(|j| j.device_key()).collect();

        let new_devices: Vec<Jid> = all_devices
            .into_iter()
            .filter(|device| !known_set.contains(&device.device_key()))
            .collect();

        assert_eq!(new_devices.len(), 1);
        assert_eq!(new_devices[0].user, "45857667830004");
        assert_eq!(new_devices[0].device, 15);
    }

    #[test]
    fn test_skdm_recipient_filtering_all_known() {
        use std::collections::HashSet;

        let known_recipients: Vec<Jid> =
            ["1234567890:0@s.whatsapp.net", "1234567890:5@s.whatsapp.net"]
                .into_iter()
                .map(|s| Jid::from_str(s).unwrap())
                .collect();

        let all_devices: Vec<Jid> = ["1234567890:0@s.whatsapp.net", "1234567890:5@s.whatsapp.net"]
            .into_iter()
            .map(|s| Jid::from_str(s).unwrap())
            .collect();

        let known_set: HashSet<DeviceKey<'_>> =
            known_recipients.iter().map(|j| j.device_key()).collect();

        let new_devices: Vec<Jid> = all_devices
            .into_iter()
            .filter(|device| !known_set.contains(&device.device_key()))
            .collect();

        assert!(new_devices.is_empty());
    }

    #[test]
    fn test_skdm_recipient_filtering_all_new() {
        use std::collections::HashSet;

        let known_recipients: Vec<Jid> = vec![];

        let all_devices: Vec<Jid> = ["1234567890:0@s.whatsapp.net", "9876543210:0@s.whatsapp.net"]
            .into_iter()
            .map(|s| Jid::from_str(s).unwrap())
            .collect();

        let known_set: HashSet<DeviceKey<'_>> =
            known_recipients.iter().map(|j| j.device_key()).collect();

        let new_devices: Vec<Jid> = all_devices
            .clone()
            .into_iter()
            .filter(|device| !known_set.contains(&device.device_key()))
            .collect();

        assert_eq!(new_devices.len(), all_devices.len());
    }

    #[test]
    fn test_device_key_comparison() {
        // Jid parse/display normalizes :0 (omitted in Display, missing ':N' parses as device 0).
        // This test ensures DeviceKey comparisons work correctly under that normalization.
        let test_cases = [
            (
                "1234567890:0@s.whatsapp.net",
                "1234567890@s.whatsapp.net",
                true,
            ),
            (
                "1234567890:5@s.whatsapp.net",
                "1234567890:5@s.whatsapp.net",
                true,
            ),
            (
                "1234567890:5@s.whatsapp.net",
                "1234567890:6@s.whatsapp.net",
                false,
            ),
            ("236395184570386:91@lid", "236395184570386:91@lid", true),
            ("236395184570386:0@lid", "236395184570386@lid", true),
            ("user1@s.whatsapp.net", "user2@s.whatsapp.net", false),
        ];

        for (jid1_str, jid2_str, should_match) in test_cases {
            let jid1: Jid = jid1_str.parse().expect("should parse jid1");
            let jid2: Jid = jid2_str.parse().expect("should parse jid2");

            let key1 = jid1.device_key();
            let key2 = jid2.device_key();

            assert_eq!(
                key1 == key2,
                should_match,
                "DeviceKey comparison failed for '{}' vs '{}': expected match={}, got match={}",
                jid1_str,
                jid2_str,
                should_match,
                key1 == key2
            );

            assert_eq!(
                jid1.device_eq(&jid2),
                should_match,
                "device_eq failed for '{}' vs '{}'",
                jid1_str,
                jid2_str
            );
        }
    }

    #[test]
    fn test_skdm_filtering_large_group() {
        use std::collections::HashSet;

        let mut known_recipients: Vec<Jid> = Vec::with_capacity(1000);
        let mut all_devices: Vec<Jid> = Vec::with_capacity(1010);

        for i in 0..1000i64 {
            let jid_str = format!("{}:1@lid", 100000000000000i64 + i);
            let jid = Jid::from_str(&jid_str).unwrap();
            known_recipients.push(jid.clone());
            all_devices.push(jid);
        }

        for i in 1000i64..1010i64 {
            let jid_str = format!("{}:1@lid", 100000000000000i64 + i);
            all_devices.push(Jid::from_str(&jid_str).unwrap());
        }

        let known_set: HashSet<DeviceKey<'_>> =
            known_recipients.iter().map(|j| j.device_key()).collect();

        let new_devices: Vec<Jid> = all_devices
            .into_iter()
            .filter(|device| !known_set.contains(&device.device_key()))
            .collect();

        assert_eq!(new_devices.len(), 10);
    }

    mod infer_stanza {
        use super::*;

        #[test]
        fn regular_message_returns_none() {
            let msg = wa::Message {
                conversation: Some("hello".into()),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert!(edit.is_none());
            assert!(node.is_none());
        }

        #[test]
        fn pin_returns_edit_attribute() {
            let msg = wa::Message {
                pin_in_chat_message: Some(wa::message::PinInChatMessage::default()),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert_eq!(edit, Some(EditAttribute::PinInChat));
            assert!(node.is_none());
        }

        #[test]
        fn poll_creation_v3_returns_meta_node() {
            let msg = wa::Message {
                poll_creation_message_v3: Some(Box::default()),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert!(edit.is_none());
            let node = node.expect("should have meta node");
            assert_eq!(node.tag, "meta");
            let mut attrs = node.attrs();
            assert_eq!(
                attrs.optional_string("polltype").unwrap().as_ref(),
                "creation"
            );
        }

        #[test]
        fn event_returns_meta_node() {
            let msg = wa::Message {
                event_message: Some(Box::default()),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert!(edit.is_none());
            let node = node.expect("should have meta node");
            assert_eq!(node.tag, "meta");
            let mut attrs = node.attrs();
            assert_eq!(
                attrs.optional_string("event_type").unwrap().as_ref(),
                "creation"
            );
        }

        #[test]
        fn empty_message_returns_none() {
            let (edit, node) = infer_stanza_metadata(&wa::Message::default());
            assert!(edit.is_none());
            assert!(node.is_none());
        }

        #[test]
        fn poll_creation_v1_returns_meta_node() {
            let msg = wa::Message {
                poll_creation_message: Some(Box::default()),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert!(edit.is_none());
            let node = node.expect("should have meta node");
            assert_eq!(node.tag, "meta");
            let mut attrs = node.attrs();
            assert_eq!(
                attrs.optional_string("polltype").unwrap().as_ref(),
                "creation"
            );
        }

        #[test]
        fn poll_creation_v2_returns_meta_node() {
            let msg = wa::Message {
                poll_creation_message_v2: Some(Box::default()),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert!(edit.is_none());
            let node = node.expect("should have meta node");
            assert_eq!(node.tag, "meta");
            let mut attrs = node.attrs();
            assert_eq!(
                attrs.optional_string("polltype").unwrap().as_ref(),
                "creation"
            );
        }

        #[test]
        fn poll_vote_returns_meta_node() {
            let msg = wa::Message {
                poll_update_message: Some(wa::message::PollUpdateMessage {
                    vote: Some(wa::message::PollEncValue::default()),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert!(edit.is_none());
            let node = node.expect("should have meta node");
            assert_eq!(node.tag, "meta");
            let mut attrs = node.attrs();
            assert_eq!(attrs.optional_string("polltype").unwrap().as_ref(), "vote");
        }

        #[test]
        fn event_response_returns_meta_node() {
            let msg = wa::Message {
                enc_event_response_message: Some(Default::default()),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert!(edit.is_none());
            let node = node.expect("should have meta node");
            assert_eq!(node.tag, "meta");
            let mut attrs = node.attrs();
            assert_eq!(
                attrs.optional_string("event_type").unwrap().as_ref(),
                "response"
            );
        }

        #[test]
        fn poll_update_without_vote_returns_none() {
            let msg = wa::Message {
                poll_update_message: Some(wa::message::PollUpdateMessage {
                    vote: None,
                    ..Default::default()
                }),
                ..Default::default()
            };
            let (edit, node) = infer_stanza_metadata(&msg);
            assert!(edit.is_none());
            assert!(node.is_none());
        }
    }

    mod infer_biz {
        use super::*;
        use wa::message::interactive_message::{
            self, NativeFlowMessage, native_flow_message::NativeFlowButton,
        };

        fn msg_with_native_flow(button_name: &str) -> wa::Message {
            wa::Message {
                document_with_caption_message: Some(Box::new(wa::message::FutureProofMessage {
                    message: Some(Box::new(wa::Message {
                        interactive_message: Some(Box::new(wa::message::InteractiveMessage {
                            interactive_message: Some(
                                interactive_message::InteractiveMessage::NativeFlowMessage(
                                    NativeFlowMessage {
                                        buttons: vec![NativeFlowButton {
                                            name: Some(button_name.to_string()),
                                            button_params_json: None,
                                        }],
                                        message_version: Some(1),
                                        message_params_json: None,
                                    },
                                ),
                            ),
                            ..Default::default()
                        })),
                        ..Default::default()
                    })),
                })),
                ..Default::default()
            }
        }

        fn assert_biz_node(node: &Node, expected_flow_name: &str) {
            assert_eq!(node.tag, "biz");
            assert!(
                node.attrs().optional_string("native_flow_name").is_none(),
                "should NOT use simple attribute form"
            );
            let interactive = node.get_optional_child("interactive").unwrap();
            let mut attrs = interactive.attrs();
            assert_eq!(
                attrs.optional_string("type").unwrap().as_ref(),
                "native_flow"
            );
            assert_eq!(attrs.optional_string("v").unwrap().as_ref(), "1");
            let nf = interactive.get_optional_child("native_flow").unwrap();
            let mut nf_attrs = nf.attrs();
            assert_eq!(
                nf_attrs.optional_string("name").unwrap().as_ref(),
                expected_flow_name
            );
        }

        #[test]
        fn all_button_types_use_nested_structure() {
            for (button, expected_flow) in [
                ("cta_url", "cta_url"),
                ("payment_info", "payment_info"),
                ("review_and_pay", "order_details"),
                ("cta_catalog", "cta_catalog"),
                ("mpm", "mpm"),
                ("quick_reply", "quick_reply"),
            ] {
                let node = infer_biz_node(&msg_with_native_flow(button))
                    .unwrap_or_else(|| panic!("{button} should produce biz node"));
                assert_biz_node(&node, expected_flow);
            }
        }

        #[test]
        fn no_interactive_returns_none() {
            let msg = wa::Message {
                conversation: Some("hello".into()),
                ..Default::default()
            };
            assert!(infer_biz_node(&msg).is_none());
        }

        #[test]
        fn interactive_without_native_flow_returns_none() {
            let msg = wa::Message {
                interactive_message: Some(Box::new(wa::message::InteractiveMessage {
                    interactive_message: Some(
                        interactive_message::InteractiveMessage::CollectionMessage(
                            Default::default(),
                        ),
                    ),
                    ..Default::default()
                })),
                ..Default::default()
            };
            assert!(infer_biz_node(&msg).is_none());
        }

        #[test]
        fn native_flow_without_buttons_returns_none() {
            let msg = wa::Message {
                interactive_message: Some(Box::new(wa::message::InteractiveMessage {
                    interactive_message: Some(
                        interactive_message::InteractiveMessage::NativeFlowMessage(
                            NativeFlowMessage {
                                buttons: vec![],
                                message_version: Some(1),
                                message_params_json: None,
                            },
                        ),
                    ),
                    ..Default::default()
                })),
                ..Default::default()
            };
            assert!(infer_biz_node(&msg).is_none());
        }

        #[test]
        fn direct_interactive_message_without_wrapper() {
            let msg = wa::Message {
                interactive_message: Some(Box::new(wa::message::InteractiveMessage {
                    interactive_message: Some(
                        interactive_message::InteractiveMessage::NativeFlowMessage(
                            NativeFlowMessage {
                                buttons: vec![NativeFlowButton {
                                    name: Some("cta_url".to_string()),
                                    button_params_json: None,
                                }],
                                message_version: Some(1),
                                message_params_json: None,
                            },
                        ),
                    ),
                    ..Default::default()
                })),
                ..Default::default()
            };
            let node = infer_biz_node(&msg).unwrap();
            assert_biz_node(&node, "cta_url");
        }
    }

    /// Regression tests for #462: send path session lock keys must match decrypt path.
    mod session_lock_regression {
        use super::*;

        #[tokio::test]
        async fn per_device_lock_keys_cover_all_devices() {
            let client = crate::test_utils::create_test_client().await;

            let devices: Vec<Jid> = [
                "100000012345678@lid",
                "100000012345678:5@lid",
                "100000012345678:33@lid",
            ]
            .iter()
            .map(|s| Jid::from_str(s).unwrap())
            .collect();

            // Uses the production helper (resolve_encryption_jid + sort + dedup)
            let send_lock_keys = client.build_session_lock_keys(&devices).await;

            assert_eq!(send_lock_keys.len(), 3);
            assert_eq!(send_lock_keys[0], "100000012345678:33@lid.0");
            assert_eq!(send_lock_keys[1], "100000012345678:5@lid.0");
            assert_eq!(send_lock_keys[2], "100000012345678@lid.0");

            // Send keys must match what the decrypt path would use
            for device_jid in &devices {
                let decrypt_key = device_jid.to_protocol_address().to_string();
                assert!(
                    send_lock_keys.contains(&decrypt_key),
                    "decrypt key {decrypt_key} not in send keys: {send_lock_keys:?}"
                );
            }

            // Bare JID key alone wouldn't protect linked devices
            let bare_key = devices[0].to_protocol_address_string();
            let device5_key = devices[1].to_protocol_address_string();
            assert_ne!(bare_key, device5_key);
        }

        #[tokio::test]
        async fn per_device_lock_serializes_concurrent_session_access() {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicU32, Ordering};

            let session_locks: crate::cache::Cache<String, Arc<async_lock::Mutex<()>>> =
                crate::cache::Cache::builder().max_capacity(100).build();

            let lock_key = "100000012345678:5@lid.0".to_string();
            let access_counter = Arc::new(AtomicU32::new(0));
            let max_concurrent = Arc::new(AtomicU32::new(0));

            let mut handles = Vec::new();
            for _ in 0..10 {
                let locks = session_locks.clone();
                let key = lock_key.clone();
                let counter = access_counter.clone();
                let max = max_concurrent.clone();

                handles.push(tokio::spawn(async move {
                    let mutex: Arc<async_lock::Mutex<()>> = locks
                        .get_with_by_ref(&key, async { Arc::new(async_lock::Mutex::new(())) })
                        .await;
                    // lock_arc() needed: guard must own the Arc since mutex is a local
                    // (production uses lock() with a separate Vec keeping Arcs alive)
                    let _guard = mutex.lock_arc().await;

                    let active = counter.fetch_add(1, Ordering::SeqCst) + 1;
                    max.fetch_max(active, Ordering::SeqCst);
                    tokio::task::yield_now().await;
                    counter.fetch_sub(1, Ordering::SeqCst);
                }));
            }

            for handle in handles {
                handle.await.unwrap();
            }

            assert_eq!(max_concurrent.load(Ordering::SeqCst), 1);
        }

        #[tokio::test]
        async fn different_device_locks_are_independent() {
            use std::sync::Arc;
            use std::sync::atomic::{AtomicU32, Ordering};

            let session_locks: crate::cache::Cache<String, Arc<async_lock::Mutex<()>>> =
                crate::cache::Cache::builder().max_capacity(100).build();

            let max_concurrent = Arc::new(AtomicU32::new(0));
            let counter = Arc::new(AtomicU32::new(0));
            let barrier = Arc::new(tokio::sync::Barrier::new(2));

            let keys = ["100000012345678@lid.0", "100000012345678:5@lid.0"];

            let mut handles = Vec::new();
            for key in keys {
                let locks = session_locks.clone();
                let key = key.to_string();
                let c = counter.clone();
                let m = max_concurrent.clone();
                let b = barrier.clone();

                handles.push(tokio::spawn(async move {
                    let mutex: Arc<async_lock::Mutex<()>> = locks
                        .get_with_by_ref(&key, async { Arc::new(async_lock::Mutex::new(())) })
                        .await;
                    // lock_arc(): same reason as above
                    let _guard = mutex.lock_arc().await;

                    let active = c.fetch_add(1, Ordering::SeqCst) + 1;
                    m.fetch_max(active, Ordering::SeqCst);
                    b.wait().await;
                    c.fetch_sub(1, Ordering::SeqCst);
                }));
            }

            for handle in handles {
                handle.await.unwrap();
            }

            assert_eq!(max_concurrent.load(Ordering::SeqCst), 2);
        }

        /// Regression: 1:1 DM recipient must use bare Signal address matching
        /// the receive path. Starts from device-specific JID and verifies
        /// to_non_ad() normalization produces the correct bare key.
        #[tokio::test]
        async fn dm_recipient_uses_bare_address() {
            let client = crate::test_utils::create_test_client().await;

            // Start from device-specific JID, exercise the production path
            let recipient_device33 = Jid::from_str("100000012345678:33@lid").unwrap();
            let own_device_5 = Jid::from_str("999999999999:5@s.whatsapp.net").unwrap();

            // Same normalization as send_message_impl
            let recipient_bare = client
                .resolve_encryption_jid(&recipient_device33)
                .await
                .to_non_ad();

            let all_dm_jids = vec![recipient_bare.clone(), own_device_5.clone()];
            let lock_keys = client.build_session_lock_keys(&all_dm_jids).await;

            // Recipient lock key must be BARE (device 0), matching decrypt path
            assert_eq!(
                recipient_bare.to_protocol_address_string(),
                "100000012345678@lid.0"
            );
            assert!(lock_keys.contains(&"100000012345678@lid.0".to_string()));

            // Own device lock key must be device-specific
            assert!(lock_keys.contains(&"999999999999:5@c.us.0".to_string()));

            // Device-specific recipient key must NOT be present
            assert!(
                !lock_keys.contains(&"100000012345678:33@lid.0".to_string()),
                "recipient must NOT use device-specific address"
            );
        }

        /// Verify bare normalization deduplicates multiple recipient devices.
        #[test]
        fn bare_normalization_deduplicates_recipient_devices() {
            let devices: Vec<Jid> = [
                "100000012345678@lid",
                "100000012345678:5@lid",
                "100000012345678:33@lid",
            ]
            .iter()
            .map(|s| Jid::from_str(s).unwrap())
            .collect();

            // All collapse to the same bare JID
            let bare: Vec<Jid> = devices.iter().map(|j| j.to_non_ad()).collect();
            assert!(bare.windows(2).all(|w| w[0] == w[1]));
            assert_eq!(
                bare[0].to_protocol_address_string(),
                "100000012345678@lid.0"
            );
        }
    }
}
