use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use anyhow::anyhow;
use wacore::client::context::SendContextResolver;
use wacore::libsignal::protocol::SignalProtocolError;
use wacore::types::jid::JidExt;
use wacore_binary::jid::{DeviceKey, Jid, JidExt as _};
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

/// Options for sending messages with additional customization.
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Extra XML nodes to add to the message stanza.
    pub extra_stanza_nodes: Vec<Node>,
}

/// Specifies who is revoking (deleting) the message.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RevokeType {
    /// The message sender deleting their own message.
    #[default]
    Sender,
    /// A group admin deleting another user's message.
    /// `original_sender` is the JID of the user who sent the message being deleted.
    Admin { original_sender: Jid },
}

impl Client {
    pub async fn send_message(
        &self,
        to: Jid,
        message: wa::Message,
    ) -> Result<String, anyhow::Error> {
        self.send_message_with_options(to, message, SendOptions::default())
            .await
    }

    /// Send a message with additional options.
    pub async fn send_message_with_options(
        &self,
        to: Jid,
        message: wa::Message,
        options: SendOptions,
    ) -> Result<String, anyhow::Error> {
        let request_id = self.generate_message_id().await;
        self.send_message_impl(
            to,
            &message,
            Some(request_id.clone()),
            false,
            false,
            None,
            options.extra_stanza_nodes,
        )
        .await?;
        Ok(request_id)
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
        // Verify we're logged in
        self.get_pn()
            .await
            .ok_or_else(|| anyhow!("Not logged in"))?;

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
        // Generate request ID early (doesn't need lock)
        let request_id = match request_id_override {
            Some(id) => id,
            None => self.generate_message_id().await,
        };

        let stanza_to_send: wacore_binary::Node = if peer && !to.is_group() {
            // Peer messages are only valid for individual users, not groups
            // Resolve encryption JID and acquire lock ONLY for encryption
            let encryption_jid = self.resolve_encryption_jid(&to).await;
            let signal_addr_str = encryption_jid.to_protocol_address().to_string();

            let session_mutex = self
                .session_locks
                .get_with(signal_addr_str.clone(), async {
                    std::sync::Arc::new(tokio::sync::Mutex::new(()))
                })
                .await;
            let _session_guard = session_mutex.lock().await;

            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc);

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
                .ok_or_else(|| anyhow!("Not logged in"))?;
            let own_lid = device_snapshot
                .lid
                .clone()
                .ok_or_else(|| anyhow!("LID not set, cannot send to group"))?;
            let account_info = device_snapshot.account.clone();

            // Store serialized message bytes for retry (lightweight)
            self.add_recent_message(to.clone(), request_id.clone(), message)
                .await;

            let device_store_arc = self.persistence_manager.get_device_arc().await;

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
                use wacore::libsignal::protocol::SenderKeyStore;
                use wacore::libsignal::store::sender_key_name::SenderKeyName;
                let mut device_guard = device_store_arc.write().await;
                let sender_address = own_sending_jid.to_protocol_address();
                let sender_key_name =
                    SenderKeyName::new(to.to_string(), sender_address.to_string());

                let key_exists = device_guard
                    .load_sender_key(&sender_key_name)
                    .await?
                    .is_some();

                force_key_distribution || !key_exists
            };

            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc.clone());

            let mut stores = wacore::send::SignalStores {
                session_store: &mut store_adapter.session_store,
                identity_store: &mut store_adapter.identity_store,
                prekey_store: &mut store_adapter.pre_key_store,
                signed_prekey_store: &store_adapter.signed_pre_key_store,
                sender_key_store: &mut store_adapter.sender_key_store,
            };

            // Consume forget marks - these participants need fresh SKDMs (matches WhatsApp Web)
            // markForgetSenderKey is called during retry handling, this consumes those marks
            let marked_for_fresh_skdm = self
                .consume_forget_marks(&to.to_string())
                .await
                .unwrap_or_default();

            // Determine which devices need SKDM distribution
            let skdm_target_devices: Option<Vec<Jid>> = if force_skdm {
                // Forcing full distribution (either first message or explicit request)
                None // Let prepare_group_stanza resolve all devices
            } else {
                // Check known recipients FIRST (fast local DB query)
                // This short-circuits for first messages, avoiding unnecessary device resolution
                let known_recipients = self
                    .persistence_manager
                    .get_skdm_recipients(&to.to_string())
                    .await
                    .unwrap_or_default();

                if known_recipients.is_empty() {
                    // First message to group: no known recipients, need full distribution
                    // Let prepare_group_stanza handle device resolution
                    None
                } else {
                    // Consecutive messages: resolve devices to find new ones that need SKDM
                    let jids_to_resolve: Vec<Jid> = group_info
                        .participants
                        .iter()
                        .map(|jid| jid.to_non_ad())
                        .collect();

                    match SendContextResolver::resolve_devices(self, &jids_to_resolve).await {
                        Ok(all_devices) => {
                            // OPTIMIZATION: Zero-allocation O(n+m) device comparison
                            //
                            // Using DeviceKey for O(1) HashSet lookups without string allocation.
                            // DeviceKey compares only (user, server, device) fields, ignoring
                            // agent/integrator which may not roundtrip through string serialization.
                            use std::collections::HashSet;

                            // O(n) - parse known recipients to Jids (one-time allocation)
                            let known_jids: Vec<Jid> = known_recipients
                                .iter()
                                .filter_map(|s| s.parse::<Jid>().ok())
                                .collect();

                            // Build HashSet<DeviceKey> - zero allocation, just borrows from known_jids
                            let known_set: HashSet<DeviceKey<'_>> =
                                known_jids.iter().map(|j| j.device_key()).collect();

                            // O(m) - filter devices with O(1) lookups, no allocation per device
                            let new_devices: Vec<Jid> = all_devices
                                .into_iter()
                                .filter(|device| !known_set.contains(&device.device_key()))
                                .collect();

                            if new_devices.is_empty() {
                                Some(vec![]) // No new devices, no SKDM needed
                            } else {
                                log::debug!(
                                    "Found {} new devices needing SKDM for group {}",
                                    new_devices.len(),
                                    to
                                );
                                Some(new_devices)
                            }
                        }
                        Err(e) => {
                            log::warn!("Failed to resolve devices for SKDM check: {:?}", e);
                            None // Fall back to full distribution
                        }
                    }
                }
            };

            // Merge marked_for_fresh_skdm into skdm_target_devices
            // These are devices that need fresh SKDMs due to retry/error handling
            let skdm_target_devices: Option<Vec<Jid>> = if !marked_for_fresh_skdm.is_empty() {
                match skdm_target_devices {
                    None => None, // Already doing full distribution
                    Some(mut devices) => {
                        // Parse marked JID strings and add to target list
                        for marked_jid_str in &marked_for_fresh_skdm {
                            if let Ok(marked_jid) = marked_jid_str.parse::<Jid>()
                                && !devices.iter().any(|d| d.to_string() == *marked_jid_str)
                            {
                                log::debug!(
                                    "Adding {} to SKDM targets (marked for fresh key)",
                                    marked_jid_str
                                );
                                devices.push(marked_jid);
                            }
                        }
                        Some(devices)
                    }
                }
            } else {
                skdm_target_devices
            };

            // Track devices that will receive SKDM in this message
            let devices_receiving_skdm: Vec<String> = skdm_target_devices
                .as_ref()
                .map(|devices: &Vec<Jid>| devices.iter().map(|d: &Jid| d.to_string()).collect())
                .unwrap_or_default();

            // Encryption happens here (per-device locking handled internally)
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
                skdm_target_devices.clone(),
                edit.clone(),
                extra_stanza_nodes.clone(),
            )
            .await
            {
                Ok(stanza) => {
                    // Update SKDM recipients tracking after preparing the stanza
                    if !devices_receiving_skdm.is_empty() {
                        if let Err(e) = self
                            .persistence_manager
                            .add_skdm_recipients(&to.to_string(), &devices_receiving_skdm)
                            .await
                        {
                            log::warn!("Failed to update SKDM recipients: {:?}", e);
                        }
                    } else if force_skdm || skdm_target_devices.is_none() {
                        // Full distribution happened, query all devices and track them
                        let jids_to_resolve: Vec<Jid> = group_info
                            .participants
                            .iter()
                            .map(|jid| jid.to_non_ad())
                            .collect();

                        if let Ok(all_devices) =
                            SendContextResolver::resolve_devices(self, &jids_to_resolve).await
                        {
                            let all_device_strs: Vec<String> =
                                all_devices.iter().map(|d| d.to_string()).collect();
                            if let Err(e) = self
                                .persistence_manager
                                .add_skdm_recipients(&to.to_string(), &all_device_strs)
                                .await
                            {
                                log::warn!("Failed to update SKDM recipients: {:?}", e);
                            }
                        }
                    }
                    stanza
                }
                Err(e) => {
                    if let Some(SignalProtocolError::NoSenderKeyState(_)) =
                        e.downcast_ref::<SignalProtocolError>()
                    {
                        log::warn!("No sender key for group {}, forcing distribution.", to);

                        // Clear SKDM recipients since we're rotating the key
                        if let Err(e) = self
                            .persistence_manager
                            .clear_skdm_recipients(&to.to_string())
                            .await
                        {
                            log::warn!("Failed to clear SKDM recipients: {:?}", e);
                        }

                        let mut store_adapter_retry =
                            SignalProtocolStoreAdapter::new(device_store_arc.clone());
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
                            to,
                            message,
                            request_id,
                            true, // Force distribution on retry
                            None, // Distribute to all devices
                            edit.clone(),
                            extra_stanza_nodes.clone(),
                        )
                        .await?
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            // Direct message: Acquire lock only during encryption

            // Ensure E2E sessions exist before encryption (matches WhatsApp Web)
            // This deduplicates concurrent prekey fetches for the same recipient
            let recipient_devices = self.get_user_devices(std::slice::from_ref(&to)).await?;
            self.ensure_e2e_sessions(recipient_devices).await?;

            // Resolve encryption JID and prepare lock acquisition
            let encryption_jid = self.resolve_encryption_jid(&to).await;
            let signal_addr_str = encryption_jid.to_protocol_address().to_string();

            // Store serialized message bytes for retry (lightweight)
            self.add_recent_message(to.clone(), request_id.clone(), message)
                .await;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_jid = device_snapshot
                .pn
                .clone()
                .ok_or_else(|| anyhow!("Not logged in"))?;
            let account_info = device_snapshot.account.clone();

            // Acquire lock only for encryption
            let session_mutex = self
                .session_locks
                .get_with(signal_addr_str.clone(), async {
                    std::sync::Arc::new(tokio::sync::Mutex::new(()))
                })
                .await;
            let _session_guard = session_mutex.lock().await;

            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc);

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
                &own_jid,
                account_info.as_ref(),
                to,
                message,
                request_id,
                edit,
                extra_stanza_nodes,
            )
            .await?
        };

        self.send_node(stanza_to_send).await.map_err(|e| e.into())
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

    // ==========================================================================
    // SKDM Recipient Filtering Tests
    //
    // These tests validate the HashSet<&str> filtering logic used to determine
    // which devices need SKDM (Sender Key Distribution Message) distribution.
    // We use string comparison instead of Jid struct comparison because:
    // 1. Jid parsing has edge cases (agent/integrator fields may not roundtrip)
    // 2. String comparison is guaranteed to work correctly
    // 3. O(n+m) complexity with HashSet lookup
    // ==========================================================================

    #[test]
    fn test_skdm_recipient_filtering_basic() {
        use std::collections::HashSet;

        // Simulate known recipients from database
        let known_recipients = vec![
            "1234567890:0@s.whatsapp.net".to_string(),
            "1234567890:5@s.whatsapp.net".to_string(),
            "9876543210:0@s.whatsapp.net".to_string(),
        ];

        // Simulate resolved devices from usync
        let all_devices = vec![
            Jid::from_str("1234567890:0@s.whatsapp.net").unwrap(),
            Jid::from_str("1234567890:5@s.whatsapp.net").unwrap(),
            Jid::from_str("9876543210:0@s.whatsapp.net").unwrap(),
            Jid::from_str("5555555555:0@s.whatsapp.net").unwrap(), // New device
        ];

        // Same logic as production code: use DeviceKey for zero-allocation comparison
        let known_jids: Vec<Jid> = known_recipients
            .iter()
            .filter_map(|s| s.parse::<Jid>().ok())
            .collect();

        let known_set: HashSet<DeviceKey<'_>> = known_jids.iter().map(|j| j.device_key()).collect();

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

        // LID (Linked ID) JIDs - common in modern WhatsApp
        let known_recipients = vec![
            "236395184570386:91@lid".to_string(),
            "129171292463295:0@lid".to_string(),
            "45857667830004:14@lid".to_string(),
        ];

        let all_devices = vec![
            Jid::from_str("236395184570386:91@lid").unwrap(),
            Jid::from_str("129171292463295:0@lid").unwrap(),
            Jid::from_str("45857667830004:14@lid").unwrap(),
            Jid::from_str("45857667830004:15@lid").unwrap(), // New device for existing user
        ];

        // Same logic as production code: use DeviceKey
        let known_jids: Vec<Jid> = known_recipients
            .iter()
            .filter_map(|s| s.parse::<Jid>().ok())
            .collect();

        let known_set: HashSet<DeviceKey<'_>> = known_jids.iter().map(|j| j.device_key()).collect();

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

        // All devices already known - common case for consecutive messages
        let known_recipients = vec![
            "1234567890:0@s.whatsapp.net".to_string(),
            "1234567890:5@s.whatsapp.net".to_string(),
        ];

        let all_devices = vec![
            Jid::from_str("1234567890:0@s.whatsapp.net").unwrap(),
            Jid::from_str("1234567890:5@s.whatsapp.net").unwrap(),
        ];

        // Same logic as production code: use DeviceKey
        let known_jids: Vec<Jid> = known_recipients
            .iter()
            .filter_map(|s| s.parse::<Jid>().ok())
            .collect();

        let known_set: HashSet<DeviceKey<'_>> = known_jids.iter().map(|j| j.device_key()).collect();

        let new_devices: Vec<Jid> = all_devices
            .into_iter()
            .filter(|device| !known_set.contains(&device.device_key()))
            .collect();

        assert!(
            new_devices.is_empty(),
            "All devices known - should return empty"
        );
    }

    #[test]
    fn test_skdm_recipient_filtering_all_new() {
        use std::collections::HashSet;

        // First message to group - no known recipients
        let known_recipients: Vec<String> = vec![];

        let all_devices = vec![
            Jid::from_str("1234567890:0@s.whatsapp.net").unwrap(),
            Jid::from_str("9876543210:0@s.whatsapp.net").unwrap(),
        ];

        // Same logic as production code: use DeviceKey
        let known_jids: Vec<Jid> = known_recipients
            .iter()
            .filter_map(|s| s.parse::<Jid>().ok())
            .collect();

        let known_set: HashSet<DeviceKey<'_>> = known_jids.iter().map(|j| j.device_key()).collect();

        let new_devices: Vec<Jid> = all_devices
            .clone()
            .into_iter()
            .filter(|device| !known_set.contains(&device.device_key()))
            .collect();

        assert_eq!(
            new_devices.len(),
            all_devices.len(),
            "All devices new - should return all"
        );
    }

    #[test]
    fn test_device_key_comparison() {
        // Verify that DeviceKey comparison works correctly regardless of string format
        // This is critical: DB may store ":0" but Jid.to_string() omits it
        let test_cases = [
            // (jid_str_1, jid_str_2, should_match)
            (
                "1234567890:0@s.whatsapp.net",
                "1234567890@s.whatsapp.net",
                true,
            ), // :0 omitted
            (
                "1234567890:5@s.whatsapp.net",
                "1234567890:5@s.whatsapp.net",
                true,
            ),
            (
                "1234567890:5@s.whatsapp.net",
                "1234567890:6@s.whatsapp.net",
                false,
            ), // different device
            ("236395184570386:91@lid", "236395184570386:91@lid", true),
            ("236395184570386:0@lid", "236395184570386@lid", true), // :0 omitted
            ("user1@s.whatsapp.net", "user2@s.whatsapp.net", false), // different user
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

            // Also verify device_eq method
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

        // Simulate a large group scenario
        let mut known_recipients: Vec<String> = Vec::with_capacity(1000);
        let mut all_devices: Vec<Jid> = Vec::with_capacity(1010);

        // Generate 1000 known devices
        for i in 0..1000i64 {
            let jid_str = format!("{}:1@lid", 100000000000000i64 + i);
            known_recipients.push(jid_str.clone());
            all_devices.push(Jid::from_str(&jid_str).unwrap());
        }

        // Add 10 new devices
        for i in 1000i64..1010i64 {
            let jid_str = format!("{}:1@lid", 100000000000000i64 + i);
            all_devices.push(Jid::from_str(&jid_str).unwrap());
        }

        // Same logic as production code: use DeviceKey
        let known_jids: Vec<Jid> = known_recipients
            .iter()
            .filter_map(|s| s.parse::<Jid>().ok())
            .collect();

        let known_set: HashSet<DeviceKey<'_>> = known_jids.iter().map(|j| j.device_key()).collect();

        let new_devices: Vec<Jid> = all_devices
            .into_iter()
            .filter(|device| !known_set.contains(&device.device_key()))
            .collect();

        assert_eq!(new_devices.len(), 10, "Should find exactly 10 new devices");
    }
}
