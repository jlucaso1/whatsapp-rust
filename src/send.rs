use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use anyhow::anyhow;
use wacore::client::context::SendContextResolver;
use wacore::libsignal::protocol::SignalProtocolError;
use wacore::types::jid::JidExt;
use wacore_binary::jid::{Jid, JidExt as _};
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

/// Options for sending messages with additional customization.
#[derive(Debug, Clone, Default)]
pub struct SendOptions {
    /// Extra XML nodes to add to the message stanza.
    pub extra_stanza_nodes: Vec<Node>,
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

            // Lock is held only during encryption
            let device_store_arc = self.persistence_manager.get_device_arc().await;
            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc);

            wacore::send::prepare_peer_stanza(
                &mut store_adapter.session_store,
                &mut store_adapter.identity_store,
                to,
                message,
                request_id,
            )
            .await?
            // Lock released here automatically
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
                // Check which devices already have SKDM and find new ones
                let known_recipients = self
                    .persistence_manager
                    .get_skdm_recipients(&to.to_string())
                    .await
                    .unwrap_or_default();

                if known_recipients.is_empty() {
                    // No known recipients, need full distribution
                    None
                } else {
                    // Get current devices for all participants
                    let jids_to_resolve: Vec<Jid> = group_info
                        .participants
                        .iter()
                        .map(|jid| jid.to_non_ad())
                        .collect();

                    match SendContextResolver::resolve_devices(self, &jids_to_resolve).await {
                        Ok(all_devices) => {
                            // Filter to find devices that don't have SKDM yet
                            let new_devices: Vec<Jid> = all_devices
                                .into_iter()
                                .filter(|device: &Jid| {
                                    !known_recipients.contains(&device.to_string())
                                })
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

            // Lock is held only during encryption
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
            // Lock released here automatically
        };
        // Network send happens with NO lock held
        self.send_node(stanza_to_send).await.map_err(|e| e.into())
    }

    /// Archive a chat.
    pub async fn archive_chat(&self, chat: Jid) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::ArchiveChatAction;
        self.push_sync_action(ArchiveChatAction::archive(chat))
            .await
    }

    /// Unarchive a chat.
    pub async fn unarchive_chat(&self, chat: Jid) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::ArchiveChatAction;
        self.push_sync_action(ArchiveChatAction::unarchive(chat))
            .await
    }

    /// Pin a chat.
    pub async fn pin_chat(&self, chat: Jid) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::PinChatAction;
        self.push_sync_action(PinChatAction::pin(chat)).await
    }

    /// Unpin a chat.
    pub async fn unpin_chat(&self, chat: Jid) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::PinChatAction;
        self.push_sync_action(PinChatAction::unpin(chat)).await
    }

    /// Mute a chat for a specified duration.
    pub async fn mute_chat(
        &self,
        chat: Jid,
        duration: std::time::Duration,
    ) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::MuteChatAction;
        self.push_sync_action(MuteChatAction::mute_for(chat, duration))
            .await
    }

    /// Mute a chat indefinitely.
    pub async fn mute_chat_forever(&self, chat: Jid) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::MuteChatAction;
        self.push_sync_action(MuteChatAction::mute_forever(chat))
            .await
    }

    /// Unmute a chat.
    pub async fn unmute_chat(&self, chat: Jid) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::MuteChatAction;
        self.push_sync_action(MuteChatAction::unmute(chat)).await
    }

    /// Mark a chat as read.
    pub async fn mark_chat_read(&self, chat: Jid) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::MarkChatAsReadAction;
        self.push_sync_action(MarkChatAsReadAction::mark_read(chat))
            .await
    }

    /// Mark a chat as unread.
    pub async fn mark_chat_unread(&self, chat: Jid) -> Result<(), crate::sync_actions::SyncError> {
        use crate::sync_actions::MarkChatAsReadAction;
        self.push_sync_action(MarkChatAsReadAction::mark_unread(chat))
            .await
    }
}
