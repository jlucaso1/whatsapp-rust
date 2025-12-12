use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use anyhow::anyhow;
use wacore::client::context::SendContextResolver;
use wacore::libsignal::protocol::SignalProtocolError;
use wacore::types::jid::JidExt;
use wacore_binary::jid::{Jid, JidExt as _};
use waproto::whatsapp as wa;

impl Client {
    pub async fn send_message(
        &self,
        to: Jid,
        message: wa::Message,
    ) -> Result<String, anyhow::Error> {
        let request_id = self.generate_message_id().await;
        self.send_message_impl(to, &message, Some(request_id.clone()), false, false, None)
            .await?;
        Ok(request_id)
    }

    pub(crate) async fn send_message_impl(
        &self,
        to: Jid,
        message: &wa::Message,
        request_id_override: Option<String>,
        peer: bool,
        force_key_distribution: bool,
        edit: Option<crate::types::message::EditAttribute>,
    ) -> Result<(), anyhow::Error> {
        let session_mutex = self
            .session_locks
            .get_with(to.clone(), async {
                std::sync::Arc::new(tokio::sync::Mutex::new(()))
            })
            .await;
        let _session_guard = session_mutex.lock().await;

        let request_id = match request_id_override {
            Some(id) => id,
            None => self.generate_message_id().await,
        };

        let stanza_to_send: wacore_binary::Node = if peer {
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
        } else if to.is_group() {
            let mut group_info = self.query_group_info(&to).await?;

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

            // Track devices that will receive SKDM in this message
            let devices_receiving_skdm: Vec<String> = skdm_target_devices
                .as_ref()
                .map(|devices: &Vec<Jid>| devices.iter().map(|d: &Jid| d.to_string()).collect())
                .unwrap_or_default();

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
                        )
                        .await?
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            // Store serialized message bytes for retry (lightweight)
            self.add_recent_message(to.clone(), request_id.clone(), message)
                .await;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_jid = device_snapshot
                .pn
                .clone()
                .ok_or_else(|| anyhow!("Not logged in"))?;
            let account_info = device_snapshot.account.clone();

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
            )
            .await?
        };
        self.send_node(stanza_to_send).await.map_err(|e| e.into())
    }
}
