use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use anyhow::anyhow;
use std::sync::Arc;
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
        self.send_message_impl(
            to,
            Arc::new(message),
            Some(request_id.clone()),
            false,
            false,
            None,
        )
        .await?;
        Ok(request_id)
    }

    pub(crate) async fn send_message_impl(
        &self,
        to: Jid,
        message: Arc<wa::Message>,
        request_id_override: Option<String>,
        peer: bool,
        force_key_distribution: bool,
        edit: Option<crate::types::message::EditAttribute>,
    ) -> Result<(), anyhow::Error> {
        let chat_mutex = self
            .chat_locks
            .entry(to.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _chat_guard = chat_mutex.lock().await;

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
                message.as_ref(),
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

            let _ = self
                .add_recent_message(to.clone(), request_id.clone(), Arc::clone(&message))
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

            match wacore::send::prepare_group_stanza(
                &mut stores,
                self,
                &mut group_info,
                &own_jid,
                &own_lid,
                account_info.as_ref(),
                to.clone(),
                message.as_ref(),
                request_id.clone(),
                force_skdm,
                edit.clone(),
            )
            .await
            {
                Ok(stanza) => stanza,
                Err(e) => {
                    if let Some(SignalProtocolError::NoSenderKeyState(_)) =
                        e.downcast_ref::<SignalProtocolError>()
                    {
                        log::warn!("No sender key for group {}, forcing distribution.", to);

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
                            message.as_ref(),
                            request_id,
                            true, // Force distribution on retry
                            edit.clone(),
                        )
                        .await?
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            let _ = self
                .add_recent_message(to.clone(), request_id.clone(), Arc::clone(&message))
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
                message.as_ref(),
                request_id,
                edit,
            )
            .await?
        };
        self.send_node(stanza_to_send).await.map_err(|e| e.into())
    }
}
