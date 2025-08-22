use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use anyhow::anyhow;
use std::sync::Arc;
use wacore::libsignal::protocol::SignalProtocolError;
use wacore::{signal::store::GroupSenderKeyStore, types::jid::JidExt};
use wacore_binary::jid::{Jid, JidExt as _};
use waproto::whatsapp as wa;

impl Client {
    pub async fn send_message(&self, to: Jid, message: wa::Message) -> Result<(), anyhow::Error> {
        let request_id = self.generate_message_id().await;
        self.send_message_impl(to, Arc::new(message), request_id, false, false)
            .await
    }

    pub(crate) async fn send_message_impl(
        &self,
        to: Jid,
        message: Arc<wa::Message>,
        request_id: String,
        peer: bool,
        force_key_distribution: bool,
    ) -> Result<(), anyhow::Error> {
        let chat_mutex = self
            .chat_locks
            .entry(to.clone())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone();
        let _chat_guard = chat_mutex.lock().await;

        let stanza_to_send = if peer {
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

            self.add_recent_message(to.clone(), request_id.clone(), Arc::clone(&message))
                .await;

            let device_store_arc = self.persistence_manager.get_device_arc().await;

            let (own_sending_jid, _) = match group_info.addressing_mode {
                crate::types::message::AddressingMode::Lid => (own_lid.clone(), "lid"),
                crate::types::message::AddressingMode::Pn => (own_jid.clone(), "pn"),
            };

            let force_skdm = {
                let device_guard = device_store_arc.read().await;
                let sender_address = own_sending_jid.to_protocol_address();

                let key_exists = device_guard
                    .load_sender_key(&to, &sender_address)
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
            )
            .await
            {
                Ok(stanza) => stanza,
                Err(e) => {
                    if let Some(SignalProtocolError::NoSenderKeyState) =
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
                        )
                        .await?
                    } else {
                        return Err(e);
                    }
                }
            }
        } else {
            self.add_recent_message(to.clone(), request_id.clone(), Arc::clone(&message))
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
            )
            .await?
        };

        self.send_node(stanza_to_send).await.map_err(|e| e.into())
    }
}
