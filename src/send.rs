use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::jid::Jid;
use anyhow::anyhow;
use libsignal_protocol::{ProtocolAddress, SignalProtocolError};
use wacore::{signal::sender_key_name::SenderKeyName, types::jid::JidExt};
use waproto::whatsapp as wa;

impl Client {
    pub async fn send_text_message(&self, to: Jid, text: &str) -> Result<(), anyhow::Error> {
        let content = wa::Message {
            conversation: Some(text.to_string()),
            ..Default::default()
        };
        let request_id = self.generate_message_id().await;
        self.send_message_impl(to, content, request_id, false).await
    }

    pub async fn send_message_impl(
        &self,
        to: Jid,
        message: wa::Message,
        request_id: String,
        peer: bool,
    ) -> Result<(), anyhow::Error> {
        let stanza_to_send = if peer {
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
            self.add_recent_message(to.clone(), request_id.clone(), message.clone())
                .await;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_jid = device_snapshot
                .id
                .clone()
                .ok_or_else(|| anyhow!("Not logged in"))?;
            let own_lid = device_snapshot
                .lid
                .clone()
                .ok_or_else(|| anyhow!("LID not set, cannot send to group"))?;
            let account_info = device_snapshot.account.clone();

            let device_store_arc = self.persistence_manager.get_device_arc().await;

            let group_info = self.query_group_info(&to).await?;
            let (own_sending_jid, _) = match group_info.addressing_mode {
                crate::types::message::AddressingMode::Lid => (own_lid.clone(), "lid"),
                crate::types::message::AddressingMode::Pn => (own_jid.clone(), "pn"),
            };

            let force_skdm = {
                let mut device_guard = device_store_arc.lock().await;
                let sender_address = ProtocolAddress::new(
                    own_sending_jid.user.clone(),
                    u32::from(own_sending_jid.device).into(),
                );
                let sender_key_name =
                    SenderKeyName::new(to.to_string(), sender_address.to_string());

                let group_sender_address = libsignal_protocol::ProtocolAddress::new(
                    format!(
                        "{}\n{}",
                        sender_key_name.group_id(),
                        sender_key_name.sender_id()
                    ),
                    0.into(),
                );

                let store_ref: &mut (dyn libsignal_protocol::SenderKeyStore + Send + Sync) =
                    &mut *device_guard;
                store_ref
                    .load_sender_key(&group_sender_address)
                    .await?
                    .is_none()
            };

            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc.clone());

            let mut stores = wacore::send::SignalStores {
                session_store: &mut store_adapter.session_store,
                identity_store: &mut store_adapter.identity_store,
                prekey_store: &mut store_adapter.pre_key_store,
                signed_prekey_store: &store_adapter.signed_pre_key_store,
                kyber_prekey_store: &mut store_adapter.kyber_pre_key_store,
                sender_key_store: &mut store_adapter.sender_key_store,
            };

            match wacore::send::prepare_group_stanza(
                &mut stores,
                self,
                &own_jid,
                &own_lid,
                account_info.as_ref(),
                to.clone(),
                message.clone(),
                request_id.clone(),
                force_skdm,
            )
            .await
            {
                Ok(stanza) => stanza,
                Err(e) => {
                    // If encryption fails because the key is missing, force a distribution.
                    if let Some(SignalProtocolError::NoSenderKeyState) =
                        e.downcast_ref::<SignalProtocolError>()
                    {
                        log::warn!("No sender key for group {}, forcing distribution.", to);

                        // Re-create the store adapter to ensure state is fresh
                        let mut store_adapter_retry =
                            SignalProtocolStoreAdapter::new(device_store_arc.clone());
                        let mut stores_retry = wacore::send::SignalStores {
                            session_store: &mut store_adapter_retry.session_store,
                            identity_store: &mut store_adapter_retry.identity_store,
                            prekey_store: &mut store_adapter_retry.pre_key_store,
                            signed_prekey_store: &store_adapter_retry.signed_pre_key_store,
                            kyber_prekey_store: &mut store_adapter_retry.kyber_pre_key_store,
                            sender_key_store: &mut store_adapter_retry.sender_key_store,
                        };

                        wacore::send::prepare_group_stanza(
                            &mut stores_retry,
                            self,
                            &own_jid,
                            &own_lid,
                            account_info.as_ref(),
                            to,
                            message,
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
            self.add_recent_message(to.clone(), request_id.clone(), message.clone())
                .await;

            let device_snapshot = self.persistence_manager.get_device_snapshot().await;
            let own_jid = device_snapshot
                .id
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
                kyber_prekey_store: &mut store_adapter.kyber_pre_key_store,
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
            )
            .await?
        };

        self.send_node(stanza_to_send).await.map_err(|e| e.into())
    }
}
