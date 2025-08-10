use crate::client::Client;
use crate::store::signal_adapter::SignalProtocolStoreAdapter;
use crate::types::jid::Jid;
use anyhow::anyhow;
use wacore::types::jid::JidExt;
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

            let mut device_guard = device_store_arc.lock().await;
            let mut store_adapter = SignalProtocolStoreAdapter::new(device_store_arc.clone());

            let mut stores = wacore::send::SignalStores {
                session_store: &mut store_adapter.session_store,
                identity_store: &mut store_adapter.identity_store,
                prekey_store: &mut store_adapter.pre_key_store,
                signed_prekey_store: &store_adapter.signed_pre_key_store,
                kyber_prekey_store: &mut store_adapter.kyber_pre_key_store,
            };

            wacore::send::prepare_group_stanza(
                &mut *device_guard,
                &mut stores,
                self,
                &own_jid,
                &own_lid,
                account_info.as_ref(),
                to,
                message,
                request_id,
            )
            .await?
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
