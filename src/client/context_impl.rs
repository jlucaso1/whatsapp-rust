use crate::client::Client;
use async_trait::async_trait;
use std::collections::HashMap;
use wacore::client::context::{GroupInfo, SendContextResolver};
use wacore::iq::prekeys::PreKeyFetchReason;
use wacore::libsignal::protocol::PreKeyBundle;
use wacore_binary::jid::Jid;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl SendContextResolver for Client {
    async fn resolve_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error> {
        self.get_user_devices(jids).await
    }

    async fn fetch_prekeys(
        &self,
        jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        self.fetch_pre_keys(jids, None).await
    }

    async fn fetch_prekeys_for_identity_check(
        &self,
        jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        self.fetch_pre_keys(jids, Some(PreKeyFetchReason::Identity))
            .await
            .map_err(|e| {
                // Re-wrap server errors as wacore::ServerErrorCode so
                // encrypt_for_devices can downcast across crate boundaries
                if let Some(crate::request::IqError::ServerError { code, text }) =
                    e.downcast_ref::<crate::request::IqError>()
                {
                    return anyhow::Error::new(wacore::request::ServerErrorCode {
                        code: *code,
                        text: text.clone(),
                    });
                }
                e
            })
    }

    async fn resolve_group_info(&self, jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
        self.groups().query_info(jid).await
    }

    async fn get_lid_for_phone(&self, phone_user: &str) -> Option<String> {
        self.lid_pn_cache.get_current_lid(phone_user).await
    }
}
