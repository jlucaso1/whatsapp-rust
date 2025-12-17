use crate::client::Client;
use async_trait::async_trait;
use std::collections::HashMap;
use wacore::client::context::{GroupInfo, SendContextResolver};
use wacore::libsignal::protocol::PreKeyBundle;
use wacore_binary::jid::Jid;

#[async_trait]
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
        self.fetch_pre_keys(jids, Some("identity")).await
    }

    async fn resolve_group_info(&self, jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
        self.groups().query_info(jid).await
    }

    async fn get_lid_for_phone(&self, phone_user: &str) -> Option<String> {
        self.lid_pn_cache.get_current_lid(phone_user).await
    }
}
