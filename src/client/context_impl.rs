use crate::client::Client;
use async_trait::async_trait;
use std::collections::HashMap;
use wacore::client::context::{GroupInfo, SendContextResolver};
use wacore::libsignal::protocol::PreKeyBundle;
use wacore::store::traits::LIDStore;
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
        self.query_group_info(jid).await
    }

    async fn resolve_encryption_jids(
        &self,
        pns: &[Jid],
    ) -> Result<std::collections::HashMap<Jid, Jid>, anyhow::Error> {
        if pns.is_empty() {
            return Ok(Default::default());
        }
        let store = self
            .persistence_manager
            .sqlite_store()
            .ok_or_else(|| anyhow::anyhow!("No sqlite store configured"))?;
        let map = store.get_many_lids_for_pns(pns).await?;
        Ok(map)
    }
}
