use crate::client::Client;
use async_trait::async_trait;
use wacore::libsignal::protocol::PreKeyBundle;
use std::collections::HashMap;
use wacore::{
    client::context::{GroupInfo, SendContextResolver},
    types::jid::Jid,
};

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
        self.fetch_pre_keys(jids, Some("identity")).await // Pass "identity" for group setup
    }

    async fn resolve_group_info(&self, jid: &Jid) -> Result<GroupInfo, anyhow::Error> {
        self.query_group_info(jid).await
    }
}
