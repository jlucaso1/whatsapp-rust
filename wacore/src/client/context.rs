use crate::libsignal::protocol::PreKeyBundle;
use crate::types::message::AddressingMode;
use async_trait::async_trait;
use std::collections::HashMap;
use wacore_binary::jid::Jid;

#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub participants: Vec<Jid>,
    pub addressing_mode: AddressingMode,
    /// Maps LID JIDs to their corresponding phone number JIDs
    /// This is used for device queries since LID usync queries may not work
    pub lid_to_pn_map: HashMap<String, Jid>,
}

#[async_trait]
pub trait SendContextResolver: Send + Sync {
    async fn resolve_devices(&self, jids: &[Jid]) -> Result<Vec<Jid>, anyhow::Error>;

    async fn fetch_prekeys(
        &self,
        jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error>;

    async fn fetch_prekeys_for_identity_check(
        &self,
        jids: &[Jid],
    ) -> Result<HashMap<Jid, PreKeyBundle>, anyhow::Error>;

    async fn resolve_group_info(&self, jid: &Jid) -> Result<GroupInfo, anyhow::Error>;
}
