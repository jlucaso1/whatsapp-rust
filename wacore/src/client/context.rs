use crate::libsignal::protocol::PreKeyBundle;
use crate::types::message::AddressingMode;
use async_trait::async_trait;
use std::collections::HashMap;
use wacore_binary::jid::Jid;

#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub participants: Vec<Jid>,
    pub addressing_mode: AddressingMode,
    /// Maps a LID user identifier (the `user` part of the LID JID) to the
    /// corresponding phone-number JID. This is used for device queries since
    /// LID usync requests may not work reliably.
    lid_to_pn_map: HashMap<String, Jid>,
}

impl GroupInfo {
    /// Create a [`GroupInfo`] with the provided participants and addressing mode.
    ///
    /// The LID-to-phone mapping defaults to empty. Call
    /// [`GroupInfo::set_lid_to_pn_map`] or [`GroupInfo::with_lid_to_pn_map`] to
    /// populate it when a mapping is available.
    pub fn new(participants: Vec<Jid>, addressing_mode: AddressingMode) -> Self {
        Self {
            participants,
            addressing_mode,
            lid_to_pn_map: HashMap::new(),
        }
    }

    /// Create a [`GroupInfo`] and populate the LID-to-phone mapping.
    pub fn with_lid_to_pn_map(
        participants: Vec<Jid>,
        addressing_mode: AddressingMode,
        lid_to_pn_map: HashMap<String, Jid>,
    ) -> Self {
        Self {
            participants,
            addressing_mode,
            lid_to_pn_map,
        }
    }

    /// Replace the current LID-to-phone mapping.
    pub fn set_lid_to_pn_map(&mut self, lid_to_pn_map: HashMap<String, Jid>) {
        self.lid_to_pn_map = lid_to_pn_map;
    }

    /// Access the LID-to-phone mapping.
    pub fn lid_to_pn_map(&self) -> &HashMap<String, Jid> {
        &self.lid_to_pn_map
    }

    /// Look up the mapped phone-number JID for a given LID user identifier.
    pub fn phone_jid_for_lid_user(&self, lid_user: &str) -> Option<&Jid> {
        self.lid_to_pn_map.get(lid_user)
    }
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
