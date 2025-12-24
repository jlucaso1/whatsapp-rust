use crate::libsignal::protocol::PreKeyBundle;
use crate::types::message::AddressingMode;
use async_trait::async_trait;
use std::collections::HashMap;
use wacore_binary::jid::Jid;

fn build_pn_to_lid_map(lid_to_pn_map: &HashMap<String, Jid>) -> HashMap<String, Jid> {
    lid_to_pn_map
        .iter()
        .map(|(lid_user, phone_jid)| {
            let lid_jid = Jid::lid(lid_user);
            (phone_jid.user.clone(), lid_jid)
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub participants: Vec<Jid>,
    pub addressing_mode: AddressingMode,
    /// Maps a LID user identifier (the `user` part of the LID JID) to the
    /// corresponding phone-number JID. This is used for device queries since
    /// LID usync requests may not work reliably.
    lid_to_pn_map: HashMap<String, Jid>,
    /// Reverse mapping: phone number (user part) to LID JID.
    /// This is used to convert device JIDs back to LID format after device resolution.
    pn_to_lid_map: HashMap<String, Jid>,
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
            pn_to_lid_map: HashMap::new(),
        }
    }

    /// Create a [`GroupInfo`] and populate the LID-to-phone mapping.
    pub fn with_lid_to_pn_map(
        participants: Vec<Jid>,
        addressing_mode: AddressingMode,
        lid_to_pn_map: HashMap<String, Jid>,
    ) -> Self {
        let pn_to_lid_map = build_pn_to_lid_map(&lid_to_pn_map);

        Self {
            participants,
            addressing_mode,
            lid_to_pn_map,
            pn_to_lid_map,
        }
    }

    /// Replace the current LID-to-phone mapping.
    pub fn set_lid_to_pn_map(&mut self, lid_to_pn_map: HashMap<String, Jid>) {
        self.pn_to_lid_map = build_pn_to_lid_map(&lid_to_pn_map);
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

    /// Look up the mapped LID JID for a given phone number (user part).
    pub fn lid_jid_for_phone_user(&self, phone_user: &str) -> Option<&Jid> {
        self.pn_to_lid_map.get(phone_user)
    }

    /// Convert a phone-based device JID to a LID-based device JID using the mapping.
    /// If no mapping exists, returns the original JID unchanged.
    pub fn phone_device_jid_to_lid(&self, phone_device_jid: &Jid) -> Jid {
        if phone_device_jid.is_pn()
            && let Some(lid_base) = self.lid_jid_for_phone_user(&phone_device_jid.user)
        {
            return Jid::lid_device(&lid_base.user, phone_device_jid.device);
        }
        phone_device_jid.clone()
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

    /// Get the LID (Linked ID) for a phone number, if known.
    /// This is used to find existing sessions that were established under a LID address
    /// when sending to a phone number address.
    ///
    /// Returns None if no LID mapping is known for this phone number.
    async fn get_lid_for_phone(&self, phone_user: &str) -> Option<String> {
        // Default implementation returns None - subclasses can override
        let _ = phone_user;
        None
    }
}
