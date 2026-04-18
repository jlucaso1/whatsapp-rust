use crate::libsignal::protocol::PreKeyBundle;
use crate::types::message::AddressingMode;
use async_trait::async_trait;
use std::collections::HashMap;
use wacore_binary::CompactString;
use wacore_binary::Jid;

fn build_pn_to_lid_map(lid_to_pn_map: &HashMap<CompactString, Jid>) -> HashMap<CompactString, Jid> {
    lid_to_pn_map
        .iter()
        .map(|(lid_user, phone_jid)| {
            let lid_jid = Jid::lid(lid_user.clone());
            (phone_jid.user.clone(), lid_jid)
        })
        .collect()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct GroupInfo {
    pub participants: Vec<Jid>,
    pub addressing_mode: AddressingMode,
    /// Maps a LID user identifier (the `user` part of the LID JID) to the
    /// corresponding phone-number JID. This is used for device queries since
    /// LID usync requests may not work reliably.
    lid_to_pn_map: HashMap<CompactString, Jid>,
    /// Reverse mapping: phone number (user part) to LID JID.
    /// This is used to convert device JIDs back to LID format after device resolution.
    pn_to_lid_map: HashMap<CompactString, Jid>,
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
        lid_to_pn_map: HashMap<CompactString, Jid>,
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
    pub fn set_lid_to_pn_map(&mut self, lid_to_pn_map: HashMap<CompactString, Jid>) {
        self.pn_to_lid_map = build_pn_to_lid_map(&lid_to_pn_map);
        self.lid_to_pn_map = lid_to_pn_map;
    }

    /// Access the LID-to-phone mapping.
    pub fn lid_to_pn_map(&self) -> &HashMap<CompactString, Jid> {
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

    /// Append participants that are not already present.
    ///
    /// For LID-addressed groups, also updates the LID-to-PN and PN-to-LID maps
    /// using the `phone_number` field from each participant.  Maps are updated
    /// even for already-present participants so that a later call with
    /// `Some(phone_number)` backfills a previous `None` entry.
    pub fn add_participants<'a, I>(&mut self, new: I)
    where
        I: IntoIterator<Item = (&'a Jid, Option<&'a Jid>)>,
    {
        for (jid, phone_number) in new {
            // Always backfill LID maps — a re-add with phone_number fills a
            // previous None (e.g., client-initiated add followed by server
            // notification that carries the phone number).
            if self.addressing_mode == AddressingMode::Lid
                && let Some(pn) = phone_number
            {
                self.pn_to_lid_map
                    .insert(pn.user.clone(), Jid::lid(jid.user.clone()));
                self.lid_to_pn_map.insert(jid.user.clone(), pn.clone());
            }

            if self.participants.iter().any(|p| p.user == jid.user) {
                continue;
            }
            self.participants.push(jid.clone());
        }
    }

    /// Remove participants whose user part is in `users_to_remove`.
    ///
    /// Also cleans up the LID-to-PN and PN-to-LID maps.
    pub fn remove_participants(&mut self, users_to_remove: &[&str]) {
        self.participants
            .retain(|p| !users_to_remove.iter().any(|u| *u == p.user));
        for user in users_to_remove {
            if let Some(pn_jid) = self.lid_to_pn_map.remove(*user) {
                self.pn_to_lid_map.remove(&pn_jid.user);
            }
            // Also try reverse: user might be a PN
            if let Some(lid_jid) = self.pn_to_lid_map.remove(*user) {
                self.lid_to_pn_map.remove(&lid_jid.user);
            }
        }
    }

    /// Convert a phone-based device JID to a LID-based device JID using the mapping.
    /// If no mapping exists, returns the original JID unchanged.
    pub fn phone_device_jid_to_lid(&self, phone_device_jid: &Jid) -> Jid {
        if phone_device_jid.is_pn()
            && let Some(lid_base) = self.lid_jid_for_phone_user(&phone_device_jid.user)
        {
            return Jid::lid_device(lid_base.user.clone(), phone_device_jid.device);
        }
        phone_device_jid.clone()
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pn(user: &str) -> Jid {
        Jid::pn(user)
    }
    fn lid(user: &str) -> Jid {
        Jid::lid(user)
    }

    #[test]
    fn add_participants_pn_mode() {
        let mut info = GroupInfo::new(vec![pn("alice")], AddressingMode::Pn);
        let bob = pn("bob");
        let carol = pn("carol");
        info.add_participants([(&bob, None), (&carol, None)]);
        assert_eq!(info.participants.len(), 3);
        assert!(info.participants.iter().any(|p| p.user == "bob"));
    }

    #[test]
    fn add_participants_deduplicates() {
        let mut info = GroupInfo::new(vec![pn("alice"), pn("bob")], AddressingMode::Pn);
        let bob = pn("bob");
        let carol = pn("carol");
        info.add_participants([(&bob, None), (&carol, None)]);
        assert_eq!(info.participants.len(), 3); // bob not duplicated
    }

    #[test]
    fn add_participants_lid_mode_updates_maps() {
        let mut info = GroupInfo::new(vec![lid("lid_alice")], AddressingMode::Lid);
        let bob_lid = lid("lid_bob");
        let bob_pn = pn("bob_pn");
        info.add_participants([(&bob_lid, Some(&bob_pn))]);

        assert_eq!(info.participants.len(), 2);
        assert_eq!(
            info.phone_jid_for_lid_user("lid_bob")
                .map(|j| j.user.as_str()),
            Some("bob_pn")
        );
        assert_eq!(
            info.lid_jid_for_phone_user("bob_pn")
                .map(|j| j.user.as_str()),
            Some("lid_bob")
        );
    }

    #[test]
    fn remove_participants_basic() {
        let mut info = GroupInfo::new(
            vec![pn("alice"), pn("bob"), pn("carol")],
            AddressingMode::Pn,
        );
        info.remove_participants(&["bob"]);
        assert_eq!(info.participants.len(), 2);
        assert!(!info.participants.iter().any(|p| p.user == "bob"));
    }

    #[test]
    fn remove_participants_cleans_lid_maps() {
        let lid_to_pn = HashMap::from([
            (CompactString::from("lid_alice"), pn("alice_pn")),
            (CompactString::from("lid_bob"), pn("bob_pn")),
        ]);
        let mut info = GroupInfo::with_lid_to_pn_map(
            vec![lid("lid_alice"), lid("lid_bob")],
            AddressingMode::Lid,
            lid_to_pn,
        );

        assert!(info.phone_jid_for_lid_user("lid_bob").is_some());
        assert!(info.lid_jid_for_phone_user("bob_pn").is_some());

        info.remove_participants(&["lid_bob"]);

        assert_eq!(info.participants.len(), 1);
        assert!(info.phone_jid_for_lid_user("lid_bob").is_none());
        assert!(info.lid_jid_for_phone_user("bob_pn").is_none());
        assert!(info.phone_jid_for_lid_user("lid_alice").is_some());
    }

    #[test]
    fn remove_nonexistent_is_noop() {
        let mut info = GroupInfo::new(vec![pn("alice")], AddressingMode::Pn);
        info.remove_participants(&["nobody"]);
        assert_eq!(info.participants.len(), 1);
    }

    #[test]
    fn add_participants_backfills_lid_map_for_existing() {
        let mut info = GroupInfo::new(vec![lid("lid_bob")], AddressingMode::Lid);
        // First add without phone_number (simulates client-initiated add)
        let bob_lid = lid("lid_bob");
        let bob_pn = pn("bob_pn");
        info.add_participants([(&bob_lid, None)]);
        assert!(info.phone_jid_for_lid_user("lid_bob").is_none());

        // Second add with phone_number (simulates server notification backfill)
        info.add_participants([(&bob_lid, Some(&bob_pn))]);
        assert_eq!(info.participants.len(), 1); // not duplicated
        assert_eq!(
            info.phone_jid_for_lid_user("lid_bob")
                .map(|j| j.user.as_str()),
            Some("bob_pn")
        );
        assert_eq!(
            info.lid_jid_for_phone_user("bob_pn")
                .map(|j| j.user.as_str()),
            Some("lid_bob")
        );
    }
}
