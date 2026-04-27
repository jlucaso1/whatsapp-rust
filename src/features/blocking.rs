//! Blocking feature for managing blocked contacts.
//!
//! This module provides high-level APIs for blocking and unblocking contacts.
//! Protocol-level types are defined in `wacore::iq::blocklist`.

use crate::client::Client;
use crate::request::IqError;
use log::debug;
pub use wacore::iq::blocklist::BlocklistEntry;
use wacore::iq::blocklist::{GetBlocklistSpec, UpdateBlocklistSpec};
use wacore_binary::Jid;

/// Feature handle for blocklist operations.
pub struct Blocking<'a> {
    client: &'a Client,
}

impl<'a> Blocking<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Resolve `bare` (LID or PN) into the `(lid, pn)` pair the server expects
    /// on blocklist stanzas. Errors stay generic to avoid leaking user IDs.
    async fn resolve_lid_pn(&self, bare: Jid) -> Result<(Jid, Jid), IqError> {
        if bare.is_lid() {
            let entry = self
                .client
                .get_lid_pn_entry(&bare)
                .await
                .map_err(|_| IqError::ServerError {
                    code: 0,
                    text: "blocklist: LID↔PN lookup failed".to_string(),
                })?
                .ok_or(IqError::ServerError {
                    code: 0,
                    text: "blocklist: no LID↔PN mapping for provided jid".to_string(),
                })?;
            Ok((bare, Jid::pn(entry.phone_number)))
        } else if bare.is_pn() {
            let entry = self
                .client
                .get_lid_pn_entry(&bare)
                .await
                .map_err(|_| IqError::ServerError {
                    code: 0,
                    text: "blocklist: LID↔PN lookup failed".to_string(),
                })?
                .ok_or(IqError::ServerError {
                    code: 0,
                    text: "blocklist: no LID↔PN mapping for provided jid".to_string(),
                })?;
            Ok((Jid::lid(entry.lid), bare))
        } else {
            Err(IqError::ServerError {
                code: 0,
                text: "blocklist: jid is neither PN nor LID".to_string(),
            })
        }
    }

    /// Block a contact. Accepts either LID or PN; the wire stanza always
    /// carries both (`jid=LID, pn_jid=PN`) — modern WA rejects PN-only blocks.
    pub async fn block(&self, jid: &Jid) -> Result<(), IqError> {
        debug!(target: "Blocking", "Blocking contact");
        let (lid_jid, pn_jid) = self.resolve_lid_pn(jid.to_non_ad()).await?;
        self.client
            .execute(UpdateBlocklistSpec::block_with_pn(&lid_jid, &pn_jid))
            .await?;
        debug!(target: "Blocking", "Successfully blocked contact");
        Ok(())
    }

    /// Unblock a contact. Stanza only needs the LID, but PN input is accepted
    /// and resolved through the mapping.
    pub async fn unblock(&self, jid: &Jid) -> Result<(), IqError> {
        debug!(target: "Blocking", "Unblocking contact");
        let (lid_jid, _) = self.resolve_lid_pn(jid.to_non_ad()).await?;
        self.client
            .execute(UpdateBlocklistSpec::unblock(&lid_jid))
            .await?;
        debug!(target: "Blocking", "Successfully unblocked contact");
        Ok(())
    }

    /// Get the full blocklist.
    pub async fn get_blocklist(&self) -> anyhow::Result<Vec<BlocklistEntry>> {
        debug!(target: "Blocking", "Fetching blocklist...");
        let entries = self.client.execute(GetBlocklistSpec).await?;
        debug!(target: "Blocking", "Fetched {} blocked contacts", entries.len());
        Ok(entries)
    }

    /// Check if a contact is blocked.
    ///
    /// Compares only the user part of the JID, ignoring device ID,
    /// since blocking applies to the entire user account, not individual devices.
    pub async fn is_blocked(&self, jid: &Jid) -> anyhow::Result<bool> {
        let blocklist = self.get_blocklist().await?;
        Ok(blocklist.iter().any(|e| e.jid.user == jid.user))
    }
}

impl Client {
    /// Access blocking operations.
    pub fn blocking(&self) -> Blocking<'_> {
        Blocking::new(self)
    }
}
