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

    /// Block a contact.
    ///
    /// Modern WA exige `jid=LID` + `pn_jid=PN` no stanza; sem `pn_jid` o
    /// servidor responde `400 bad-request`. Resolve o par via
    /// `get_lid_pn_entry` antes de enviar — aceita LID ou PN como input.
    pub async fn block(&self, jid: &Jid) -> Result<(), IqError> {
        debug!(target: "Blocking", "Blocking contact: {}", jid);
        let bare = jid.to_non_ad();
        let (lid_jid, pn_jid) = if bare.is_lid() {
            let entry = self
                .client
                .get_lid_pn_entry(&bare)
                .await
                .map_err(|e| IqError::ServerError {
                    code: 0,
                    text: format!("get_lid_pn_entry: {e}"),
                })?
                .ok_or(IqError::ServerError {
                    code: 0,
                    text: format!("no LID↔PN mapping for {bare}"),
                })?;
            (bare, Jid::pn(entry.phone_number))
        } else if bare.is_pn() {
            let entry = self
                .client
                .get_lid_pn_entry(&bare)
                .await
                .map_err(|e| IqError::ServerError {
                    code: 0,
                    text: format!("get_lid_pn_entry: {e}"),
                })?
                .ok_or(IqError::ServerError {
                    code: 0,
                    text: format!("no LID↔PN mapping for {bare}"),
                })?;
            (Jid::lid(entry.lid), bare)
        } else {
            return Err(IqError::ServerError {
                code: 0,
                text: format!("block: jid {bare} is neither PN nor LID"),
            });
        };
        self.client
            .execute(UpdateBlocklistSpec::block_with_pn(&lid_jid, &pn_jid))
            .await?;
        debug!(target: "Blocking", "Successfully blocked contact: lid={lid_jid} pn={pn_jid}");
        Ok(())
    }

    /// Unblock a contact.
    ///
    /// Modern WA exige `jid=LID` no `<item action="unblock"/>`. Resolve para
    /// LID via mapping se o input for PN.
    pub async fn unblock(&self, jid: &Jid) -> Result<(), IqError> {
        debug!(target: "Blocking", "Unblocking contact: {}", jid);
        let bare = jid.to_non_ad();
        let lid_jid = if bare.is_lid() {
            bare
        } else if bare.is_pn() {
            let entry = self
                .client
                .get_lid_pn_entry(&bare)
                .await
                .map_err(|e| IqError::ServerError {
                    code: 0,
                    text: format!("get_lid_pn_entry: {e}"),
                })?
                .ok_or(IqError::ServerError {
                    code: 0,
                    text: format!("no LID↔PN mapping for {bare}"),
                })?;
            Jid::lid(entry.lid)
        } else {
            return Err(IqError::ServerError {
                code: 0,
                text: format!("unblock: jid {bare} is neither PN nor LID"),
            });
        };
        self.client
            .execute(UpdateBlocklistSpec::unblock(&lid_jid))
            .await?;
        debug!(target: "Blocking", "Successfully unblocked contact: lid={lid_jid}");
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
