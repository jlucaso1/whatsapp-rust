//! Blocking feature for managing blocked contacts.
//!
//! This module provides high-level APIs for blocking and unblocking contacts.
//! Protocol-level types are defined in `wacore::iq::blocklist`.

use crate::client::Client;
use crate::request::IqError;
use log::debug;
pub use wacore::iq::blocklist::BlocklistEntry;
use wacore::iq::blocklist::{GetBlocklistSpec, UpdateBlocklistSpec};
use wacore_binary::jid::Jid;

/// Feature handle for blocklist operations.
pub struct Blocking<'a> {
    client: &'a Client,
}

impl<'a> Blocking<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    /// Block a contact.
    pub async fn block(&self, jid: &Jid) -> Result<(), IqError> {
        debug!(target: "Blocking", "Blocking contact: {}", jid);
        self.client.execute(UpdateBlocklistSpec::block(jid)).await?;
        debug!(target: "Blocking", "Successfully blocked contact: {}", jid);
        Ok(())
    }

    /// Unblock a contact.
    pub async fn unblock(&self, jid: &Jid) -> Result<(), IqError> {
        debug!(target: "Blocking", "Unblocking contact: {}", jid);
        self.client
            .execute(UpdateBlocklistSpec::unblock(jid))
            .await?;
        debug!(target: "Blocking", "Successfully unblocked contact: {}", jid);
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
