//! LID-PN (Linked ID to Phone Number) mapping methods for Client.
//!
//! This module contains methods for managing the bidirectional mapping
//! between LIDs (Linked IDs) and phone numbers.
//!
//! Key features:
//! - Cache warm-up from persistent storage
//! - Adding new LID-PN mappings with automatic migration
//! - Resolving JIDs to their LID equivalents
//! - Bidirectional lookup (LID to PN and PN to LID)

use anyhow::Result;
use log::debug;
use wacore_binary::jid::Jid;

use super::Client;
use crate::lid_pn_cache::{LearningSource, LidPnEntry};

impl Client {
    /// Warm up the LID-PN cache from persistent storage.
    /// This is called during client initialization to populate the in-memory cache
    /// with previously learned LID-PN mappings.
    pub(crate) async fn warm_up_lid_pn_cache(&self) -> Result<(), anyhow::Error> {
        let backend = self.persistence_manager.backend();
        let entries = backend.get_all_lid_mappings().await?;

        if entries.is_empty() {
            debug!("LID-PN cache warm-up: no entries found in storage");
            return Ok(());
        }

        let cache_entries: Vec<LidPnEntry> = entries
            .into_iter()
            .map(|e| {
                LidPnEntry::with_timestamp(
                    e.lid,
                    e.phone_number,
                    e.created_at,
                    LearningSource::parse(&e.learning_source),
                )
            })
            .collect();

        self.lid_pn_cache.warm_up(cache_entries).await;
        Ok(())
    }

    /// Add a LID-PN mapping to both the in-memory cache and persistent storage.
    /// This is called when we learn about a mapping from messages, usync, etc.
    /// Also migrates any existing PN-keyed device registry entries to LID.
    pub(crate) async fn add_lid_pn_mapping(
        &self,
        lid: &str,
        phone_number: &str,
        source: LearningSource,
    ) -> Result<()> {
        use anyhow::anyhow;
        use wacore::store::traits::LidPnMappingEntry;

        // Check if this is a new mapping (not just an update)
        let is_new_mapping = self
            .lid_pn_cache
            .get_current_lid(phone_number)
            .await
            .is_none();

        // Add to in-memory cache
        let entry = LidPnEntry::new(lid.to_string(), phone_number.to_string(), source);
        self.lid_pn_cache.add(entry.clone()).await;

        // Persist to storage
        let backend = self.persistence_manager.backend();
        let storage_entry = LidPnMappingEntry {
            lid: entry.lid,
            phone_number: entry.phone_number,
            created_at: entry.created_at,
            updated_at: entry.created_at,
            learning_source: entry.learning_source.as_str().to_string(),
        };

        backend
            .put_lid_mapping(&storage_entry)
            .await
            .map_err(|e| anyhow!("persisting LID-PN mapping: {e}"))?;

        // If this is a new LID mapping, migrate any existing PN-keyed device registry entries
        if is_new_mapping {
            self.migrate_device_registry_on_lid_discovery(phone_number, lid)
                .await;
        }

        Ok(())
    }

    /// Ensure phone-to-LID mappings are resolved for the given JIDs.
    /// Matches WhatsApp Web's WAWebManagePhoneNumberMappingJob.ensurePhoneNumberToLidMapping().
    /// Should be called before establishing new E2E sessions to avoid duplicate sessions.
    ///
    /// This checks the local cache for existing mappings. For JIDs without cached mappings,
    /// the caller should consider fetching them via usync query if establishing sessions.
    pub(crate) async fn resolve_lid_mappings(&self, jids: &[Jid]) -> Vec<Jid> {
        let mut resolved = Vec::with_capacity(jids.len());

        for jid in jids {
            // Only resolve for user JIDs (not groups, status, etc.)
            if !jid.is_pn() && !jid.is_lid() {
                resolved.push(jid.clone());
                continue;
            }

            // If it's already a LID, use as-is
            if jid.is_lid() {
                resolved.push(jid.clone());
                continue;
            }

            // Try to resolve PN to LID from cache
            if let Some(lid_user) = self.lid_pn_cache.get_current_lid(&jid.user).await {
                resolved.push(Jid::lid_device(lid_user, jid.device));
            } else {
                // No cached mapping — use original JID. Mapping will be learned
                // organically from incoming messages or usync responses.
                resolved.push(jid.clone());
            }
        }

        resolved
    }

    /// Resolve the encryption JID for a given target JID.
    /// This uses the same logic as the receiving path to ensure consistent
    /// lock keys between sending and receiving.
    ///
    /// For PN JIDs, this checks if a LID mapping exists and returns the LID.
    /// This ensures that sending and receiving use the same session lock.
    pub(crate) async fn resolve_encryption_jid(&self, target: &Jid) -> Jid {
        let pn_server = wacore_binary::jid::DEFAULT_USER_SERVER;
        let lid_server = wacore_binary::jid::HIDDEN_USER_SERVER;

        if target.server == lid_server {
            // Already a LID - use it directly
            target.clone()
        } else if target.server == pn_server {
            // PN JID - check if we have a LID mapping
            if let Some(lid_user) = self.lid_pn_cache.get_current_lid(&target.user).await {
                let lid_jid = Jid {
                    user: lid_user,
                    server: lid_server.to_string(),
                    device: target.device,
                    agent: target.agent,
                    integrator: target.integrator,
                };
                debug!(
                    "[SEND-LOCK] Resolved {} to LID {} for session lock",
                    target, lid_jid
                );
                lid_jid
            } else {
                // No LID mapping - use PN as-is
                debug!("[SEND-LOCK] No LID mapping for {}, using PN", target);
                target.clone()
            }
        } else {
            // Other server type - use as-is
            target.clone()
        }
    }

    /// Get the phone number (user part) for a given LID.
    /// Looks up the LID-PN mapping from the in-memory cache.
    ///
    /// # Arguments
    ///
    /// * `lid` - The LID user part (e.g., "100000012345678") or full JID (e.g., "100000012345678@lid")
    ///
    /// # Returns
    ///
    /// The phone number user part if a mapping exists, None otherwise.
    pub async fn get_phone_number_from_lid(&self, lid: &str) -> Option<String> {
        // Handle both full JID (e.g., "100000012345678@lid") and user part only
        let lid_user = if lid.contains('@') {
            lid.split('@').next().unwrap_or(lid)
        } else {
            lid
        };
        self.lid_pn_cache.get_phone_number(lid_user).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lid_pn_cache::LearningSource;
    use crate::test_utils::create_test_client;
    use std::sync::Arc;
    use wacore_binary::jid::HIDDEN_USER_SERVER;

    #[tokio::test]
    async fn test_resolve_encryption_jid_pn_to_lid() {
        let client: Arc<Client> = create_test_client().await;
        let pn = "55999999999";
        let lid = "100000012345678";

        // Add mapping to cache
        client
            .add_lid_pn_mapping(lid, pn, LearningSource::PeerPnMessage)
            .await
            .unwrap();

        let pn_jid = Jid::pn(pn);
        let resolved = client.resolve_encryption_jid(&pn_jid).await;

        assert_eq!(resolved.user, lid);
        assert_eq!(resolved.server, HIDDEN_USER_SERVER);
    }

    #[tokio::test]
    async fn test_resolve_encryption_jid_preserves_lid() {
        let client: Arc<Client> = create_test_client().await;
        let lid = "100000012345678";
        let lid_jid = Jid::lid(lid);

        let resolved = client.resolve_encryption_jid(&lid_jid).await;

        assert_eq!(resolved, lid_jid);
    }

    #[tokio::test]
    async fn test_resolve_encryption_jid_no_mapping_returns_pn() {
        let client: Arc<Client> = create_test_client().await;
        let pn = "55999999999";
        let pn_jid = Jid::pn(pn);

        let resolved = client.resolve_encryption_jid(&pn_jid).await;

        assert_eq!(resolved, pn_jid);
    }
}
