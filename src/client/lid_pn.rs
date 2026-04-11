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

        // If this is a new LID mapping, migrate any existing PN-keyed entries to LID
        if is_new_mapping {
            self.migrate_device_registry_on_lid_discovery(phone_number, lid)
                .await;
            self.migrate_signal_sessions_on_lid_discovery(phone_number, lid)
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
                    user: lid_user.into(),
                    server: wacore_binary::jid::cow_server_from_str(lid_server),
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

    /// Migrate Signal sessions and identity keys from PN to LID address.
    ///
    /// All reads/writes go through `signal_cache` to avoid reading stale data
    /// from the backend when the cache has unflushed mutations (e.g., after
    /// SKDM encryption ratcheted the session).
    pub(crate) async fn migrate_signal_sessions_on_lid_discovery(&self, pn: &str, lid: &str) {
        use log::{info, warn};
        use wacore::types::jid::JidExt;

        let backend = self.persistence_manager.backend();

        for device_id in 0..=99u16 {
            let pn_jid = Jid::pn_device(pn.to_string(), device_id);
            let lid_jid = Jid::lid_device(lid.to_string(), device_id);

            let pn_proto = pn_jid.to_protocol_address();
            let lid_proto = lid_jid.to_protocol_address();

            // Migrate session: read from cache (authoritative), write to cache
            if let Ok(Some(session)) = self
                .signal_cache
                .get_session(&pn_proto, backend.as_ref())
                .await
            {
                if self
                    .signal_cache
                    .get_session(&lid_proto, backend.as_ref())
                    .await
                    .ok()
                    .flatten()
                    .is_some()
                {
                    self.signal_cache.delete_session(&pn_proto).await;
                    info!("Deleted stale PN session {} (LID exists)", pn_proto);
                } else {
                    self.signal_cache.put_session(&lid_proto, session).await;
                    self.signal_cache.delete_session(&pn_proto).await;
                    info!("Migrated session {} -> {}", pn_proto, lid_proto);
                }
            }

            // Migrate identity: same cache-first pattern
            if let Ok(Some(identity_data)) = self
                .signal_cache
                .get_identity(&pn_proto, backend.as_ref())
                .await
            {
                if self
                    .signal_cache
                    .get_identity(&lid_proto, backend.as_ref())
                    .await
                    .ok()
                    .flatten()
                    .is_none()
                {
                    self.signal_cache
                        .put_identity(&lid_proto, &identity_data)
                        .await;
                    info!("Migrated identity {} -> {}", pn_proto, lid_proto);
                }
                self.signal_cache.delete_identity(&pn_proto).await;
            }
        }

        // Flush migrated state to backend so it survives restarts
        if let Err(e) = self.signal_cache.flush(backend.as_ref()).await {
            warn!("Failed to flush signal cache after migration: {e:?}");
        }
    }

    /// Look up the LID↔phone mapping for a JID.
    ///
    /// Routes automatically: LID JIDs search by LID, PN JIDs search by phone.
    /// Returns `None` for non-user JIDs (groups, newsletters, etc.).
    pub async fn get_lid_pn_entry(&self, jid: &Jid) -> Option<LidPnEntry> {
        if jid.is_lid() {
            self.lid_pn_cache.get_entry_by_lid(&jid.user).await
        } else if jid.is_pn() {
            self.lid_pn_cache.get_entry_by_phone(&jid.user).await
        } else {
            None
        }
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

    #[tokio::test]
    async fn test_get_lid_pn_entry_from_pn() {
        let client: Arc<Client> = create_test_client().await;
        let pn = "55999999999";
        let lid = "100000012345678";

        assert!(client.get_lid_pn_entry(&Jid::pn(pn)).await.is_none());

        client
            .add_lid_pn_mapping(lid, pn, LearningSource::Usync)
            .await
            .unwrap();

        let entry = client.get_lid_pn_entry(&Jid::pn(pn)).await.unwrap();
        assert_eq!(entry.lid, lid);
        assert_eq!(entry.phone_number, pn);
    }

    #[tokio::test]
    async fn test_get_lid_pn_entry_from_lid() {
        let client: Arc<Client> = create_test_client().await;
        let pn = "55999999999";
        let lid = "100000012345678";

        assert!(client.get_lid_pn_entry(&Jid::lid(lid)).await.is_none());

        client
            .add_lid_pn_mapping(lid, pn, LearningSource::Usync)
            .await
            .unwrap();

        let entry = client.get_lid_pn_entry(&Jid::lid(lid)).await.unwrap();
        assert_eq!(entry.lid, lid);
        assert_eq!(entry.phone_number, pn);
    }
}
