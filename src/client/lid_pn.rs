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

use std::sync::Arc;

use anyhow::Result;
use log::debug;
use wacore::store::traits::LidPnMappingEntry;
use wacore_binary::Jid;

use super::Client;
use crate::lid_pn_cache::{LearningSource, LidPnEntry};

/// Backend `LidPnMappingEntry` → in-memory `LidPnEntry`.
fn mapping_to_entry(m: LidPnMappingEntry) -> LidPnEntry {
    LidPnEntry::with_timestamp(
        m.lid,
        m.phone_number,
        m.created_at,
        LearningSource::parse(&m.learning_source),
    )
}

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

        self.lid_pn_cache
            .warm_up(entries.into_iter().map(mapping_to_entry))
            .await;
        Ok(())
    }

    /// Awaits the persist + any device/session migrations. Hot paths should
    /// prefer [`learn_lid_pn_mapping_fast`].
    pub(crate) async fn add_lid_pn_mapping(
        &self,
        lid: &str,
        phone_number: &str,
        source: LearningSource,
    ) -> Result<()> {
        let (entry, is_new_mapping) = self
            .record_lid_pn_in_memory(lid, phone_number, source)
            .await;
        self.persist_and_migrate_lid_pn(entry, is_new_mapping).await
    }

    /// Hot-path variant: cache is updated synchronously (so a subsequent
    /// `resolve_encryption_jid` sees the mapping), DB write + migrations run
    /// in a detached task. Matches WA Web's `warmUpLidPnMapping` + the
    /// deferred `lidPnCacheDirtySet` flush in `WAWebDBCreateLidPnMappings`.
    ///
    /// `is_offline` mirrors WA Web's `flushImmediately = msgInfo.offline == null`:
    /// offline replays only warm the in-memory cache, so a burst of queued
    /// messages on reconnect doesn't fan out one persist task per message.
    /// Offline mappings are re-learned from the next live message or usync.
    ///
    /// Durability: if the spawned persist task fails (DB error, shutdown
    /// mid-write), the mapping is only in-memory and will be lost on restart.
    /// Use [`add_lid_pn_mapping`] when the caller needs a durable guarantee.
    ///
    /// Concurrent calls for the same phone number may both observe
    /// `is_new_mapping = true` and each spawn a persist task. The downstream
    /// work tolerates this:
    /// - `put_lid_mapping` is an upsert
    /// - `migrate_device_registry_on_lid_discovery` no-ops after the PN-keyed
    ///   record is gone
    /// - `migrate_signal_sessions_on_lid_discovery` no-ops after the sessions
    ///   are migrated
    pub(crate) async fn learn_lid_pn_mapping_fast(
        self: &Arc<Self>,
        lid: &str,
        phone_number: &str,
        source: LearningSource,
        is_offline: bool,
    ) {
        let (entry, is_new_mapping) = self
            .record_lid_pn_in_memory(lid, phone_number, source)
            .await;
        if is_offline {
            return;
        }
        let client = Arc::clone(self);
        self.runtime
            .spawn(Box::pin(async move {
                if let Err(err) = client
                    .persist_and_migrate_lid_pn(entry, is_new_mapping)
                    .await
                {
                    log::warn!("Background LID-PN persist failed: {err}");
                }
            }))
            .detach();
    }

    /// Batched variant of [`learn_lid_pn_mapping_fast`]. Updates the in-memory
    /// cache synchronously for every entry, then fires one detached task that
    /// persists the whole batch in a single backend transaction and runs the
    /// device/session migrations for newly discovered PN↔LID pairs.
    ///
    /// Mirrors WA Web's `createLidPnMappings({ mappings, flushImmediately, learningSource })`
    /// call shape: one backend write for N participants instead of N detached
    /// tasks racing each other. The savings are linear in batch size and
    /// matter most on first `query_info` of large groups.
    ///
    /// `is_offline` mirrors the single-entry path: skip the persist task for
    /// offline replays; mappings are re-learned from the next live event.
    ///
    /// Takes owned `(lid, phone_number)` pairs; each `String` moves directly
    /// into the `LidPnEntry` stored in the cache, then (via `into_iter`) into
    /// the `LidPnMappingEntry` that's persisted — no clones on either step.
    /// The `Vec` itself is consumed, so no copy of the outer container either.
    pub(crate) async fn learn_lid_pn_mappings_batch(
        self: &Arc<Self>,
        mappings: Vec<(String, String)>,
        source: LearningSource,
        is_offline: bool,
    ) {
        if mappings.is_empty() {
            return;
        }
        let cap = mappings.len();
        let mut entries: Vec<LidPnEntry> = Vec::with_capacity(cap);
        let mut is_new_flags: Vec<bool> = Vec::with_capacity(cap);
        for (lid, phone_number) in mappings {
            let is_new = self
                .lid_pn_cache
                .get_current_lid(&phone_number)
                .await
                .is_none();
            let entry = LidPnEntry::new(lid, phone_number, source);
            self.lid_pn_cache.add(&entry).await;
            entries.push(entry);
            is_new_flags.push(is_new);
        }

        if is_offline {
            return;
        }

        let client = Arc::clone(self);
        self.runtime
            .spawn(Box::pin(async move {
                if let Err(err) = client
                    .persist_and_migrate_lid_pn_batch(entries, is_new_flags)
                    .await
                {
                    log::warn!("Background LID-PN batch persist failed: {err}");
                }
            }))
            .detach();
    }

    async fn record_lid_pn_in_memory(
        &self,
        lid: &str,
        phone_number: &str,
        source: LearningSource,
    ) -> (LidPnEntry, bool) {
        let is_new_mapping = self
            .lid_pn_cache
            .get_current_lid(phone_number)
            .await
            .is_none();
        let entry = LidPnEntry::new(lid.to_string(), phone_number.to_string(), source);
        self.lid_pn_cache.add(&entry).await;
        (entry, is_new_mapping)
    }

    async fn persist_and_migrate_lid_pn(
        &self,
        entry: LidPnEntry,
        is_new_mapping: bool,
    ) -> Result<()> {
        use anyhow::anyhow;

        let storage_entry = LidPnMappingEntry {
            lid: entry.lid,
            phone_number: entry.phone_number,
            created_at: entry.created_at,
            updated_at: entry.created_at,
            learning_source: entry.learning_source.as_str().to_string(),
        };

        self.persistence_manager
            .backend()
            .put_lid_mapping(&storage_entry)
            .await
            .map_err(|e| anyhow!("persisting LID-PN mapping: {e}"))?;

        if is_new_mapping {
            self.migrate_device_registry_on_lid_discovery(
                &storage_entry.phone_number,
                &storage_entry.lid,
            )
            .await;
            self.migrate_signal_sessions_on_lid_discovery(
                &storage_entry.phone_number,
                &storage_entry.lid,
            )
            .await;
        }

        Ok(())
    }

    async fn persist_and_migrate_lid_pn_batch(
        &self,
        entries: Vec<LidPnEntry>,
        is_new_flags: Vec<bool>,
    ) -> Result<()> {
        use anyhow::anyhow;

        // Consume entries so `lid`/`phone_number` move into storage rather
        // than being cloned. Only `learning_source` is allocated, and only
        // because `LidPnMappingEntry.learning_source` is a `String` field.
        let storage: Vec<LidPnMappingEntry> = entries
            .into_iter()
            .map(|entry| LidPnMappingEntry {
                lid: entry.lid,
                phone_number: entry.phone_number,
                created_at: entry.created_at,
                updated_at: entry.created_at,
                learning_source: entry.learning_source.as_str().to_string(),
            })
            .collect();

        self.persistence_manager
            .backend()
            .put_lid_mappings(&storage)
            .await
            .map_err(|e| anyhow!("persisting LID-PN mapping batch: {e}"))?;

        for (entry, is_new) in storage.iter().zip(is_new_flags.iter()) {
            if *is_new {
                self.migrate_device_registry_on_lid_discovery(&entry.phone_number, &entry.lid)
                    .await;
                self.migrate_signal_sessions_on_lid_discovery(&entry.phone_number, &entry.lid)
                    .await;
            }
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
        if target.is_lid() {
            // Already a LID - use it directly
            target.clone()
        } else if target.is_pn() {
            // PN JID - check if we have a LID mapping
            if let Some(lid_user) = self.lid_pn_cache.get_current_lid(&target.user).await {
                let lid_jid = Jid {
                    user: lid_user.into(),
                    server: wacore_binary::Server::Lid,
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

    /// Swap a JID's namespace between PN and LID, preserving device/agent/integrator.
    /// Returns `None` if no mapping exists or the JID is neither PN nor LID.
    pub(crate) async fn swap_pn_lid_namespace(&self, jid: &Jid) -> Option<Jid> {
        if jid.is_lid() {
            let pn_user = self.lid_pn_cache.get_phone_number(&jid.user).await?;
            Some(Jid {
                user: pn_user.into(),
                server: wacore_binary::Server::Pn,
                device: jid.device,
                agent: jid.agent,
                integrator: jid.integrator,
            })
        } else if jid.is_pn() {
            let lid_user = self.lid_pn_cache.get_current_lid(&jid.user).await?;
            Some(Jid {
                user: lid_user.into(),
                server: wacore_binary::Server::Lid,
                device: jid.device,
                agent: jid.agent,
                integrator: jid.integrator,
            })
        } else {
            None
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

            // Migrate session: take from cache (authoritative), write to cache
            if let Ok(Some(session)) = self
                .signal_cache
                .get_session(&pn_proto, backend.as_ref())
                .await
            {
                match self
                    .signal_cache
                    .has_session(&lid_proto, backend.as_ref())
                    .await
                {
                    Ok(true) => {
                        self.signal_cache.delete_session(&pn_proto).await;
                        info!("Deleted stale PN session {} (LID exists)", pn_proto);
                    }
                    Ok(false) => {
                        self.signal_cache.put_session(&lid_proto, session).await;
                        self.signal_cache.delete_session(&pn_proto).await;
                        info!("Migrated session {} -> {}", pn_proto, lid_proto);
                    }
                    Err(e) => {
                        // Restore the taken PN session to avoid losing it
                        self.signal_cache.put_session(&pn_proto, session).await;
                        log::warn!(
                            "Skipping session migration {} -> {}: {e}",
                            pn_proto,
                            lid_proto
                        );
                    }
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

    /// Look up the LID↔phone mapping for a JID. Cache-aside: falls back to
    /// the backend on cache miss so mappings survive cache eviction and any
    /// backend implementation gets the fallback without warm-up.
    ///
    /// Backend errors are propagated — callers can distinguish "no mapping"
    /// (`Ok(None)`) from "lookup failed" (`Err(_)`).
    pub async fn get_lid_pn_entry(&self, jid: &Jid) -> Result<Option<LidPnEntry>> {
        let (hit, is_lid) = if jid.is_lid() {
            (self.lid_pn_cache.get_entry_by_lid(&jid.user).await, true)
        } else if jid.is_pn() {
            (self.lid_pn_cache.get_entry_by_phone(&jid.user).await, false)
        } else {
            return Ok(None);
        };

        if let Some(entry) = hit {
            return Ok(Some(entry));
        }

        let backend = self.persistence_manager.backend();
        let mapping = if is_lid {
            backend.get_lid_mapping(&jid.user).await?
        } else {
            backend.get_pn_mapping(&jid.user).await?
        };

        let Some(mapping) = mapping else {
            return Ok(None);
        };

        let entry = mapping_to_entry(mapping);
        self.lid_pn_cache.add(&entry).await;
        Ok(Some(entry))
    }

    /// Resolve any user JID to its bare LID form, or `None` when no LID is
    /// available. Mirrors WA Web's `WAWebLidMigrationUtils.toUserLid`
    /// (`docs/captured-js/WAWeb/Lid/MigrationUtils.js:17-20`): LID passes
    /// through, PN goes through the cache-aside mapping, anything else and
    /// any lookup failure returns `None`.
    ///
    /// Used by `send_status_message` to replicate WA Web's
    /// `compactMap(list, toUserLid)` skip-on-unresolvable semantics.
    pub(crate) async fn resolve_recipient_to_lid(&self, jid: &Jid) -> Option<Jid> {
        if jid.is_lid() {
            return Some(jid.to_non_ad());
        }
        if !jid.is_pn() {
            return None;
        }
        match self.get_lid_pn_entry(jid).await {
            Ok(Some(entry)) => Some(Jid::new(entry.lid, wacore_binary::Server::Lid)),
            Ok(None) => None,
            Err(e) => {
                log::warn!(
                    "resolve_recipient_to_lid: LID lookup for {} failed: {:?}",
                    jid,
                    e
                );
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lid_pn_cache::LearningSource;
    use crate::test_utils::create_test_client;
    use std::sync::Arc;
    use wacore_binary::Server;

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
        assert_eq!(resolved.server, Server::Lid);
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

        assert!(
            client
                .get_lid_pn_entry(&Jid::pn(pn))
                .await
                .unwrap()
                .is_none()
        );

        client
            .add_lid_pn_mapping(lid, pn, LearningSource::Usync)
            .await
            .unwrap();

        let entry = client
            .get_lid_pn_entry(&Jid::pn(pn))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.lid, lid);
        assert_eq!(entry.phone_number, pn);
    }

    #[tokio::test]
    async fn test_get_lid_pn_entry_from_lid() {
        let client: Arc<Client> = create_test_client().await;
        let pn = "55999999999";
        let lid = "100000012345678";

        assert!(
            client
                .get_lid_pn_entry(&Jid::lid(lid))
                .await
                .unwrap()
                .is_none()
        );

        client
            .add_lid_pn_mapping(lid, pn, LearningSource::Usync)
            .await
            .unwrap();

        let entry = client
            .get_lid_pn_entry(&Jid::lid(lid))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.lid, lid);
        assert_eq!(entry.phone_number, pn);
    }

    /// Cache-aside fallback: if the in-memory cache is missing an entry the
    /// backend has, the lookup should still succeed and re-populate the cache.
    #[tokio::test]
    async fn test_get_lid_pn_entry_falls_back_to_backend() {
        use wacore::store::traits::LidPnMappingEntry;

        let client: Arc<Client> = create_test_client().await;
        let pn = "15555550123";
        let lid = "100000000000123";

        let backend = client.persistence_manager.backend();
        backend
            .put_lid_mapping(&LidPnMappingEntry {
                lid: lid.into(),
                phone_number: pn.into(),
                created_at: 1,
                updated_at: 1,
                learning_source: "usync".into(),
            })
            .await
            .unwrap();

        // Cache was never warmed from this backend write → cache miss path.
        let entry = client
            .get_lid_pn_entry(&Jid::lid(lid))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.lid, lid);
        assert_eq!(entry.phone_number, pn);

        // Subsequent lookup served from cache.
        let entry = client
            .get_lid_pn_entry(&Jid::pn(pn))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(entry.lid, lid);
    }

    /// `learn_lid_pn_mapping_fast` must leave the in-memory cache populated
    /// by the time it returns — `resolve_encryption_jid` runs immediately
    /// after on the decrypt hot path and needs to find the LID.
    #[tokio::test]
    async fn test_learn_lid_pn_mapping_fast_populates_cache_synchronously() {
        let client: Arc<Client> = create_test_client().await;
        let pn = "5511999998877";
        let lid = "200000000007788";

        client
            .learn_lid_pn_mapping_fast(lid, pn, LearningSource::PeerPnMessage, false)
            .await;

        let resolved = client.resolve_encryption_jid(&Jid::pn(pn)).await;
        assert_eq!(resolved.user, lid, "cache must have the mapping on return");
        assert_eq!(resolved.server, Server::Lid);
    }

    /// Batched variant must populate the in-memory cache synchronously for
    /// every entry before returning; WA Web parity for `createLidPnMappings`.
    #[tokio::test]
    async fn test_learn_lid_pn_mappings_batch_populates_cache_synchronously() {
        let client: Arc<Client> = create_test_client().await;
        let pairs = [
            ("200000000000001", "5511911111111"),
            ("200000000000002", "5511922222222"),
            ("200000000000003", "5511933333333"),
        ];

        let batch: Vec<(String, String)> = pairs
            .iter()
            .map(|(lid, pn)| ((*lid).to_string(), (*pn).to_string()))
            .collect();
        client
            .learn_lid_pn_mappings_batch(batch, LearningSource::Other, false)
            .await;

        for (lid, pn) in &pairs {
            let resolved = client.resolve_encryption_jid(&Jid::pn(*pn)).await;
            assert_eq!(resolved.user, *lid, "batch entry {pn} missing from cache");
            assert_eq!(resolved.server, Server::Lid);
        }
    }

    /// Empty batch is a no-op (no detached task, no panic).
    #[tokio::test]
    async fn test_learn_lid_pn_mappings_batch_empty_is_noop() {
        let client: Arc<Client> = create_test_client().await;
        client
            .learn_lid_pn_mappings_batch(Vec::new(), LearningSource::Other, false)
            .await;
        assert_eq!(client.lid_pn_cache.lid_count().await, 0);
    }

    /// Offline batch only warms the in-memory cache; the persist task never
    /// fires. Mirrors WA Web's `flushImmediately = false` semantics.
    #[tokio::test]
    async fn test_learn_lid_pn_mappings_batch_offline_skips_persist() {
        use wacore_binary::Jid;

        let client: Arc<Client> = create_test_client().await;
        let lid = "200000000009999";
        let pn = "5511900009999";

        client
            .learn_lid_pn_mappings_batch(
                vec![(lid.to_string(), pn.to_string())],
                LearningSource::Other,
                true,
            )
            .await;

        let resolved = client.resolve_encryption_jid(&Jid::pn(pn)).await;
        assert_eq!(resolved.user, lid);

        assert!(
            client
                .persistence_manager
                .backend()
                .get_lid_mapping(lid)
                .await
                .unwrap()
                .is_none(),
            "offline batch must not persist to DB"
        );
    }
}
