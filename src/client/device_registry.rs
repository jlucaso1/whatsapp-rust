//! Device Registry methods for Client.
//!
//! Manages the device registry cache for tracking known devices per user.
//! Uses LID-first storage with bidirectional lookup support.

use anyhow::Result;
use log::{debug, info, warn};
use wacore_binary::jid::Jid;

use super::Client;

/// Result of resolving a user identifier to lookup keys.
/// This makes the LID/PN relationship explicit instead of using magic indices.
#[derive(Debug, Clone)]
enum UserLookupKeys {
    /// User is a LID with known phone number mapping.
    /// Keys: [LID, PN]
    LidWithPn { lid: String, pn: String },
    /// User is a phone number with known LID mapping.
    /// Keys: [LID, PN]
    PnWithLid { lid: String, pn: String },
    /// Unknown user - no LID-PN mapping exists.
    /// Could be either a LID or PN, we don't know.
    Unknown { user: String },
}

impl UserLookupKeys {
    /// Returns all keys to try for lookups, in preference order.
    fn all_keys(&self) -> Vec<&str> {
        match self {
            Self::LidWithPn { lid, pn } | Self::PnWithLid { lid, pn } => vec![lid, pn],
            Self::Unknown { user } => vec![user],
        }
    }

    /// Returns the canonical (preferred) key for storage.
    fn canonical_key(&self) -> &str {
        match self {
            Self::LidWithPn { lid, .. } | Self::PnWithLid { lid, .. } => lid,
            Self::Unknown { user } => user,
        }
    }
}

impl Client {
    /// Resolve a user identifier to its canonical storage key (LID preferred).
    ///
    /// This is a convenience wrapper around `resolve_lookup_keys().canonical_key()`.
    #[cfg(test)]
    pub(crate) async fn resolve_to_canonical_key(&self, user: &str) -> String {
        self.resolve_lookup_keys(user)
            .await
            .canonical_key()
            .to_string()
    }

    /// Resolve a user identifier to its lookup keys with type information.
    ///
    /// Returns a `UserLookupKeys` enum that explicitly represents:
    /// - `LidWithPn`: User is a LID with known phone number mapping
    /// - `PnWithLid`: User is a phone number with known LID mapping
    /// - `Unknown`: No LID-PN mapping exists (could be either type)
    async fn resolve_lookup_keys(&self, user: &str) -> UserLookupKeys {
        // Check if user is a LID (has a phone number mapping)
        if let Some(pn) = self.lid_pn_cache.get_phone_number(user).await {
            return UserLookupKeys::LidWithPn {
                lid: user.to_string(),
                pn,
            };
        }

        // Check if user is a PN (has a LID mapping)
        if let Some(lid) = self.lid_pn_cache.get_current_lid(user).await {
            return UserLookupKeys::PnWithLid {
                lid,
                pn: user.to_string(),
            };
        }

        // Unknown user - no mapping exists
        UserLookupKeys::Unknown {
            user: user.to_string(),
        }
    }

    /// Get all possible lookup keys for a user (for bidirectional lookup).
    /// Returns keys in order of preference: [canonical_key, fallback_key].
    ///
    /// Note: Prefer `resolve_lookup_keys` when you need type information.
    pub(crate) async fn get_lookup_keys(&self, user: &str) -> Vec<String> {
        self.resolve_lookup_keys(user)
            .await
            .all_keys()
            .into_iter()
            .map(String::from)
            .collect()
    }

    /// Check if a device exists for a user.
    /// Returns true for device_id 0 (primary device always exists).
    pub(crate) async fn has_device(&self, user: &str, device_id: u32) -> bool {
        if device_id == 0 {
            return true;
        }

        let lookup_keys = self.get_lookup_keys(user).await;

        for key in &lookup_keys {
            if let Some(record) = self.device_registry_cache.get(key).await {
                return record.devices.iter().any(|d| d.device_id == device_id);
            }
        }

        let backend = self.persistence_manager.backend();
        for key in &lookup_keys {
            match backend.get_devices(key).await {
                Ok(Some(record)) => {
                    let has_device = record.devices.iter().any(|d| d.device_id == device_id);
                    // Cache under the record's actual user key (the key it was stored under
                    // in the backend), not lookup_keys[0] which is our guessed canonical key.
                    // This ensures consistency between the in-memory cache and the backend.
                    self.device_registry_cache
                        .insert(record.user.clone(), record)
                        .await;
                    return has_device;
                }
                Ok(None) => continue,
                Err(e) => {
                    warn!("Failed to check device registry for {}: {e}", key);
                }
            }
        }

        false
    }

    /// Update the device list for a user.
    /// Stores under LID when mapping is known, otherwise under PN.
    pub(crate) async fn update_device_list(
        &self,
        mut record: wacore::store::traits::DeviceListRecord,
    ) -> Result<()> {
        use anyhow::Context;

        let original_user = record.user.clone();
        let lookup = self.resolve_lookup_keys(&original_user).await;
        let canonical_key = lookup.canonical_key().to_string();
        record.user.clone_from(&canonical_key); // More efficient: reuses allocation

        // Clone record for cache before moving to backend
        let record_for_cache = record.clone();

        // Use canonical_key directly as cache key (no extra clone)
        self.device_registry_cache
            .insert(canonical_key.clone(), record_for_cache)
            .await;

        let backend = self.persistence_manager.backend();
        backend
            .update_device_list(record)
            .await
            .context("Failed to update device list in backend")?;

        if canonical_key != original_user {
            self.device_registry_cache.invalidate(&original_user).await;
            debug!(
                "Device registry: stored under LID {} (resolved from {})",
                canonical_key, original_user
            );
        }

        Ok(())
    }

    /// Invalidate the device cache for a specific user.
    ///
    /// This invalidates both the device registry cache (keyed by string) and
    /// the device cache (keyed by JID). For unknown users, we invalidate both
    /// possible JID types (LID and PN) to ensure cleanup regardless of which
    /// type was used when the cache was populated.
    pub(crate) async fn invalidate_device_cache(&self, user: &str) {
        let lookup = self.resolve_lookup_keys(user).await;

        // Invalidate device registry cache (string keys)
        for key in lookup.all_keys() {
            self.device_registry_cache.invalidate(key).await;
        }

        // Invalidate device cache (JID keys) with proper types
        let device_cache = self.get_device_cache().await;
        match &lookup {
            UserLookupKeys::LidWithPn { lid, pn } | UserLookupKeys::PnWithLid { lid, pn } => {
                // We know the exact types - invalidate each with correct JID type
                device_cache.invalidate(&Jid::lid(lid)).await;
                device_cache.invalidate(&Jid::pn(pn)).await;
            }
            UserLookupKeys::Unknown { user } => {
                // Unknown user - invalidate BOTH types to ensure cleanup.
                // This handles the edge case where devices were cached under
                // a JID type we can no longer determine.
                device_cache.invalidate(&Jid::lid(user)).await;
                device_cache.invalidate(&Jid::pn(user)).await;
            }
        }

        debug!("Invalidated device cache for user: {} ({:?})", user, lookup);
    }

    /// Granularly patch device caches after a device notification.
    ///
    /// Matches WA Web's approach: read current → apply diff → write back.
    /// Patches **all** cached PN/LID aliases so stale alternate-key lookups
    /// are avoided.  Also persists the patched `DeviceListRecord` to the
    /// backend so the change survives cache eviction / restart.
    ///
    /// If no entry is cached, the patch is a no-op — the next read will
    /// fetch fresh from the backend.
    pub(crate) async fn patch_device_add(
        &self,
        user: &str,
        from_jid: &Jid,
        device: &wacore::stanza::devices::DeviceElement,
    ) {
        let device_id = device.device_id();
        let device_hw = device_id as u16;

        // Patch device_cache — all PN/LID aliases
        let device_cache = self.get_device_cache().await;
        let lookup = self.resolve_lookup_keys(user).await;
        for jid in self.jids_for_lookup(&lookup, from_jid) {
            if let Some(mut devices) = device_cache.get(&jid).await
                && !devices.iter().any(|d| d.device == device_hw)
            {
                devices.push(Jid {
                    user: jid.user.clone(),
                    server: jid.server.clone(),
                    device: device_hw,
                    ..Default::default()
                });
                device_cache.insert(jid, devices).await;
            }
        }

        // Patch device_registry_cache + persist
        for key in lookup.all_keys() {
            if let Some(mut record) = self.device_registry_cache.get(key).await {
                if !record.devices.iter().any(|d| d.device_id == device_id) {
                    record.devices.push(wacore::store::traits::DeviceInfo {
                        device_id,
                        key_index: device.key_index,
                    });
                    if let Err(e) = self.update_device_list(record).await {
                        warn!("patch_device_add: failed to persist: {e}");
                    }
                }
                return;
            }
        }
    }

    /// Remove a device from both caches after a device remove notification.
    pub(crate) async fn patch_device_remove(&self, user: &str, from_jid: &Jid, device_id: u32) {
        let device_hw = device_id as u16;

        // Patch device_cache — all PN/LID aliases
        let device_cache = self.get_device_cache().await;
        let lookup = self.resolve_lookup_keys(user).await;
        for jid in self.jids_for_lookup(&lookup, from_jid) {
            if let Some(mut devices) = device_cache.get(&jid).await {
                let before = devices.len();
                devices.retain(|d| d.device != device_hw);
                if devices.len() != before {
                    device_cache.insert(jid, devices).await;
                }
            }
        }

        // Patch device_registry_cache + persist
        for key in lookup.all_keys() {
            if let Some(mut record) = self.device_registry_cache.get(key).await {
                let before = record.devices.len();
                record.devices.retain(|d| d.device_id != device_id);
                if record.devices.len() != before
                    && let Err(e) = self.update_device_list(record).await
                {
                    warn!("patch_device_remove: failed to persist: {e}");
                }
                return;
            }
        }
    }

    /// Update key_index for a device in the registry cache + backend.
    pub(crate) async fn patch_device_update(
        &self,
        user: &str,
        device: &wacore::stanza::devices::DeviceElement,
    ) {
        let device_id = device.device_id();
        let lookup = self.resolve_lookup_keys(user).await;
        for key in lookup.all_keys() {
            if let Some(mut record) = self.device_registry_cache.get(key).await {
                if let Some(d) = record.devices.iter_mut().find(|d| d.device_id == device_id) {
                    d.key_index = device.key_index;
                    if let Err(e) = self.update_device_list(record).await {
                        warn!("patch_device_update: failed to persist: {e}");
                    }
                }
                return;
            }
        }
    }

    /// Resolve all JID forms (PN + LID) that might be cached in `device_cache`.
    fn jids_for_lookup(&self, lookup: &UserLookupKeys, from_jid: &Jid) -> Vec<Jid> {
        match lookup {
            UserLookupKeys::LidWithPn { lid, pn } | UserLookupKeys::PnWithLid { lid, pn } => {
                vec![Jid::lid(lid), Jid::pn(pn)]
            }
            UserLookupKeys::Unknown { .. } => {
                // Unknown — use from_jid's non-AD form only
                vec![from_jid.to_non_ad()]
            }
        }
    }

    /// Background loop placeholder for device registry cleanup.
    /// Note: Cleanup functionality was removed as part of trait simplification.
    /// Device registry entries are managed through normal update/get operations.
    pub(super) async fn device_registry_cleanup_loop(&self) {
        // Simply wait for shutdown signal
        self.shutdown_notifier.listen().await;
        debug!(
            target: "Client/DeviceRegistry",
            "Shutdown signaled, exiting cleanup loop"
        );
    }

    /// Migrate device registry entries from PN key to LID key.
    pub(crate) async fn migrate_device_registry_on_lid_discovery(&self, pn: &str, lid: &str) {
        let backend = self.persistence_manager.backend();

        match backend.get_devices(pn).await {
            Ok(Some(mut record)) => {
                info!(
                    "Migrating device registry entry from PN {} to LID {} ({} devices)",
                    pn,
                    lid,
                    record.devices.len()
                );

                record.user = lid.to_string();

                if let Err(e) = backend.update_device_list(record.clone()).await {
                    warn!("Failed to migrate device registry to LID: {}", e);
                    return;
                }

                self.device_registry_cache
                    .insert(lid.to_string(), record)
                    .await;

                // Invalidate both the string-keyed device_registry_cache AND the
                // JID-keyed device cache. Using invalidate_device_cache ensures
                // we clean up Jid::pn(pn) entries that would otherwise become stale.
                self.invalidate_device_cache(pn).await;
            }
            Ok(None) => {}
            Err(e) => {
                warn!("Failed to check for PN device registry entry: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lid_pn_cache::LearningSource;
    use crate::test_utils::create_test_client_with_failing_http;
    use std::sync::Arc;

    async fn create_test_client() -> Arc<Client> {
        create_test_client_with_failing_http("device_registry").await
    }

    #[tokio::test]
    async fn test_resolve_to_canonical_key_unknown_user() {
        let client = create_test_client().await;
        let result = client.resolve_to_canonical_key("15551234567").await;
        assert_eq!(result, "15551234567");
    }

    #[tokio::test]
    async fn test_resolve_to_canonical_key_with_lid_mapping() {
        use crate::lid_pn_cache::LidPnEntry;

        let client = create_test_client().await;
        let lid = "100000000000001";
        let pn = "15551234567";

        // Add directly to cache (avoids persistence layer which needs DB tables)
        let entry = LidPnEntry::new(lid.to_string(), pn.to_string(), LearningSource::Usync);
        client.lid_pn_cache.add(entry).await;

        // PN should resolve to LID
        let result = client.resolve_to_canonical_key(pn).await;
        assert_eq!(result, lid);

        // LID should stay as LID
        let result = client.resolve_to_canonical_key(lid).await;
        assert_eq!(result, lid);
    }

    #[tokio::test]
    async fn test_get_lookup_keys_unknown_user() {
        let client = create_test_client().await;
        let keys = client.get_lookup_keys("15551234567").await;
        assert_eq!(keys, vec!["15551234567"]);
    }

    #[tokio::test]
    async fn test_get_lookup_keys_with_lid_mapping() {
        use crate::lid_pn_cache::LidPnEntry;

        let client = create_test_client().await;
        let lid = "100000000000001";
        let pn = "15551234567";

        // Add directly to cache (avoids persistence layer which needs DB tables)
        let entry = LidPnEntry::new(lid.to_string(), pn.to_string(), LearningSource::Usync);
        client.lid_pn_cache.add(entry).await;

        // Looking up by PN should return [LID, PN]
        let keys = client.get_lookup_keys(pn).await;
        assert_eq!(keys, vec![lid.to_string(), pn.to_string()]);

        // Looking up by LID should return [LID, PN]
        let keys = client.get_lookup_keys(lid).await;
        assert_eq!(keys, vec![lid.to_string(), pn.to_string()]);
    }

    #[tokio::test]
    async fn test_15_digit_lid_handling() {
        use crate::lid_pn_cache::LidPnEntry;

        let client = create_test_client().await;
        // Real example: 15-digit LID
        let lid = "100000000000001";
        let pn = "15551234567";

        assert_eq!(lid.len(), 15, "LID should be 15 digits");

        // Add directly to cache (avoids persistence layer which needs DB tables)
        let entry = LidPnEntry::new(lid.to_string(), pn.to_string(), LearningSource::Usync);
        client.lid_pn_cache.add(entry).await;

        // 15-digit LID should be properly recognized via cache lookup
        let canonical = client.resolve_to_canonical_key(lid).await;
        assert_eq!(canonical, lid);

        let keys = client.get_lookup_keys(lid).await;
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], lid);
        assert_eq!(keys[1], pn);
    }

    #[tokio::test]
    async fn test_has_device_primary_always_exists() {
        let client = create_test_client().await;
        assert!(client.has_device("anyuser", 0).await);
    }

    #[tokio::test]
    async fn test_has_device_unknown_device() {
        let client = create_test_client().await;
        assert!(!client.has_device("15551234567", 5).await);
    }

    #[tokio::test]
    async fn test_has_device_with_cached_record() {
        use crate::lid_pn_cache::LidPnEntry;

        let client = create_test_client().await;
        let lid = "100000000000001";
        let pn = "15551234567";

        // Add directly to cache (avoids persistence layer which needs DB tables)
        let entry = LidPnEntry::new(lid.to_string(), pn.to_string(), LearningSource::Usync);
        client.lid_pn_cache.add(entry).await;

        // Manually insert into cache to test lookup logic
        let record = wacore::store::traits::DeviceListRecord {
            user: lid.to_string(),
            devices: vec![wacore::store::traits::DeviceInfo {
                device_id: 1,
                key_index: None,
            }],
            timestamp: 12345,
            phash: None,
        };
        client
            .device_registry_cache
            .insert(lid.to_string(), record)
            .await;

        // Device should be findable via both PN and LID (bidirectional lookup)
        assert!(client.has_device(pn, 1).await);
        assert!(client.has_device(lid, 1).await);
        // Non-existent device should return false
        assert!(!client.has_device(lid, 99).await);
    }

    /// Test that invalidate_device_cache uses correctly-typed JIDs.
    ///
    /// This test prevents a regression where the code was using both
    /// Jid::pn(user) and Jid::lid(user) on the raw user string, which
    /// creates invalid JIDs (e.g., "15551234567@lid" for a phone number).
    ///
    /// The fix uses the lid_pn_cache to determine the correct Jid type
    /// for each lookup key.
    #[tokio::test]
    async fn test_invalidate_device_cache_uses_correct_jid_types() {
        use crate::lid_pn_cache::LidPnEntry;
        use wacore_binary::jid::Jid;

        let client = create_test_client().await;
        let lid = "100000000000001";
        let pn = "15551234567";

        // Set up LID-to-PN mapping
        let entry = LidPnEntry::new(lid.to_string(), pn.to_string(), LearningSource::Usync);
        client.lid_pn_cache.add(entry).await;

        // Insert device registry record
        let record = wacore::store::traits::DeviceListRecord {
            user: lid.to_string(),
            devices: vec![wacore::store::traits::DeviceInfo {
                device_id: 1,
                key_index: None,
            }],
            timestamp: 12345,
            phash: None,
        };
        client
            .device_registry_cache
            .insert(lid.to_string(), record)
            .await;

        // Insert into device cache using correctly-typed JIDs
        let lid_jid = Jid::lid(lid);
        let pn_jid = Jid::pn(pn);

        // Simulate devices being cached under both JID types
        let device_cache = client.get_device_cache().await;
        device_cache
            .insert(lid_jid.clone(), vec![lid_jid.clone()])
            .await;
        device_cache
            .insert(pn_jid.clone(), vec![pn_jid.clone()])
            .await;

        // Verify cache entries exist before invalidation
        assert!(
            client.device_registry_cache.get(lid).await.is_some(),
            "Device registry cache should have LID entry before invalidation"
        );
        assert!(
            device_cache.get(&lid_jid).await.is_some(),
            "Device cache should have LID JID entry before invalidation"
        );
        assert!(
            device_cache.get(&pn_jid).await.is_some(),
            "Device cache should have PN JID entry before invalidation"
        );

        // Call invalidate_device_cache with the phone number (tests PN -> LID resolution)
        client.invalidate_device_cache(pn).await;

        // Verify all caches are properly invalidated
        assert!(
            client.device_registry_cache.get(lid).await.is_none(),
            "Device registry cache should be invalidated for LID"
        );
        assert!(
            device_cache.get(&lid_jid).await.is_none(),
            "Device cache should be invalidated for LID JID"
        );
        assert!(
            device_cache.get(&pn_jid).await.is_none(),
            "Device cache should be invalidated for PN JID"
        );

        // Also test invalidation when called with LID directly
        // Re-insert entries
        let record2 = wacore::store::traits::DeviceListRecord {
            user: lid.to_string(),
            devices: vec![wacore::store::traits::DeviceInfo {
                device_id: 2,
                key_index: None,
            }],
            timestamp: 12346,
            phash: None,
        };
        client
            .device_registry_cache
            .insert(lid.to_string(), record2)
            .await;
        device_cache
            .insert(lid_jid.clone(), vec![lid_jid.clone()])
            .await;
        device_cache
            .insert(pn_jid.clone(), vec![pn_jid.clone()])
            .await;

        // Call invalidate_device_cache with the LID
        client.invalidate_device_cache(lid).await;

        // Verify all caches are properly invalidated
        assert!(
            client.device_registry_cache.get(lid).await.is_none(),
            "Device registry cache should be invalidated for LID (called with LID)"
        );
        assert!(
            device_cache.get(&lid_jid).await.is_none(),
            "Device cache should be invalidated for LID JID (called with LID)"
        );
        assert!(
            device_cache.get(&pn_jid).await.is_none(),
            "Device cache should be invalidated for PN JID (called with LID)"
        );
    }

    /// Test that invalidate_device_cache handles unknown users correctly.
    ///
    /// When a user has no LID-PN mapping, we don't know if it's a LID or PN.
    /// The fix invalidates BOTH types to ensure we clean up regardless.
    #[tokio::test]
    async fn test_invalidate_device_cache_unknown_user_invalidates_both_types() {
        use wacore_binary::jid::Jid;

        let client = create_test_client().await;
        // This user has NO LID-PN mapping in the cache
        let unknown_user = "100000000000999";

        // Create both possible JID types
        let lid_jid = Jid::lid(unknown_user);
        let pn_jid = Jid::pn(unknown_user);

        // Simulate devices being cached under the LID type
        // (this could happen if we queried usync with an @lid JID)
        let device_cache = client.get_device_cache().await;
        device_cache
            .insert(lid_jid.clone(), vec![lid_jid.clone()])
            .await;

        // Verify cache entry exists
        assert!(
            device_cache.get(&lid_jid).await.is_some(),
            "Device cache should have LID JID entry before invalidation"
        );

        // Call invalidate_device_cache with the unknown user
        client.invalidate_device_cache(unknown_user).await;

        // Verify BOTH types are invalidated (even though only LID was cached)
        assert!(
            device_cache.get(&lid_jid).await.is_none(),
            "Device cache should be invalidated for LID JID (unknown user)"
        );
        assert!(
            device_cache.get(&pn_jid).await.is_none(),
            "Device cache should be invalidated for PN JID (unknown user)"
        );

        // Test the reverse case: PN cached but we don't know the type
        let unknown_user2 = "15559998888";
        let lid_jid2 = Jid::lid(unknown_user2);
        let pn_jid2 = Jid::pn(unknown_user2);

        // Simulate devices being cached under the PN type
        device_cache
            .insert(pn_jid2.clone(), vec![pn_jid2.clone()])
            .await;

        assert!(
            device_cache.get(&pn_jid2).await.is_some(),
            "Device cache should have PN JID entry before invalidation"
        );

        client.invalidate_device_cache(unknown_user2).await;

        // Verify BOTH types are invalidated
        assert!(
            device_cache.get(&lid_jid2).await.is_none(),
            "Device cache should be invalidated for LID JID (unknown PN user)"
        );
        assert!(
            device_cache.get(&pn_jid2).await.is_none(),
            "Device cache should be invalidated for PN JID (unknown PN user)"
        );
    }

    // ── Granular patch tests ──────────────────────────────────────────────

    fn make_device_element(
        device_id: u16,
        key_index: Option<u32>,
    ) -> wacore::stanza::devices::DeviceElement {
        wacore::stanza::devices::DeviceElement {
            jid: Jid {
                user: "15551234567".into(),
                server: "s.whatsapp.net".into(),
                device: device_id,
                ..Default::default()
            },
            key_index,
            lid: None,
        }
    }

    #[tokio::test]
    async fn test_patch_device_add_to_existing_cache() {
        let client = create_test_client().await;
        let from_jid = Jid::pn("15551234567");
        let non_ad = from_jid.to_non_ad();

        // Pre-populate device_cache with device 0
        let device_cache = client.get_device_cache().await;
        let dev0 = Jid {
            user: "15551234567".into(),
            server: "s.whatsapp.net".into(),
            device: 0,
            ..Default::default()
        };
        device_cache.insert(non_ad.clone(), vec![dev0]).await;

        // Patch: add device 3
        let elem = make_device_element(3, Some(5));
        client
            .patch_device_add("15551234567", &from_jid, &elem)
            .await;

        let devices = device_cache.get(&non_ad).await.unwrap();
        assert_eq!(devices.len(), 2);
        assert!(devices.iter().any(|d| d.device == 3));
    }

    #[tokio::test]
    async fn test_patch_device_add_deduplicates() {
        let client = create_test_client().await;
        let from_jid = Jid::pn("15551234567");
        let non_ad = from_jid.to_non_ad();

        let dev3 = Jid {
            user: "15551234567".into(),
            server: "s.whatsapp.net".into(),
            device: 3,
            ..Default::default()
        };
        let device_cache = client.get_device_cache().await;
        device_cache.insert(non_ad.clone(), vec![dev3]).await;

        // Patch: add device 3 again — should not duplicate
        let elem = make_device_element(3, None);
        client
            .patch_device_add("15551234567", &from_jid, &elem)
            .await;

        let devices = device_cache.get(&non_ad).await.unwrap();
        assert_eq!(devices.len(), 1);
    }

    #[tokio::test]
    async fn test_patch_device_add_noop_on_miss() {
        let client = create_test_client().await;
        let from_jid = Jid::pn("15551234567");

        // No pre-populated cache — patch should be a no-op
        let elem = make_device_element(3, None);
        client
            .patch_device_add("15551234567", &from_jid, &elem)
            .await;

        let device_cache = client.get_device_cache().await;
        assert!(device_cache.get(&from_jid.to_non_ad()).await.is_none());
    }

    #[tokio::test]
    async fn test_patch_device_remove() {
        let client = create_test_client().await;
        let from_jid = Jid::pn("15551234567");
        let non_ad = from_jid.to_non_ad();

        let dev0 = Jid {
            user: "15551234567".into(),
            server: "s.whatsapp.net".into(),
            device: 0,
            ..Default::default()
        };
        let dev3 = Jid {
            user: "15551234567".into(),
            server: "s.whatsapp.net".into(),
            device: 3,
            ..Default::default()
        };
        let device_cache = client.get_device_cache().await;
        device_cache.insert(non_ad.clone(), vec![dev0, dev3]).await;

        client
            .patch_device_remove("15551234567", &from_jid, 3)
            .await;

        let devices = device_cache.get(&non_ad).await.unwrap();
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].device, 0);
    }

    #[tokio::test]
    async fn test_patch_device_update_key_index() {
        let client = create_test_client().await;

        // Pre-populate registry cache
        let record = wacore::store::traits::DeviceListRecord {
            user: "15551234567".to_string(),
            devices: vec![
                wacore::store::traits::DeviceInfo {
                    device_id: 0,
                    key_index: None,
                },
                wacore::store::traits::DeviceInfo {
                    device_id: 3,
                    key_index: Some(1),
                },
            ],
            timestamp: 1000,
            phash: None,
        };
        client
            .device_registry_cache
            .insert("15551234567".to_string(), record)
            .await;

        // Patch: update device 3 key_index to 5
        let elem = make_device_element(3, Some(5));
        client.patch_device_update("15551234567", &elem).await;

        let updated = client
            .device_registry_cache
            .get("15551234567")
            .await
            .unwrap();
        let dev3 = updated.devices.iter().find(|d| d.device_id == 3).unwrap();
        assert_eq!(dev3.key_index, Some(5));
    }

    #[tokio::test]
    async fn test_patch_device_add_updates_registry() {
        let client = create_test_client().await;
        let from_jid = Jid::pn("15551234567");

        // Pre-populate registry cache
        let record = wacore::store::traits::DeviceListRecord {
            user: "15551234567".to_string(),
            devices: vec![wacore::store::traits::DeviceInfo {
                device_id: 0,
                key_index: None,
            }],
            timestamp: 1000,
            phash: None,
        };
        client
            .device_registry_cache
            .insert("15551234567".to_string(), record)
            .await;

        // Patch: add device 3
        let elem = make_device_element(3, Some(2));
        client
            .patch_device_add("15551234567", &from_jid, &elem)
            .await;

        let updated = client
            .device_registry_cache
            .get("15551234567")
            .await
            .unwrap();
        assert_eq!(updated.devices.len(), 2);
        let dev3 = updated.devices.iter().find(|d| d.device_id == 3).unwrap();
        assert_eq!(dev3.key_index, Some(2));
    }
}
