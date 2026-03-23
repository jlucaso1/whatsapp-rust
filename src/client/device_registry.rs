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

    /// Invalidate cached device data for a specific user.
    ///
    /// Removes all device registry cache entries (all LID/PN aliases) so the
    /// next lookup falls through to the database or network.
    pub(crate) async fn invalidate_device_cache(&self, user: &str) {
        let lookup = self.resolve_lookup_keys(user).await;

        for key in lookup.all_keys() {
            self.device_registry_cache.invalidate(key).await;
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
        _from_jid: &Jid,
        device: &wacore::stanza::devices::DeviceElement,
    ) {
        let device_id = device.device_id();
        let lookup = self.resolve_lookup_keys(user).await;

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

    /// Remove a device from the registry cache + backend after a device remove notification.
    pub(crate) async fn patch_device_remove(&self, user: &str, _from_jid: &Jid, device_id: u32) {
        let lookup = self.resolve_lookup_keys(user).await;

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

    /// Look up device JIDs from the device registry (cache + DB) for a single user.
    ///
    /// Returns `None` if no record exists. On DB hit, re-populates the
    /// `device_registry_cache` for subsequent `has_device()` calls.
    ///
    /// This follows the same 2-tier pattern as [`has_device`]: registry cache first,
    /// then the backend database.
    pub(crate) async fn get_devices_from_registry(&self, jid: &Jid) -> Option<Vec<Jid>> {
        let lookup_keys = self.get_lookup_keys(&jid.user).await;

        // L1: device_registry_cache (moka, fast)
        for key in &lookup_keys {
            if let Some(record) = self.device_registry_cache.get(key).await {
                return Some(Self::reconstruct_device_jids(jid, &record));
            }
        }

        // L2: backend DB
        let backend = self.persistence_manager.backend();
        for key in &lookup_keys {
            match backend.get_devices(key).await {
                Ok(Some(record)) => {
                    let devices = Self::reconstruct_device_jids(jid, &record);
                    self.device_registry_cache
                        .insert(record.user.clone(), record)
                        .await;
                    return Some(devices);
                }
                Ok(None) => continue,
                Err(e) => {
                    warn!("get_devices_from_registry: DB lookup failed for {key}: {e}");
                }
            }
        }

        None
    }

    /// Reconstruct `Vec<Jid>` from a `DeviceListRecord`, using the query JID's
    /// server type to produce correctly-typed device JIDs (LID vs PN).
    fn reconstruct_device_jids(
        query_jid: &Jid,
        record: &wacore::store::traits::DeviceListRecord,
    ) -> Vec<Jid> {
        record
            .devices
            .iter()
            .map(|d| {
                if query_jid.is_lid() {
                    Jid::lid_device(record.user.clone(), d.device_id as u16)
                } else {
                    Jid::pn_device(record.user.clone(), d.device_id as u16)
                }
            })
            .collect()
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

                // Clean up stale PN-keyed entry without touching the fresh LID entry.
                self.device_registry_cache.invalidate(pn).await;
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

    /// Test that invalidate_device_cache clears registry cache entries for
    /// all LID/PN aliases when called with either identifier.
    #[tokio::test]
    async fn test_invalidate_device_cache_uses_correct_jid_types() {
        use crate::lid_pn_cache::LidPnEntry;

        let client = create_test_client().await;
        let lid = "100000000000001";
        let pn = "15551234567";

        let entry = LidPnEntry::new(lid.to_string(), pn.to_string(), LearningSource::Usync);
        client.lid_pn_cache.add(entry).await;

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

        assert!(client.device_registry_cache.get(lid).await.is_some());

        // Invalidate via PN — should clear LID entry too (bidirectional resolution)
        client.invalidate_device_cache(pn).await;
        assert!(
            client.device_registry_cache.get(lid).await.is_none(),
            "LID entry should be invalidated when called with PN"
        );

        // Re-insert and invalidate via LID
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

        client.invalidate_device_cache(lid).await;
        assert!(
            client.device_registry_cache.get(lid).await.is_none(),
            "LID entry should be invalidated when called with LID"
        );
    }

    /// Test that invalidate_device_cache handles unknown users (no LID-PN mapping).
    #[tokio::test]
    async fn test_invalidate_device_cache_unknown_user_invalidates_both_types() {
        let client = create_test_client().await;
        let unknown_user = "100000000000999";

        let record = wacore::store::traits::DeviceListRecord {
            user: unknown_user.to_string(),
            devices: vec![wacore::store::traits::DeviceInfo {
                device_id: 1,
                key_index: None,
            }],
            timestamp: 12345,
            phash: None,
        };
        client
            .device_registry_cache
            .insert(unknown_user.to_string(), record)
            .await;

        assert!(
            client
                .device_registry_cache
                .get(unknown_user)
                .await
                .is_some()
        );

        client.invalidate_device_cache(unknown_user).await;
        assert!(
            client
                .device_registry_cache
                .get(unknown_user)
                .await
                .is_none(),
            "Unknown user entry should be invalidated"
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
        use wacore::store::traits::{DeviceInfo, DeviceListRecord};

        let client = create_test_client().await;
        let from_jid = Jid::pn("15551234567");

        // Pre-populate registry cache with device 0
        let record = DeviceListRecord {
            user: "15551234567".into(),
            devices: vec![DeviceInfo {
                device_id: 0,
                key_index: None,
            }],
            timestamp: wacore::time::now_secs(),
            phash: None,
        };
        client
            .device_registry_cache
            .insert("15551234567".into(), record)
            .await;

        // Patch: add device 3
        let elem = make_device_element(3, Some(5));
        client
            .patch_device_add("15551234567", &from_jid, &elem)
            .await;

        let updated = client
            .device_registry_cache
            .get("15551234567")
            .await
            .unwrap();
        assert_eq!(updated.devices.len(), 2);
        assert!(updated.devices.iter().any(|d| d.device_id == 3));
        let dev3 = updated.devices.iter().find(|d| d.device_id == 3).unwrap();
        assert_eq!(dev3.key_index, Some(5));
    }

    #[tokio::test]
    async fn test_patch_device_add_deduplicates() {
        use wacore::store::traits::{DeviceInfo, DeviceListRecord};

        let client = create_test_client().await;
        let from_jid = Jid::pn("15551234567");

        let record = DeviceListRecord {
            user: "15551234567".into(),
            devices: vec![DeviceInfo {
                device_id: 3,
                key_index: None,
            }],
            timestamp: wacore::time::now_secs(),
            phash: None,
        };
        client
            .device_registry_cache
            .insert("15551234567".into(), record)
            .await;

        // Patch: add device 3 again — should not duplicate
        let elem = make_device_element(3, None);
        client
            .patch_device_add("15551234567", &from_jid, &elem)
            .await;

        let updated = client
            .device_registry_cache
            .get("15551234567")
            .await
            .unwrap();
        assert_eq!(updated.devices.len(), 1);
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

        assert!(
            client
                .device_registry_cache
                .get("15551234567")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_patch_device_remove() {
        use wacore::store::traits::{DeviceInfo, DeviceListRecord};

        let client = create_test_client().await;
        let from_jid = Jid::pn("15551234567");

        let record = DeviceListRecord {
            user: "15551234567".into(),
            devices: vec![
                DeviceInfo {
                    device_id: 0,
                    key_index: None,
                },
                DeviceInfo {
                    device_id: 3,
                    key_index: None,
                },
            ],
            timestamp: wacore::time::now_secs(),
            phash: None,
        };
        client
            .device_registry_cache
            .insert("15551234567".into(), record)
            .await;

        client
            .patch_device_remove("15551234567", &from_jid, 3)
            .await;

        let updated = client
            .device_registry_cache
            .get("15551234567")
            .await
            .unwrap();
        assert_eq!(updated.devices.len(), 1);
        assert_eq!(updated.devices[0].device_id, 0);
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

    #[tokio::test]
    async fn test_lid_migration_preserves_registry_cache() {
        use crate::lid_pn_cache::LidPnEntry;
        use wacore::store::traits::{DeviceInfo, DeviceListRecord};

        let client = create_test_client().await;
        let pn = "559984726662";
        let lid = "236395184570386";

        // Store device list under PN in backend
        let record = DeviceListRecord {
            user: pn.to_string(),
            devices: vec![
                DeviceInfo {
                    device_id: 0,
                    key_index: None,
                },
                DeviceInfo {
                    device_id: 39,
                    key_index: Some(25),
                },
            ],
            timestamp: wacore::time::now_secs(),
            phash: None,
        };
        client
            .persistence_manager
            .backend()
            .update_device_list(record)
            .await
            .unwrap();

        // Add LID-PN mapping so resolution works
        let entry = LidPnEntry::new(lid.to_string(), pn.to_string(), LearningSource::Usync);
        client.lid_pn_cache.add(entry).await;

        // Migrate
        client
            .migrate_device_registry_on_lid_discovery(pn, lid)
            .await;

        // LID entry should exist in registry cache
        let cached = client.device_registry_cache.get(lid).await;
        assert!(
            cached.is_some(),
            "LID key should be in registry cache after migration"
        );
        assert_eq!(cached.unwrap().devices.len(), 2);

        // PN entry should be gone
        let pn_cached = client.device_registry_cache.get(pn).await;
        assert!(
            pn_cached.is_none(),
            "PN key should be invalidated after migration"
        );

        // get_devices_from_registry should find devices via LID lookup
        let lid_jid = Jid::lid(lid);
        let devices = client.get_devices_from_registry(&lid_jid).await;
        assert!(devices.is_some(), "should resolve devices via LID");
        assert_eq!(devices.unwrap().len(), 2);
    }
}
