//! Device Registry methods for Client.
//!
//! Manages the device registry cache for tracking known devices per user.
//! Uses LID-first storage with bidirectional lookup support.

use anyhow::Result;
use log::{debug, info, warn};
use wacore_binary::jid::Jid;

use super::Client;

impl Client {
    /// Resolve a user identifier to its canonical storage key (LID preferred).
    pub(crate) async fn resolve_to_canonical_key(&self, user: &str) -> String {
        if self.lid_pn_cache.get_phone_number(user).await.is_some() {
            return user.to_string();
        }

        if let Some(lid) = self.lid_pn_cache.get_current_lid(user).await {
            return lid;
        }

        user.to_string()
    }

    /// Get all possible lookup keys for a user (for bidirectional lookup).
    /// Returns keys in order of preference: [canonical_key, fallback_key].
    pub(crate) async fn get_lookup_keys(&self, user: &str) -> Vec<String> {
        let mut keys = Vec::with_capacity(2);

        if let Some(pn) = self.lid_pn_cache.get_phone_number(user).await {
            keys.push(user.to_string());
            keys.push(pn);
        } else if let Some(lid) = self.lid_pn_cache.get_current_lid(user).await {
            keys.push(lid);
            keys.push(user.to_string());
        } else {
            keys.push(user.to_string());
        }

        keys
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
                    self.device_registry_cache
                        .insert(lookup_keys[0].clone(), record)
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
        use anyhow::anyhow;

        let original_user = record.user.clone();
        let canonical_key = self.resolve_to_canonical_key(&original_user).await;
        record.user = canonical_key.clone();

        self.device_registry_cache
            .insert(canonical_key.clone(), record.clone())
            .await;

        let backend = self.persistence_manager.backend();
        backend
            .update_device_list(record)
            .await
            .map_err(|e| anyhow!("{e}"))?;

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
    pub(crate) async fn invalidate_device_cache(&self, user: &str) {
        let keys = self.get_lookup_keys(user).await;
        for key in &keys {
            self.device_registry_cache.invalidate(key).await;
        }

        // Invalidate device cache using properly-typed JIDs from lookup_keys.
        // get_lookup_keys returns: [LID, PN] when mapping is known, or [user] when unknown.
        // We use the cache to determine the correct type for each key.
        let device_cache = self.get_device_cache().await;
        for key in &keys {
            // Check if this key is a LID (has a phone number mapping)
            if self.lid_pn_cache.get_phone_number(key).await.is_some() {
                device_cache.invalidate(&Jid::lid(key)).await;
            } else {
                // Key is a phone number or unknown - use PN JID
                device_cache.invalidate(&Jid::pn(key)).await;
            }
        }

        debug!(
            "Invalidated device cache for user: {} (keys: {:?})",
            user, keys
        );
    }

    /// Background loop to periodically clean up stale device registry entries.
    pub(super) async fn device_registry_cleanup_loop(&self) {
        use tokio::time::{Duration, interval};

        const CLEANUP_INTERVAL_HOURS: u64 = 6;
        const MAX_AGE_DAYS: i64 = 7;
        const MAX_AGE_SECS: i64 = MAX_AGE_DAYS * 24 * 60 * 60;

        let mut interval = interval(Duration::from_secs(CLEANUP_INTERVAL_HOURS * 60 * 60));

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown_notifier.notified() => {
                    debug!(
                        target: "Client/DeviceRegistry",
                        "Shutdown signaled, exiting cleanup loop"
                    );
                    return;
                }
                _ = interval.tick() => {
                    let backend = self.persistence_manager.backend();
                    match backend.cleanup_stale_entries(MAX_AGE_SECS).await {
                        Ok(deleted) => {
                            if deleted > 0 {
                                info!(
                                    target: "Client/DeviceRegistry",
                                    "Cleaned up {} stale device registry entries (older than {} days)",
                                    deleted, MAX_AGE_DAYS
                                );
                            }
                        }
                        Err(e) => {
                            warn!(
                                target: "Client/DeviceRegistry",
                                "Failed to clean up stale device registry entries: {}",
                                e
                            );
                        }
                    }
                }
            }
        }
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
    use std::sync::Arc;

    async fn create_test_client() -> Arc<Client> {
        let backend = Arc::new(
            crate::store::SqliteStore::new(":memory:")
                .await
                .expect("test backend should initialize"),
        ) as Arc<dyn crate::store::traits::Backend>;
        let pm = Arc::new(
            crate::store::persistence_manager::PersistenceManager::new(backend)
                .await
                .expect("persistence manager should initialize"),
        );

        let (client, _rx) = Client::new(
            pm,
            Arc::new(crate::transport::mock::MockTransportFactory::new()),
            Arc::new(MockHttpClient),
            None,
        )
        .await;

        client
    }

    #[derive(Debug, Clone)]
    struct MockHttpClient;

    #[async_trait::async_trait]
    impl crate::http::HttpClient for MockHttpClient {
        async fn execute(
            &self,
            _request: crate::http::HttpRequest,
        ) -> Result<crate::http::HttpResponse, anyhow::Error> {
            Err(anyhow::anyhow!("Not implemented"))
        }
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
}
