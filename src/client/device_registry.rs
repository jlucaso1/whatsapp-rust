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

        self.get_device_cache()
            .await
            .invalidate(&Jid::pn(user))
            .await;
        self.get_device_cache()
            .await
            .invalidate(&Jid::lid(user))
            .await;

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
        let result = client.resolve_to_canonical_key("559984726662").await;
        assert_eq!(result, "559984726662");
    }

    #[tokio::test]
    async fn test_resolve_to_canonical_key_with_lid_mapping() {
        let client = create_test_client().await;
        let lid = "236395184570386";
        let pn = "559984726662";

        client
            .add_lid_pn_mapping(lid, pn, LearningSource::Usync)
            .await
            .unwrap();

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
        let keys = client.get_lookup_keys("559984726662").await;
        assert_eq!(keys, vec!["559984726662"]);
    }

    #[tokio::test]
    async fn test_get_lookup_keys_with_lid_mapping() {
        let client = create_test_client().await;
        let lid = "236395184570386";
        let pn = "559984726662";

        client
            .add_lid_pn_mapping(lid, pn, LearningSource::Usync)
            .await
            .unwrap();

        // Looking up by PN should return [LID, PN]
        let keys = client.get_lookup_keys(pn).await;
        assert_eq!(keys, vec![lid.to_string(), pn.to_string()]);

        // Looking up by LID should return [LID, PN]
        let keys = client.get_lookup_keys(lid).await;
        assert_eq!(keys, vec![lid.to_string(), pn.to_string()]);
    }

    #[tokio::test]
    async fn test_15_digit_lid_handling() {
        let client = create_test_client().await;
        // Real example: 15-digit LID
        let lid = "236395184570386";
        let pn = "559984726662";

        assert_eq!(lid.len(), 15, "LID should be 15 digits");

        client
            .add_lid_pn_mapping(lid, pn, LearningSource::Usync)
            .await
            .unwrap();

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
        assert!(!client.has_device("559984726662", 5).await);
    }

    #[tokio::test]
    async fn test_update_device_list_stores_under_lid() {
        let client = create_test_client().await;
        let lid = "236395184570386";
        let pn = "559984726662";

        client
            .add_lid_pn_mapping(lid, pn, LearningSource::Usync)
            .await
            .unwrap();

        let record = wacore::store::traits::DeviceListRecord {
            user: pn.to_string(),
            devices: vec![wacore::store::traits::DeviceInfo {
                device_id: 1,
                key_index: None,
            }],
            timestamp: 12345,
            phash: None,
        };

        client.update_device_list(record).await.unwrap();

        // Device should be findable via both PN and LID
        assert!(client.has_device(pn, 1).await);
        assert!(client.has_device(lid, 1).await);
    }
}
