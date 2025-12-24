//! Device Registry methods for Client.
//!
//! This module contains methods for managing the device registry cache,
//! which tracks known devices per user for validation in retry handling.
//!
//! Key features:
//! - LID-first storage: Stores under LID when mapping is known
//! - Bidirectional lookup: Can find devices by either LID or PN
//! - Automatic migration: Migrates PN entries to LID when mapping is learned

use anyhow::Result;
use log::{debug, info, warn};
use wacore_binary::jid::Jid;

use super::Client;

impl Client {
    // ---- Device Registry LID Normalization Helpers ----
    //
    // These methods support LID-first storage for device registry.
    // We store under LID when known, fall back to PN otherwise.

    /// Resolve a user identifier to its canonical storage key (LID preferred).
    /// Returns LID if mapping exists, otherwise returns the original user.
    pub(crate) async fn resolve_to_canonical_key(&self, user: &str) -> String {
        // If it already looks like a LID, use as-is
        if self.looks_like_lid(user) {
            return user.to_string();
        }

        // Try to resolve PN to LID
        if let Some(lid) = self.lid_pn_cache.get_current_lid(user).await {
            return lid;
        }

        // No mapping found, use original (likely PN)
        user.to_string()
    }

    /// Get all possible lookup keys for a user (for bidirectional lookup).
    /// Returns keys in order of preference: [canonical_key, fallback_key].
    pub(crate) async fn get_lookup_keys(&self, user: &str) -> Vec<String> {
        let mut keys = Vec::with_capacity(2);

        if self.looks_like_lid(user) {
            // User is a LID
            keys.push(user.to_string());
            // Also try to find the PN for fallback (old entries stored under PN)
            if let Some(pn) = self.lid_pn_cache.get_phone_number(user).await {
                keys.push(pn);
            }
        } else {
            // User is a PN
            // First try LID (preferred storage)
            if let Some(lid) = self.lid_pn_cache.get_current_lid(user).await {
                keys.push(lid);
            }
            // Then try PN itself (fallback for entries before LID was known)
            keys.push(user.to_string());
        }

        keys
    }

    /// Check if a user identifier looks like a LID (vs a phone number).
    /// LIDs are typically 15+ digit numbers, while phone numbers are shorter.
    pub(crate) fn looks_like_lid(&self, user: &str) -> bool {
        // LIDs are long numeric strings (typically 15+ digits)
        // Phone numbers are typically 10-15 digits
        // This is a heuristic - LIDs tend to be longer
        user.len() >= 15 && user.chars().all(|c| c.is_ascii_digit())
    }

    /// Check if a device exists for a user.
    /// Uses the in-memory cache first, then falls back to persistent storage.
    /// Returns true for device_id 0 (primary device always exists).
    /// Matches WhatsApp Web's WAWebApiDeviceList.hasDevice behavior.
    /// Supports bidirectional lookup (LID or PN) via lid_pn_cache.
    pub(crate) async fn has_device(&self, user: &str, device_id: u32) -> bool {
        // Device ID 0 (primary device) always exists
        if device_id == 0 {
            return true;
        }

        // Get all possible lookup keys (LID preferred, then PN fallback)
        let lookup_keys = self.get_lookup_keys(user).await;

        // Check cache first for any key
        for key in &lookup_keys {
            if let Some(record) = self.device_registry_cache.get(key).await {
                return record.devices.iter().any(|d| d.device_id == device_id);
            }
        }

        // Fall back to persistence - try each key
        let backend = self.persistence_manager.backend();
        for key in &lookup_keys {
            match backend.get_devices(key).await {
                Ok(Some(record)) => {
                    let has_device = record.devices.iter().any(|d| d.device_id == device_id);
                    // Cache under the canonical key (first key)
                    self.device_registry_cache
                        .insert(lookup_keys[0].clone(), record)
                        .await;
                    return has_device;
                }
                Ok(None) => continue, // Try next key
                Err(e) => {
                    warn!("Failed to check device registry for {}: {e}", key);
                }
            }
        }

        // No record found for any key
        false
    }

    /// Update the device list for a user.
    /// Called when we receive device list updates from usync responses.
    /// Stores under LID when mapping is known, otherwise under PN.
    pub(crate) async fn update_device_list(
        &self,
        mut record: wacore::store::traits::DeviceListRecord,
    ) -> Result<()> {
        use anyhow::anyhow;

        let original_user = record.user.clone();

        // Resolve to canonical key (LID preferred)
        let canonical_key = self.resolve_to_canonical_key(&original_user).await;
        record.user = canonical_key.clone();

        // Update cache under canonical key
        self.device_registry_cache
            .insert(canonical_key.clone(), record.clone())
            .await;

        // Persist to storage under canonical key
        let backend = self.persistence_manager.backend();
        backend
            .update_device_list(record)
            .await
            .map_err(|e| anyhow!("{e}"))?;

        // If we resolved PN to LID, invalidate old PN cache entry
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
    /// Called when we receive device change notifications (add/remove/update).
    /// This forces the next device lookup to fetch fresh data.
    /// Invalidates both LID and PN keys to ensure complete cache clearance.
    pub(crate) async fn invalidate_device_cache(&self, user: &str) {
        // Get all possible keys (LID and PN) and invalidate both
        let keys = self.get_lookup_keys(user).await;
        for key in &keys {
            self.device_registry_cache.invalidate(key).await;
        }

        // Also invalidate the device cache (Jid -> Vec<Jid>)
        // Remove from device cache for both PN and LID servers
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
    /// Runs every 6 hours, deleting entries older than 7 days.
    /// Terminates gracefully when shutdown is signaled.
    pub(super) async fn device_registry_cleanup_loop(&self) {
        use tokio::time::{Duration, interval};

        const CLEANUP_INTERVAL_HOURS: u64 = 6;
        const MAX_AGE_DAYS: i64 = 7;
        const MAX_AGE_SECS: i64 = MAX_AGE_DAYS * 24 * 60 * 60;

        // Run cleanup immediately on startup, then every 6 hours
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
                            } else {
                                debug!(
                                    target: "Client/DeviceRegistry",
                                    "No stale device registry entries to clean up"
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

    /// Called when we learn a new LID mapping.
    /// Migrates any device registry entries from PN key to LID key.
    pub(crate) async fn migrate_device_registry_on_lid_discovery(&self, pn: &str, lid: &str) {
        let backend = self.persistence_manager.backend();

        // Check if there's an existing PN-keyed entry
        match backend.get_devices(pn).await {
            Ok(Some(mut record)) => {
                info!(
                    "Migrating device registry entry from PN {} to LID {} ({} devices)",
                    pn,
                    lid,
                    record.devices.len()
                );

                // Update the record with the LID key
                record.user = lid.to_string();

                // Store under LID
                if let Err(e) = backend.update_device_list(record.clone()).await {
                    warn!("Failed to migrate device registry to LID: {}", e);
                    return;
                }

                // Update cache under LID key
                self.device_registry_cache
                    .insert(lid.to_string(), record)
                    .await;

                // Invalidate old PN cache entry
                self.device_registry_cache.invalidate(pn).await;
            }
            Ok(None) => {
                // No PN-keyed entry to migrate
            }
            Err(e) => {
                warn!("Failed to check for PN device registry entry: {}", e);
            }
        }
    }
}
