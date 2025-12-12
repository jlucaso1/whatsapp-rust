//! LID-PN (Linked ID to Phone Number) Cache
//!
//! This module implements a cache for mapping between WhatsApp's Linked IDs (LIDs)
//! and phone numbers. The cache is used for Signal address resolution - WhatsApp Web
//! uses LID-based addresses for Signal sessions when available.
//!
//! The cache maintains bidirectional mappings:
//! - LID -> Entry (for getting phone number from LID)
//! - Phone Number -> Entry (for getting LID from phone number)
//!
//! When multiple LIDs exist for the same phone number (rare), the most recent one
//! (by `created_at` timestamp) is considered "current".

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// The source from which a LID-PN mapping was learned.
/// Different sources have different trust levels and handling for identity changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LearningSource {
    /// Mapping learned from usync (device sync) query response
    Usync,
    /// Mapping learned from incoming message with sender_lid attribute (sender is PN)
    PeerPnMessage,
    /// Mapping learned from incoming message with sender_pn attribute (sender is LID)
    PeerLidMessage,
    /// Mapping learned when looking up recipient's latest LID
    RecipientLatestLid,
    /// Mapping learned from latest history sync migration
    MigrationSyncLatest,
    /// Mapping learned from old history sync records
    MigrationSyncOld,
    /// Mapping learned from active blocklist entry
    BlocklistActive,
    /// Mapping learned from inactive blocklist entry
    BlocklistInactive,
    /// Mapping learned from device pairing (own JID <-> LID)
    Pairing,
    /// Mapping learned from other/unknown source
    Other,
}

impl LearningSource {
    /// Convert to string for database storage
    pub fn as_str(&self) -> &'static str {
        match self {
            LearningSource::Usync => "usync",
            LearningSource::PeerPnMessage => "peer_pn_message",
            LearningSource::PeerLidMessage => "peer_lid_message",
            LearningSource::RecipientLatestLid => "recipient_latest_lid",
            LearningSource::MigrationSyncLatest => "migration_sync_latest",
            LearningSource::MigrationSyncOld => "migration_sync_old",
            LearningSource::BlocklistActive => "blocklist_active",
            LearningSource::BlocklistInactive => "blocklist_inactive",
            LearningSource::Pairing => "pairing",
            LearningSource::Other => "other",
        }
    }

    /// Parse from database string
    pub fn parse(s: &str) -> Self {
        match s {
            "usync" => LearningSource::Usync,
            "peer_pn_message" => LearningSource::PeerPnMessage,
            "peer_lid_message" => LearningSource::PeerLidMessage,
            "recipient_latest_lid" => LearningSource::RecipientLatestLid,
            "migration_sync_latest" => LearningSource::MigrationSyncLatest,
            "migration_sync_old" => LearningSource::MigrationSyncOld,
            "blocklist_active" => LearningSource::BlocklistActive,
            "blocklist_inactive" => LearningSource::BlocklistInactive,
            "pairing" => LearningSource::Pairing,
            _ => LearningSource::Other,
        }
    }
}

/// An entry in the LID-PN cache containing the full mapping information.
#[derive(Debug, Clone)]
pub struct LidPnEntry {
    /// The LID user part (e.g., "100000012345678")
    pub lid: String,
    /// The phone number user part (e.g., "559980000001")
    pub phone_number: String,
    /// Unix timestamp when the mapping was first learned
    pub created_at: i64,
    /// The source from which this mapping was learned
    pub learning_source: LearningSource,
}

impl LidPnEntry {
    /// Create a new entry with the current timestamp
    pub fn new(lid: String, phone_number: String, learning_source: LearningSource) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        Self {
            lid,
            phone_number,
            created_at: now,
            learning_source,
        }
    }

    /// Create an entry with a specific timestamp
    pub fn with_timestamp(
        lid: String,
        phone_number: String,
        created_at: i64,
        learning_source: LearningSource,
    ) -> Self {
        Self {
            lid,
            phone_number,
            created_at,
            learning_source,
        }
    }
}

/// Cache for LID to Phone Number mappings.
///
/// This cache maintains bidirectional mappings between LIDs and phone numbers,
/// similar to WhatsApp Web's LidPnCache class. It provides fast lookups for
/// Signal address resolution.
///
/// The cache is thread-safe and can be shared across async tasks.
#[derive(Debug)]
pub struct LidPnCache {
    /// LID -> Entry mapping
    lid_to_entry: RwLock<HashMap<String, LidPnEntry>>,
    /// Phone number -> Entry mapping (stores the most recent LID for that PN)
    pn_to_entry: RwLock<HashMap<String, LidPnEntry>>,
}

impl Default for LidPnCache {
    fn default() -> Self {
        Self::new()
    }
}

impl LidPnCache {
    /// Create a new empty cache
    pub fn new() -> Self {
        Self {
            lid_to_entry: RwLock::new(HashMap::new()),
            pn_to_entry: RwLock::new(HashMap::new()),
        }
    }

    /// Get the current LID for a phone number.
    ///
    /// Returns the LID user part if a mapping exists, None otherwise.
    pub async fn get_current_lid(&self, phone: &str) -> Option<String> {
        let pn_map = self.pn_to_entry.read().await;
        pn_map.get(phone).map(|e| e.lid.clone())
    }

    /// Get the phone number for a LID.
    ///
    /// Returns the phone number user part if a mapping exists, None otherwise.
    pub async fn get_phone_number(&self, lid: &str) -> Option<String> {
        let lid_map = self.lid_to_entry.read().await;
        lid_map.get(lid).map(|e| e.phone_number.clone())
    }

    /// Get the full entry for a LID.
    pub async fn get_entry_by_lid(&self, lid: &str) -> Option<LidPnEntry> {
        let lid_map = self.lid_to_entry.read().await;
        lid_map.get(lid).cloned()
    }

    /// Get the full entry for a phone number.
    pub async fn get_entry_by_phone(&self, phone: &str) -> Option<LidPnEntry> {
        let pn_map = self.pn_to_entry.read().await;
        pn_map.get(phone).cloned()
    }

    /// Add or update a mapping in the cache.
    ///
    /// For the LID -> Entry map, this always updates.
    /// For the PN -> Entry map, this only updates if the new entry has a
    /// newer or equal `created_at` timestamp (matching WhatsApp Web behavior).
    pub async fn add(&self, entry: LidPnEntry) {
        // Update LID -> Entry map
        {
            let mut lid_map = self.lid_to_entry.write().await;
            lid_map.insert(entry.lid.clone(), entry.clone());
        }

        // Update PN -> Entry map (only if newer or equal timestamp)
        {
            let mut pn_map = self.pn_to_entry.write().await;
            let should_update = match pn_map.get(&entry.phone_number) {
                Some(existing) => existing.created_at <= entry.created_at,
                None => true,
            };

            if should_update {
                pn_map.insert(entry.phone_number.clone(), entry);
            }
        }
    }

    /// Warm up the cache with entries from persistent storage.
    ///
    /// This should be called during client initialization to populate
    /// the cache from the database.
    pub async fn warm_up(&self, entries: Vec<LidPnEntry>) {
        let count = entries.len();
        let start = std::time::Instant::now();

        for entry in entries {
            self.add(entry).await;
        }

        log::info!(
            "LID-PN cache warmed up with {} entries in {:?}",
            count,
            start.elapsed()
        );
    }

    /// Clear all entries from the cache.
    pub async fn clear(&self) {
        {
            let mut lid_map = self.lid_to_entry.write().await;
            lid_map.clear();
        }
        {
            let mut pn_map = self.pn_to_entry.write().await;
            pn_map.clear();
        }
    }

    /// Get the number of LID entries in the cache.
    pub async fn lid_count(&self) -> usize {
        let lid_map = self.lid_to_entry.read().await;
        lid_map.len()
    }

    /// Get the number of phone number entries in the cache.
    pub async fn pn_count(&self) -> usize {
        let pn_map = self.pn_to_entry.read().await;
        pn_map.len()
    }
}

/// Thread-safe shared reference to the LID-PN cache
pub type SharedLidPnCache = Arc<LidPnCache>;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_operations() {
        let cache = LidPnCache::new();

        // Initially empty
        assert!(cache.get_current_lid("559980000001").await.is_none());
        assert!(cache.get_phone_number("100000012345678").await.is_none());

        // Add a mapping
        let entry = LidPnEntry::new(
            "100000012345678".to_string(),
            "559980000001".to_string(),
            LearningSource::Usync,
        );
        cache.add(entry).await;

        // Should be retrievable both ways
        assert_eq!(
            cache.get_current_lid("559980000001").await,
            Some("100000012345678".to_string())
        );
        assert_eq!(
            cache.get_phone_number("100000012345678").await,
            Some("559980000001".to_string())
        );
    }

    #[tokio::test]
    async fn test_timestamp_conflict_resolution() {
        let cache = LidPnCache::new();

        // Add old mapping
        let old_entry = LidPnEntry::with_timestamp(
            "100000012345678".to_string(),
            "559980000001".to_string(),
            1000,
            LearningSource::Other,
        );
        cache.add(old_entry).await;

        assert_eq!(
            cache.get_current_lid("559980000001").await,
            Some("100000012345678".to_string())
        );

        // Add newer mapping for same phone (different LID)
        let new_entry = LidPnEntry::with_timestamp(
            "100000087654321".to_string(),
            "559980000001".to_string(),
            2000,
            LearningSource::Usync,
        );
        cache.add(new_entry).await;

        // Should return the newer LID for PN lookup
        assert_eq!(
            cache.get_current_lid("559980000001").await,
            Some("100000087654321".to_string())
        );

        // Both LIDs should still be in the LID -> Entry map
        assert_eq!(
            cache.get_phone_number("100000012345678").await,
            Some("559980000001".to_string())
        );
        assert_eq!(
            cache.get_phone_number("100000087654321").await,
            Some("559980000001".to_string())
        );
    }

    #[tokio::test]
    async fn test_older_entry_does_not_override() {
        let cache = LidPnCache::new();

        // Add new mapping first
        let new_entry = LidPnEntry::with_timestamp(
            "100000087654321".to_string(),
            "559980000001".to_string(),
            2000,
            LearningSource::Usync,
        );
        cache.add(new_entry).await;

        // Try to add older mapping
        let old_entry = LidPnEntry::with_timestamp(
            "100000012345678".to_string(),
            "559980000001".to_string(),
            1000,
            LearningSource::Other,
        );
        cache.add(old_entry).await;

        // PN -> LID should still return the newer one
        assert_eq!(
            cache.get_current_lid("559980000001").await,
            Some("100000087654321".to_string())
        );
    }

    #[tokio::test]
    async fn test_warm_up() {
        let cache = LidPnCache::new();

        let entries = vec![
            LidPnEntry::with_timestamp(
                "lid1".to_string(),
                "pn1".to_string(),
                1,
                LearningSource::Other,
            ),
            LidPnEntry::with_timestamp(
                "lid2".to_string(),
                "pn2".to_string(),
                2,
                LearningSource::Usync,
            ),
            LidPnEntry::with_timestamp(
                "lid3".to_string(),
                "pn3".to_string(),
                3,
                LearningSource::PeerPnMessage,
            ),
        ];

        cache.warm_up(entries).await;

        assert_eq!(cache.lid_count().await, 3);
        assert_eq!(cache.pn_count().await, 3);

        assert_eq!(cache.get_current_lid("pn1").await, Some("lid1".to_string()));
        assert_eq!(cache.get_current_lid("pn2").await, Some("lid2".to_string()));
        assert_eq!(cache.get_current_lid("pn3").await, Some("lid3".to_string()));
    }

    #[tokio::test]
    async fn test_clear() {
        let cache = LidPnCache::new();

        let entry = LidPnEntry::new(
            "100000012345678".to_string(),
            "559980000001".to_string(),
            LearningSource::Usync,
        );
        cache.add(entry).await;

        assert_eq!(cache.lid_count().await, 1);
        assert_eq!(cache.pn_count().await, 1);

        cache.clear().await;

        assert_eq!(cache.lid_count().await, 0);
        assert_eq!(cache.pn_count().await, 0);
        assert!(cache.get_current_lid("559980000001").await.is_none());
    }

    #[test]
    fn test_learning_source_serialization() {
        let sources = [
            (LearningSource::Usync, "usync"),
            (LearningSource::PeerPnMessage, "peer_pn_message"),
            (LearningSource::PeerLidMessage, "peer_lid_message"),
            (LearningSource::RecipientLatestLid, "recipient_latest_lid"),
            (LearningSource::MigrationSyncLatest, "migration_sync_latest"),
            (LearningSource::MigrationSyncOld, "migration_sync_old"),
            (LearningSource::BlocklistActive, "blocklist_active"),
            (LearningSource::BlocklistInactive, "blocklist_inactive"),
            (LearningSource::Pairing, "pairing"),
            (LearningSource::Other, "other"),
        ];

        for (source, expected_str) in sources {
            assert_eq!(source.as_str(), expected_str);
            assert_eq!(LearningSource::parse(expected_str), source);
        }

        // Unknown string should map to Other
        assert_eq!(LearningSource::parse("unknown"), LearningSource::Other);
    }
}
