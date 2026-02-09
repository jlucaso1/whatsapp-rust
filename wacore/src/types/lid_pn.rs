//! LID-PN (Linked ID to Phone Number) Types
//!
//! This module provides types for mapping between WhatsApp's Linked IDs (LIDs)
//! and phone numbers. The cache is used for Signal address resolution - WhatsApp Web
//! uses LID-based addresses for Signal sessions when available.
//!
//! The cache maintains bidirectional mappings:
//! - LID -> Entry (for getting phone number from LID)
//! - Phone Number -> Entry (for getting LID from phone number)
//!
//! When multiple LIDs exist for the same phone number (rare), the most recent one
//! (by `created_at` timestamp) is considered "current".

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
    /// Mapping learned from device notification (when `lid` attribute present)
    DeviceNotification,
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
            LearningSource::DeviceNotification => "device_notification",
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
            "device_notification" => LearningSource::DeviceNotification,
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

#[cfg(test)]
mod tests {
    use super::*;

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
            (LearningSource::DeviceNotification, "device_notification"),
            (LearningSource::Other, "other"),
        ];

        for (source, expected_str) in sources {
            assert_eq!(source.as_str(), expected_str);
            assert_eq!(LearningSource::parse(expected_str), source);
        }

        // Unknown string should map to Other
        assert_eq!(LearningSource::parse("unknown"), LearningSource::Other);
    }

    #[test]
    fn test_lid_pn_entry_new() {
        let entry = LidPnEntry::new(
            "100000012345678".to_string(),
            "559980000001".to_string(),
            LearningSource::Usync,
        );

        assert_eq!(entry.lid, "100000012345678");
        assert_eq!(entry.phone_number, "559980000001");
        assert_eq!(entry.learning_source, LearningSource::Usync);
        assert!(entry.created_at > 0);
    }

    #[test]
    fn test_lid_pn_entry_with_timestamp() {
        let entry = LidPnEntry::with_timestamp(
            "100000012345678".to_string(),
            "559980000001".to_string(),
            1234567890,
            LearningSource::Pairing,
        );

        assert_eq!(entry.lid, "100000012345678");
        assert_eq!(entry.phone_number, "559980000001");
        assert_eq!(entry.created_at, 1234567890);
        assert_eq!(entry.learning_source, LearningSource::Pairing);
    }
}
