//! ADV (Advanced Device Verification) key index utilities.
//!
//! Decodes `ADVSignedKeyIndexList` protobuf from `key-index-list` elements
//! and filters device lists by `valid_indexes`.
//!
//! Reference: WAWebHandleAdvDeviceNotificationUtils.decodeSignedKeyIndexBytes()

use crate::store::traits::DeviceInfo;
use buffa::Message;

/// Decoded fields from `ADVKeyIndexList` protobuf.
#[derive(Debug, Clone)]
pub struct DecodedKeyIndex {
    pub raw_id: u32,
    pub timestamp: u64,
    pub current_index: u32,
    pub valid_indexes: Vec<u32>,
}

/// Decode signed key index bytes from a `key-index-list` element.
///
/// The bytes are an `ADVSignedKeyIndexList` protobuf whose `details` field
/// contains a serialized `ADVKeyIndexList`. Signature verification is deferred
/// (the notification arrives over a Noise-encrypted connection, so content is
/// already authenticated).
pub fn decode_key_index_list(signed_bytes: &[u8]) -> Option<DecodedKeyIndex> {
    let signed = waproto::whatsapp::ADVSignedKeyIndexList::decode_from_slice(signed_bytes).ok()?;
    let details_bytes = signed.details.as_ref()?;
    let key_index =
        waproto::whatsapp::ADVKeyIndexList::decode_from_slice(details_bytes.as_slice()).ok()?;

    let raw_id = key_index.raw_id?;
    let timestamp = key_index.timestamp?;
    let current_index = key_index.current_index.unwrap_or(0);

    Some(DecodedKeyIndex {
        raw_id,
        timestamp,
        current_index,
        valid_indexes: key_index.valid_indexes,
    })
}

/// Filter a device list using `valid_indexes` and `current_index` from an
/// `ADVKeyIndexList`, matching WA Web's filtering algorithm.
///
/// Retention rules (from `AdvDeviceNotificationApi` and `AdvKeyIndexResultApi`):
/// - Primary device (id=0): **always kept**
/// - Device with `key_index ∈ valid_indexes`: kept
/// - Device with `key_index > current_index`: kept (newer than server knows)
/// - Everything else: removed
pub fn filter_devices_by_key_index(
    devices: &[DeviceInfo],
    decoded: &DecodedKeyIndex,
) -> Vec<DeviceInfo> {
    let valid_set: std::collections::HashSet<u32> = decoded.valid_indexes.iter().copied().collect();

    devices
        .iter()
        .filter(|d| {
            // Primary device always kept
            if d.device_id == 0 {
                return true;
            }
            match d.key_index {
                Some(ki) => valid_set.contains(&ki) || ki > decoded.current_index,
                // WA Web: h.has(null) → false, null > y → false → device removed
                None => false,
            }
        })
        .cloned()
        .collect()
}

/// Check if a key_index is accepted by the decoded ADV list.
/// Used to validate a newly-notified device before adding it to the registry.
///
/// WA Web `AdvDeviceNotificationApi`: device added only if
/// `keyIndex != null && (validIndexes.has(keyIndex) || keyIndex > currentIndex)`
pub fn is_key_index_valid(key_index: Option<u32>, decoded: &DecodedKeyIndex) -> bool {
    match key_index {
        Some(ki) => decoded.valid_indexes.contains(&ki) || ki > decoded.current_index,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dev(id: u32, key_index: Option<u32>) -> DeviceInfo {
        DeviceInfo {
            device_id: id,
            key_index,
        }
    }

    #[test]
    fn primary_device_always_kept() {
        let devices = vec![dev(0, None), dev(5, Some(3))];
        let decoded = DecodedKeyIndex {
            raw_id: 1,
            timestamp: 100,
            current_index: 10,
            valid_indexes: vec![], // empty — nothing valid
        };
        let result = filter_devices_by_key_index(&devices, &decoded);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].device_id, 0);
    }

    #[test]
    fn valid_index_kept_invalid_removed() {
        let devices = vec![dev(0, None), dev(11, Some(5)), dev(12, Some(7))];
        let decoded = DecodedKeyIndex {
            raw_id: 1,
            timestamp: 100,
            current_index: 10,
            valid_indexes: vec![7], // only key_index=7 is valid
        };
        let result = filter_devices_by_key_index(&devices, &decoded);
        assert_eq!(result.len(), 2); // device 0 + device 12
        assert!(result.iter().any(|d| d.device_id == 0));
        assert!(result.iter().any(|d| d.device_id == 12));
        assert!(!result.iter().any(|d| d.device_id == 11));
    }

    #[test]
    fn device_newer_than_current_index_kept() {
        let devices = vec![dev(0, None), dev(15, Some(20))];
        let decoded = DecodedKeyIndex {
            raw_id: 1,
            timestamp: 100,
            current_index: 10,
            valid_indexes: vec![7],
        };
        let result = filter_devices_by_key_index(&devices, &decoded);
        assert_eq!(result.len(), 2); // device 0 + device 15 (key_index 20 > current 10)
    }

    #[test]
    fn device_without_key_index_removed() {
        // WA Web: h.has(null) → false, null > y → false → device removed
        let devices = vec![dev(0, None), dev(5, None)];
        let decoded = DecodedKeyIndex {
            raw_id: 1,
            timestamp: 100,
            current_index: 10,
            valid_indexes: vec![7],
        };
        let result = filter_devices_by_key_index(&devices, &decoded);
        assert_eq!(result.len(), 1); // only primary device kept
        assert_eq!(result[0].device_id, 0);
    }

    #[test]
    fn is_key_index_valid_in_valid_set() {
        let decoded = DecodedKeyIndex {
            raw_id: 1,
            timestamp: 100,
            current_index: 5,
            valid_indexes: vec![3, 7],
        };
        assert!(is_key_index_valid(Some(3), &decoded));
        assert!(is_key_index_valid(Some(7), &decoded));
    }

    #[test]
    fn is_key_index_valid_not_in_valid_set() {
        let decoded = DecodedKeyIndex {
            raw_id: 1,
            timestamp: 100,
            current_index: 5,
            valid_indexes: vec![3, 7],
        };
        assert!(!is_key_index_valid(Some(4), &decoded));
    }

    #[test]
    fn is_key_index_valid_newer_than_current() {
        let decoded = DecodedKeyIndex {
            raw_id: 1,
            timestamp: 100,
            current_index: 5,
            valid_indexes: vec![3],
        };
        assert!(is_key_index_valid(Some(10), &decoded));
    }

    #[test]
    fn is_key_index_valid_none_rejected() {
        let decoded = DecodedKeyIndex {
            raw_id: 1,
            timestamp: 100,
            current_index: 5,
            valid_indexes: vec![3, 7],
        };
        assert!(!is_key_index_valid(None, &decoded));
    }

    #[test]
    fn decode_roundtrip() {
        use buffa::Message;

        let key_index = waproto::whatsapp::ADVKeyIndexList {
            raw_id: Some(42),
            timestamp: Some(1000),
            current_index: Some(5),
            valid_indexes: vec![3, 5, 7],
            ..Default::default()
        };
        let details = key_index.encode_to_vec();

        let signed = waproto::whatsapp::ADVSignedKeyIndexList {
            details: Some(details),
            ..Default::default()
        };
        let bytes = signed.encode_to_vec();

        let decoded = decode_key_index_list(&bytes).unwrap();
        assert_eq!(decoded.raw_id, 42);
        assert_eq!(decoded.timestamp, 1000);
        assert_eq!(decoded.current_index, 5);
        assert_eq!(decoded.valid_indexes, vec![3, 5, 7]);
    }
}
