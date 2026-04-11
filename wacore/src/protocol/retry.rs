//! Pure helpers for retry receipt protocol logic.
//!
//! Constants and utility functions for parsing retry receipts. These have no
//! runtime dependencies (`self`, `Client`, spawn, sleep). All orchestration
//! (session management, message resend, cache interaction) remains in
//! `whatsapp-rust/src/retry.rs`.

use wacore_binary::node::{Node, NodeContent};

/// Maximum retry attempts we'll honor (matches WhatsApp Web's MAX_RETRY = 5).
/// We refuse to resend if the requester has already retried this many times.
pub const MAX_RETRY_COUNT: u8 = 5;

/// Minimum retry count before we include keys in retry receipts.
/// WhatsApp Web only includes keys when retryCount >= 2, giving the first
/// retry a chance to succeed without key exchange overhead.
pub const MIN_RETRY_COUNT_FOR_KEYS: u8 = 2;

/// Minimum retry count before we start tracking base keys.
/// WhatsApp Web saves base key on retry 2, checks on retry > 2.
pub const MIN_RETRY_FOR_BASE_KEY_CHECK: u8 = 2;

/// Retry reason codes matching WhatsApp Web's RetryReason enum.
/// These are included in the retry receipt to help the sender understand
/// why the message couldn't be decrypted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
#[allow(dead_code)] // All variants defined for WhatsApp Web compatibility
pub enum RetryReason {
    /// Unknown or unspecified error
    UnknownError = 0,
    /// No session exists with the sender (SessionNotFound)
    NoSession = 1,
    /// Invalid key in the message
    InvalidKey = 2,
    /// PreKey ID not found (InvalidPreKeyId)
    InvalidKeyId = 3,
    /// Invalid message format or content (InvalidMessage)
    InvalidMessage = 4,
    /// Invalid signature
    InvalidSignature = 5,
    /// Message from the future (timestamp issue)
    FutureMessage = 6,
    /// MAC verification failed (bad MAC)
    BadMac = 7,
    /// Invalid session state
    InvalidSession = 8,
    /// Invalid message key
    InvalidMsgKey = 9,
    /// Bad broadcast ephemeral setting
    BadBroadcastEphemeralSetting = 10,
    /// Unknown companion device, not in our device list
    UnknownCompanionNoPrekey = 11,
    /// ADV signature or device identity failure
    AdvFailure = 12,
    /// Status revoke delay exceeded
    StatusRevokeDelay = 13,
}

/// Helper to extract bytes content from a Node.
pub fn get_bytes_content(node: &Node) -> Option<&[u8]> {
    match &node.content {
        Some(NodeContent::Bytes(b)) => Some(b.as_slice()),
        _ => None,
    }
}

/// Helper to extract registration ID from a node (4 bytes big-endian).
///
/// Looks for a `<registration>` child node and parses its bytes content
/// as a big-endian `u32`. Handles variable-length encoding (1-4 bytes)
/// by zero-padding on the left.
pub fn extract_registration_id_from_node(node: &Node) -> Option<u32> {
    let registration_node = node.get_optional_child("registration")?;
    let bytes = get_bytes_content(registration_node)?;

    if bytes.len() == 4 {
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    } else if bytes.len() > 4 {
        // Registration IDs are u32; reject oversized payloads rather than silently truncating.
        None
    } else if !bytes.is_empty() {
        // Handle variable-length encoding.
        let mut arr = [0u8; 4];
        let start = 4 - bytes.len();
        arr[start..].copy_from_slice(bytes);
        Some(u32::from_be_bytes(arr))
    } else {
        None
    }
}

/// Returns whether keys should be included in a retry receipt for the given
/// retry count and reason.
///
/// WhatsApp Web only includes keys when `retryCount >= 2`. As an optimization,
/// keys are included on retry #1 for `NoSession` errors to reduce round-trips
/// for skmsg-only message failures.
pub fn should_include_keys(retry_count: u8, reason: RetryReason) -> bool {
    let include_keys_early =
        reason == RetryReason::NoSession || reason == RetryReason::UnknownCompanionNoPrekey;
    retry_count >= MIN_RETRY_COUNT_FOR_KEYS || include_keys_early
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::borrow::Cow;
    use wacore_binary::node::Attrs;

    #[test]
    fn get_bytes_content_extracts_bytes() {
        let node = Node {
            tag: Cow::Borrowed("test"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Bytes(vec![1, 2, 3, 4])),
        };
        assert_eq!(get_bytes_content(&node), Some(&[1, 2, 3, 4][..]));
    }

    #[test]
    fn get_bytes_content_returns_none_for_string() {
        let node = Node {
            tag: Cow::Borrowed("test"),
            attrs: Attrs::new(),
            content: Some(NodeContent::String("hello".into())),
        };
        assert_eq!(get_bytes_content(&node), None);
    }

    #[test]
    fn get_bytes_content_returns_none_for_empty() {
        let node = Node {
            tag: Cow::Borrowed("test"),
            attrs: Attrs::new(),
            content: None,
        };
        assert_eq!(get_bytes_content(&node), None);
    }

    #[test]
    fn extract_registration_id_4_bytes() {
        let reg_node = Node {
            tag: Cow::Borrowed("registration"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Bytes(vec![0x00, 0x01, 0x02, 0x03])),
        };
        let parent = Node {
            tag: Cow::Borrowed("receipt"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![reg_node])),
        };
        assert_eq!(extract_registration_id_from_node(&parent), Some(0x00010203));
    }

    #[test]
    fn extract_registration_id_3_bytes() {
        let reg_node = Node {
            tag: Cow::Borrowed("registration"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Bytes(vec![0x01, 0x02, 0x03])),
        };
        let parent = Node {
            tag: Cow::Borrowed("receipt"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![reg_node])),
        };
        assert_eq!(extract_registration_id_from_node(&parent), Some(0x00010203));
    }

    #[test]
    fn extract_registration_id_missing() {
        let parent = Node {
            tag: Cow::Borrowed("receipt"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![])),
        };
        assert_eq!(extract_registration_id_from_node(&parent), None);
    }

    #[test]
    fn extract_registration_id_empty_bytes() {
        let reg_node = Node {
            tag: Cow::Borrowed("registration"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Bytes(vec![])),
        };
        let parent = Node {
            tag: Cow::Borrowed("receipt"),
            attrs: Attrs::new(),
            content: Some(NodeContent::Nodes(vec![reg_node])),
        };
        assert_eq!(extract_registration_id_from_node(&parent), None);
    }

    #[test]
    fn should_include_keys_no_session_retry_1() {
        assert!(
            should_include_keys(1, RetryReason::NoSession),
            "NoSession at retry#1 should include keys (optimization)"
        );
    }

    #[test]
    fn should_include_keys_unknown_companion_retry_1() {
        assert!(
            should_include_keys(1, RetryReason::UnknownCompanionNoPrekey),
            "UnknownCompanionNoPrekey at retry#1 should include keys"
        );
    }

    #[test]
    fn should_include_keys_invalid_message_retry_1() {
        assert!(
            !should_include_keys(1, RetryReason::InvalidMessage),
            "InvalidMessage at retry#1 should NOT include keys"
        );
    }

    #[test]
    fn should_include_keys_retry_2_any_reason() {
        assert!(should_include_keys(2, RetryReason::InvalidMessage));
        assert!(should_include_keys(2, RetryReason::UnknownError));
        assert!(should_include_keys(2, RetryReason::BadMac));
        assert!(should_include_keys(2, RetryReason::NoSession));
    }

    #[test]
    fn should_include_keys_retry_3_any_reason() {
        assert!(should_include_keys(3, RetryReason::InvalidMessage));
        assert!(should_include_keys(3, RetryReason::UnknownError));
    }

    #[test]
    fn constants_match_wa_web() {
        assert_eq!(MAX_RETRY_COUNT, 5);
        assert_eq!(MIN_RETRY_COUNT_FOR_KEYS, 2);
        assert_eq!(MIN_RETRY_FOR_BASE_KEY_CHECK, 2);
    }
}
