//! Pure helpers for notification stanza parsing.
//!
//! The notification handler (`whatsapp-rust/src/handlers/notification.rs`) is
//! tightly coupled to `Client` -- every handler dispatches events via
//! `client.core.event_bus`, accesses caches, spawns tasks, etc.  The actual
//! notification type parsing is already delegated to typed parsers in sibling
//! modules (`DeviceNotification`, `GroupNotification`, `BusinessNotification`).
//!
//! This module exposes the small remaining pure helpers that were inlined in
//! the handler.  If more parsing logic is added to the handler in the future,
//! it should be extracted here as pure functions.

use wacore_binary::node::Node;

/// Extract a notification timestamp from a node's `t` attribute.
///
/// Parses the `t` attribute as a Unix timestamp (seconds) and converts to
/// a `chrono::DateTime<Utc>`. Falls back to `crate::time::now_utc()` if the attribute
/// is missing or cannot be parsed.
pub fn notification_timestamp(node: &Node) -> chrono::DateTime<chrono::Utc> {
    node.attrs()
        .optional_u64("t")
        .and_then(|t| chrono::DateTime::from_timestamp(t as i64, 0))
        .unwrap_or_else(crate::time::now_utc)
}

/// Parse a `<disappearing_mode>` child from a notification node.
///
/// Returns `(duration, setting_timestamp)` or `None` if the child is missing
/// or the required `t` attribute is absent.
///
/// - `duration`: seconds (0 = disabled). Defaults to 0 if attribute is missing
///   (matches WA Web's `attrInt("duration", 0)`).
/// - `setting_timestamp`: Unix timestamp, required (WA Web: `attrTime("t")`).
pub fn parse_disappearing_mode(node: &Node) -> Option<(u32, u64)> {
    let dm_node = node.get_optional_child("disappearing_mode")?;
    let mut dm_attrs = dm_node.attrs();
    let duration = dm_attrs
        .optional_string("duration")
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    let setting_timestamp = dm_attrs
        .optional_string("t")
        .and_then(|s| s.parse::<u64>().ok())?;
    Some((duration, setting_timestamp))
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;

    #[test]
    fn notification_timestamp_with_valid_t() {
        let node = NodeBuilder::new("notification")
            .attr("t", "1773519041")
            .build();
        let ts = notification_timestamp(&node);
        assert_eq!(ts.timestamp(), 1773519041);
    }

    #[test]
    fn notification_timestamp_missing_t() {
        let node = NodeBuilder::new("notification").build();
        let ts = notification_timestamp(&node);
        // Should fall back to approximately now
        let now = crate::time::now_secs();
        assert!((ts.timestamp() - now).abs() < 2);
    }

    #[test]
    fn parse_disappearing_mode_valid() {
        let node = NodeBuilder::new("notification")
            .children([NodeBuilder::new("disappearing_mode")
                .attr("duration", "86400")
                .attr("t", "1773519041")
                .build()])
            .build();
        let (duration, ts) = parse_disappearing_mode(&node).unwrap();
        assert_eq!(duration, 86400);
        assert_eq!(ts, 1773519041);
    }

    #[test]
    fn parse_disappearing_mode_disabled() {
        let node = NodeBuilder::new("notification")
            .children([NodeBuilder::new("disappearing_mode")
                .attr("duration", "0")
                .attr("t", "1773519041")
                .build()])
            .build();
        let (duration, _) = parse_disappearing_mode(&node).unwrap();
        assert_eq!(duration, 0);
    }

    #[test]
    fn parse_disappearing_mode_missing_child() {
        let node = NodeBuilder::new("notification").build();
        assert!(parse_disappearing_mode(&node).is_none());
    }

    #[test]
    fn parse_disappearing_mode_missing_timestamp() {
        let node = NodeBuilder::new("notification")
            .children([NodeBuilder::new("disappearing_mode")
                .attr("duration", "86400")
                .build()])
            .build();
        assert!(parse_disappearing_mode(&node).is_none());
    }

    #[test]
    fn parse_disappearing_mode_missing_duration_defaults_to_zero() {
        let node = NodeBuilder::new("notification")
            .children([NodeBuilder::new("disappearing_mode")
                .attr("t", "1773519041")
                .build()])
            .build();
        let (duration, _) = parse_disappearing_mode(&node).unwrap();
        assert_eq!(duration, 0);
    }
}
