//! Device notification stanza types.
//!
//! Parses `<notification type="devices">` stanzas for device add/remove/update.
//!
//! Reference: WhatsApp Web `WAWebHandleDeviceNotification` (5Yec01dI04o.js:23109-23305)
//!
//! Key behaviors:
//! - Only ONE operation per notification (priority: remove > add > update)
//! - `key-index-list` is REQUIRED for add/remove
//! - Timestamp is REQUIRED (non-zero) for remove
//! - `hash` attribute is REQUIRED for update

use crate::StringEnum;
use crate::iq::node::{optional_attr, optional_child, required_attr, required_child};
use crate::protocol::ProtocolNode;
use anyhow::{Result, anyhow};
use serde::Serialize;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::{Node, NodeContent};

/// Device notification operation type.
///
/// Wire format: Child element tag of `<notification type="devices">`
/// - `<add>` - Device was added
/// - `<remove>` - Device was removed
/// - `<update>` - Device info updated (hash-based lookup)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, StringEnum)]
pub enum DeviceNotificationType {
    #[str = "add"]
    Add,
    #[str = "remove"]
    Remove,
    #[str = "update"]
    Update,
}

/// Key index information from `<key-index-list>` element.
///
/// Wire format:
/// ```xml
/// <!-- For add: has signed bytes content -->
/// <key-index-list ts="1769296600">SIGNED_BYTES</key-index-list>
/// <!-- For remove: empty, ts required -->
/// <key-index-list ts="1769296600"/>
/// ```
///
/// Required for add/remove operations per WhatsApp Web.
#[derive(Debug, Clone, Serialize)]
pub struct KeyIndexInfo {
    /// Timestamp (required for remove per WhatsApp Web)
    pub timestamp: i64,
    /// Signed key index bytes (only present for add)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signed_bytes: Option<Vec<u8>>,
}

impl ProtocolNode for KeyIndexInfo {
    fn tag(&self) -> &'static str {
        "key-index-list"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("key-index-list").attr("ts", self.timestamp.to_string());
        if let Some(bytes) = self.signed_bytes {
            builder = builder.bytes(bytes);
        }
        builder.build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "key-index-list" {
            return Err(anyhow!("expected <key-index-list>, got <{}>", node.tag));
        }
        let ts_u64 = node
            .attrs()
            .optional_u64("ts")
            .ok_or_else(|| anyhow!("key-index-list missing required 'ts' attribute"))?;
        let timestamp = i64::try_from(ts_u64)
            .map_err(|_| anyhow!("key-index-list 'ts' value {} exceeds i64::MAX", ts_u64))?;
        let signed_bytes = match &node.content {
            Some(NodeContent::Bytes(b)) if !b.is_empty() => Some(b.clone()),
            _ => None,
        };
        Ok(Self {
            timestamp,
            signed_bytes,
        })
    }
}

/// Device element from notification.
///
/// Wire format:
/// ```xml
/// <device jid="185169143189667:75@lid" key-index="2" lid="..."/>
/// ```
///
/// Device ID is extracted from the JID's device part (e.g., 75 from "user:75@lid").
///
/// Per WhatsApp Web: if both `jid` and `lid` attributes are present, the device IDs
/// must match or the notification is rejected.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceElement {
    /// Device JID (contains user and device ID)
    pub jid: Jid,
    /// Optional key index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_index: Option<u32>,
    /// Optional LID (device ID must match jid's device ID if present)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lid: Option<Jid>,
}

impl DeviceElement {
    /// Extract the device ID from the JID.
    #[inline]
    pub fn device_id(&self) -> u32 {
        self.jid.device as u32
    }
}

impl ProtocolNode for DeviceElement {
    fn tag(&self) -> &'static str {
        "device"
    }

    fn into_node(self) -> Node {
        let mut builder = NodeBuilder::new("device").attr("jid", self.jid.to_string());
        if let Some(ki) = self.key_index {
            builder = builder.attr("key-index", ki.to_string());
        }
        if let Some(lid) = self.lid {
            builder = builder.attr("lid", lid.to_string());
        }
        builder.build()
    }

    fn try_from_node(node: &Node) -> Result<Self> {
        if node.tag != "device" {
            return Err(anyhow!("expected <device>, got <{}>", node.tag));
        }
        let jid = node
            .attrs()
            .optional_jid("jid")
            .ok_or_else(|| anyhow!("device missing required 'jid' attribute"))?;

        // Parse key-index with checked conversion (u64 -> u32)
        let key_index = match node.attrs().optional_u64("key-index") {
            Some(v) => Some(
                u32::try_from(v)
                    .map_err(|_| anyhow!("device 'key-index' value {} exceeds u32::MAX", v))?,
            ),
            None => None,
        };

        let lid = node.attrs().optional_jid("lid");

        // Per WhatsApp Web: validate device ID matches between jid and lid attributes
        // Reference: 5Yec01dI04o.js:23169-23175
        if let Some(ref lid_jid) = lid {
            let jid_device_id = jid.device;
            let lid_device_id = lid_jid.device;
            if jid_device_id != lid_device_id {
                return Err(anyhow!(
                    "device id mismatch between jid ({}) and lid ({}) attributes",
                    jid_device_id,
                    lid_device_id
                ));
            }
        }

        Ok(Self {
            jid,
            key_index,
            lid,
        })
    }
}

/// Operation content (add/remove/update child element).
///
/// Wire format per WhatsApp Web (5Yec01dI04o.js:23141-23180):
/// ```xml
/// <add>
///   <device jid="user:75@lid" key-index="2"/>
///   <key-index-list ts="...">SIGNED_BYTES</key-index-list>
/// </add>
/// <!-- OR -->
/// <remove>
///   <device jid="user:75@lid"/>
///   <key-index-list ts="..."/>  <!-- ts required for remove -->
/// </remove>
/// <!-- OR -->
/// <update hash="CONTACT_HASH"/>
/// ```
///
/// Note: WhatsApp Web does NOT read any attributes from add/remove nodes.
/// The `device_hash` attribute (if present) is not used by the official client.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceOperation {
    /// Operation type (add/remove/update)
    pub operation_type: DeviceNotificationType,
    /// Contact hash (for update only) - from `hash` attribute, used for contact lookup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_hash: Option<String>,
    /// Device elements (for add/remove, single device per WhatsApp Web)
    pub devices: Vec<DeviceElement>,
    /// Key index info (required for add/remove per WhatsApp Web)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_index: Option<KeyIndexInfo>,
}

impl DeviceOperation {
    /// Parse from an add/remove/update child node.
    ///
    /// Per WhatsApp Web (5Yec01dI04o.js:23141-23157):
    /// - `key-index-list` is REQUIRED for add/remove operations
    /// - `ts` attribute is REQUIRED for remove operations
    pub fn try_from_child(node: &Node) -> Result<Self> {
        let operation_type = DeviceNotificationType::try_from(node.tag.as_str())
            .map_err(|_| anyhow!("unknown device operation: {}", node.tag))?;

        match operation_type {
            DeviceNotificationType::Add | DeviceNotificationType::Remove => {
                // Per WhatsApp Web: key-index-list is required for add/remove
                let key_index_node = required_child(node, "key-index-list")?;
                let key_index = KeyIndexInfo::try_from_node(key_index_node)?;

                // Per WhatsApp Web: timestamp is required for remove
                if operation_type == DeviceNotificationType::Remove && key_index.timestamp == 0 {
                    return Err(anyhow!(
                        "timestamp is required to handle device remove notification"
                    ));
                }

                // Parse device element
                let device_node = required_child(node, "device")?;
                let device = DeviceElement::try_from_node(device_node)?;

                Ok(Self {
                    operation_type,
                    contact_hash: None,
                    devices: vec![device],
                    key_index: Some(key_index),
                })
            }
            DeviceNotificationType::Update => {
                // Per WhatsApp Web: hash attribute is REQUIRED for update
                // Uses attrString (not maybeAttrString) which throws if missing
                let contact_hash = required_attr(node, "hash")?;

                Ok(Self {
                    operation_type,
                    contact_hash: Some(contact_hash),
                    devices: Vec::new(),
                    key_index: None,
                })
            }
        }
    }

    /// Get device IDs as a Vec (convenience method for logging).
    pub fn device_ids(&self) -> Vec<u32> {
        self.devices.iter().map(|d| d.device_id()).collect()
    }
}

/// Parsed device notification stanza.
///
/// Wire format:
/// ```xml
/// <notification from="185169143189667@lid" id="..." t="..." type="devices" lid="...">
///   <remove>
///     <device jid="185169143189667:75@lid"/>
///     <key-index-list ts="1769296600"/>
///   </remove>
/// </notification>
/// ```
///
/// Reference: WhatsApp Web `WAWebHandleDeviceNotification` parser (5Yec01dI04o.js:23125-23183)
///
/// Per WhatsApp Web: Only ONE operation per notification is processed.
/// Priority order: remove > add > update
#[derive(Debug, Clone, Serialize)]
pub struct DeviceNotification {
    /// User JID (from attribute)
    pub from: Jid,
    /// Optional LID user (for LID-PN mapping learning)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lid_user: Option<Jid>,
    /// Stanza ID (for ACK)
    pub stanza_id: String,
    /// Timestamp
    pub timestamp: i64,
    /// The operation (one per notification, priority: remove > add > update)
    pub operation: DeviceOperation,
}

impl DeviceNotification {
    /// Parse from a `<notification type="devices">` node.
    ///
    /// Per WhatsApp Web: Only ONE operation per notification is processed.
    /// Priority order: remove > add > update
    /// Returns error if no operation is found.
    pub fn try_parse(node: &Node) -> Result<Self> {
        if node.tag != "notification" {
            return Err(anyhow!("expected <notification>, got <{}>", node.tag));
        }
        if optional_attr(node, "type") != Some("devices") {
            return Err(anyhow!("expected type='devices'"));
        }

        let from = node
            .attrs()
            .optional_jid("from")
            .ok_or_else(|| anyhow!("notification missing required 'from' attribute"))?;
        let lid_user = node.attrs().optional_jid("lid");
        let stanza_id = optional_attr(node, "id")
            .map(String::from)
            .unwrap_or_default();

        // Parse timestamp with checked conversion
        let timestamp = match node.attrs().optional_u64("t") {
            Some(t) => i64::try_from(t)
                .map_err(|_| anyhow!("notification timestamp {} exceeds i64::MAX", t))?,
            None => 0,
        };

        // Per WhatsApp Web: Priority order is remove > add > update
        // Only one operation is processed per notification
        let operation = if let Some(remove_node) = optional_child(node, "remove") {
            DeviceOperation::try_from_child(remove_node)?
        } else if let Some(add_node) = optional_child(node, "add") {
            DeviceOperation::try_from_child(add_node)?
        } else if let Some(update_node) = optional_child(node, "update") {
            DeviceOperation::try_from_child(update_node)?
        } else {
            return Err(anyhow!(
                "device notification missing required operation (add/remove/update)"
            ));
        };

        Ok(Self {
            from,
            lid_user,
            stanza_id,
            timestamp,
            operation,
        })
    }

    /// Get the user string for cache operations.
    #[inline]
    pub fn user(&self) -> &str {
        &self.from.user
    }

    /// Check if this notification provides a LID-PN mapping to learn.
    ///
    /// Returns `Some((lid, pn))` if:
    /// - `lid` attribute is present and is a LID
    /// - `from` attribute is a phone number (not LID)
    ///
    /// Per WhatsApp Web: mappings are learned when both are present.
    pub fn lid_pn_mapping(&self) -> Option<(&str, &str)> {
        let lid = self.lid_user.as_ref()?;
        if !self.from.is_lid() && lid.is_lid() {
            Some((&lid.user, &self.from.user))
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::builder::NodeBuilder;

    #[test]
    fn test_device_notification_type_as_str() {
        assert_eq!(DeviceNotificationType::Add.as_str(), "add");
        assert_eq!(DeviceNotificationType::Remove.as_str(), "remove");
        assert_eq!(DeviceNotificationType::Update.as_str(), "update");
    }

    #[test]
    fn test_device_notification_type_try_from() {
        assert_eq!(
            DeviceNotificationType::try_from("add").unwrap(),
            DeviceNotificationType::Add
        );
        assert_eq!(
            DeviceNotificationType::try_from("remove").unwrap(),
            DeviceNotificationType::Remove
        );
        assert!(DeviceNotificationType::try_from("invalid").is_err());
    }

    #[test]
    fn test_parse_remove_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "185169143189667@lid")
            .attr("id", "511477682")
            .attr("t", "1769296817")
            .children([NodeBuilder::new("remove")
                .children([
                    NodeBuilder::new("device")
                        .attr("jid", "185169143189667:75@lid")
                        .build(),
                    NodeBuilder::new("key-index-list")
                        .attr("ts", "1769296600")
                        .build(),
                ])
                .build()])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        assert_eq!(parsed.from.user, "185169143189667");
        assert_eq!(parsed.stanza_id, "511477682");
        assert_eq!(parsed.timestamp, 1769296817);

        let op = &parsed.operation;
        assert_eq!(op.operation_type, DeviceNotificationType::Remove);
        assert_eq!(op.devices.len(), 1);
        assert_eq!(op.devices[0].device_id(), 75);
        assert_eq!(op.key_index.as_ref().unwrap().timestamp, 1769296600);
        assert!(op.key_index.as_ref().unwrap().signed_bytes.is_none());
    }

    #[test]
    fn test_parse_add_notification_with_key_bytes() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("lid", "100000000000001@lid")
            .attr("id", "123")
            .attr("t", "1000")
            .children([NodeBuilder::new("add")
                .children([
                    NodeBuilder::new("device")
                        .attr("jid", "15551234567:64@s.whatsapp.net")
                        .attr("key-index", "5")
                        .build(),
                    NodeBuilder::new("key-index-list")
                        .attr("ts", "999")
                        .bytes(vec![0x01, 0x02, 0x03])
                        .build(),
                ])
                .build()])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();

        // Check LID-PN mapping detection
        let (lid, pn) = parsed.lid_pn_mapping().unwrap();
        assert_eq!(lid, "100000000000001");
        assert_eq!(pn, "15551234567");

        let op = &parsed.operation;
        assert_eq!(op.operation_type, DeviceNotificationType::Add);
        assert_eq!(op.devices[0].device_id(), 64);
        assert_eq!(op.devices[0].key_index, Some(5));
        assert_eq!(
            op.key_index.as_ref().unwrap().signed_bytes,
            Some(vec![0x01, 0x02, 0x03])
        );
    }

    #[test]
    fn test_parse_update_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "456")
            .attr("t", "2000")
            .children([NodeBuilder::new("update")
                .attr("hash", "contact_hash_value")
                .build()])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();

        let op = &parsed.operation;
        assert_eq!(op.operation_type, DeviceNotificationType::Update);
        assert_eq!(op.contact_hash, Some("contact_hash_value".to_string()));
        assert!(op.devices.is_empty());
    }

    #[test]
    fn test_lid_pn_mapping_not_detected_when_from_is_lid() {
        // When from is a LID, we shouldn't learn a LID->PN mapping
        // (both are LIDs, no phone number to learn)
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "185169143189667@lid")
            .attr("lid", "185169143189667@lid")
            .attr("id", "123")
            .attr("t", "1000")
            .children([NodeBuilder::new("update").attr("hash", "test_hash").build()])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        // No mapping should be detected when from is also a LID
        assert!(parsed.lid_pn_mapping().is_none());
    }

    #[test]
    fn test_missing_key_index_list_fails() {
        // Per WhatsApp Web: key-index-list is required for add/remove
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123")
            .attr("t", "1000")
            .children([NodeBuilder::new("add")
                .children([NodeBuilder::new("device")
                    .attr("jid", "15551234567:64@s.whatsapp.net")
                    .build()])
                .build()])
            .build();

        let result = DeviceNotification::try_parse(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key-index-list"));
    }

    #[test]
    fn test_remove_without_timestamp_fails() {
        // Per WhatsApp Web: timestamp is required for remove
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123")
            .attr("t", "1000")
            .children([NodeBuilder::new("remove")
                .children([
                    NodeBuilder::new("device")
                        .attr("jid", "15551234567:64@s.whatsapp.net")
                        .build(),
                    NodeBuilder::new("key-index-list")
                        .attr("ts", "0") // Zero timestamp should fail for remove
                        .build(),
                ])
                .build()])
            .build();

        let result = DeviceNotification::try_parse(&node);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("timestamp is required")
        );
    }

    #[test]
    fn test_device_id_mismatch_fails() {
        // Per WhatsApp Web: device ID must match between jid and lid attributes
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123")
            .attr("t", "1000")
            .children([NodeBuilder::new("add")
                .children([
                    NodeBuilder::new("device")
                        .attr("jid", "15551234567:64@s.whatsapp.net")
                        .attr("lid", "100000000000001:99@lid") // Different device ID
                        .build(),
                    NodeBuilder::new("key-index-list").attr("ts", "999").build(),
                ])
                .build()])
            .build();

        let result = DeviceNotification::try_parse(&node);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("device id mismatch")
        );
    }

    #[test]
    fn test_device_with_matching_lid() {
        // Device IDs match - should succeed
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123")
            .attr("t", "1000")
            .children([NodeBuilder::new("add")
                .children([
                    NodeBuilder::new("device")
                        .attr("jid", "15551234567:64@s.whatsapp.net")
                        .attr("lid", "100000000000001:64@lid") // Same device ID
                        .build(),
                    NodeBuilder::new("key-index-list").attr("ts", "999").build(),
                ])
                .build()])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        assert_eq!(parsed.operation.devices[0].device_id(), 64);
        assert!(parsed.operation.devices[0].lid.is_some());
    }

    #[test]
    fn test_no_operation_fails() {
        // Per WhatsApp Web: at least one operation (add/remove/update) is required
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123")
            .attr("t", "1000")
            .build(); // No operation children

        let result = DeviceNotification::try_parse(&node);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("missing required operation")
        );
    }

    #[test]
    fn test_remove_priority_over_add() {
        // Per WhatsApp Web: priority is remove > add > update
        // If both remove and add are present, remove should be processed
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123")
            .attr("t", "1000")
            .children([
                NodeBuilder::new("add")
                    .children([
                        NodeBuilder::new("device")
                            .attr("jid", "15551234567:64@s.whatsapp.net")
                            .build(),
                        NodeBuilder::new("key-index-list").attr("ts", "999").build(),
                    ])
                    .build(),
                NodeBuilder::new("remove")
                    .children([
                        NodeBuilder::new("device")
                            .attr("jid", "15551234567:75@s.whatsapp.net")
                            .build(),
                        NodeBuilder::new("key-index-list").attr("ts", "888").build(),
                    ])
                    .build(),
            ])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        // Should process remove, not add
        assert_eq!(
            parsed.operation.operation_type,
            DeviceNotificationType::Remove
        );
        assert_eq!(parsed.operation.devices[0].device_id(), 75);
    }

    #[test]
    fn test_update_without_hash_fails() {
        // Per WhatsApp Web: hash attribute is required for update
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "123")
            .attr("t", "1000")
            .children([NodeBuilder::new("update").build()]) // Missing hash attribute
            .build();

        let result = DeviceNotification::try_parse(&node);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash"));
    }
}
