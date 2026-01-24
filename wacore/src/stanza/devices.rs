use crate::StringEnum;
use crate::iq::node::{collect_children_lenient, optional_attr, optional_child};
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
        let timestamp = node
            .attrs()
            .optional_u64("ts")
            .ok_or_else(|| anyhow!("key-index-list missing required 'ts' attribute"))?
            as i64;
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
#[derive(Debug, Clone, Serialize)]
pub struct DeviceElement {
    /// Device JID (contains user and device ID)
    pub jid: Jid,
    /// Optional key index
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_index: Option<u32>,
    /// Optional LID (should match jid device ID if present)
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
        let key_index = node.attrs().optional_u64("key-index").map(|v| v as u32);
        let lid = node.attrs().optional_jid("lid");
        Ok(Self {
            jid,
            key_index,
            lid,
        })
    }
}

/// Operation content (add/remove/update child element).
///
/// Wire format:
/// ```xml
/// <add device_hash="2:nivm0MNH">
///   <device jid="user:75@lid"/>
///   <key-index-list ts="...">SIGNED_BYTES</key-index-list>
/// </add>
/// <!-- OR -->
/// <remove device_hash="2:nivm0MNH">
///   <device jid="user:75@lid"/>
///   <key-index-list ts="..."/>
/// </remove>
/// <!-- OR -->
/// <update hash="CONTACT_HASH"/>
/// ```
#[derive(Debug, Clone, Serialize)]
pub struct DeviceOperation {
    /// Operation type (add/remove/update)
    pub operation_type: DeviceNotificationType,
    /// Device hash (for add/remove) - from `device_hash` attribute
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_hash: Option<String>,
    /// Contact hash (for update) - from `hash` attribute, used for contact lookup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contact_hash: Option<String>,
    /// Device elements (for add/remove)
    pub devices: Vec<DeviceElement>,
    /// Key index info (required for add/remove)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_index: Option<KeyIndexInfo>,
}

impl DeviceOperation {
    /// Parse from an add/remove/update child node.
    pub fn try_from_child(node: &Node) -> Result<Self> {
        let operation_type = DeviceNotificationType::try_from(node.tag.as_str())
            .map_err(|_| anyhow!("unknown device operation: {}", node.tag))?;

        let (device_hash, contact_hash) = match operation_type {
            DeviceNotificationType::Add | DeviceNotificationType::Remove => {
                (optional_attr(node, "device_hash").map(String::from), None)
            }
            DeviceNotificationType::Update => (None, optional_attr(node, "hash").map(String::from)),
        };

        let devices = collect_children_lenient::<DeviceElement>(node, "device");

        let key_index = optional_child(node, "key-index-list")
            .map(KeyIndexInfo::try_from_node)
            .transpose()?;

        Ok(Self {
            operation_type,
            device_hash,
            contact_hash,
            devices,
            key_index,
        })
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
///   <remove device_hash="2:nivm0MNH">
///     <device jid="185169143189667:75@lid"/>
///     <key-index-list ts="1769296600"/>
///   </remove>
/// </notification>
/// ```
///
/// Reference: WhatsApp Web `WAWebHandleDeviceNotification` parser (lines 23125-23183)
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
    /// Operations (add/remove/update)
    pub operations: Vec<DeviceOperation>,
}

impl DeviceNotification {
    /// Parse from a `<notification type="devices">` node.
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
        let timestamp = node.attrs().optional_u64("t").unwrap_or(0) as i64;

        let mut operations = Vec::new();
        if let Some(children) = node.children() {
            for child in children.iter() {
                if matches!(child.tag.as_str(), "add" | "remove" | "update") {
                    operations.push(DeviceOperation::try_from_child(child)?);
                }
            }
        }

        Ok(Self {
            from,
            lid_user,
            stanza_id,
            timestamp,
            operations,
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
                .attr("device_hash", "2:nivm0MNH")
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
        assert_eq!(parsed.operations.len(), 1);

        let op = &parsed.operations[0];
        assert_eq!(op.operation_type, DeviceNotificationType::Remove);
        assert_eq!(op.device_hash, Some("2:nivm0MNH".to_string()));
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
                .attr("device_hash", "2:abc123")
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

        let op = &parsed.operations[0];
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
        assert_eq!(parsed.operations.len(), 1);

        let op = &parsed.operations[0];
        assert_eq!(op.operation_type, DeviceNotificationType::Update);
        assert_eq!(op.contact_hash, Some("contact_hash_value".to_string()));
        assert!(op.device_hash.is_none());
        assert!(op.devices.is_empty());
    }

    #[test]
    fn test_lid_pn_mapping_not_detected_when_from_is_lid() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "185169143189667@lid")
            .attr("lid", "185169143189667@lid")
            .attr("id", "123")
            .attr("t", "1000")
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        // No mapping should be detected when from is also a LID
        assert!(parsed.lid_pn_mapping().is_none());
    }

    #[test]
    fn test_multiple_operations() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "15551234567@s.whatsapp.net")
            .attr("id", "789")
            .attr("t", "3000")
            .children([
                NodeBuilder::new("add")
                    .attr("device_hash", "2:hash1")
                    .children([
                        NodeBuilder::new("device")
                            .attr("jid", "15551234567:64@s.whatsapp.net")
                            .build(),
                        NodeBuilder::new("key-index-list")
                            .attr("ts", "2999")
                            .build(),
                    ])
                    .build(),
                NodeBuilder::new("remove")
                    .attr("device_hash", "2:hash2")
                    .children([
                        NodeBuilder::new("device")
                            .attr("jid", "15551234567:32@s.whatsapp.net")
                            .build(),
                        NodeBuilder::new("key-index-list")
                            .attr("ts", "2998")
                            .build(),
                    ])
                    .build(),
            ])
            .build();

        let parsed = DeviceNotification::try_parse(&node).unwrap();
        assert_eq!(parsed.operations.len(), 2);

        assert_eq!(
            parsed.operations[0].operation_type,
            DeviceNotificationType::Add
        );
        assert_eq!(parsed.operations[0].device_ids(), vec![64]);

        assert_eq!(
            parsed.operations[1].operation_type,
            DeviceNotificationType::Remove
        );
        assert_eq!(parsed.operations[1].device_ids(), vec![32]);
    }
}
