use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::Event;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::sync::Arc;
use wacore::store::traits::{DeviceInfo, DeviceListRecord};
use wacore::types::events::{DeviceListUpdate, DeviceListUpdateType};
use wacore_binary::jid::{Jid, JidExt};
use wacore_binary::{jid::SERVER_JID, node::Node};

/// Handler for `<notification>` stanzas.
///
/// Processes various notification types including:
/// - Encrypt notifications (key upload requests)
/// - Server sync notifications
/// - Account sync notifications (push name updates)
/// - Device notifications (device add/remove/update)
#[derive(Default)]
pub struct NotificationHandler;

impl NotificationHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for NotificationHandler {
    fn tag(&self) -> &'static str {
        "notification"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        handle_notification_impl(&client, &node).await;
        true
    }
}

async fn handle_notification_impl(client: &Arc<Client>, node: &Node) {
    let notification_type = node.attrs().optional_string("type").unwrap_or_default();

    match notification_type {
        "encrypt" => {
            if node.attrs().optional_string("from") == Some(SERVER_JID) {
                let client_clone = client.clone();
                tokio::spawn(async move {
                    if let Err(e) = client_clone.upload_pre_keys().await {
                        warn!("Failed to upload pre-keys after notification: {:?}", e);
                    }
                });
            }
        }
        "server_sync" => {
            info!(target: "Client", "Received `server_sync` notification, scheduling app state sync(s).");
            if let Some(children) = node.children() {
                for collection_node in children.iter().filter(|c| c.tag == "collection") {
                    let name = collection_node.attrs().string("name");
                    let mut attrs = collection_node.attrs();
                    let version = attrs.optional_u64("version").unwrap_or(0);
                    info!(
                        target: "Client/AppState",
                        "scheduling sync for collection '{name}' from version {version}."
                    );
                }
            }
        }
        "account_sync" => {
            // Handle push name updates
            if let Some(new_push_name) = node.attrs().optional_string("pushname") {
                client
                    .clone()
                    .update_push_name_and_notify(new_push_name.to_string())
                    .await;
            }

            // Handle device list updates (when a new device is paired)
            // Matches WhatsApp Web's handleAccountSyncNotification for DEVICES type
            if let Some(devices_node) = node.get_optional_child_by_tag(&["devices"]) {
                handle_account_sync_devices(client, node, devices_node).await;
            }
        }
        "devices" => {
            // Handle device list change notifications (WhatsApp Web: handleDevicesNotification)
            // These are sent when a user adds, removes, or updates a device
            handle_devices_notification(client, node).await;
        }
        _ => {
            warn!(target: "Client", "TODO: Implement handler for <notification type='{notification_type}'>");
            client
                .core
                .event_bus
                .dispatch(&Event::Notification(node.clone()));
        }
    }
}

/// Handle device list change notifications.
/// Matches WhatsApp Web's WAWebHandleDeviceNotification.handleDevicesNotification().
///
/// Device notifications have the structure:
/// ```xml
/// <notification type="devices" from="user@s.whatsapp.net">
///   <add> or <remove> or <update hash="...">
///     <device id="1" />
///     <device id="2" />
///   </add/remove/update>
/// </notification>
/// ```
async fn handle_devices_notification(client: &Arc<Client>, node: &Node) {
    // Extract user JID from the "from" attribute
    let from_jid = match node.attrs().optional_jid("from") {
        Some(jid) => jid,
        None => {
            warn!(target: "Client", "Device notification missing 'from' attribute");
            return;
        }
    };

    let user = from_jid.user.clone();

    // Determine update type and extract device list
    let Some(children) = node.children() else {
        warn!(target: "Client", "Device notification has no children");
        return;
    };

    for child in children.iter() {
        let (update_type, hash) = match child.tag.as_str() {
            "add" => (DeviceListUpdateType::Add, None),
            "remove" => (DeviceListUpdateType::Remove, None),
            "update" => {
                let hash = child.attrs().optional_string("hash").map(|s| s.to_string());
                (DeviceListUpdateType::Update, hash)
            }
            _ => continue,
        };

        // Extract device IDs from child <device> elements
        let devices: Vec<u32> = child
            .children()
            .map(|device_nodes| {
                device_nodes
                    .iter()
                    .filter(|n| n.tag == "device")
                    .filter_map(|n| n.attrs().optional_u64("id").map(|id| id as u32))
                    .collect()
            })
            .unwrap_or_default();

        debug!(
            target: "Client",
            "Device notification: user={}, type={:?}, devices={:?}, hash={:?}",
            user, update_type, devices, hash
        );

        // Invalidate the device cache for this user
        // This ensures the next lookup fetches fresh data
        client.invalidate_device_cache(&user).await;

        // Dispatch event to notify application layer
        let event = Event::DeviceListUpdate(DeviceListUpdate {
            user: from_jid.clone(),
            update_type,
            devices,
            hash,
        });
        client.core.event_bus.dispatch(&event);
    }
}

/// Parsed device info from account_sync notification
struct AccountSyncDevice {
    jid: Jid,
    key_index: Option<u32>,
}

/// Parse devices from account_sync notification's <devices> child.
///
/// Example structure:
/// ```xml
/// <devices dhash="2:FnEWjS13">
///   <device jid="559984726662@s.whatsapp.net"/>
///   <device jid="559984726662:64@s.whatsapp.net" key-index="2"/>
///   <key-index-list ts="1766612162"><!-- bytes --></key-index-list>
/// </devices>
/// ```
fn parse_account_sync_device_list(devices_node: &Node) -> Vec<AccountSyncDevice> {
    let Some(children) = devices_node.children() else {
        return Vec::new();
    };

    children
        .iter()
        .filter(|n| n.tag == "device")
        .filter_map(|n| {
            let jid = n.attrs().optional_jid("jid")?;
            let key_index = n.attrs().optional_u64("key-index").map(|v| v as u32);
            Some(AccountSyncDevice { jid, key_index })
        })
        .collect()
}

/// Handle account_sync notification with <devices> child.
///
/// This is sent when devices are added/removed from OUR account (e.g., pairing a new WhatsApp Web).
/// Matches WhatsApp Web's `handleAccountSyncNotification` for `AccountSyncType.DEVICES`.
///
/// Key behaviors:
/// 1. Check if notification is for our own account (isSameAccountAndAddressingMode)
/// 2. Parse device list from notification
/// 3. Update device registry with new device list
/// 4. Does NOT trigger app state sync (that's handled by server_sync)
async fn handle_account_sync_devices(client: &Arc<Client>, node: &Node, devices_node: &Node) {
    // Extract the "from" JID - this is the account the notification is about
    let from_jid = match node.attrs().optional_jid("from") {
        Some(jid) => jid,
        None => {
            warn!(target: "Client/AccountSync", "account_sync devices missing 'from' attribute");
            return;
        }
    };

    // Get our own JIDs (PN and LID) to verify this is about our account
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let own_pn = device_snapshot.pn.as_ref();
    let own_lid = device_snapshot.lid.as_ref();

    // Check if notification is about our own account
    // Matches WhatsApp Web's isSameAccountAndAddressingMode check
    let is_own_account = own_pn.is_some_and(|pn| pn.is_same_user_as(&from_jid))
        || own_lid.is_some_and(|lid| lid.is_same_user_as(&from_jid));

    if !is_own_account {
        // WhatsApp Web logs "wid-is-not-self" error in this case
        warn!(
            target: "Client/AccountSync",
            "Received account_sync devices for non-self user: {} (our PN: {:?}, LID: {:?})",
            from_jid,
            own_pn.map(|j| j.user.as_str()),
            own_lid.map(|j| j.user.as_str())
        );
        return;
    }

    // Parse device list from notification
    let devices = parse_account_sync_device_list(devices_node);
    if devices.is_empty() {
        debug!(target: "Client/AccountSync", "account_sync devices list is empty");
        return;
    }

    // Extract dhash (device hash) for cache validation
    let dhash = devices_node
        .attrs()
        .optional_string("dhash")
        .map(String::from);

    // Get timestamp from notification
    let timestamp = node.attrs().optional_u64("t").unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }) as i64;

    // Build DeviceListRecord for storage
    let device_list = DeviceListRecord {
        user: from_jid.user.clone(),
        devices: devices
            .iter()
            .map(|d| DeviceInfo {
                device_id: d.jid.device as u32,
                key_index: d.key_index,
            })
            .collect(),
        timestamp,
        phash: dhash, // Use dhash as phash (they serve similar purposes)
    };

    // Update cache + persistent storage
    if let Err(e) = client.update_device_list(device_list).await {
        warn!(
            target: "Client/AccountSync",
            "Failed to update device list from account_sync: {}",
            e
        );
        return;
    }

    info!(
        target: "Client/AccountSync",
        "Updated own device list from account_sync: {} devices (user: {})",
        devices.len(),
        from_jid.user
    );

    // Log individual devices at debug level
    for device in &devices {
        debug!(
            target: "Client/AccountSync",
            "  Device: {} (key-index: {:?})",
            device.jid,
            device.key_index
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore::types::events::DeviceListUpdateType;
    use wacore_binary::builder::NodeBuilder;

    /// Helper to parse device notification and extract update info
    fn parse_device_notification_info(
        node: &wacore_binary::node::Node,
    ) -> Vec<(DeviceListUpdateType, Vec<u32>, Option<String>)> {
        let Some(children) = node.children() else {
            return vec![];
        };

        let mut results = vec![];
        for child in children.iter() {
            let (update_type, hash) = match child.tag.as_str() {
                "add" => (DeviceListUpdateType::Add, None),
                "remove" => (DeviceListUpdateType::Remove, None),
                "update" => {
                    let hash = child.attrs().optional_string("hash").map(|s| s.to_string());
                    (DeviceListUpdateType::Update, hash)
                }
                _ => continue,
            };

            let devices: Vec<u32> = child
                .children()
                .map(|device_nodes| {
                    device_nodes
                        .iter()
                        .filter(|n| n.tag == "device")
                        .filter_map(|n| n.attrs().optional_u64("id").map(|id| id as u32))
                        .collect()
                })
                .unwrap_or_default();

            results.push((update_type, devices, hash));
        }
        results
    }

    #[test]
    fn test_parse_device_add_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("add")
                .children([
                    NodeBuilder::new("device").attr("id", "1").build(),
                    NodeBuilder::new("device").attr("id", "2").build(),
                ])
                .build()])
            .build();

        let results = parse_device_notification_info(&node);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, DeviceListUpdateType::Add);
        assert_eq!(results[0].1, vec![1, 2]);
        assert_eq!(results[0].2, None);
    }

    #[test]
    fn test_parse_device_remove_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("remove")
                .children([NodeBuilder::new("device").attr("id", "3").build()])
                .build()])
            .build();

        let results = parse_device_notification_info(&node);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, DeviceListUpdateType::Remove);
        assert_eq!(results[0].1, vec![3]);
    }

    #[test]
    fn test_parse_device_update_notification_with_hash() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([NodeBuilder::new("update")
                .attr("hash", "2:abcdef123456")
                .children([NodeBuilder::new("device").attr("id", "0").build()])
                .build()])
            .build();

        let results = parse_device_notification_info(&node);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, DeviceListUpdateType::Update);
        assert_eq!(results[0].1, vec![0]);
        assert_eq!(results[0].2, Some("2:abcdef123456".to_string()));
    }

    #[test]
    fn test_parse_empty_device_notification() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .build();

        let results = parse_device_notification_info(&node);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_multiple_device_operations() {
        let node = NodeBuilder::new("notification")
            .attr("type", "devices")
            .attr("from", "1234567890@s.whatsapp.net")
            .children([
                NodeBuilder::new("add")
                    .children([NodeBuilder::new("device").attr("id", "5").build()])
                    .build(),
                NodeBuilder::new("remove")
                    .children([NodeBuilder::new("device").attr("id", "2").build()])
                    .build(),
            ])
            .build();

        let results = parse_device_notification_info(&node);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, DeviceListUpdateType::Add);
        assert_eq!(results[0].1, vec![5]);
        assert_eq!(results[1].0, DeviceListUpdateType::Remove);
        assert_eq!(results[1].1, vec![2]);
    }

    // Tests for account_sync device parsing

    #[test]
    fn test_parse_account_sync_device_list_basic() {
        let devices_node = NodeBuilder::new("devices")
            .attr("dhash", "2:FnEWjS13")
            .children([
                NodeBuilder::new("device")
                    .attr("jid", "559984726662@s.whatsapp.net")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "559984726662:64@s.whatsapp.net")
                    .attr("key-index", "2")
                    .build(),
            ])
            .build();

        let devices = parse_account_sync_device_list(&devices_node);
        assert_eq!(devices.len(), 2);

        // Primary device (device 0)
        assert_eq!(devices[0].jid.user, "559984726662");
        assert_eq!(devices[0].jid.device, 0);
        assert_eq!(devices[0].key_index, None);

        // Companion device (device 64)
        assert_eq!(devices[1].jid.user, "559984726662");
        assert_eq!(devices[1].jid.device, 64);
        assert_eq!(devices[1].key_index, Some(2));
    }

    #[test]
    fn test_parse_account_sync_device_list_with_key_index_list() {
        // Real-world structure includes <key-index-list> which should be ignored
        let devices_node = NodeBuilder::new("devices")
            .attr("dhash", "2:FnEWjS13")
            .children([
                NodeBuilder::new("device")
                    .attr("jid", "559984726662@s.whatsapp.net")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "559984726662:77@s.whatsapp.net")
                    .attr("key-index", "15")
                    .build(),
                NodeBuilder::new("key-index-list")
                    .attr("ts", "1766612162")
                    .bytes(vec![0x01, 0x02, 0x03]) // Simulated signed bytes
                    .build(),
            ])
            .build();

        let devices = parse_account_sync_device_list(&devices_node);
        // Should only parse <device> tags, not <key-index-list>
        assert_eq!(devices.len(), 2);
        assert_eq!(devices[0].jid.device, 0);
        assert_eq!(devices[1].jid.device, 77);
        assert_eq!(devices[1].key_index, Some(15));
    }

    #[test]
    fn test_parse_account_sync_device_list_empty() {
        let devices_node = NodeBuilder::new("devices")
            .attr("dhash", "2:FnEWjS13")
            .build();

        let devices = parse_account_sync_device_list(&devices_node);
        assert!(devices.is_empty());
    }

    #[test]
    fn test_parse_account_sync_device_list_multiple_devices() {
        let devices_node = NodeBuilder::new("devices")
            .attr("dhash", "2:XYZ123")
            .children([
                NodeBuilder::new("device")
                    .attr("jid", "1234567890@s.whatsapp.net")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "1234567890:1@s.whatsapp.net")
                    .attr("key-index", "1")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "1234567890:2@s.whatsapp.net")
                    .attr("key-index", "5")
                    .build(),
                NodeBuilder::new("device")
                    .attr("jid", "1234567890:3@s.whatsapp.net")
                    .attr("key-index", "10")
                    .build(),
            ])
            .build();

        let devices = parse_account_sync_device_list(&devices_node);
        assert_eq!(devices.len(), 4);

        // Verify device IDs are correctly parsed
        assert_eq!(devices[0].jid.device, 0);
        assert_eq!(devices[1].jid.device, 1);
        assert_eq!(devices[2].jid.device, 2);
        assert_eq!(devices[3].jid.device, 3);

        // Verify key indexes
        assert_eq!(devices[0].key_index, None);
        assert_eq!(devices[1].key_index, Some(1));
        assert_eq!(devices[2].key_index, Some(5));
        assert_eq!(devices[3].key_index, Some(10));
    }
}
