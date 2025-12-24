use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::Event;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::sync::Arc;
use wacore::types::events::{DeviceListUpdate, DeviceListUpdateType};
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
            if let Some(new_push_name) = node.attrs().optional_string("pushname") {
                client
                    .clone()
                    .update_push_name_and_notify(new_push_name.to_string())
                    .await;
            } else {
                warn!(target: "Client", "TODO: Implement full handler for <notification type='account_sync'>, for now dispatching generic event.");
                client
                    .core
                    .event_bus
                    .dispatch(&Event::Notification(node.clone()));
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
