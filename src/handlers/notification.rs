use crate::appstate_sync;
use crate::binary::node::Node;
use crate::client::Client;
use crate::types::events::Event;
use crate::types::presence::Presence;
use log::{info, warn};
use std::sync::Arc;

pub async fn handle_notification(client: &Arc<Client>, node: &Node) {
    let notification_type = node.attrs.get("type").cloned().unwrap_or_default();
    match notification_type.as_str() {
        "server_sync" => {
            info!(target: "Client", "Received `server_sync` notification, scheduling app state sync(s).");
            for collection_node in node.get_children_by_tag("collection") {
                let name = collection_node
                    .attrs
                    .get("name")
                    .cloned()
                    .unwrap_or_default();
                let version = collection_node
                    .attrs
                    .get("version")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                info!(
                    target: "Client/AppState",
                    "scheduling sync for collection '{name}' from version {version}."
                );

                let client_clone = client.clone();
                tokio::spawn(async move {
                    appstate_sync::app_state_sync(&client_clone, &name, false).await;
                });
            }
        }
        "account_sync" => {
            if let Some(push_name_attr) = node.attrs.get("pushname") {
                let new_push_name = push_name_attr.clone();

                let device_snapshot = client.persistence_manager.get_device_snapshot().await;
                let old_name = device_snapshot.push_name.clone();
                // drop(device_snapshot); // Not needed

                if old_name != new_push_name {
                    info!(
                        "Received push name '{}' via account_sync notification, updating store.",
                        new_push_name
                    );
                    // Use command to update push name
                    client
                        .persistence_manager
                        .process_command(crate::store::commands::DeviceCommand::SetPushName(
                            new_push_name.clone(),
                        ))
                        .await;

                    client
                        .dispatch_event(Event::SelfPushNameUpdated(
                            crate::types::events::SelfPushNameUpdated {
                                from_server: true,
                                old_name,
                                new_name: new_push_name, // Use new_push_name
                            },
                        ))
                        .await;

                    let client_clone = client.clone();
                    tokio::spawn(async move {
                        if let Err(e) = client_clone.send_presence(Presence::Available).await {
                            warn!("Failed to send presence after account_sync update: {e:?}");
                        } else {
                            info!("✅ Successfully sent presence after receiving push_name via account_sync");
                        }
                    });
                }
            } else {
                // The 'account_sync' can also contain other things like blocklist updates etc.
                // For now, dispatching a generic event. A more complete implementation could parse these.
                warn!(target: "Client", "TODO: Implement full handler for <notification type='account_sync'>, for now dispatching generic event.");
                client
                    .dispatch_event(Event::Notification(node.clone()))
                    .await;
            }
        }
        _ => {
            warn!(target: "Client", "TODO: Implement handler for <notification type='{}'>", notification_type);
            client
                .dispatch_event(Event::Notification(node.clone()))
                .await;
        }
    }
}
