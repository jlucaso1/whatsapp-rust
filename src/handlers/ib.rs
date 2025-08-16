use crate::client::Client;
use crate::types::events::{Event, OfflineSyncCompleted, OfflineSyncPreview};
use log::{info, warn};
use std::sync::Arc;
use wacore_binary::node::Node;

pub async fn handle_ib(client: Arc<Client>, node: &Node) {
    for child in node.children().unwrap_or_default() {
        match child.tag.as_str() {
            "dirty" => {
                let mut attrs = child.attrs();
                let dirty_type = attrs.string("type");

                info!(
                    target: "Client",
                    "Received dirty state notification for type: '{dirty_type}'. Awaiting server_sync notification."
                );
            }
            "edge_routing" => {
                info!(target: "Client", "Received edge routing info, ignoring for now.");
            }
            "offline_preview" => {
                let mut attrs = child.attrs();
                let total = attrs.optional_u64("count").unwrap_or(0) as i32;
                let app_data_changes = attrs.optional_u64("appdata").unwrap_or(0) as i32;
                let messages = attrs.optional_u64("message").unwrap_or(0) as i32;
                let notifications = attrs.optional_u64("notification").unwrap_or(0) as i32;
                let receipts = attrs.optional_u64("receipt").unwrap_or(0) as i32;

                info!(
                    target: "Client/OfflineSync",
                    "Offline preview: {} total ({} messages, {} notifications, {} receipts, {} app data changes)",
                    total, messages, notifications, receipts, app_data_changes,
                );

                client
                    .core
                    .event_bus
                    .dispatch(&Event::OfflineSyncPreview(OfflineSyncPreview {
                        total,
                        app_data_changes,
                        messages,
                        notifications,
                        receipts,
                    }));
            }
            "offline" => {
                let mut attrs = child.attrs();
                let count = attrs.optional_u64("count").unwrap_or(0) as i32;

                info!(target: "Client/OfflineSync", "Offline sync completed, received {} items", count);
                client
                    .core
                    .event_bus
                    .dispatch(&Event::OfflineSyncCompleted(OfflineSyncCompleted { count }));
            }
            "thread_metadata" => {
                // Present in some sessions; safe to ignore for now until feature implemented.
                info!(target: "Client", "Received thread metadata, ignoring for now.");
            }
            _ => {
                warn!(target: "Client", "Unhandled ib child: <{}>", child.tag);
            }
        }
    }
}
