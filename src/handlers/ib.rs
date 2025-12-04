use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::{Event, OfflineSyncCompleted, OfflineSyncPreview};
use async_trait::async_trait;
use log::{info, warn};
use std::sync::Arc;
use wacore_binary::node::NodeRef;

/// Handler for `<ib>` (information broadcast) stanzas.
///
/// Processes various server notifications including:
/// - Dirty state notifications
/// - Edge routing information
/// - Offline sync previews and completion notifications
/// - Thread metadata
pub struct IbHandler;

impl Default for IbHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl IbHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for IbHandler {
    fn tag(&self) -> &'static str {
        "ib"
    }

    async fn handle(&self, client: Arc<Client>, node: &NodeRef<'_>, _cancelled: &mut bool) -> bool {
        handle_ib_impl(client, node).await;
        true
    }
}

async fn handle_ib_impl(client: Arc<Client>, node: &NodeRef<'_>) {
    for child in node.children().unwrap_or_default() {
        match child.tag.as_ref() {
            "dirty" => {
                let mut attrs = child.attr_parser();
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
                let mut attrs = child.attr_parser();
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


                let mut preview = client.offline_preview.lock().await;
                preview.expected_count = total as u32;
                preview.received_count = 0;
                preview.total_received = 0;

                client.request_offline_batch(client.offline_batch_size).await;
            }
            "offline" => {
                let mut attrs = child.attr_parser();
                let count = attrs.optional_u64("count").unwrap_or(0) as i32;

                info!(target: "Client/OfflineSync", "Offline sync completed, received {} items", count);
                
                client.send_offline_batch().await.unwrap();
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
