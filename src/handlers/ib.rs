use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::{Event, OfflineSyncCompleted, OfflineSyncPreview};
use async_trait::async_trait;
use log::{debug, warn};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use wacore_binary::node::{Node, NodeContent};

/// Handler for `<ib>` (information broadcast) stanzas.
///
/// Processes various server notifications including:
/// - Dirty state notifications
/// - Edge routing information
/// - Offline sync previews and completion notifications
/// - Thread metadata
#[derive(Default)]
pub struct IbHandler;

#[async_trait]
impl StanzaHandler for IbHandler {
    fn tag(&self) -> &'static str {
        "ib"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        handle_ib_impl(client, &node).await;
        true
    }
}

async fn handle_ib_impl(client: Arc<Client>, node: &Node) {
    for child in node.children().unwrap_or_default() {
        match child.tag.as_str() {
            "dirty" => {
                let mut attrs = child.attrs();
                let dirty_type = match attrs.optional_string("type") {
                    Some(t) => t.to_string(),
                    None => {
                        warn!("Dirty notification missing 'type' attribute");
                        continue;
                    }
                };
                let timestamp = attrs.optional_string("timestamp").map(|s| s.to_string());

                debug!(
                    "Received dirty state notification for type: '{dirty_type}'. Sending clean IQ."
                );

                let client_clone = client.clone();

                tokio::spawn(async move {
                    if let Err(e) = client_clone
                        .clean_dirty_bits(&dirty_type, timestamp.as_deref())
                        .await
                    {
                        warn!("Failed to send clean dirty bits IQ: {e:?}");
                    }
                });
            }
            "edge_routing" => {
                // Edge routing info is used for optimized reconnection to WhatsApp servers.
                // When present, it should be sent as a pre-intro before the Noise handshake.
                // Format on wire: ED (2 bytes) + length (3 bytes BE) + routing_data + WA header
                if let Some(routing_info_node) = child.get_optional_child("routing_info") {
                    if let Some(NodeContent::Bytes(routing_bytes)) = &routing_info_node.content {
                        if !routing_bytes.is_empty() {
                            debug!(
                                "Received edge routing info ({} bytes), storing for reconnection",
                                routing_bytes.len()
                            );
                            let routing_bytes = routing_bytes.clone();
                            client
                                .persistence_manager
                                .modify_device(|device| {
                                    device.edge_routing_info = Some(routing_bytes);
                                })
                                .await;
                        } else {
                            debug!("Received empty edge routing info, ignoring");
                        }
                    } else {
                        debug!("Edge routing info node has no bytes content");
                    }
                } else {
                    debug!("Edge routing stanza has no routing_info child");
                }
            }
            "offline_preview" => {
                let mut attrs = child.attrs();
                let total = attrs.optional_u64("count").unwrap_or(0) as i32;
                let app_data_changes = attrs.optional_u64("appdata").unwrap_or(0) as i32;
                let messages = attrs.optional_u64("message").unwrap_or(0) as i32;
                let notifications = attrs.optional_u64("notification").unwrap_or(0) as i32;
                let receipts = attrs.optional_u64("receipt").unwrap_or(0) as i32;

                debug!(
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

                debug!(target: "Client/OfflineSync", "Offline sync completed, received {} items", count);

                // Signal that offline sync is complete - post-login tasks are waiting for this.
                // This mimics WhatsApp Web's offlineDeliveryEnd event.
                client.offline_sync_completed.store(true, Ordering::Relaxed);
                client.offline_sync_notifier.notify_waiters();

                // NOTE: Session with primary phone (device 0) is established on login
                // BEFORE offline messages arrive (see client.rs post-login task).
                // This ensures PDO can send immediately when decryption fails.

                client
                    .core
                    .event_bus
                    .dispatch(&Event::OfflineSyncCompleted(OfflineSyncCompleted { count }));
            }
            "thread_metadata" => {
                // Present in some sessions; safe to ignore for now until feature implemented.
                debug!("Received thread metadata, ignoring for now.");
            }
            _ => {
                warn!("Unhandled ib child: <{}>", child.tag);
            }
        }
    }
}
