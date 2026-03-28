use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::{Event, OfflineSyncPreview};
use async_trait::async_trait;
use log::{debug, info, warn};
use std::sync::Arc;
use wacore::appstate::patch_decode::WAPatchName;
use wacore::iq::dirty::{DirtyBit, DirtyType};

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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
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
        match child.tag.as_ref() {
            "dirty" => {
                let mut attrs = child.attrs();
                let dirty_type_str = match attrs.optional_string("type") {
                    Some(t) => t.to_string(),
                    None => {
                        warn!("Dirty notification missing 'type' attribute");
                        continue;
                    }
                };
                let timestamp_str = attrs.optional_string("timestamp");

                let bit = match DirtyBit::from_raw(&dirty_type_str, timestamp_str.as_deref()) {
                    Ok(b) => b,
                    Err(e) => {
                        warn!("Invalid dirty notification: {e}");
                        continue;
                    }
                };

                let needs_offline_wait = matches!(
                    bit.dirty_type,
                    DirtyType::Groups | DirtyType::NewsletterMetadata
                );
                let needs_resync = bit.dirty_type == DirtyType::SyncdAppState;

                debug!(
                    "Received dirty state notification for type: '{dirty_type_str}'. Sending clean IQ."
                );

                let client_clone = client.clone();

                // Groups/newsletter_metadata: wait for offline sync per WAWebHandleDirtyBits.
                client.connection_tasks.spawn(
                    &*client.runtime,
                    Box::pin(async move {
                        if needs_offline_wait {
                            client_clone.wait_for_offline_delivery_end().await;
                        }
                        if client_clone.is_shutting_down() {
                            return;
                        }
                        if let Err(e) = client_clone.clean_dirty_bits(bit).await
                            && !client_clone.is_shutting_down()
                        {
                            warn!("Failed to send clean dirty bits IQ: {e:?}");
                        }

                        if needs_resync && !client_clone.is_shutting_down() {
                            info!("syncd_app_state dirty -- re-syncing all app state collections");
                            if let Err(e) = client_clone
                                .sync_collections_batched(vec![
                                    WAPatchName::CriticalBlock,
                                    WAPatchName::CriticalUnblockLow,
                                    WAPatchName::RegularLow,
                                    WAPatchName::RegularHigh,
                                    WAPatchName::Regular,
                                ])
                                .await
                                && !client_clone.is_shutting_down()
                            {
                                warn!("App state re-sync after dirty notification failed: {e:?}");
                            }
                        }
                    }),
                );
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
                client.complete_offline_sync(count);
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
