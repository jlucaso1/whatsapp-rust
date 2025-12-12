use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::Event;
use async_trait::async_trait;
use log::{info, warn};
use std::sync::Arc;
use wacore_binary::{jid::SERVER_JID, node::Node};

/// Handler for `<notification>` stanzas.
///
/// Processes various notification types including:
/// - Encrypt notifications (key upload requests)
/// - Server sync notifications
/// - Account sync notifications (push name updates)
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
        _ => {
            warn!(target: "Client", "TODO: Implement handler for <notification type='{notification_type}'>");
            client
                .core
                .event_bus
                .dispatch(&Event::Notification(node.clone()));
        }
    }
}
