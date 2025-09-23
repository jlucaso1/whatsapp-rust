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

    async fn handle(&self, client: Arc<Client>, node: &Node, _cancelled: &mut bool) -> bool {
        handle_notification_impl(&client, node).await;
        true
    }
}

async fn handle_notification_impl(client: &Arc<Client>, node: &Node) {
    let notification_type = node.attrs.get("type").cloned().unwrap_or_default();

    match notification_type.as_str() {
        "encrypt" => {
            if let Some(from) = node.attrs.get("from")
                && from == SERVER_JID
            {
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
            }
        }
        "account_sync" => {
            if let Some(push_name_attr) = node.attrs.get("pushname") {
                let new_push_name = push_name_attr.clone();
                client
                    .clone()
                    .update_push_name_and_notify(new_push_name)
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
