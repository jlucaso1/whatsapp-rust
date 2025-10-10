use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::Event;
use async_trait::async_trait;
use log::{info, warn};
use std::sync::Arc;
use wacore_binary::{jid::SERVER_JID, node::NodeRef};

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

    async fn handle(&self, client: Arc<Client>, node: &NodeRef<'_>, _cancelled: &mut bool) -> bool {
        handle_notification_impl(&client, node).await;
        true
    }
}

async fn handle_notification_impl(client: &Arc<Client>, node: &NodeRef<'_>) {
    let notification_type = node.get_attr("type").map(|s| s.as_ref()).unwrap_or("");

    match notification_type {
        "encrypt" => {
            if let Some(from) = node.get_attr("from")
                && from.as_ref() == SERVER_JID
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
                    .get_attr("name")
                    .map(|s| s.to_string())
                    .unwrap_or_default();
                let version = collection_node
                    .get_attr("version")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                info!(
                    target: "Client/AppState",
                    "scheduling sync for collection '{name}' from version {version}."
                );
            }
        }
        "account_sync" => {
            if let Some(push_name_attr) = node.get_attr("pushname") {
                let new_push_name = push_name_attr.to_string();
                client
                    .clone()
                    .update_push_name_and_notify(new_push_name)
                    .await;
            } else {
                warn!(target: "Client", "TODO: Implement full handler for <notification type='account_sync'>, for now dispatching generic event.");
                client
                    .core
                    .event_bus
                    .dispatch(&Event::Notification(node.to_owned()));
            }
        }
        _ => {
            warn!(target: "Client", "TODO: Implement handler for <notification type='{notification_type}'>");
            client
                .core
                .event_bus
                .dispatch(&Event::Notification(node.to_owned()));
        }
    }
}
