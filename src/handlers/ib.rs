use crate::appstate::keys::ALL_PATCH_NAMES;
use crate::appstate_sync;
use crate::binary::node::Node;
use crate::client::Client;
use log::{info, warn};
use std::sync::Arc;

pub async fn handle_ib(client: Arc<Client>, node: &Node) {
    for child in node.children().unwrap_or_default() {
        match child.tag.as_str() {
            "dirty" => {
                let mut attrs = child.attrs();
                let dirty_type = attrs.string("type");
                if dirty_type == "account_sync" {
                    info!(
                        target: "Client",
                        "Received 'account_sync' dirty state notification. Triggering sync for all app state categories."
                    );
                    let client_clone = client.clone();
                    tokio::spawn(async move {
                        for name in ALL_PATCH_NAMES {
                            appstate_sync::app_state_sync(&client_clone, name, false).await;
                        }
                    });
                } else {
                    info!(
                        target: "Client",
                        "Received dirty state notification for type: '{dirty_type}'. Triggering App State Sync."
                    );
                    let client_clone = client.clone();
                    tokio::spawn(async move {
                        appstate_sync::app_state_sync(&client_clone, &dirty_type, false).await;
                    });
                }
            }
            "edge_routing" => {
                info!(target: "Client", "Received edge routing info, ignoring for now.");
            }
            _ => {
                warn!(target: "Client", "Unhandled ib child: <{}>", child.tag);
            }
        }
    }
}
