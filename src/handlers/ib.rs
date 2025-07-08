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

                info!(
                    target: "Client",
                    "Received dirty state notification for type: '{dirty_type}'. Triggering App State Sync."
                );

                let client_clone = client.clone();
                let dirty_type_clone = dirty_type.clone();
                tokio::spawn(async move {
                    appstate_sync::app_state_sync(&client_clone, &dirty_type_clone, false).await;
                });
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
