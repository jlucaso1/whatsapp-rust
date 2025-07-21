use crate::binary::node::Node;
use crate::client::Client;
use log::{info, warn};
use std::sync::Arc;

pub async fn handle_ib(_client: Arc<Client>, node: &Node) {
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
            _ => {
                warn!(target: "Client", "Unhandled ib child: <{}>", child.tag);
            }
        }
    }
}
