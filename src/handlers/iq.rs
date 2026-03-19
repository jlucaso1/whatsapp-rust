use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use log::{debug, warn};
use std::sync::Arc;
use wacore::xml::DisplayableNode;
use wacore_binary::node::Node;

/// Handler for `<iq>` (Info/Query) stanzas.
///
/// Processes various query types including:
/// - Ping/pong exchanges
/// - Pairing requests
/// - Feature queries
/// - Settings updates
#[derive(Default)]
pub struct IqHandler;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StanzaHandler for IqHandler {
    fn tag(&self) -> &'static str {
        "iq"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        if !client.handle_iq(&node).await {
            if node.attrs.get("type").is_some_and(|s| s == "result") {
                debug!(
                    "Received late IQ response (waiter already removed): {}",
                    DisplayableNode(&node)
                );
            } else {
                warn!("Received unhandled IQ: {}", DisplayableNode(&node));
            }
        }
        true
    }
}
