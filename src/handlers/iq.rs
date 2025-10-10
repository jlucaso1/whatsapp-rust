use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use log::warn;
use std::sync::Arc;
use wacore::xml::DisplayableNodeRef;
use wacore_binary::node::NodeRef;

/// Handler for `<iq>` (Info/Query) stanzas.
///
/// Processes various query types including:
/// - Ping/pong exchanges
/// - Pairing requests
/// - Feature queries
/// - Settings updates
#[derive(Default)]
pub struct IqHandler;

impl IqHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for IqHandler {
    fn tag(&self) -> &'static str {
        "iq"
    }

    async fn handle(&self, client: Arc<Client>, node: &NodeRef<'_>, _cancelled: &mut bool) -> bool {
        if !client.handle_iq_ref(node).await {
            warn!(target: "Client", "Received unhandled IQ: {}", DisplayableNodeRef(node));
        }
        true
    }
}
