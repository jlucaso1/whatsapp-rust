//! Handler for incoming `<presence>` stanzas.

use super::traits::StanzaHandler;
use crate::client::Client;
use async_trait::async_trait;
use log::debug;
use std::sync::Arc;
use wacore::types::events::{Event, PresenceUpdate};
use wacore_binary::node::Node;

/// Handler for `<presence>` stanzas.
///
/// Parses incoming presence updates and dispatches `Event::Presence` via the event bus.
#[derive(Default)]
pub struct PresenceHandler;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StanzaHandler for PresenceHandler {
    fn tag(&self) -> &'static str {
        "presence"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        let from_jid = match node.attrs.get("from").and_then(|v| v.to_jid()) {
            Some(jid) => jid,
            None => {
                debug!(target: "PresenceHandler", "Presence stanza missing or invalid 'from' attribute");
                return true;
            }
        };

        let unavailable = node.attrs.get("type").is_some_and(|v| v == "unavailable");

        // Parse last_seen from 'last' attribute if present
        let last_seen = node
            .attrs
            .get("last")
            .and_then(|v| v.to_string().parse::<i64>().ok())
            .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0));

        debug!(
            target: "PresenceHandler",
            "Received presence from {}: unavailable={}",
            from_jid, unavailable
        );

        client
            .core
            .event_bus
            .dispatch(&Event::Presence(PresenceUpdate {
                from: from_jid,
                unavailable,
                last_seen,
            }));

        true
    }
}
