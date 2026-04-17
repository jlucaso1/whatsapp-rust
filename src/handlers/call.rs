use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, warn};
use wacore::stanza::call::parse_call_stanza;
use wacore::types::call::{CallAction, IncomingCall};
use wacore::types::events::Event;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::{OwnedNodeRef, Server};

use crate::client::Client;

use super::traits::StanzaHandler;

/// Router sends the generic `<ack>` via `should_ack`, so this handler only
/// parses and dispatches. On `Offer` it also emits the `<receipt><offer/></receipt>`
/// ack-of-offer so the caller's signaling layer knows the device received the ring.
#[derive(Default)]
pub struct CallHandler;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl StanzaHandler for CallHandler {
    fn tag(&self) -> &'static str {
        "call"
    }

    async fn handle(
        &self,
        client: Arc<Client>,
        node: Arc<OwnedNodeRef>,
        _cancelled: &mut bool,
    ) -> bool {
        let nr = node.get();
        match parse_call_stanza(nr) {
            Ok(Some(call)) => {
                if matches!(call.action, CallAction::Offer { .. })
                    && let Err(e) = send_offer_ack_receipt(&client, &call).await
                {
                    warn!("call: failed to send offer ack receipt: {e}");
                }
                client.core.event_bus.dispatch(Event::IncomingCall(call));
            }
            Ok(None) => {
                debug!("call: ignoring unrecognized action (forward-compat)");
            }
            Err(e) => {
                warn!("call: failed to parse stanza: {e}");
            }
        }
        true
    }
}

async fn send_offer_ack_receipt(client: &Client, call: &IncomingCall) -> anyhow::Result<()> {
    let CallAction::Offer {
        call_id,
        call_creator,
        ..
    } = &call.action
    else {
        return Ok(());
    };

    let own_from = match call.from.server {
        Server::Lid => client.get_lid().await,
        _ => client.get_pn().await,
    };

    let mut receipt = NodeBuilder::new("receipt")
        .attr("to", &call.from)
        .attr("id", call.stanza_id.as_str());
    if let Some(jid) = own_from {
        receipt = receipt.attr("from", jid);
    }

    let offer = NodeBuilder::new("offer")
        .attr("call-id", call_id.as_str())
        .attr("call-creator", call_creator)
        .build();

    client
        .send_node(receipt.children([offer]).build())
        .await
        .map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{MockHttpClient, create_test_backend, node_to_owned_ref};
    use std::sync::Arc;
    use wacore::types::events::{ChannelEventHandler, Event};
    use wacore_binary::{Jid, Server};

    fn caller_lid() -> Jid {
        Jid::new("271240153559280", Server::Lid)
    }

    fn offer_stanza() -> wacore_binary::Node {
        NodeBuilder::new("call")
            .attr("from", caller_lid())
            .attr("id", "STANZA1")
            .attr("t", "1766847151")
            .children([NodeBuilder::new("offer")
                .attr("call-creator", caller_lid())
                .attr("call-id", "CALLID")
                .children([NodeBuilder::new("audio")
                    .attr("enc", "opus")
                    .attr("rate", "16000")
                    .build()])
                .build()])
            .build()
    }

    async fn make_client() -> Arc<Client> {
        use crate::store::persistence_manager::PersistenceManager;
        let backend = create_test_backend().await;
        let pm = PersistenceManager::new(backend)
            .await
            .expect("persistence manager should initialize");
        let transport = Arc::new(crate::transport::mock::MockTransportFactory::new());
        let http_client = Arc::new(MockHttpClient);
        let (client, _rx) = Client::new(
            Arc::new(crate::runtime_impl::TokioRuntime),
            Arc::new(pm),
            transport,
            http_client,
            None,
        )
        .await;
        client
    }

    #[tokio::test]
    async fn offer_dispatches_event() {
        let client = make_client().await;
        let (handler, rx) = ChannelEventHandler::new();
        client.register_handler(handler);

        let node = node_to_owned_ref(&offer_stanza());
        let mut cancelled = false;
        assert!(CallHandler.handle(client, node, &mut cancelled).await);

        let mut seen = false;
        while let Ok(ev) = rx.try_recv() {
            if matches!(&*ev, Event::IncomingCall(call) if call.action.call_id() == "CALLID") {
                seen = true;
                break;
            }
        }
        assert!(seen, "IncomingCall event must be dispatched");
    }

    #[tokio::test]
    async fn unrecognized_action_does_not_dispatch() {
        let client = make_client().await;
        let (handler, rx) = ChannelEventHandler::new();
        client.register_handler(handler);

        let node = node_to_owned_ref(
            &NodeBuilder::new("call")
                .attr("from", caller_lid())
                .attr("id", "S")
                .attr("t", "1766847151")
                .children([NodeBuilder::new("surprise").build()])
                .build(),
        );
        let mut cancelled = false;
        assert!(CallHandler.handle(client, node, &mut cancelled).await);

        while let Ok(ev) = rx.try_recv() {
            assert!(
                !matches!(&*ev, Event::IncomingCall(_)),
                "must not dispatch IncomingCall for unknown action"
            );
        }
    }

    #[tokio::test]
    async fn malformed_stanza_does_not_error_or_dispatch() {
        let client = make_client().await;
        let (handler, rx) = ChannelEventHandler::new();
        client.register_handler(handler);

        let node = node_to_owned_ref(
            &NodeBuilder::new("call")
                .attr("from", caller_lid())
                .attr("id", "S")
                .children([NodeBuilder::new("offer")
                    .attr("call-creator", caller_lid())
                    .attr("call-id", "X")
                    .build()])
                .build(),
        );
        let mut cancelled = false;
        assert!(CallHandler.handle(client, node, &mut cancelled).await);
        while let Ok(ev) = rx.try_recv() {
            assert!(!matches!(&*ev, Event::IncomingCall(_)));
        }
    }
}
