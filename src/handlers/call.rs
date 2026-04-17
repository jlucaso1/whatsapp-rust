use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, warn};
use wacore::stanza::call::{build_offer_ack_receipt, parse_call_stanza};
use wacore::types::call::{CallAction, IncomingCall};
use wacore::types::events::Event;
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
    let own_from = match call.from.server {
        Server::Lid => client.get_lid().await,
        _ => client.get_pn().await,
    };

    let Some(receipt) = build_offer_ack_receipt(call, own_from.as_ref()) else {
        return Ok(());
    };

    client.send_node(receipt).await.map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{MockHttpClient, create_test_backend, node_to_owned_ref};
    use std::sync::Arc;
    use wacore::types::events::{ChannelEventHandler, Event};
    use wacore_binary::builder::NodeBuilder;
    use wacore_binary::{Jid, Server};

    fn fake_caller_lid() -> Jid {
        Jid::new("111111111111111", Server::Lid)
    }

    fn offer_stanza() -> wacore_binary::Node {
        NodeBuilder::new("call")
            .attr("from", fake_caller_lid())
            .attr("id", "STANZA-ID-0001")
            .attr("t", "1766847151")
            .children([NodeBuilder::new("offer")
                .attr("call-creator", fake_caller_lid())
                .attr("call-id", "CALL-ID-0001")
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
            if matches!(&*ev, Event::IncomingCall(call) if call.action.call_id() == "CALL-ID-0001")
            {
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
                .attr("from", fake_caller_lid())
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
                .attr("from", fake_caller_lid())
                .attr("id", "S")
                .children([NodeBuilder::new("offer")
                    .attr("call-creator", fake_caller_lid())
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
