//! Call stanza handler.

use super::signaling::{ResponseType, SignalingType};
use super::stanza::{ParsedCallStanza, build_call_ack, build_call_receipt};
use crate::client::Client;
use crate::handlers::traits::StanzaHandler;
use async_trait::async_trait;
use log::{debug, warn};
use std::sync::Arc;
use wacore::types::events::{CallAccepted, CallEnded, CallOffer, CallRejected, Event};
use wacore_binary::node::Node;

/// Handler for `<call>` stanzas.
#[derive(Default)]
pub struct CallHandler;

#[async_trait]
impl StanzaHandler for CallHandler {
    fn tag(&self) -> &'static str {
        "call"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, cancelled: &mut bool) -> bool {
        // Cancel the deferred ack - we send our own typed ack/receipt in send_response()
        *cancelled = true;

        let parsed = match ParsedCallStanza::parse(&node) {
            Ok(p) => p,
            Err(e) => {
                warn!("Failed to parse call stanza: {}", e);
                return false;
            }
        };

        debug!(
            "Received call signaling: {} from {} (call_id: {})",
            parsed.signaling_type, parsed.from, parsed.call_id
        );

        // Send appropriate response (ack or receipt)
        if let Err(e) = self.send_response(&client, &parsed).await {
            warn!("Failed to send call response: {}", e);
        }

        // Handle the signaling type
        match parsed.signaling_type {
            SignalingType::Offer | SignalingType::OfferNotice => {
                self.handle_incoming_offer(&client, &parsed).await;
            }
            SignalingType::Accept => {
                self.handle_accept(&client, &parsed).await;
            }
            SignalingType::Reject => {
                self.handle_reject(&client, &parsed).await;
            }
            SignalingType::Terminate => {
                self.handle_terminate(&client, &parsed).await;
            }
            SignalingType::Transport => {
                debug!(
                    "Received transport (ICE candidates) for call {}",
                    parsed.call_id
                );
                // Phase 2: Handle ICE candidates
            }
            SignalingType::EncRekey => {
                if let Some(enc_data) = &parsed.enc_rekey_data {
                    debug!(
                        "Received enc_rekey for call {} (type: {:?}, {} bytes)",
                        parsed.call_id,
                        enc_data.enc_type,
                        enc_data.ciphertext.len()
                    );
                } else {
                    warn!(
                        "Received enc_rekey for call {} but failed to parse enc data",
                        parsed.call_id
                    );
                }
            }
            SignalingType::PreAccept => {
                debug!(
                    "Received preaccept for call {} (peer is preparing to answer)",
                    parsed.call_id
                );
            }
            SignalingType::Mute => {
                debug!("Received mute state change for call {}", parsed.call_id);
            }
            SignalingType::VideoState => {
                debug!("Received video state change for call {}", parsed.call_id);
            }
            SignalingType::GroupInfo => {
                debug!("Received group info for call {}", parsed.call_id);
            }
            _ => {
                debug!(
                    "Unhandled call signaling type: {} for call {}",
                    parsed.signaling_type, parsed.call_id
                );
            }
        }

        true
    }
}

impl CallHandler {
    async fn send_response(
        &self,
        client: &Client,
        parsed: &ParsedCallStanza,
    ) -> Result<(), anyhow::Error> {
        let device = client.persistence_manager.get_device_snapshot().await;

        // Match WhatsApp Web JS: use LID if sender is LID, otherwise use PN
        // Device must have at least one identity (lid or pn) to send responses
        let our_jid = if parsed.from.is_lid() {
            device.lid.clone().or_else(|| device.pn.clone())
        } else {
            device.pn.clone().or_else(|| device.lid.clone())
        }
        .ok_or_else(|| anyhow::anyhow!("Device has no identity (lid or pn) for call response"))?;

        match parsed.signaling_type.response_type() {
            Some(ResponseType::Receipt) => {
                let receipt = build_call_receipt(
                    &parsed.stanza_id,
                    &parsed.from,
                    &our_jid,
                    &parsed.call_id,
                    &parsed.call_creator,
                    parsed.signaling_type,
                );
                client.send_node(receipt).await?;
            }
            Some(ResponseType::Ack) => {
                let ack = build_call_ack(&parsed.stanza_id, &parsed.from, parsed.signaling_type);
                client.send_node(ack).await?;
            }
            None => {}
        }
        Ok(())
    }

    async fn handle_incoming_offer(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!(
            "Incoming {} call (call_id: {}, offline: {})",
            if parsed.is_video { "video" } else { "audio" },
            parsed.call_id,
            parsed.is_offline
        );

        if let Some(enc_data) = &parsed.offer_enc_data {
            debug!(
                "Call {} has encrypted key: type={:?}, {} bytes",
                parsed.call_id,
                enc_data.enc_type,
                enc_data.ciphertext.len()
            );
        }

        if let Some(relay) = &parsed.relay_data {
            debug!(
                "Call {} relay: uuid={:?}, self_pid={:?}, peer_pid={:?}, hbh_key={} bytes, relay_key={} bytes",
                parsed.call_id,
                relay.uuid,
                relay.self_pid,
                relay.peer_pid,
                relay.hbh_key.as_ref().map(|k| k.len()).unwrap_or(0),
                relay.relay_key.as_ref().map(|k| k.len()).unwrap_or(0),
            );
        }

        // Emit CallOffer event
        let event = Event::CallOffer(CallOffer {
            meta: parsed.basic_meta(),
            media_type: parsed.media_type(),
            is_offline: parsed.is_offline,
            remote_meta: parsed.remote_meta(),
            group_jid: parsed.group_jid.clone(),
        });
        client.core.event_bus.dispatch(&event);
    }

    async fn handle_accept(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!("Call {} accepted", parsed.call_id);
        let event = Event::CallAccepted(CallAccepted {
            meta: parsed.basic_meta(),
        });
        client.core.event_bus.dispatch(&event);
    }

    async fn handle_reject(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!("Call {} rejected", parsed.call_id);
        let event = Event::CallRejected(CallRejected {
            meta: parsed.basic_meta(),
        });
        client.core.event_bus.dispatch(&event);
    }

    async fn handle_terminate(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!("Call {} terminated", parsed.call_id);
        let event = Event::CallEnded(CallEnded {
            meta: parsed.basic_meta(),
        });
        client.core.event_bus.dispatch(&event);
    }
}
