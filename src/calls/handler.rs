//! Call stanza handler.

use super::encryption::derive_call_keys;
use super::signaling::{ResponseType, SignalingType};
use super::stanza::{OfferEncData, ParsedCallStanza, build_call_ack, build_call_receipt};
use super::transport::TransportPayload;
use crate::client::Client;
use crate::handlers::traits::StanzaHandler;
use async_trait::async_trait;
use log::{debug, info, warn};
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
                self.handle_transport(&client, &parsed).await;
            }
            SignalingType::RelayLatency => {
                self.handle_relay_latency(&client, &parsed).await;
            }
            SignalingType::RelayElection => {
                self.handle_relay_election(&client, &parsed).await;
            }
            SignalingType::EncRekey => {
                self.handle_enc_rekey(&client, &parsed).await;
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
        let media = if parsed.is_video { "video" } else { "audio" };
        debug!(
            "Incoming {} call: {} (offline={})",
            media, parsed.call_id, parsed.is_offline
        );

        let call_manager = client.get_call_manager().await;

        // Register call unless offline (stale)
        if parsed.is_offline {
            debug!("Skipping offline call {} (stale)", parsed.call_id);
        } else if let Err(e) = call_manager.register_incoming_call(parsed).await {
            warn!("Failed to register call {}: {}", parsed.call_id, e);
        }

        // Notify callback with parsed offer data
        if parsed.offer_enc_data.is_some() || parsed.relay_data.is_some() {
            let relay_data = parsed.relay_data.clone().unwrap_or_default();
            let media_params = parsed.media_params.clone().unwrap_or_default();
            let enc_data = parsed
                .offer_enc_data
                .clone()
                .unwrap_or_else(|| OfferEncData {
                    enc_type: super::encryption::EncType::Msg,
                    ciphertext: Vec::new(),
                    version: 0,
                });

            call_manager
                .notify_offer_received(&parsed.call_id, &relay_data, &media_params, &enc_data)
                .await;
        }

        let event = Event::CallOffer(CallOffer {
            meta: parsed.basic_meta(),
            media_type: parsed.media_type(),
            is_offline: parsed.is_offline,
            remote_meta: parsed.remote_meta(),
            group_jid: parsed.group_jid.clone(),
        });
        client.core.event_bus.dispatch(&event);
    }

    async fn handle_transport(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!("Received transport for call {}", parsed.call_id);

        if let Some(payload_bytes) = &parsed.payload {
            let transport = TransportPayload::from_raw(payload_bytes.clone());
            client
                .get_call_manager()
                .await
                .notify_transport_received(&parsed.call_id, &transport)
                .await;
        }
    }

    async fn handle_relay_latency(&self, client: &Client, parsed: &ParsedCallStanza) {
        if parsed.relay_latency.is_empty() {
            return;
        }

        debug!(
            "Relay latency for {}: {} measurements",
            parsed.call_id,
            parsed.relay_latency.len()
        );

        client
            .get_call_manager()
            .await
            .notify_relay_latency(&parsed.call_id, &parsed.relay_latency)
            .await;
    }

    async fn handle_accept(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!("Call {} accepted", parsed.call_id);

        let call_manager = client.get_call_manager().await;
        if let Err(e) = call_manager.handle_remote_accept(parsed).await {
            warn!("Failed to handle accept for {}: {}", parsed.call_id, e);
        }

        call_manager.notify_call_accepted(&parsed.call_id).await;

        client
            .core
            .event_bus
            .dispatch(&Event::CallAccepted(CallAccepted {
                meta: parsed.basic_meta(),
            }));
    }

    async fn handle_reject(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!("Call {} rejected", parsed.call_id);
        client
            .core
            .event_bus
            .dispatch(&Event::CallRejected(CallRejected {
                meta: parsed.basic_meta(),
            }));
    }

    async fn handle_terminate(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!("Call {} terminated", parsed.call_id);
        client.core.event_bus.dispatch(&Event::CallEnded(CallEnded {
            meta: parsed.basic_meta(),
        }));
    }

    async fn handle_relay_election(&self, client: &Client, parsed: &ParsedCallStanza) {
        let Some(election) = &parsed.relay_election else {
            debug!("relay_election for {} missing data", parsed.call_id);
            return;
        };

        info!(
            "relay_election for {}: relay_idx={}",
            parsed.call_id, election.elected_relay_idx
        );

        let call_manager = client.get_call_manager().await;
        let call_id = wacore::types::call::CallId::new(&parsed.call_id);

        if let Err(e) = call_manager
            .store_elected_relay(&call_id, election.elected_relay_idx)
            .await
        {
            warn!(
                "Failed to store elected relay for {}: {}",
                parsed.call_id, e
            );
        }

        // Switch transport to elected relay if already bound
        if let Some(transport) = call_manager.get_bound_transport(&call_id).await {
            if transport
                .select_relay_by_id(election.elected_relay_idx)
                .await
            {
                info!(
                    "Switched to elected relay {} for {}",
                    election.elected_relay_idx, parsed.call_id
                );
            } else {
                warn!(
                    "Elected relay {} not connected for {}",
                    election.elected_relay_idx, parsed.call_id
                );
            }
        }
    }

    async fn handle_enc_rekey(&self, client: &Client, parsed: &ParsedCallStanza) {
        let Some(enc_data) = &parsed.enc_rekey_data else {
            warn!("enc_rekey for {} missing data", parsed.call_id);
            return;
        };

        let call_key = match client
            .decrypt_call_key_from(
                &parsed.call_creator,
                &enc_data.ciphertext,
                enc_data.enc_type,
            )
            .await
        {
            Ok(key) => key,
            Err(e) => {
                warn!("Failed to decrypt enc_rekey for {}: {}", parsed.call_id, e);
                return;
            }
        };

        info!(
            "enc_rekey for {} decrypted (generation={})",
            parsed.call_id, call_key.generation
        );

        let derived_keys = derive_call_keys(&call_key);
        client
            .get_call_manager()
            .await
            .notify_enc_rekey(&parsed.call_id, &derived_keys)
            .await;
    }
}
