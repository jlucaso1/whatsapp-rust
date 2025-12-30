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
                "Call {} relay: uuid={:?}, self_pid={:?}, peer_pid={:?}, hbh_key={} bytes, relay_key={} bytes, endpoints={}",
                parsed.call_id,
                relay.uuid,
                relay.self_pid,
                relay.peer_pid,
                relay.hbh_key.as_ref().map(|k| k.len()).unwrap_or(0),
                relay.relay_key.as_ref().map(|k| k.len()).unwrap_or(0),
                relay.endpoints.len(),
            );
        }

        // Register the call with CallManager (skip offline calls as they're stale)
        let call_manager = client.get_call_manager().await;
        if parsed.is_offline {
            debug!(
                "Skipping registration of offline call {} (stale)",
                parsed.call_id
            );
        } else if let Err(e) = call_manager.register_incoming_call(parsed).await {
            warn!("Failed to register incoming call {}: {}", parsed.call_id, e);
        }

        // Notify callback with parsed offer data
        if parsed.offer_enc_data.is_some() || parsed.relay_data.is_some() {
            let relay_data = parsed.relay_data.as_ref().cloned().unwrap_or_default();
            let media_params = parsed.media_params.as_ref().cloned().unwrap_or_default();
            let enc_data =
                parsed
                    .offer_enc_data
                    .as_ref()
                    .cloned()
                    .unwrap_or_else(|| OfferEncData {
                        enc_type: super::encryption::EncType::Msg,
                        ciphertext: Vec::new(),
                        version: 0,
                    });

            call_manager
                .notify_offer_received(&parsed.call_id, &relay_data, &media_params, &enc_data)
                .await;
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

    async fn handle_transport(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!(
            "Received transport (ICE candidates) for call {}",
            parsed.call_id
        );

        // Parse transport payload if present
        if let Some(payload_bytes) = &parsed.payload {
            let transport = TransportPayload::from_raw(payload_bytes.clone());
            debug!(
                "Call {} transport: {} candidates, ufrag={:?}, raw_bytes={}",
                parsed.call_id,
                transport.candidates.len(),
                transport.ufrag,
                transport.raw_data.len(),
            );

            // Notify callback
            let call_manager = client.get_call_manager().await;
            call_manager
                .notify_transport_received(&parsed.call_id, &transport)
                .await;
        }
    }

    async fn handle_relay_latency(&self, client: &Client, parsed: &ParsedCallStanza) {
        if parsed.relay_latency.is_empty() {
            debug!("Received empty relay latency for call {}", parsed.call_id);
            return;
        }

        debug!(
            "Received relay latency for call {}: {} measurements",
            parsed.call_id,
            parsed.relay_latency.len()
        );

        for lat in &parsed.relay_latency {
            debug!(
                "  Relay {}: {}ms (raw={}, ipv4={:?}, ipv6={:?})",
                lat.relay_name, lat.latency_ms, lat.raw_latency, lat.ipv4, lat.ipv6
            );
        }

        // Notify callback
        let call_manager = client.get_call_manager().await;
        call_manager
            .notify_relay_latency(&parsed.call_id, &parsed.relay_latency)
            .await;
    }

    async fn handle_accept(&self, client: &Client, parsed: &ParsedCallStanza) {
        debug!("Call {} accepted by peer", parsed.call_id);

        // Update call state in manager
        let call_manager = client.get_call_manager().await;
        if let Err(e) = call_manager.handle_remote_accept(parsed).await {
            warn!("Failed to update call state for accept: {}", e);
        }

        // Notify callback that the call was accepted (so media connection can start)
        call_manager.notify_call_accepted(&parsed.call_id).await;

        // Emit CallAccepted event for UI
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

    async fn handle_relay_election(&self, client: &Client, parsed: &ParsedCallStanza) {
        if let Some(election) = &parsed.relay_election {
            log::info!(
                "Received relay_election for call {}: elected_relay_idx={}",
                parsed.call_id,
                election.elected_relay_idx
            );

            let call_manager = client.get_call_manager().await;
            let call_id = wacore::types::call::CallId::new(&parsed.call_id);

            // Store the elected relay index
            if let Err(e) = call_manager
                .store_elected_relay(&call_id, election.elected_relay_idx)
                .await
            {
                warn!(
                    "Failed to store elected relay for call {}: {}",
                    parsed.call_id, e
                );
            }

            // If we have a bound transport, switch it to the elected relay NOW
            // This ensures we're on the right relay before the peer accepts
            if let Some(transport) = call_manager.get_bound_transport(&call_id).await {
                if transport
                    .select_relay_by_id(election.elected_relay_idx)
                    .await
                {
                    log::info!(
                        "Switched to elected relay {} for call {}",
                        election.elected_relay_idx,
                        parsed.call_id
                    );
                } else {
                    warn!(
                        "Could not switch to elected relay {} for call {} (not connected to it)",
                        election.elected_relay_idx, parsed.call_id
                    );
                }
            } else {
                debug!(
                    "No bound transport for call {} yet, will use elected relay when connected",
                    parsed.call_id
                );
            }
        } else {
            debug!(
                "Received relay_election for call {} but failed to parse election data",
                parsed.call_id
            );
        }
    }

    /// Handle enc_rekey signaling (SRTP key rotation).
    ///
    /// The enc_rekey stanza contains a Signal-encrypted call key that we need to:
    /// 1. Decrypt using Signal Protocol
    /// 2. Derive new SRTP keys from the master key
    /// 3. Notify the media session via callback to rotate keys
    async fn handle_enc_rekey(&self, client: &Client, parsed: &ParsedCallStanza) {
        let enc_data = match &parsed.enc_rekey_data {
            Some(data) => data,
            None => {
                warn!(
                    "Received enc_rekey for call {} but failed to parse enc data",
                    parsed.call_id
                );
                return;
            }
        };

        debug!(
            "Processing enc_rekey for call {} (type: {:?}, {} bytes)",
            parsed.call_id,
            enc_data.enc_type,
            enc_data.ciphertext.len()
        );

        // Decrypt the call key using Signal Protocol
        let call_key = match client
            .decrypt_call_key_from(
                &parsed.call_creator,
                &enc_data.ciphertext,
                enc_data.enc_type,
            )
            .await
        {
            Ok(key) => {
                info!(
                    "Successfully decrypted enc_rekey for call {} (generation={})",
                    parsed.call_id, key.generation
                );
                key
            }
            Err(e) => {
                warn!(
                    "Failed to decrypt enc_rekey for call {}: {}",
                    parsed.call_id, e
                );
                return;
            }
        };

        // Derive SRTP keys from the master key
        let derived_keys = derive_call_keys(&call_key);

        debug!(
            "Derived new SRTP keys for call {} from enc_rekey",
            parsed.call_id
        );

        // Notify callback to rotate keys in the media session
        let call_manager = client.get_call_manager().await;
        call_manager
            .notify_enc_rekey(&parsed.call_id, &derived_keys)
            .await;

        info!(
            "Completed enc_rekey processing for call {} - keys rotated",
            parsed.call_id
        );
    }
}
