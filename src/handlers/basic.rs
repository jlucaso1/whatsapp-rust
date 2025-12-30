use super::traits::StanzaHandler;
use crate::calls::{RelayLatencyMeasurement, parse_relay_data_from_ack};
use crate::client::Client;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::sync::Arc;
use wacore::types::call::CallId;
use wacore_binary::node::Node;

/// Handler for `<success>` stanzas.
///
/// Processes successful authentication/connection events.
#[derive(Default)]
pub struct SuccessHandler;

#[async_trait]
impl StanzaHandler for SuccessHandler {
    fn tag(&self) -> &'static str {
        "success"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        client.handle_success(&node).await;
        true
    }
}

/// Handler for `<failure>` stanzas.
///
/// Processes connection or authentication failures.
#[derive(Default)]
pub struct FailureHandler;

#[async_trait]
impl StanzaHandler for FailureHandler {
    fn tag(&self) -> &'static str {
        "failure"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        client.handle_connect_failure(&node).await;
        true
    }
}

/// Handler for `<stream:error>` stanzas.
///
/// Processes stream-level errors that may require connection reset.
#[derive(Default)]
pub struct StreamErrorHandler;

#[async_trait]
impl StanzaHandler for StreamErrorHandler {
    fn tag(&self) -> &'static str {
        "stream:error"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        client.handle_stream_error(&node).await;
        true
    }
}

/// Handler for `<ack>` stanzas.
///
/// Processes acknowledgment messages, including special handling for
/// call offer ACKs which contain relay allocation data.
#[derive(Default)]
pub struct AckHandler;

#[async_trait]
impl StanzaHandler for AckHandler {
    fn tag(&self) -> &'static str {
        "ack"
    }

    async fn handle(&self, client: Arc<Client>, node: Arc<Node>, _cancelled: &mut bool) -> bool {
        // Check for call offer ACK with relay data
        // Format: <ack class="call" type="offer"><relay call-id="...">...</relay></ack>
        let is_call_offer_ack = node
            .attrs
            .get("class")
            .map(|c| c == "call")
            .unwrap_or(false)
            && node
                .attrs
                .get("type")
                .map(|t| t == "offer")
                .unwrap_or(false);

        if is_call_offer_ack {
            // Parse relay data from the ACK
            if let Some(relay_data) = parse_relay_data_from_ack(&node) {
                // Extract call_id from the relay node
                if let Some(call_id_str) = node
                    .get_optional_child("relay")
                    .and_then(|r| r.attrs.get("call-id"))
                    .cloned()
                {
                    info!(
                        "Received offer ACK with relay data for call {}: {} endpoints, hbh_key={} bytes, relay_key={} bytes",
                        call_id_str,
                        relay_data.endpoints.len(),
                        relay_data.hbh_key.as_ref().map(|k| k.len()).unwrap_or(0),
                        relay_data.relay_key.as_ref().map(|k| k.len()).unwrap_or(0)
                    );

                    // Log c2r_rtt values from each endpoint
                    for endpoint in &relay_data.endpoints {
                        info!(
                            "  Endpoint {}: c2r_rtt={:?}ms",
                            endpoint.relay_name, endpoint.c2r_rtt_ms
                        );
                    }

                    let call_manager = client.get_call_manager().await;
                    let call_id = CallId::new(&call_id_str);

                    // Store the relay data in the call manager first
                    if let Err(e) = call_manager
                        .store_relay_data(&call_id, relay_data.clone())
                        .await
                    {
                        debug!("Failed to store relay data for call {}: {}", call_id, e);
                    }

                    // CRITICAL: Send latencies IMMEDIATELY using server-provided c2r_rtt estimates.
                    // The server needs latencies from BOTH peers quickly to elect a common relay.
                    // If we wait for binding (which can timeout), the peer may already be on a
                    // different relay before we report our latencies.
                    info!(
                        "Sending relay latencies IMMEDIATELY using c2r_rtt for call {} ({} endpoints)",
                        call_id,
                        relay_data.endpoints.len()
                    );

                    for endpoint in &relay_data.endpoints {
                        // Get token for this endpoint
                        let token = relay_data
                            .relay_tokens
                            .get(endpoint.token_id as usize)
                            .cloned()
                            .unwrap_or_default();

                        // Get first IPv4 address
                        let (ipv4, port) = endpoint
                            .addresses
                            .iter()
                            .find_map(|addr| {
                                addr.ipv4.as_ref().map(|ip| (Some(ip.clone()), addr.port))
                            })
                            .unwrap_or((None, 3478));

                        // Use server-provided c2r_rtt, fallback to 50ms if not available
                        let latency_ms = endpoint.c2r_rtt_ms.unwrap_or(50);

                        let measurement = RelayLatencyMeasurement {
                            relay_name: endpoint.relay_name.clone(),
                            latency_ms,
                            ipv4,
                            port,
                            token,
                        };

                        match call_manager
                            .send_relay_latency(&call_id, vec![measurement.clone()])
                            .await
                        {
                            Ok(stanza) => {
                                if let Err(e) = client.send_node(stanza).await {
                                    warn!(
                                        "Failed to send relay latency for {}: {}",
                                        measurement.relay_name, e
                                    );
                                } else {
                                    info!(
                                        "Sent relay latency for {} ({}ms c2r_rtt) for call {}",
                                        measurement.relay_name, measurement.latency_ms, call_id
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Failed to build relay latency stanza for {}: {}",
                                    measurement.relay_name, e
                                );
                            }
                        }
                    }

                    info!(
                        "Sent {} relay latencies using c2r_rtt for call {}",
                        relay_data.endpoints.len(),
                        call_id
                    );

                    // Send TRANSPORT stanza - this is CRITICAL for call setup
                    // The peer expects this to confirm candidate selection and transition state
                    let transport_params = crate::calls::TransportParams {
                        p2p_cand_round: Some(0),
                        transport_message_type: Some(0),
                        net_protocol: 0,
                        net_medium: 2, // WiFi/LAN
                    };

                    match call_manager
                        .send_transport(&call_id, transport_params)
                        .await
                    {
                        Ok(transport_node) => {
                            if let Err(e) = client.send_node(transport_node).await {
                                warn!(
                                    "Failed to send TRANSPORT stanza for call {}: {}",
                                    call_id, e
                                );
                            } else {
                                info!("Sent TRANSPORT stanza for call {}", call_id);
                            }
                        }
                        Err(e) => {
                            warn!(
                                "Failed to build TRANSPORT stanza for call {}: {}",
                                call_id, e
                            );
                        }
                    }

                    // Now spawn background task for early binding and keepalives.
                    // This maintains the relay bindings but doesn't block latency reporting.
                    let relay_data_clone = relay_data.clone();
                    let call_id_clone = call_id.clone();
                    let call_manager_clone = Arc::clone(&call_manager);
                    tokio::spawn(async move {
                        info!(
                            "Starting background early binding for call {} ({} endpoints)",
                            call_id_clone,
                            relay_data_clone.endpoints.len()
                        );

                        match call_manager_clone
                            .bind_relays_early(&call_id_clone, &relay_data_clone)
                            .await
                        {
                            Ok(latencies) => {
                                info!(
                                    "Background binding SUCCESSFUL for call {}: {} relays bound (RTTs: {:?})",
                                    call_id_clone,
                                    latencies.len(),
                                    latencies
                                        .iter()
                                        .map(|l| format!("{}={:?}", l.relay_name, l.rtt))
                                        .collect::<Vec<_>>()
                                );

                                // Start keepalive loop
                                if let Some(transport) =
                                    call_manager_clone.get_bound_transport(&call_id_clone).await
                                {
                                    let call_manager_weak = Arc::downgrade(&call_manager_clone);
                                    let mut interval =
                                        tokio::time::interval(std::time::Duration::from_secs(3));

                                    loop {
                                        interval.tick().await;

                                        let Some(cm) = call_manager_weak.upgrade() else {
                                            debug!(
                                                "Call manager dropped, stopping keepalive for {}",
                                                call_id_clone
                                            );
                                            break;
                                        };

                                        if cm.get_bound_transport(&call_id_clone).await.is_none() {
                                            info!(
                                                "Transport taken for call {}, stopping keepalives",
                                                call_id_clone
                                            );
                                            break;
                                        }

                                        match transport.send_keepalives().await {
                                            Ok(()) => {
                                                debug!("Keepalive sent for call {}", call_id_clone);
                                            }
                                            Err(e) => {
                                                warn!(
                                                    "Keepalive failed for call {}: {}",
                                                    call_id_clone, e
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!(
                                    "Background binding FAILED for call {}: {} - media connection may not work",
                                    call_id_clone, e
                                );
                            }
                        }
                    });
                }
            }
        }

        // Delegate to the client to check if any task is waiting for this ack.
        // The client will resolve pending response waiters if the ID matches.
        // Try to unwrap Arc or clone Node if there are other references
        let owned_node = Arc::try_unwrap(node).unwrap_or_else(|arc| (*arc).clone());
        client.handle_ack_response(owned_node).await;
        // We return `true` because this handler's purpose is to consume all <ack> stanzas.
        true
    }
}
