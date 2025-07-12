use crate::binary::node::{Node, NodeContent};
use crate::client::Client;
use crate::types::events::{Event, PairError, PairSuccess, Qr};
use crate::types::jid::Jid;
use log::{debug, error, info, warn};
use prost::Message;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use whatsapp_proto::whatsapp as wa;

// Re-export core utilities
pub use whatsapp_core::pair::{DeviceState, PairCryptoError, PairUtils};

/// Backward compatibility function for tests
pub fn make_qr_data(store: &crate::store::Device, ref_str: String) -> String {
    let device_state = DeviceState {
        identity_key: store.identity_key.clone(),
        noise_key: store.noise_key.clone(),
        adv_secret_key: store.adv_secret_key,
    };
    PairUtils::make_qr_data(&device_state, ref_str)
}

/// Handles incoming IQ stanzas related to the pairing process.
pub async fn handle_iq(client: &Arc<Client>, node: &Node) -> bool {
    if node.attrs.get("from").cloned().unwrap_or_default() != "s.whatsapp.net" {
        return false;
    }

    if let Some(children) = node.children() {
        for child in children {
            let handled = match child.tag.as_str() {
                "pair-device" => {
                    // 1. Acknowledge the request immediately using core logic
                    if let Some(ack_node) = PairUtils::build_ack_node(node) {
                        if let Err(e) = client.send_node(ack_node).await {
                            warn!("Failed to send acknowledgement: {e:?}");
                        }
                    }

                    // 2. Extract QR code refs and generate full QR data strings (async)
                    let mut codes = Vec::new();
                    for grandchild in child.get_children_by_tag("ref") {
                        if let Some(NodeContent::Bytes(bytes)) = &grandchild.content
                            && let Ok(r) = String::from_utf8(bytes.clone())
                        {
                            let device_snapshot =
                                client.persistence_manager.get_device_snapshot().await;

                            // Convert to core DeviceState
                            let device_state = DeviceState {
                                identity_key: device_snapshot.identity_key.clone(),
                                noise_key: device_snapshot.noise_key.clone(),
                                adv_secret_key: device_snapshot.adv_secret_key,
                            };

                            codes.push(PairUtils::make_qr_data(&device_state, r));
                        }
                    }

                    debug!(target: "Client/Pair", "Dispatching QR event with {} codes", codes.len());
                    client.dispatch_event(Event::Qr(Qr { codes })).await;
                    true
                }
                "pair-success" => {
                    handle_pair_success(client, node, child).await;
                    true
                }
                _ => false,
            };
            if handled {
                return true;
            }
        }
    }

    false
}

/// Handles the <pair-success> stanza, finalizing the pairing process.
async fn handle_pair_success(client: &Arc<Client>, request_node: &Node, success_node: &Node) {
    let req_id = match request_node.attrs.get("id") {
        Some(id) => id.to_string(),
        None => {
            error!("Received pair-success without request ID");
            return;
        }
    };

    // Extract all data from the success node.
    let device_identity_bytes = match success_node
        .get_optional_child_by_tag(&["device-identity"])
        .and_then(|n| n.content.as_ref())
    {
        Some(NodeContent::Bytes(b)) => b.clone(),
        _ => {
            let error_node = PairUtils::build_pair_error_node(&req_id, 500, "internal-error");
            if let Err(e) = client.send_node(error_node).await {
                error!("Failed to send pair error node: {e}");
            }
            error!("pair-success is missing device-identity");
            return;
        }
    };

    let business_name = success_node
        .get_optional_child_by_tag(&["biz"])
        .map(|n| n.attrs().optional_string("name").unwrap_or("").to_string())
        .unwrap_or_default();

    let platform = success_node
        .get_optional_child_by_tag(&["platform"])
        .map(|n| n.attrs().optional_string("name").unwrap_or("").to_string())
        .unwrap_or_default();

    // For jid and lid, parse them together to handle errors correctly
    let (jid, lid) = if let Some(device_node) = success_node.get_optional_child_by_tag(&["device"])
    {
        let mut parser = device_node.attrs();
        let parsed_jid = parser.optional_jid("jid").unwrap_or_default();
        let parsed_lid = parser.optional_jid("lid").unwrap_or_default();

        if let Err(e) = parser.finish() {
            warn!(target: "Client/Pair", "Error parsing device node attributes: {e:?}");
            (Jid::default(), Jid::default()) // Return defaults on parsing error
        } else {
            (parsed_jid, parsed_lid)
        }
    } else {
        (Jid::default(), Jid::default())
    };

    // Perform the crypto operations using core logic
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let device_state = DeviceState {
        identity_key: device_snapshot.identity_key.clone(),
        noise_key: device_snapshot.noise_key.clone(),
        adv_secret_key: device_snapshot.adv_secret_key,
    };

    let result = PairUtils::do_pair_crypto(&device_state, &device_identity_bytes);

    match result {
        Ok((self_signed_identity_bytes, key_index)) => {
            let signed_identity_for_event = match wa::AdvSignedDeviceIdentity::decode(
                self_signed_identity_bytes.as_slice(),
            ) {
                Ok(identity) => identity,
                Err(e) => {
                    error!(
                        "FATAL: Failed to re-decode self-signed identity for event, pairing cannot complete: {e}"
                    );
                    client
                        .dispatch_event(Event::PairError(PairError {
                            id: jid.clone(),
                            lid: lid.clone(),
                            business_name: business_name.clone(),
                            platform: platform.clone(),
                            error: format!(
                                "internal error: failed to decode identity for event: {e}"
                            ),
                        }))
                        .await;
                    return;
                }
            };

            // Update the store via PersistenceManager commands
            client
                .persistence_manager
                .process_command(crate::store::commands::DeviceCommand::SetId(Some(
                    jid.clone(),
                )))
                .await;
            client
                .persistence_manager
                .process_command(crate::store::commands::DeviceCommand::SetAccount(Some(
                    signed_identity_for_event.clone(),
                )))
                .await;
            client
                .persistence_manager
                .process_command(crate::store::commands::DeviceCommand::SetLid(Some(
                    lid.clone(),
                )))
                .await;

            // Only set push_name if we actually got one.
            if !business_name.is_empty() {
                info!("✅ Setting push_name during pairing: '{}'", &business_name);
                client
                    .persistence_manager
                    .process_command(crate::store::commands::DeviceCommand::SetPushName(
                        business_name.clone(),
                    ))
                    .await;
            } else {
                info!(
                    "⚠️ business_name not found in pair-success, push_name remains unset for now."
                );
            }

            // Build response using core logic
            let response_node = PairUtils::build_pair_success_response(
                &req_id,
                self_signed_identity_bytes,
                key_index,
            );

            if let Err(e) = client.send_node(response_node).await {
                error!("Failed to send pair-device-sign: {e}");
                return;
            }

            // Tell the client that the upcoming disconnect is expected and part of the flow.
            client.expected_disconnect.store(true, Ordering::Relaxed);

            info!("Successfully paired {jid}");

            let success_event = PairSuccess {
                id: jid,
                lid,
                business_name,
                platform,
            };
            client
                .dispatch_event(Event::PairSuccess(success_event))
                .await;
        }
        Err(e) => {
            error!("Pairing crypto failed: {e}");
            let error_node = PairUtils::build_pair_error_node(&req_id, e.code, e.text);
            if let Err(send_err) = client.send_node(error_node).await {
                error!("Failed to send pair error node: {send_err}");
            }

            let pair_error_event = crate::types::events::PairError {
                id: jid,
                lid,
                business_name,
                platform,
                error: e.to_string(),
            };
            client
                .dispatch_event(Event::PairError(pair_error_event))
                .await;
        }
    }
}

/// Simulates a phone scanning a QR code and pairing with a new device.
/// This is the logic that the "master" client will use in tests.
pub async fn pair_with_qr_code(
    client: &Arc<Client>, // The "master" client
    qr_code: &str,
) -> Result<(), anyhow::Error> {
    info!(target: "Client/PairTest", "Master client attempting to pair with QR code.");

    // Parse QR code using core logic
    let (pairing_ref, dut_noise_pub, dut_identity_pub) = PairUtils::parse_qr_code(qr_code)?;

    // The master client (phone) generates its own ephemeral key
    let master_ephemeral = crate::crypto::key_pair::KeyPair::new();

    // Get device state
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let device_state = DeviceState {
        identity_key: device_snapshot.identity_key.clone(),
        noise_key: device_snapshot.noise_key.clone(),
        adv_secret_key: device_snapshot.adv_secret_key,
    };

    // Prepare pairing message using core logic
    let encrypted = PairUtils::prepare_master_pairing_message(
        &device_state,
        &pairing_ref,
        &dut_noise_pub,
        &dut_identity_pub,
        &master_ephemeral,
    )?;

    // Send the final pairing IQ stanza to the server
    let master_jid = device_snapshot.id.clone().unwrap();
    let req_id = client.generate_request_id();

    let iq = PairUtils::build_master_pair_iq(&master_jid, encrypted, req_id);

    client.send_node(iq).await?;

    info!(target: "Client/PairTest", "Master client sent pairing confirmation.");
    Ok(())
}
