use crate::client::Client;
use crate::lid_pn_cache::LearningSource;
use crate::types::events::{Event, PairError, PairSuccess};
use log::{error, info, warn};
use prost::Message;
use rand::TryRngCore;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use wacore::libsignal::protocol::KeyPair;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::{Node, NodeContent};
use waproto::whatsapp as wa;

pub use wacore::pair::{DeviceState, PairCryptoError, PairUtils};

pub fn make_qr_data(store: &crate::store::Device, ref_str: String) -> String {
    let device_state = DeviceState {
        identity_key: store.identity_key.clone(),
        noise_key: store.noise_key.clone(),
        adv_secret_key: store.adv_secret_key,
    };
    PairUtils::make_qr_data(&device_state, ref_str)
}

pub async fn handle_iq(client: &Arc<Client>, node: &Node) -> bool {
    // Server JID is "s.whatsapp.net" (no @ prefix for server-only JIDs)
    if !node
        .attrs
        .get("from")
        .map(|from| from == SERVER_JID)
        .unwrap_or(false)
    {
        return false;
    }

    if let Some(children) = node.children() {
        for child in children {
            let handled = match child.tag.as_str() {
                "pair-device" => {
                    if let Some(ack_node) = PairUtils::build_ack_node(node)
                        && let Err(e) = client.send_node(ack_node).await
                    {
                        warn!("Failed to send acknowledgement: {e:?}");
                    }

                    let mut codes = Vec::new();

                    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
                    let device_state = DeviceState {
                        identity_key: device_snapshot.identity_key.clone(),
                        noise_key: device_snapshot.noise_key.clone(),
                        adv_secret_key: device_snapshot.adv_secret_key,
                    };

                    for grandchild in child.get_children_by_tag("ref") {
                        if let Some(NodeContent::Bytes(bytes)) = &grandchild.content
                            && let Ok(r) = String::from_utf8(bytes.clone())
                        {
                            codes.push(PairUtils::make_qr_data(&device_state, r));
                        }
                    }

                    let (stop_tx, stop_rx) = tokio::sync::watch::channel(());
                    let codes_clone = codes.clone();
                    let client_clone = client.clone();

                    tokio::spawn(async move {
                        // The rotation logic is now inside the library
                        let mut is_first = true;
                        let mut stop_rx_clone = stop_rx.clone();

                        for code in codes_clone {
                            let timeout = if is_first {
                                is_first = false;
                                std::time::Duration::from_secs(60)
                            } else {
                                std::time::Duration::from_secs(20)
                            };

                            // Dispatch the new, simple event for each code
                            client_clone
                                .core
                                .event_bus
                                .dispatch(&Event::PairingQrCode { code, timeout });

                            // Wait for the timeout OR a stop signal
                            tokio::select! {
                                _ = tokio::time::sleep(timeout) => {}
                                _ = stop_rx_clone.changed() => {
                                    info!("Pairing complete. Stopping QR code rotation.");
                                    return;
                                }
                            }
                        }
                        info!("All QR codes for this session have expired.");
                        client_clone.disconnect().await;
                    });

                    *client.pairing_cancellation_tx.lock().await = Some(stop_tx);

                    // We no longer dispatch the raw Event::Qr
                    // client.core.event_bus.dispatch(&Event::Qr(Qr { codes }));
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

async fn handle_pair_success(client: &Arc<Client>, request_node: &Node, success_node: &Node) {
    // Cancel QR code rotation if active
    if let Some(tx) = client.pairing_cancellation_tx.lock().await.take() {
        let _ = tx.send(());
    }

    // Clear pair code state if active
    *client.pair_code_state.lock().await = wacore::pair_code::PairCodeState::Completed;

    client.update_server_time_offset(request_node);

    let req_id = match request_node.attrs.get("id") {
        Some(id) => id.to_string(),
        None => {
            error!("Received pair-success without request ID");
            return;
        }
    };

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
            (Jid::default(), Jid::default())
        } else {
            (parsed_jid, parsed_lid)
        }
    } else {
        (Jid::default(), Jid::default())
    };

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
                    client.core.event_bus.dispatch(&Event::PairError(PairError {
                        id: jid.clone(),
                        lid: lid.clone(),
                        business_name: business_name.clone(),
                        platform: platform.clone(),
                        error: format!("internal error: failed to decode identity for event: {e}"),
                    }));
                    return;
                }
            };

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

            // Add the own LID-PN mapping to the cache so that when sending DMs to self,
            // we can find the existing LID-based session instead of creating a new PN-based one.
            // This is critical for self-messaging to work correctly.
            if !jid.user.is_empty() && !lid.user.is_empty() {
                if let Err(err) = client
                    .add_lid_pn_mapping(&lid.user, &jid.user, LearningSource::Pairing)
                    .await
                {
                    warn!(
                        "Failed to persist own LID-PN mapping {} <-> {}: {err}",
                        lid.user, jid.user
                    );
                } else {
                    info!(
                        "Added own LID-PN mapping to cache: {} <-> {}",
                        lid.user, jid.user
                    );
                }
            }

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

            let response_node = PairUtils::build_pair_success_response(
                &req_id,
                self_signed_identity_bytes,
                key_index,
            );

            if let Err(e) = client.send_node(response_node).await {
                error!("Failed to send pair-device-sign: {e}");
                return;
            }

            let client_for_unified = client.clone();
            tokio::spawn(async move {
                client_for_unified.send_unified_session().await;
            });

            // --- START: FIX ---
            // Set the flag to trigger a full sync on the next successful connection.
            client
                .needs_initial_full_sync
                .store(true, Ordering::Relaxed);
            // --- END: FIX ---

            client.expected_disconnect.store(true, Ordering::Relaxed);

            info!("Successfully paired {jid}");

            let success_event = PairSuccess {
                id: jid,
                lid,
                business_name,
                platform,
            };
            client
                .core
                .event_bus
                .dispatch(&Event::PairSuccess(success_event));
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
                .core
                .event_bus
                .dispatch(&Event::PairError(pair_error_event));
        }
    }
}

pub async fn pair_with_qr_code(client: &Arc<Client>, qr_code: &str) -> Result<(), anyhow::Error> {
    info!(target: "Client/PairTest", "Master client attempting to pair with QR code.");

    let (pairing_ref, dut_noise_pub, dut_identity_pub) = PairUtils::parse_qr_code(qr_code)?;

    let master_ephemeral = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());

    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let device_state = DeviceState {
        identity_key: device_snapshot.identity_key.clone(),
        noise_key: device_snapshot.noise_key.clone(),
        adv_secret_key: device_snapshot.adv_secret_key,
    };

    let encrypted = PairUtils::prepare_master_pairing_message(
        &device_state,
        &pairing_ref,
        &dut_noise_pub,
        &dut_identity_pub,
        master_ephemeral,
    )?;

    let master_jid = device_snapshot
        .pn
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Cannot pair: device has no phone number JID configured"))?;
    let req_id = client.generate_request_id();

    let iq = PairUtils::build_master_pair_iq(&master_jid, encrypted, req_id);

    client.send_node(iq).await?;

    info!(target: "Client/PairTest", "Master client sent pairing confirmation.");
    Ok(())
}
