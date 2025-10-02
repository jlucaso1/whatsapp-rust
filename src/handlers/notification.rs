use super::traits::StanzaHandler;
use crate::client::Client;
use crate::types::events::Event;
use async_trait::async_trait;
use log::{info, warn};
use std::sync::Arc;
use wacore::request::{InfoQuery, InfoQueryType};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::node::NodeContent;
use wacore_binary::{jid::SERVER_JID, node::Node};

/// Handler for `<notification>` stanzas.
///
/// Processes various notification types including:
/// - Encrypt notifications (key upload requests)
/// - Server sync notifications
/// - Account sync notifications (push name updates)
/// - Pairing code notifications
#[derive(Default)]
pub struct NotificationHandler;

impl NotificationHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl StanzaHandler for NotificationHandler {
    fn tag(&self) -> &'static str {
        "notification"
    }

    async fn handle(&self, client: Arc<Client>, node: &Node, _cancelled: &mut bool) -> bool {
        handle_notification_impl(&client, node).await;
        true
    }
}

async fn handle_notification_impl(client: &Arc<Client>, node: &Node) {
    let notification_type = node.attrs.get("type").cloned().unwrap_or_default();

    match notification_type.as_str() {
        "encrypt" => {
            if let Some(from) = node.attrs.get("from")
                && from == SERVER_JID
            {
                let client_clone = client.clone();
                tokio::spawn(async move {
                    if let Err(e) = client_clone.upload_pre_keys().await {
                        warn!("Failed to upload pre-keys after notification: {:?}", e);
                    }
                });
            }
        }
        "server_sync" => {
            info!(target: "Client", "Received `server_sync` notification, scheduling app state sync(s).");
            for collection_node in node.get_children_by_tag("collection") {
                let name = collection_node
                    .attrs
                    .get("name")
                    .cloned()
                    .unwrap_or_default();
                let version = collection_node
                    .attrs
                    .get("version")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0);
                info!(
                    target: "Client/AppState",
                    "scheduling sync for collection '{name}' from version {version}."
                );
            }
        }
        "account_sync" => {
            if let Some(push_name_attr) = node.attrs.get("pushname") {
                let new_push_name = push_name_attr.clone();
                client
                    .clone()
                    .update_push_name_and_notify(new_push_name)
                    .await;
            } else {
                warn!(target: "Client", "TODO: Implement full handler for <notification type='account_sync'>, for now dispatching generic event.");
                client
                    .core
                    .event_bus
                    .dispatch(&Event::Notification(node.clone()));
            }
        }
        "link_code_companion_reg" => {
            handle_pairing_code_notification(client, node).await;
        }
        _ => {
            warn!(target: "Client", "TODO: Implement handler for <notification type='{notification_type}'>");
            client
                .core
                .event_bus
                .dispatch(&Event::Notification(node.clone()));
        }
    }
}

async fn handle_pairing_code_notification(client: &Arc<Client>, node: &Node) {
    info!(target: "Client/Pairing", "Received pairing code notification");

    // Extract the link_code_companion_reg content
    let link_code_nodes = node.get_children_by_tag("link_code_companion_reg");
    if link_code_nodes.is_empty() {
        warn!(target: "Client/Pairing", "No link_code_companion_reg found in notification");
        return;
    }

    let link_code_node = &link_code_nodes[0];
    let stage = link_code_node
        .attrs
        .get("stage")
        .cloned()
        .unwrap_or_default();

    match stage.as_str() {
        "primary_hello" => {
            handle_primary_hello(client, link_code_node).await;
        }
        _ => {
            warn!(target: "Client/Pairing", "Unknown pairing stage: {}", stage);
        }
    }
}

async fn handle_primary_hello(client: &Arc<Client>, link_code_node: &Node) {
    // Get the pairing cache
    let cache = client.phone_linking_cache.lock().await.clone();
    let cache = match cache {
        Some(c) => c,
        None => {
            warn!(target: "Client/Pairing", "No pairing cache found for primary_hello");
            return;
        }
    };

    // Extract pairing reference
    let pairing_ref_nodes = link_code_node.get_children_by_tag("link_code_pairing_ref");
    if pairing_ref_nodes.is_empty() {
        warn!(target: "Client/Pairing", "No pairing reference found in primary_hello");
        return;
    }

    let pairing_ref_node = &pairing_ref_nodes[0];
    let pairing_ref = match &pairing_ref_node.content {
        Some(wacore_binary::node::NodeContent::Bytes(bytes)) => {
            match String::from_utf8(bytes.clone()) {
                Ok(s) => s,
                Err(e) => {
                    warn!(target: "Client/Pairing", "Invalid pairing ref encoding: {}", e);
                    return;
                }
            }
        }
        _ => {
            warn!(target: "Client/Pairing", "Unexpected pairing ref content type");
            return;
        }
    };

    // Verify pairing reference matches
    if pairing_ref != cache.pairing_ref {
        warn!(target: "Client/Pairing", "Pairing reference mismatch");
        return;
    }

    // Extract wrapped primary ephemeral public key
    let wrapped_primary_nodes =
        link_code_node.get_children_by_tag("link_code_pairing_wrapped_primary_ephemeral_pub");
    if wrapped_primary_nodes.is_empty() {
        warn!(target: "Client/Pairing", "No wrapped primary ephemeral key found");
        return;
    }

    let wrapped_primary_node = &wrapped_primary_nodes[0];
    let wrapped_primary_key = match &wrapped_primary_node.content {
        Some(wacore_binary::node::NodeContent::Bytes(bytes)) => bytes.clone(),
        _ => {
            warn!(target: "Client/Pairing", "Unexpected wrapped primary key content type");
            return;
        }
    };

    // Extract primary identity public key
    let primary_identity_nodes = link_code_node.get_children_by_tag("primary_identity_pub");
    if primary_identity_nodes.is_empty() {
        warn!(target: "Client/Pairing", "No primary identity key found");
        return;
    }

    let primary_identity_node = &primary_identity_nodes[0];
    let primary_identity_pub = match &primary_identity_node.content {
        Some(wacore_binary::node::NodeContent::Bytes(bytes)) => {
            if bytes.len() != 32 {
                warn!(target: "Client/Pairing", "Invalid primary identity key length: {}", bytes.len());
                return;
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(bytes);
            arr
        }
        _ => {
            warn!(target: "Client/Pairing", "Unexpected primary identity content type");
            return;
        }
    };

    // Get device snapshot for identity keys
    let device_snapshot = client.persistence_manager.get_device_snapshot().await;

    // Decrypt the primary ephemeral public key
    let primary_ephemeral_pub = match wacore::pair::PairUtils::decrypt_primary_ephemeral_pub(
        &cache.linking_code,
        &wrapped_primary_key,
    ) {
        Ok(key) => key,
        Err(e) => {
            warn!(target: "Client/Pairing", "Failed to decrypt primary ephemeral key: {}", e);
            return;
        }
    };

    // Compute ephemeral shared secret
    let ephemeral_shared_secret = match wacore::pair::PairUtils::compute_pairing_shared_secret(
        &cache.key_pair.private_key,
        &primary_ephemeral_pub,
    ) {
        Ok(secret) => secret,
        Err(e) => {
            warn!(target: "Client/Pairing", "Failed to compute ephemeral shared secret: {}", e);
            return;
        }
    };

    // Compute identity shared secret
    let identity_shared_secret = match wacore::pair::PairUtils::compute_pairing_shared_secret(
        &device_snapshot.identity_key.private_key,
        &primary_identity_pub,
    ) {
        Ok(secret) => secret,
        Err(e) => {
            warn!(target: "Client/Pairing", "Failed to compute identity shared secret: {}", e);
            return;
        }
    };

    // Generate random bytes for ADV secret
    let adv_secret_random = {
        use rand::RngCore;
        let mut random = [0u8; 32];
        rand::rng().fill_bytes(&mut random);
        random
    };

    // Encrypt the key bundle
    let companion_identity_bytes = device_snapshot.identity_key.public_key.public_key_bytes();
    let companion_identity_arr: &[u8; 32] = match companion_identity_bytes.try_into() {
        Ok(arr) => arr,
        Err(_) => {
            warn!(target: "Client/Pairing", "Invalid companion identity key length");
            return;
        }
    };

    let wrapped_key_bundle = match wacore::pair::PairUtils::encrypt_key_bundle(
        &ephemeral_shared_secret,
        companion_identity_arr,
        &primary_identity_pub,
        &adv_secret_random,
    ) {
        Ok(bundle) => bundle,
        Err(e) => {
            warn!(target: "Client/Pairing", "Failed to encrypt key bundle: {}", e);
            return;
        }
    };

    // Compute the ADV secret key
    let adv_secret = wacore::pair::PairUtils::compute_adv_secret(
        &ephemeral_shared_secret,
        &identity_shared_secret,
        &adv_secret_random,
    );

    // Update the device's ADV secret key
    client
        .persistence_manager
        .process_command(crate::store::commands::DeviceCommand::SetAdvSecretKey(
            adv_secret,
        ))
        .await;

    info!(target: "Client/Pairing", "Successfully processed primary_hello, sending companion_finish");

    // Send companion_finish IQ
    let companion_finish_content = NodeBuilder::new("link_code_companion_reg")
        .attr("jid", cache.jid.to_string())
        .attr("stage", "companion_finish")
        .children(vec![
            NodeBuilder::new("link_code_pairing_wrapped_key_bundle")
                .bytes(wrapped_key_bundle)
                .build(),
            NodeBuilder::new("companion_identity_public")
                .bytes(
                    device_snapshot
                        .identity_key
                        .public_key
                        .public_key_bytes()
                        .to_vec(),
                )
                .build(),
            NodeBuilder::new("link_code_pairing_ref")
                .bytes(pairing_ref.as_bytes().to_vec())
                .build(),
        ])
        .build();

    let iq = InfoQuery {
        namespace: "md",
        query_type: InfoQueryType::Set,
        to: SERVER_JID.parse().unwrap(),
        target: None,
        id: None,
        content: Some(NodeContent::Nodes(vec![companion_finish_content])),
        timeout: None,
    };

    match client.send_iq(iq).await {
        Ok(_) => {
            info!(target: "Client/Pairing", "Successfully sent companion_finish, pairing should complete");
        }
        Err(e) => {
            warn!(target: "Client/Pairing", "Failed to send companion_finish: {:?}", e);
        }
    }
}
