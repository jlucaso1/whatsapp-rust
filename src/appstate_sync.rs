use crate::appstate::processor::{PatchList, Processor};
use crate::binary::node::{Attrs, Node, NodeContent};
use crate::client::Client;
use whatsapp_proto::whatsapp as wa;
use crate::request::{InfoQuery, InfoQueryType};
use crate::types::events::{ContactUpdate, Event};
use crate::types::jid::{self, Jid};
use log::{error, info, warn};
use prost::Message;
use std::str::FromStr;
use std::sync::Arc;

async fn request_app_state_keys(client: &Arc<Client>, keys: Vec<Vec<u8>>) {
    use whatsapp_proto::whatsapp::message::protocol_message;

    let key_ids = keys
        .into_iter()
        .map(|id| wa::message::AppStateSyncKeyId { key_id: Some(id) })
        .collect();

    let msg = wa::Message {
        protocol_message: Some(Box::new(wa::message::ProtocolMessage {
            r#type: Some(protocol_message::Type::AppStateSyncKeyRequest as i32),
            app_state_sync_key_request: Some(wa::message::AppStateSyncKeyRequest { key_ids }),
            ..Default::default()
        })),
        ..Default::default()
    };

    if let Some(own_jid) = client.store.read().await.id.clone() {
        let own_non_ad = own_jid.to_non_ad();
        if let Err(e) = client.send_message(own_non_ad, msg).await {
            warn!("Failed to send app state key request: {:?}", e);
        }
    } else {
        warn!("Can't request app state keys, not logged in.");
    }
}

pub async fn fetch_app_state_patches(
    client: &Arc<Client>,
    name: &str,
    version: u64,
    is_full_sync: bool,
) -> Result<Node, crate::request::IqError> {
    let mut attrs = Attrs::new();
    attrs.insert("name".to_string(), name.to_string());
    attrs.insert("return_snapshot".to_string(), is_full_sync.to_string());
    if !is_full_sync {
        attrs.insert("version".to_string(), version.to_string());
    }

    let collection_node = Node {
        tag: "collection".to_string(),
        attrs,
        content: None,
    };

    let sync_node = Node {
        tag: "sync".to_string(),
        attrs: Attrs::new(),
        content: Some(NodeContent::Nodes(vec![collection_node])),
    };

    let iq = InfoQuery {
        namespace: "w:sync:app:state",
        query_type: InfoQueryType::Set,
        to: jid::SERVER_JID.parse().unwrap(),
        target: None,
        id: None,
        content: Some(NodeContent::Nodes(vec![sync_node])),
        timeout: None,
    };

    client.send_iq(iq).await
}

pub async fn app_state_sync(client: &Arc<Client>, name: &str, full_sync: bool) {
    info!(target: "Client/AppState", "Starting AppState sync for '{}' (full_sync: {})", name, full_sync);

    let store_guard = client.store.read().await;
    let backend = store_guard.backend.clone();
    let processor = Processor::new(backend.clone(), backend.clone());
    drop(store_guard);

    let mut current_state = match backend.get_app_state_version(name).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get app state version for {}: {:?}", name, e);
            return;
        }
    };
    if full_sync {
        current_state.version = 0;
        current_state.hash = [0; 128];
    }

    let mut has_more = true;
    let mut is_first_sync = full_sync;

    while has_more {
        let resp_node = match fetch_app_state_patches(
            client,
            name,
            current_state.version,
            is_first_sync,
        )
        .await
        {
            Ok(resp) => resp,
            Err(e) => {
                error!(target: "Client/AppState", "Failed to fetch patches for {}: {:?}", name, e);
                return;
            }
        };
        is_first_sync = false;

        if let Some(sync_node) = resp_node.get_optional_child("sync") {
            if let Some(collection_node) = sync_node.get_optional_child("collection") {
                let mut attrs = collection_node.attrs();
                has_more = attrs.optional_bool("has_more_patches");

                let mut patches = Vec::new();
                if let Some(patches_node) = collection_node.get_optional_child("patches") {
                    for patch_child in patches_node.children().unwrap_or_default() {
                        if let Some(crate::binary::node::NodeContent::Bytes(b)) =
                            &patch_child.content
                        {
                            if let Ok(mut patch) = wa::SyncdPatch::decode(b.as_slice()) {
                                // --- External blob integration ---
                                if let Some(external_ref) = patch.external_mutations.take() {
                                    info!("Found patch with external mutations. Attempting download...");
                                    match client.download(&external_ref).await {
                                        Ok(decrypted_blob) => {
                                            match wa::SyncdMutations::decode(
                                                decrypted_blob.as_slice(),
                                            ) {
                                                Ok(downloaded_mutations) => {
                                                    info!("Successfully downloaded and parsed {} external mutations.", downloaded_mutations.mutations.len());
                                                    patch.mutations =
                                                        downloaded_mutations.mutations;
                                                }
                                                Err(e) => {
                                                    error!("Failed to parse downloaded mutations blob: {}. Skipping patch.", e);
                                                    continue; // Skip this patch
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to download external mutations: {}. Skipping patch.", e);
                                            continue; // Skip this patch
                                        }
                                    }
                                }
                                patches.push(patch);
                            }
                        }
                    }
                }

                let snapshot = None;

                let patch_list = PatchList {
                    name: name.to_string(),
                    has_more_patches: has_more,
                    patches,
                    snapshot,
                };

                match processor
                    .decode_patches(&patch_list, current_state.clone())
                    .await
                {
                    Ok((mutations, new_state)) => {
                        current_state = new_state;
                        info!(
                            target: "Client/AppState",
                            "Decoded {} mutations for '{}'. New version: {}",
                            mutations.len(), name, current_state.version
                        );

                        for mutation in &mutations {
                            if mutation.operation == wa::syncd_mutation::SyncdOperation::Set {
                                if let Some(contact_action) =
                                    mutation.action.contact_action.as_ref()
                                {
                                    if mutation.index.len() > 1 {
                                        let jid_str = &mutation.index[1];
                                        if let Ok(jid) = Jid::from_str(jid_str) {
                                            let _ = backend.put_identity(jid_str, [0u8; 32]).await;
                                            let event = Event::ContactUpdate(ContactUpdate {
                                                jid,
                                                timestamp: chrono::Utc::now(),
                                                action: Box::new(contact_action.clone()),
                                                from_full_sync: full_sync,
                                            });
                                            let _ = client.dispatch_event(event).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        if let crate::appstate::errors::AppStateError::KeysNotFound(missing) = e {
                            info!(
                                "Requesting {} missing app state keys for sync of '{}'",
                                missing.len(),
                                name
                            );
                            request_app_state_keys(client, missing).await;
                        } else {
                            error!("Failed to decode patches for {}: {:?}", name, e);
                            has_more = false;
                        }
                    }
                };
            } else {
                warn!(target: "Client/AppState", "Sync response for '{}' missing <collection> node", name);
                has_more = false;
            }
        } else {
            warn!(target: "Client/AppState", "Sync response for '{}' missing <sync> node", name);
            has_more = false;
        }
    }
    info!(target: "Client/AppState", "Finished AppState sync for '{}'", name);
}
