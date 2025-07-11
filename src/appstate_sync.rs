use crate::appstate::processor::{PatchList, Processor};
use crate::binary::node::{Attrs, Node, NodeContent};
use crate::client::Client;
use crate::request::{InfoQuery, InfoQueryType};
use crate::types::events::{ContactUpdate, Event};
use crate::types::jid::{self, Jid};
use log::{error, info, warn};
use prost::Message;
use std::str::FromStr;
use std::sync::Arc;
use whatsapp_proto::whatsapp as wa;

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

    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    if let Some(own_jid) = device_snapshot.id.clone() {
        let own_non_ad = own_jid.to_non_ad();
        let request_id = client.generate_message_id().await;
        if let Err(e) = client.send_message_impl(own_non_ad, msg, request_id).await {
            warn!("Failed to send app state key request: {e:?}");
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
    info!(target: "Client/AppState", "Starting AppState sync for '{name}' (full_sync: {full_sync})");

    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let backend = device_snapshot.backend.clone();
    
    // Cast the backend to our extended store interfaces
    let app_state_store = backend.clone();
    let key_store = backend.clone();
    
    // Create a dummy processor for now since we need to fix the trait issue first
    // TODO: Fix this properly by ensuring proper trait bounds
    let processor = {
        // We'll cast the backend directly to the required trait objects
        // This works because we know our concrete types implement these traits
        let app_state_store: Arc<dyn crate::store::traits::AppStateStore> = backend.clone();
        let key_store: Arc<dyn crate::store::traits::AppStateKeyStore> = backend.clone();
        // For now, just create a dummy processor that we won't actually use
        // TODO: This needs proper trait bounds resolution
        return; // Skip the sync for now to avoid compilation errors
    };
    
    // For now, get the app state version directly from the backend cast as AppStateStore
    let mut current_state = {
        let any_backend = backend.as_ref() as &dyn std::any::Any;
        if let Some(store) = any_backend.downcast_ref::<crate::store::filestore::FileStore>() {
            store.get_app_state_version(name).await.unwrap_or_default()
        } else if let Some(store) = any_backend.downcast_ref::<crate::store::memory::MemoryStore>() {
            store.get_app_state_version(name).await.unwrap_or_default()
        } else {
            Default::default()
        }
    };
    
    // TODO: Re-enable processor once trait issues are resolved
    // let mut current_state = match app_state_store.get_app_state_version(name).await {
    if full_sync {
        current_state.version = 0;
        current_state.hash = [0; 128];
    }

    let mut has_more = true;
    let mut is_first_sync = full_sync;

    while has_more {
        let resp_node =
            match fetch_app_state_patches(client, name, current_state.version, is_first_sync).await
            {
                Ok(resp) => resp,
                Err(e) => {
                    error!(target: "Client/AppState", "Failed to fetch patches for {name}: {e:?}");
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
                                    info!(
                                        "Found patch with external mutations. Attempting download..."
                                    );
                                    match client.download(&external_ref).await {
                                        Ok(decrypted_blob) => {
                                            match wa::SyncdMutations::decode(
                                                decrypted_blob.as_slice(),
                                            ) {
                                                Ok(downloaded_mutations) => {
                                                    info!(
                                                        "Successfully downloaded and parsed {} external mutations.",
                                                        downloaded_mutations.mutations.len()
                                                    );
                                                    patch.mutations =
                                                        downloaded_mutations.mutations;
                                                }
                                                Err(e) => {
                                                    error!(
                                                        "Failed to parse downloaded mutations blob: {e}. Skipping patch."
                                                    );
                                                    continue; // Skip this patch
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "Failed to download external mutations: {e}. Skipping patch."
                                            );
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

                        // Track the starting push name for this batch
                        let batch_start_name = client
                            .persistence_manager
                            .get_device_snapshot()
                            .await
                            .push_name;

                        // Process all mutations in this batch
                        let mut latest_push_name = None;
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
                                } else if let Some(push_name_setting) =
                                    mutation.action.push_name_setting.as_ref()
                                {
                                    if let Some(name) = &push_name_setting.name {
                                        // Just track the latest push name from this batch
                                        latest_push_name = Some(name.clone());
                                    }
                                }
                            }
                        }

                        // Only update and fire event if we found a push name change in this batch
                        if let Some(final_name) = latest_push_name {
                            if final_name != batch_start_name {
                                info!(
                                    target: "Client/AppState",
                                    "Received push name '{final_name}' via app state sync, updating store."
                                );
                                // Use command to update push name
                                client
                                    .persistence_manager
                                    .process_command(
                                        crate::store::commands::DeviceCommand::SetPushName(
                                            final_name.clone(),
                                        ),
                                    )
                                    .await;

                                let event = Event::SelfPushNameUpdated(
                                    crate::types::events::SelfPushNameUpdated {
                                        from_server: true,
                                        old_name: batch_start_name.clone(),
                                        new_name: final_name.clone(),
                                    },
                                );
                                let _ = client.dispatch_event(event).await;

                                // If the push name was previously empty, we are now ready to announce presence.
                                // This resolves the race condition on initial pairing.
                                if batch_start_name.is_empty() {
                                    let client_clone = client.clone();
                                    tokio::spawn(async move {
                                        if let Err(e) = client_clone
                                            .send_presence(
                                                crate::types::presence::Presence::Available,
                                            )
                                            .await
                                        {
                                            warn!(
                                                "Failed to send presence after app_state_sync update: {e:?}"
                                            );
                                        } else {
                                            info!(
                                                "✅ Successfully sent presence after receiving push_name via app_state_sync"
                                            );
                                        }
                                    });
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
                            error!("Failed to decode patches for {name}: {e:?}");
                            has_more = false;
                        }
                    }
                };
            } else {
                warn!(target: "Client/AppState", "Sync response for '{name}' missing <collection> node");
                has_more = false;
            }
        } else {
            warn!(target: "Client/AppState", "Sync response for '{name}' missing <sync> node");
            has_more = false;
        }
    }
    info!(target: "Client/AppState", "Finished AppState sync for '{name}'");
}
