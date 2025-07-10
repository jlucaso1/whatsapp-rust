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

    if let Some(own_jid) = client.store.read().await.id.clone() {
        let own_non_ad = own_jid.to_non_ad();
        if let Err(e) = client.send_message(own_non_ad, msg).await {
            warn!("Failed to send app state key request: {e:?}");
        }
    } else {
        warn!("Can't request app state keys, not logged in.");
    }
}

pub async fn fetch_app_state_patches(
    client: &Arc<Client>,
    name: &str,
    version: Option<u64>, // Changed: version is now Option<u64>
) -> Result<Node, crate::request::IqError> {
    let mut attrs = Attrs::new();
    attrs.insert("name".to_string(), name.to_string());

    // Determine if it's a full sync based on the presence of version
    let is_full_sync = version.is_none();
    attrs.insert("return_snapshot".to_string(), is_full_sync.to_string());

    if let Some(v) = version {
        // Only add version attribute if it's Some(v) (i.e., not a full sync)
        attrs.insert("version".to_string(), v.to_string());
    }
    // No else needed: if version is None (full_sync), version attribute is NOT added.

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

#[derive(Debug, Clone, Copy)]
enum SyncAttemptType {
    Initial,
    FullSyncRetry,
}

pub async fn app_state_sync(client: &Arc<Client>, name: &str, initial_full_sync_request: bool) {
    info!(target: "Client/AppState", "Initiating AppState sync for '{name}' (initial_full_sync_request: {initial_full_sync_request})");

    let store_guard = client.store.read().await;
    let backend = store_guard.backend.clone(); // Keep backend for Jid::from_str -> put_identity
    let processor = Processor::new(backend.clone(), backend.clone());
    drop(store_guard);

    let mut current_state = match backend.get_app_state_version(name).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get initial app state version for {name}: {e:?}");
            return;
        }
    };

    let mut attempt_type = SyncAttemptType::Initial;

    'attempt_loop: loop {
        let is_this_attempt_a_full_sync = match attempt_type {
            SyncAttemptType::Initial => initial_full_sync_request || current_state.version == 0,
            SyncAttemptType::FullSyncRetry => true,
        };

        if is_this_attempt_a_full_sync {
            info!(target: "Client/AppState", "Processing AppState sync for '{}' as FULL sync (attempt type: {:?}). Version reset.", name, attempt_type);
            current_state.version = 0;
            current_state.hash = [0; 128];
        } else {
            info!(target: "Client/AppState", "Processing AppState sync for '{}' as INCREMENTAL sync (attempt type: {:?}), version: {}", name, attempt_type, current_state.version);
        }

        let mut has_more = true;
        let mut local_fetch_is_full_sync = is_this_attempt_a_full_sync;

        while has_more {
            let version_param: Option<u64> = if local_fetch_is_full_sync {
                None
            } else {
                Some(current_state.version)
            };
            if current_state.version == 0 && !local_fetch_is_full_sync { // Should not happen if logic is correct
                 warn!(target: "Client/AppState", "Unexpected: current_state.version is 0 for incremental fetch in AppState sync for '{}'. Proceeding as full.", name);
                 // This case implies we might have started an incremental sync, but version is 0.
                 // Forcing version_param to None to ensure it's treated as full by server.
                 // local_fetch_is_full_sync = true; // This was already set false, this line is more for clarity of intent
            }


            match fetch_app_state_patches(client, name, version_param).await {
                Ok(resp_node) => {
                    local_fetch_is_full_sync = false; // Only first fetch in an attempt can be full based on this flag

                    if let Some(sync_node) = resp_node.get_optional_child("sync") {
                        if let Some(collection_node) = sync_node.get_optional_child("collection") {
                            let mut attrs = collection_node.attrs();
                            has_more = attrs.optional_bool("has_more_patches");

                            let mut patches = Vec::new();
                            if let Some(patches_node) = collection_node.get_optional_child("patches") {
                                for patch_child in patches_node.children().unwrap_or_default() {
                                    if let Some(NodeContent::Bytes(b)) = &patch_child.content {
                                        if let Ok(mut patch) = wa::SyncdPatch::decode(b.as_slice()) {
                                            if let Some(external_ref) = patch.external_mutations.take() {
                                                info!("Found patch with external mutations. Attempting download...");
                                                match client.download(&external_ref).await {
                                                    Ok(decrypted_blob) => {
                                                        match wa::SyncdMutations::decode(decrypted_blob.as_slice()) {
                                                            Ok(downloaded_mutations) => {
                                                                info!("Successfully downloaded and parsed {} external mutations.", downloaded_mutations.mutations.len());
                                                                patch.mutations = downloaded_mutations.mutations;
                                                            }
                                                            Err(e) => {
                                                                error!("Failed to parse downloaded mutations blob: {e}. Skipping patch.");
                                                                continue;
                                                            }
                                                        }
                                                    }
                                                    Err(e) => {
                                                        error!("Failed to download external mutations: {e}. Skipping patch.");
                                                        continue;
                                                    }
                                                }
                                            }
                                            patches.push(patch);
                                        }
                                    }
                                }
                            }

                            let mut parsed_snapshot: Option<wa::SyncdSnapshot> = None;
                            if let Some(snapshot_node) = collection_node.get_optional_child("snapshot") {
                                if let Some(NodeContent::Bytes(snapshot_bytes)) = snapshot_node.content {
                                    match wa::SyncdSnapshot::decode(snapshot_bytes.as_slice()) {
                                        Ok(sn_data) => {
                                            info!(target: "Client/AppState", "Successfully decoded snapshot for '{}', version: {}, records: {}", name, sn_data.version.as_ref().map_or(0, |v| v.version()), sn_data.records.len());
                                            parsed_snapshot = Some(sn_data);
                                        }
                                        Err(e) => {
                                            error!(target: "Client/AppState", "Failed to decode snapshot bytes for '{}': {:?}", name, e);
                                        }
                                    }
                                } else {
                                    warn!(target: "Client/AppState", "<snapshot> node for '{}' does not contain binary content.", name);
                                }
                            }

                            let patch_list = PatchList {
                                name: name.to_string(),
                                has_more_patches: has_more,
                                patches,
                                snapshot: parsed_snapshot,
                            };

                            match processor.decode_patches(&patch_list, current_state.clone()).await {
                                Ok((mutations, new_state)) => {
                                    current_state = new_state;
                                    info!(
                                        target: "Client/AppState",
                                        "Decoded {} mutations for '{}'. New version: {}. Has More: {}",
                                        mutations.len(), name, current_state.version, has_more
                                    );

                                    let batch_start_name = {
                                        let store = client.store.read().await;
                                        store.push_name.clone()
                                    };
                                    let mut latest_push_name = None;

                                    for mutation in &mutations { // Note: `mutations` is moved here, not `&mutations`
                                        if mutation.operation == wa::syncd_mutation::SyncdOperation::Set {
                                            if let Some(contact_action) = mutation.action.contact_action.as_ref() {
                                                if mutation.index.len() > 1 {
                                                    let jid_str = &mutation.index[1];
                                                    if let Ok(jid) = Jid::from_str(jid_str) {
                                                        let _ = backend.put_identity(jid_str, [0u8; 32]).await; // backend still needed
                                                        let event = Event::ContactUpdate(ContactUpdate {
                                                            jid,
                                                            timestamp: chrono::Utc::now(),
                                                            action: Box::new(contact_action.clone()),
                                                            from_full_sync: is_this_attempt_a_full_sync, // Use current attempt's full_sync status
                                                        });
                                                        let _ = client.dispatch_event(event).await;
                                                    }
                                                }
                                            } else if let Some(push_name_setting) = mutation.action.push_name_setting.as_ref() {
                                                if let Some(name_val) = &push_name_setting.name {
                                                    latest_push_name = Some(name_val.clone());
                                                }
                                            }
                                        }
                                    }

                                    if let Some(final_name) = latest_push_name {
                                        if final_name != batch_start_name {
                                            info!(
                                                target: "Client/AppState",
                                                "Received push name '{}' via app state sync for collection '{}', updating store.",
                                                final_name, name
                                            );
                                            {
                                                let mut store = client.store.write().await;
                                                store.push_name = final_name.clone();
                                            }
                                            let event = Event::SelfPushNameUpdated(
                                                crate::types::events::SelfPushNameUpdated {
                                                    from_server: true,
                                                    old_name: batch_start_name.clone(),
                                                    new_name: final_name.clone(),
                                                },
                                            );
                                            let _ = client.dispatch_event(event).await;
                                            if batch_start_name.is_empty() && !final_name.is_empty() {
                                                let client_clone = client.clone();
                                                tokio::spawn(async move {
                                                    if let Err(e) = client_clone.send_presence(crate::types::presence::Presence::Available).await {
                                                        warn!("Failed to send presence after app_state_sync push_name update: {e:?}");
                                                    } else {
                                                        info!("✅ Successfully sent presence after receiving push_name via app_state_sync for '{}'", name);
                                                    }
                                                });
                                            }
                                        }
                                    }
                                }
                                Err(proc_err) => {
                                    error!("Failed to decode patches/snapshot for {}: {:?}", name, proc_err);
                                    if let crate::appstate::errors::AppStateError::KeysNotFound(missing) = proc_err {
                                        info!( "Requesting {} missing app state keys for sync of '{}' due to decode error.", missing.len(), name);
                                        request_app_state_keys(client, missing).await;
                                        // This error might be retryable if keys are fetched.
                                        // However, the current design implies a full sync retry for decode errors.
                                    }
                                    match attempt_type {
                                        SyncAttemptType::Initial if !is_this_attempt_a_full_sync => {
                                            warn!(target: "Client/AppState", "decode_patches failed for incremental sync of '{}'. Will retry as full sync. Error: {:?}", name, proc_err);
                                            attempt_type = SyncAttemptType::FullSyncRetry;
                                            continue 'attempt_loop;
                                        }
                                        _ => {
                                            error!(target: "Client/AppState", "decode_patches failed for '{}' on full sync or retry. Aborting. Error: {:?}", name, proc_err);
                                            return;
                                        }
                                    }
                                }
                            }
                        } else {
                            warn!(target: "Client/AppState", "Sync response for '{name}' missing <collection> node. HasMore set to false.");
                            has_more = false;
                        }
                    } else {
                        warn!(target: "Client/AppState", "Sync response for '{name}' missing <sync> node. HasMore set to false.");
                        has_more = false;
                    }
                }
                Err(e) => { // Error from fetch_app_state_patches
                    error!(target: "Client/AppState", "IQError during fetch for {}: {:?}", name, e);
                    if let crate::request::IqError::BadRequest(_) = &e {
                        match attempt_type {
                            SyncAttemptType::Initial if !is_this_attempt_a_full_sync => {
                                warn!(target: "Client/AppState", "BadRequest on incremental sync for '{}'. Will retry as full sync.", name);
                                attempt_type = SyncAttemptType::FullSyncRetry;
                                continue 'attempt_loop;
                            }
                            _ => {
                                error!(target: "Client/AppState", "BadRequest for '{}' on a full sync or retry attempt. Aborting. Error: {:?}", name, e);
                                return;
                            }
                        }
                    } else {
                        error!(target: "Client/AppState", "Unrecoverable IQError for '{}'. Aborting. Error: {:?}", name, e);
                        return;
                    }
                }
            }
        } // End of `while has_more`

        // If loop finished because has_more is false
        info!(target: "Client/AppState", "Successfully processed AppState sync for '{}' in current attempt type: {:?}.", name, attempt_type);
        break 'attempt_loop;
    } // End of `'attempt_loop`

    info!(target: "Client/AppState", "Finished all AppState sync attempts for '{name}'.");
}
