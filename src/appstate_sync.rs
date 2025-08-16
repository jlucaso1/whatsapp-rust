use wacore::appstate::errors::AppStateError;

pub use wacore::appstate::*;
use wacore_binary::jid::{Jid, SERVER_JID};

use crate::client::Client;
use crate::types::events::{ContactUpdate, Event};
use log::{error, info, warn};
use processor::PatchList;
use prost::Message; // still used for decoding patches & mutations
use std::str::FromStr as _;
use std::sync::Arc;
use wacore::appstate::processor::Processor;
use wacore::appstate::snapshot::{
    apply_snapshot_mutations, decode_snapshot_records, verify_snapshot_mac,
};
use waproto::whatsapp::{self as wa, ExternalBlobReference};

async fn request_app_state_keys(client: &Arc<Client>, keys: Vec<Vec<u8>>) {
    let msg = sync::SyncUtils::build_app_state_key_request(keys);

    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    if let Some(own_jid) = device_snapshot.id.clone() {
        let own_non_ad = own_jid.to_non_ad();
        let request_id = client.generate_message_id().await;
        if let Err(e) = client
            .send_message_impl(own_non_ad, msg, request_id, true, false)
            .await
        {
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
) -> Result<wacore_binary::node::Node, crate::request::IqError> {
    let sync_node = if is_full_sync {
        sync::SyncUtils::build_fetch_patches_query(name, 0, true)
    } else {
        sync::SyncUtils::build_fetch_patches_query(name, version, false)
    };

    let iq = crate::request::InfoQuery {
        namespace: "w:sync:app:state",
        query_type: crate::request::InfoQueryType::Set,
        to: SERVER_JID.parse().unwrap(),
        target: None,
        id: None,
        content: Some(wacore_binary::node::NodeContent::Nodes(vec![sync_node])),
        timeout: None,
    };

    client.send_iq(iq).await
}

pub async fn app_state_sync(client: &Arc<Client>, name: &str, full_sync: bool) {
    info!(target: "Client/AppState", "Starting AppState sync for '{name}' (full_sync: {full_sync})");

    let device_snapshot = client.persistence_manager.get_device_snapshot().await;
    let backend = device_snapshot.backend.clone();

    // --- START: FIX ---
    // Removed the faulty AppStateWrapper. The `backend` object now directly implements all needed traits.
    let app_state_store = backend.clone();
    let key_store = backend.clone();
    // --- END: FIX ---

    let processor = Processor::new(key_store);

    let mut current_state = match app_state_store.get_app_state_version(name).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to get app state version for {name}: {e:?}");
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
                        if let Some(wacore_binary::node::NodeContent::Bytes(b)) =
                            &patch_child.content
                            && let Ok(mut patch) = wa::SyncdPatch::decode(b.as_slice())
                        {
                            if let Some(external_ref) = patch.external_mutations.take() {
                                info!(
                                    "Found patch with external mutations. Attempting download..."
                                );
                                match client.download(&external_ref).await {
                                    Ok(decrypted_blob) => {
                                        match wa::SyncdMutations::decode(decrypted_blob.as_slice())
                                        {
                                            Ok(downloaded_mutations) => {
                                                info!(
                                                    "Successfully downloaded and parsed {} external mutations.",
                                                    downloaded_mutations.mutations.len()
                                                );
                                                patch.mutations = downloaded_mutations.mutations;
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to parse downloaded mutations blob: {e}. Skipping patch."
                                                );
                                                continue;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        error!(
                                            "Failed to download external mutations: {e}. Skipping patch."
                                        );
                                        continue;
                                    }
                                }
                            }
                            patches.push(patch);
                        }
                    }
                }

                let snapshot: Option<wa::SyncdSnapshot> = None; // streaming path
                if let Some(snapshot_node) = collection_node.get_optional_child("snapshot")
                    && let Some(wacore_binary::node::NodeContent::Bytes(b)) = &snapshot_node.content
                {
                    // Get raw snapshot bytes (external or inline) then parse via wacore helper
                    let raw = if let Ok(blob_ref) = ExternalBlobReference::decode(b.as_slice()) {
                        info!(target: "Client/AppState", "Snapshot for '{name}' external blob; downloading (stream helper)...");
                        match client.download(&blob_ref).await {
                            Ok(data) => data,
                            Err(e) => {
                                error!(
                                    "Failed to download snapshot blob: {e}. Aborting collection."
                                );
                                has_more = false;
                                continue;
                            }
                        }
                    } else {
                        b.clone()
                    };

                    use wacore::appstate::snapshot_stream::process_snapshot_stream;

                    // Collect records (can't decode until keys known)
                    let mut collected_records: Vec<wa::SyncdRecord> = Vec::new();
                    let (version_opt, key_id_opt, mac_opt) =
                        match process_snapshot_stream(&raw, |rec| {
                            collected_records.push(rec);
                            async {}
                        })
                        .await
                        {
                            Ok(t) => t,
                            Err(e) => {
                                error!("Failed streaming snapshot parse for '{name}': {e}");
                                has_more = false;
                                continue;
                            }
                        };

                    let version_u64 = version_opt.as_ref().and_then(|v| v.version).unwrap_or(0);
                    current_state.version = version_u64; // hash/index reset will happen when applying mutations

                    let key_id_bytes =
                        if let Some(kid) = key_id_opt.as_ref().and_then(|k| k.id.as_deref()) {
                            kid
                        } else {
                            error!("Snapshot missing key_id for '{name}'");
                            has_more = false;
                            continue;
                        };
                    let keys = match processor.get_expanded_keys(key_id_bytes).await {
                        Ok(k) => k,
                        Err(e) => {
                            error!("Missing app state key for snapshot '{name}': {e:?}");
                            has_more = false;
                            continue;
                        }
                    };

                    let mutations = decode_snapshot_records(&keys, collected_records);
                    if !verify_snapshot_mac(&keys, mac_opt.as_deref(), &mutations) {
                        error!("Mismatching snapshot MAC for '{name}'");
                        has_more = false;
                        continue;
                    }
                    apply_snapshot_mutations(
                        version_u64,
                        &mutations,
                        &mut current_state.hash,
                        &mut current_state.index_value_map,
                    );
                    info!(target: "Client/AppState", "Stream processed {} snapshot records for '{name}' (version {version_u64})", mutations.len());
                }

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

                        let batch_start_name = client
                            .persistence_manager
                            .get_device_snapshot()
                            .await
                            .push_name
                            .clone();

                        let mut latest_push_name = None;
                        for mutation in &mutations {
                            if mutation.operation == wa::syncd_mutation::SyncdOperation::Set {
                                if let Some(contact_action) =
                                    mutation.action.contact_action.as_ref()
                                {
                                    if mutation.index.len() > 1 {
                                        let jid_str = &mutation.index[1];
                                        if let Ok(jid) = Jid::from_str(jid_str) {
                                            let event = Event::ContactUpdate(ContactUpdate {
                                                jid,
                                                timestamp: chrono::Utc::now(),
                                                action: Box::new(contact_action.clone()),
                                                from_full_sync: full_sync,
                                            });
                                            client.core.event_bus.dispatch(&event);
                                        }
                                    }
                                } else if let Some(push_name_setting) =
                                    mutation.action.push_name_setting.as_ref()
                                    && let Some(name) = &push_name_setting.name
                                {
                                    latest_push_name = Some(name.clone());
                                }
                            }
                        }

                        if let Some(final_name) = latest_push_name
                            && final_name != batch_start_name
                        {
                            info!(
                                target: "Client/AppState",
                                "Received push name '{final_name}' via app state sync, updating store."
                            );

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
                            client.core.event_bus.dispatch(&event);

                            if batch_start_name.is_empty() {
                                let client_clone = client.clone();
                                tokio::task::spawn_local(async move {
                                    if let Err(e) = client_clone
                                        .send_presence(crate::types::presence::Presence::Available)
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
                    Err(e) => {
                        if let AppStateError::KeysNotFound(missing) = e {
                            info!(
                                "Requesting {} missing app state keys for sync of '{}'. Will retry on next server notification.",
                                missing.len(),
                                name
                            );
                            request_app_state_keys(client, missing).await;

                            has_more = false;
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

    if let Err(e) = app_state_store
        .set_app_state_version(name, current_state)
        .await
    {
        error!(
            target: "Client/AppState",
            "Failed to save updated app state version for '{}': {:?}", name, e
        );
    }

    info!(target: "Client/AppState", "Finished AppState sync for '{name}'");
}
