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
use wacore::appstate::processor::{Mutation, Processor, ProcessorUtils};
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
                    // Get raw snapshot bytes (external or inline) then single-pass parse
                    let raw = if let Ok(blob_ref) = ExternalBlobReference::decode(b.as_slice()) {
                        info!(target: "Client/AppState", "Snapshot for '{name}' external blob; downloading (single-pass parse)...");
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

                    use base64::Engine as _;
                    use base64::prelude::BASE64_STANDARD;
                    use hmac::{Hmac, Mac};
                    use prost::encoding::{decode_key, decode_varint};
                    use sha2::Sha256;
                    use std::io::Cursor;
                    use wacore::appstate::lthash::WA_PATCH_INTEGRITY;

                    let mut cursor = Cursor::new(raw.as_slice());
                    let total_len = raw.len();
                    let mut version_u64: u64 = 0;
                    let mut keys_opt: Option<wacore::appstate::keys::ExpandedAppStateKeys> = None;
                    let mut snapshot_mac_server: Option<Vec<u8>> = None; // raw mac bytes from snapshot field
                    let mut buffered_records: Vec<Vec<u8>> = Vec::new(); // records seen before key_id
                    let mut mutations: Vec<Mutation> = Vec::new();

                    while (cursor.position() as usize) < total_len {
                        let Ok((field_number, wire_type)) = decode_key(&mut cursor) else {
                            break;
                        };
                        match field_number {
                            1 => {
                                // version
                                let len = decode_varint(&mut cursor).unwrap_or(0) as usize;
                                let pos = cursor.position() as usize;
                                if pos + len > total_len {
                                    break;
                                }
                                if let Ok(ver) = wa::SyncdVersion::decode(&raw[pos..pos + len]) {
                                    version_u64 = ver.version.unwrap_or(0);
                                }
                                cursor.set_position((pos + len) as u64);
                            }
                            2 => {
                                // record
                                let len = decode_varint(&mut cursor).unwrap_or(0) as usize;
                                let pos = cursor.position() as usize;
                                if pos + len > total_len {
                                    break;
                                }
                                let slice = &raw[pos..pos + len];
                                if let Some(keys) = &keys_opt {
                                    if let Ok(rec) = wa::SyncdRecord::decode(slice) {
                                        let fake = wa::SyncdMutation {
                                            operation: Some(
                                                wa::syncd_mutation::SyncdOperation::Set as i32,
                                            ),
                                            record: Some(rec),
                                        };
                                        let mut local_out = Vec::new();
                                        match ProcessorUtils::decode_mutation(
                                            keys,
                                            &fake,
                                            &mut local_out,
                                        ) {
                                            Ok(_) => {
                                                if !local_out.is_empty() {
                                                    mutations.extend(local_out);
                                                }
                                            }
                                            Err(e) => log::warn!(
                                                "Failed to decode snapshot record: {e:?}"
                                            ),
                                        }
                                    }
                                } else {
                                    buffered_records.push(slice.to_vec());
                                }
                                cursor.set_position((pos + len) as u64);
                            }
                            3 => {
                                // mac
                                let len = decode_varint(&mut cursor).unwrap_or(0) as usize;
                                let pos = cursor.position() as usize;
                                if pos + len > total_len {
                                    break;
                                }
                                snapshot_mac_server = Some(raw[pos..pos + len].to_vec());
                                cursor.set_position((pos + len) as u64);
                            }
                            4 => {
                                // key_id
                                let len = decode_varint(&mut cursor).unwrap_or(0) as usize;
                                let pos = cursor.position() as usize;
                                if pos + len > total_len {
                                    break;
                                }
                                if let Ok(kid) = wa::KeyId::decode(&raw[pos..pos + len])
                                    && let Some(id_bytes) = kid.id.as_deref()
                                {
                                    match processor.get_expanded_keys(id_bytes).await {
                                        Ok(k) => keys_opt = Some(k),
                                        Err(e) => {
                                            error!("Missing app state key for snapshot: {e:?}");
                                            has_more = false;
                                            break;
                                        }
                                    }
                                }
                                cursor.set_position((pos + len) as u64);
                            }
                            _ => {
                                // skip unknown
                                use prost::encoding::WireType;
                                match wire_type {
                                    WireType::Varint => {
                                        let _ = decode_varint(&mut cursor);
                                    }
                                    WireType::LengthDelimited => {
                                        let l = decode_varint(&mut cursor).unwrap_or(0) as usize;
                                        let pos = cursor.position() as usize;
                                        cursor.set_position((pos + l) as u64);
                                    }
                                    WireType::ThirtyTwoBit => {
                                        let pos = cursor.position() as usize;
                                        cursor.set_position((pos + 4) as u64);
                                    }
                                    WireType::SixtyFourBit => {
                                        let pos = cursor.position() as usize;
                                        cursor.set_position((pos + 8) as u64);
                                    }
                                    _ => break,
                                }
                            }
                        }
                    }

                    // Initialize state (full snapshot semantics)
                    current_state.version = version_u64;
                    current_state.hash = [0; 128];
                    current_state.index_value_map.clear();

                    // Decode any buffered records now that we (should) have keys
                    if let Some(keys) = &keys_opt {
                        for slice in buffered_records {
                            if let Ok(rec) = wa::SyncdRecord::decode(slice.as_slice()) {
                                let fake = wa::SyncdMutation {
                                    operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
                                    record: Some(rec),
                                };
                                let mut local_out = Vec::new();
                                if ProcessorUtils::decode_mutation(keys, &fake, &mut local_out)
                                    .is_ok()
                                {
                                    mutations.extend(local_out);
                                }
                            }
                        }
                    } else {
                        error!("Snapshot ended without key_id; aborting collection");
                        has_more = false;
                        continue;
                    }

                    // Verify snapshot MAC if present
                    if let (Some(keys), Some(server_mac)) = (&keys_opt, &snapshot_mac_server) {
                        // Snapshot MAC = HMAC-SHA256 over concatenated value_macs of all records in order.
                        let mut mac =
                            Hmac::<Sha256>::new_from_slice(&keys.snapshot_mac).expect("HMAC");
                        for m in &mutations {
                            mac.update(&m.value_mac);
                        }
                        let expected = mac.finalize().into_bytes().to_vec();
                        if expected != *server_mac {
                            error!("Mismatching snapshot MAC for '{name}'");
                            has_more = false;
                            continue;
                        }
                    }

                    // Update hash & index map
                    let add_refs: Vec<&[u8]> =
                        mutations.iter().map(|m| m.value_mac.as_slice()).collect();
                    for m in &mutations {
                        let index_mac_b64 = BASE64_STANDARD.encode(&m.index_mac);
                        current_state
                            .index_value_map
                            .insert(index_mac_b64, m.value_mac.clone());
                    }
                    WA_PATCH_INTEGRITY.subtract_then_add_in_place(
                        &mut current_state.hash,
                        &[],
                        &add_refs,
                    );
                    info!(target: "Client/AppState", "Single-pass streamed {} snapshot records for '{name}' (version {version_u64})", mutations.len());
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
