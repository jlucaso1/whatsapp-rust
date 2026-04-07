use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_lock::Mutex;
use async_trait::async_trait;
use prost::Message;
use thiserror::Error;

use crate::appstate::hash::HashState;
use crate::appstate::keys::ExpandedAppStateKeys;
use crate::appstate::patch_decode::{PatchList, WAPatchName, parse_patch_list, parse_patch_lists};
use crate::appstate::{
    collect_key_ids_from_patch_list, expand_app_state_keys, process_patch, process_snapshot,
};
use crate::store::traits::Backend;
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

// Re-export Mutation from appstate for convenience
pub use crate::appstate::Mutation;

fn lookup_app_state_key(
    keys_map: &HashMap<String, Arc<ExpandedAppStateKeys>>,
    key_id: &[u8],
) -> Result<ExpandedAppStateKeys, crate::appstate::AppStateError> {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD_NO_PAD;
    let id_b64 = STANDARD_NO_PAD.encode(key_id);
    keys_map
        .get(&id_b64)
        .map(|arc| (**arc).clone())
        .ok_or(crate::appstate::AppStateError::KeyNotFound)
}

#[derive(Debug, Error)]
pub enum AppStateSyncError {
    #[error("app state key not found: {0}")]
    KeyNotFound(String),
    #[error("store error: {0}")]
    Store(#[from] crate::store::error::StoreError),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

#[derive(Clone)]
pub struct AppStateProcessor {
    pub backend: Arc<dyn Backend>,
    pub runtime: Arc<dyn crate::runtime::Runtime>,
    key_cache: Arc<Mutex<HashMap<String, Arc<ExpandedAppStateKeys>>>>,
}

impl AppStateProcessor {
    pub fn new(backend: Arc<dyn Backend>, runtime: Arc<dyn crate::runtime::Runtime>) -> Self {
        Self {
            runtime,
            backend,
            key_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn get_app_state_key(
        &self,
        key_id: &[u8],
    ) -> std::result::Result<Arc<ExpandedAppStateKeys>, AppStateSyncError> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        let id_b64 = STANDARD_NO_PAD.encode(key_id);
        if let Some(cached) = self.key_cache.lock().await.get(&id_b64).cloned() {
            return Ok(cached);
        }
        let key_opt = self.backend.get_sync_key(key_id).await?;
        let key = key_opt.ok_or_else(|| AppStateSyncError::KeyNotFound(id_b64.clone()))?;
        let expanded = Arc::new(expand_app_state_keys(&key.key_data));
        self.key_cache.lock().await.insert(id_b64, expanded.clone());
        Ok(expanded)
    }

    /// Clear the in-memory key cache (e.g. on reconnect).
    /// Keys will be re-fetched from the database backend on next access.
    pub async fn clear_key_cache(&self) {
        *self.key_cache.lock().await = HashMap::new();
    }

    /// Pre-fetch and cache all keys needed for a patch list.
    async fn prefetch_keys(&self, pl: &PatchList) -> Result<()> {
        let key_ids = collect_key_ids_from_patch_list(pl.snapshot.as_ref(), &pl.patches);
        for key_id in key_ids {
            // This will fetch and cache if not already cached
            let _ = self.get_app_state_key(&key_id).await;
        }
        Ok(())
    }

    pub async fn decode_patch_list<FDownload>(
        &self,
        stanza_root: &Node,
        download: FDownload,
        validate_macs: bool,
    ) -> Result<(Vec<Mutation>, HashState, PatchList)>
    where
        FDownload: Fn(&wa::ExternalBlobReference) -> Result<Vec<u8>> + Send + Sync,
    {
        let mut pl = parse_patch_list(stanza_root)?;

        // Download external snapshot if present (matches WhatsApp Web behavior)
        if pl.snapshot.is_none()
            && let Some(ext) = &pl.snapshot_ref
            && let Ok(data) = download(ext)
            && let Ok(snapshot) = wa::SyncdSnapshot::decode(data.as_slice())
        {
            pl.snapshot = Some(snapshot);
        }

        // Download external mutations for each patch (matches WhatsApp Web behavior)
        // WhatsApp Web: if (r.externalMutations) { n = yield downloadExternalPatch(e, r) }
        for patch in &mut pl.patches {
            if let Some(ext) = &patch.external_mutations {
                let patch_version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);
                match download(ext) {
                    Ok(data) => match wa::SyncdMutations::decode(data.as_slice()) {
                        Ok(ext_mutations) => {
                            log::trace!(
                                target: "AppState",
                                "Downloaded external mutations for patch v{}: {} mutations (inline had {})",
                                patch_version,
                                ext_mutations.mutations.len(),
                                patch.mutations.len()
                            );
                            patch.mutations = ext_mutations.mutations;
                        }
                        Err(e) => {
                            log::warn!(
                                target: "AppState",
                                "Failed to decode external mutations for patch v{}: {}",
                                patch_version,
                                e
                            );
                        }
                    },
                    Err(e) => {
                        log::warn!(
                            target: "AppState",
                            "Failed to download external mutations for patch v{}: {}",
                            patch_version,
                            e
                        );
                    }
                }
            }
        }

        self.process_patch_list(pl, validate_macs).await
    }

    /// Decode a multi-collection IQ response into per-collection results.
    /// Each collection is parsed and processed independently.
    pub async fn decode_multi_patch_list<FDownload>(
        &self,
        stanza_root: &Node,
        download: &FDownload,
        validate_macs: bool,
    ) -> Result<Vec<(Vec<Mutation>, HashState, PatchList)>>
    where
        FDownload: Fn(&wa::ExternalBlobReference) -> Result<Vec<u8>> + Send + Sync,
    {
        let patch_lists = parse_patch_lists(stanza_root)?;
        let mut results = Vec::with_capacity(patch_lists.len());

        for mut pl in patch_lists {
            // Skip collections with errors — caller handles them via pl.error
            if pl.error.is_some() {
                let state = self.backend.get_version(pl.name.as_str()).await?;
                results.push((Vec::new(), state, pl));
                continue;
            }

            // Download external snapshot
            if pl.snapshot.is_none()
                && let Some(ext) = &pl.snapshot_ref
            {
                match download(ext) {
                    Ok(data) => match wa::SyncdSnapshot::decode(data.as_slice()) {
                        Ok(snapshot) => pl.snapshot = Some(snapshot),
                        Err(e) => {
                            log::warn!(target: "AppState", "Failed to decode external snapshot for {:?}: {e}", pl.name);
                        }
                    },
                    Err(e) => {
                        log::warn!(target: "AppState", "Failed to download external snapshot for {:?}: {e}", pl.name);
                    }
                }
            }

            // Download external mutations for each patch
            for patch in &mut pl.patches {
                if let Some(ext) = &patch.external_mutations {
                    match download(ext) {
                        Ok(data) => match wa::SyncdMutations::decode(data.as_slice()) {
                            Ok(ext_mutations) => {
                                patch.mutations = ext_mutations.mutations;
                            }
                            Err(e) => {
                                let v = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);
                                log::warn!(target: "AppState", "Failed to decode external mutations for {:?} v{}: {e}", pl.name, v);
                            }
                        },
                        Err(e) => {
                            let v = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);
                            log::warn!(target: "AppState", "Failed to download external mutations for {:?} v{}: {e}", pl.name, v);
                        }
                    }
                }
            }

            let (mutations, state, pl) = self.process_patch_list(pl, validate_macs).await?;
            results.push((mutations, state, pl));
        }

        Ok(results)
    }

    pub async fn process_patch_list(
        &self,
        pl: PatchList,
        validate_macs: bool,
    ) -> Result<(Vec<Mutation>, HashState, PatchList)> {
        // Pre-fetch all keys we'll need
        self.prefetch_keys(&pl).await?;

        let mut state = self.backend.get_version(pl.name.as_str()).await?;
        let mut new_mutations: Vec<Mutation> = Vec::new();
        let collection_name = pl.name.as_str();

        // Process snapshot if present
        if let Some(snapshot) = &pl.snapshot {
            let keys_map = self.key_cache.lock().await.clone();
            let snapshot_clone = snapshot.clone();
            let collection_name_owned = collection_name.to_string();

            // Offload CPU-intensive snapshot processing to a blocking thread
            let result = crate::runtime::blocking(&*self.runtime, move || {
                let mut snapshot_state = HashState::default();
                let result = process_snapshot(
                    &snapshot_clone,
                    &mut snapshot_state,
                    |key_id| lookup_app_state_key(&keys_map, key_id),
                    validate_macs,
                    &collection_name_owned,
                )?;
                Ok::<_, crate::appstate::AppStateError>((result, snapshot_state))
            })
            .await
            .map_err(|e| anyhow!("{}", e))?;

            let (snapshot_result, snapshot_state) = result;
            state = snapshot_state;

            new_mutations.extend(snapshot_result.mutations);

            // Persist state and MACs
            self.backend
                .set_version(collection_name, state.clone())
                .await?;
            if !snapshot_result.mutation_macs.is_empty() {
                self.backend
                    .put_mutation_macs(
                        collection_name,
                        state.version,
                        &snapshot_result.mutation_macs,
                    )
                    .await?;
            }
        }

        // Snapshot the key cache once for all patches (prefetch_keys already populated it)
        let keys_map = self.key_cache.lock().await.clone();
        let collection_name_owned = collection_name.to_string();

        // Process patches
        for patch in &pl.patches {
            // Collect index MACs we need to look up (pre-allocate with upper bound)
            let mut need_db_lookup: Vec<Vec<u8>> = Vec::with_capacity(patch.mutations.len());
            for m in &patch.mutations {
                if let Some(rec) = &m.record
                    && let Some(ind) = &rec.index
                    && let Some(index_mac) = &ind.blob
                    && !need_db_lookup.iter().any(|v| v == index_mac)
                {
                    need_db_lookup.push(index_mac.clone());
                }
            }

            // Batch fetch previous value MACs from database
            let mut db_prev: HashMap<Vec<u8>, Vec<u8>> =
                HashMap::with_capacity(need_db_lookup.len());
            for index_mac in need_db_lookup {
                if let Some(mac) = self
                    .backend
                    .get_mutation_mac(collection_name, &index_mac)
                    .await?
                {
                    db_prev.insert(index_mac, mac);
                }
            }

            // Clone data for blocking task
            let patch_clone = patch.clone();
            let state_clone = state.clone();
            let keys = keys_map.clone();
            let coll = collection_name_owned.clone();

            // Offload CPU-intensive patch processing to a blocking thread
            let result = crate::runtime::blocking(&*self.runtime, move || {
                let get_prev_value_mac = |index_mac: &[u8]| -> Result<
                    Option<Vec<u8>>,
                    crate::appstate::AppStateError,
                > { Ok(db_prev.get(index_mac).cloned()) };

                let mut state = state_clone;
                process_patch(
                    &patch_clone,
                    &mut state,
                    |key_id| lookup_app_state_key(&keys, key_id),
                    get_prev_value_mac,
                    validate_macs,
                    &coll,
                )
            })
            .await
            .map_err(|e| anyhow!("{}", e))?;

            // Update local state with the result from the blocking task
            state = result.state;

            new_mutations.extend(result.mutations);

            // Persist state and MACs
            self.backend
                .set_version(collection_name, state.clone())
                .await?;
            if !result.removed_index_macs.is_empty() {
                self.backend
                    .delete_mutation_macs(collection_name, &result.removed_index_macs)
                    .await?;
            }
            if !result.added_macs.is_empty() {
                self.backend
                    .put_mutation_macs(collection_name, state.version, &result.added_macs)
                    .await?;
            }
        }

        // Handle case where we only have a snapshot and no patches
        if pl.patches.is_empty() && pl.snapshot.is_some() {
            self.backend
                .set_version(collection_name, state.clone())
                .await?;
        }

        Ok((new_mutations, state, pl))
    }

    /// Build and encode a SyncdPatch for sending mutations to the server.
    ///
    /// Takes a list of pre-encoded mutations (from `encode_record`) and produces
    /// the protobuf-encoded patch bytes ready for inclusion in an IQ stanza.
    ///
    /// # Returns
    /// A tuple of (patch_bytes, updated_hash_state).
    /// Encode mutations into a SyncdPatch protobuf blob.
    ///
    /// Returns `(patch_bytes, base_version)` where `base_version` is the collection
    /// version before the patch (for the IQ `version` attribute). Does NOT persist
    /// state — the caller must only persist after the server acknowledges the patch.
    pub async fn build_patch(
        &self,
        collection_name: &str,
        mutations: Vec<wa::SyncdMutation>,
    ) -> Result<(Vec<u8>, u64)> {
        use crate::appstate::hash::generate_patch_mac;

        // Get active key
        let key_id = self
            .backend
            .get_latest_sync_key_id()
            .await?
            .ok_or_else(|| anyhow!("No app state sync key available"))?;
        let keys = self.get_app_state_key(&key_id).await?;

        // Get current hash state — save base version for the caller
        let mut state = self.backend.get_version(collection_name).await?;
        let base_version = state.version;

        // Pre-fetch previous value MACs for all index MACs in the mutations
        let mut db_prev: std::collections::HashMap<Vec<u8>, Vec<u8>> =
            std::collections::HashMap::new();
        for m in &mutations {
            if let Some(rec) = &m.record
                && let Some(ind) = &rec.index
                && let Some(index_mac) = &ind.blob
                && let Some(mac) = self
                    .backend
                    .get_mutation_mac(collection_name, index_mac)
                    .await?
            {
                db_prev.insert(index_mac.clone(), mac);
            }
        }

        // Update hash state
        let (_, hash_result) = state.update_hash(&mutations, |index_mac, _| {
            Ok(db_prev.get(index_mac).cloned())
        });
        hash_result?;

        state.version += 1;

        // Generate snapshot MAC
        let snapshot_mac = state.generate_snapshot_mac(collection_name, &keys.snapshot_mac);

        // Build the patch — matching whatsmeow: no Version or DeviceIndex fields
        let mut patch = wa::SyncdPatch {
            snapshot_mac: Some(snapshot_mac),
            key_id: Some(wa::KeyId {
                id: Some(key_id.clone()),
            }),
            mutations,
            ..Default::default()
        };

        // Generate and set patch MAC
        let patch_mac = generate_patch_mac(&patch, collection_name, &keys.patch_mac, state.version);
        patch.patch_mac = Some(patch_mac);

        // Encode to protobuf
        let patch_bytes = patch.encode_to_vec();

        Ok((patch_bytes, base_version))
    }

    pub async fn get_missing_key_ids(&self, pl: &PatchList) -> Result<Vec<Vec<u8>>> {
        let key_ids = collect_key_ids_from_patch_list(pl.snapshot.as_ref(), &pl.patches);
        let mut missing = Vec::new();
        for id in key_ids {
            if self.backend.get_sync_key(&id).await?.is_none() {
                missing.push(id);
            }
        }
        Ok(missing)
    }

    pub async fn sync_collection<D, FDownload>(
        &self,
        driver: &D,
        name: WAPatchName,
        validate_macs: bool,
        download: FDownload,
    ) -> Result<Vec<Mutation>>
    where
        D: AppStateSyncDriver + Sync,
        FDownload: Fn(&wa::ExternalBlobReference) -> Result<Vec<u8>> + Send + Sync,
    {
        let mut all = Vec::new();
        loop {
            let state = self.backend.get_version(name.as_str()).await?;
            let node = driver.fetch_collection(name, state.version).await?;
            let (mut muts, _new_state, list) = self
                .decode_patch_list(&node, &download, validate_macs)
                .await?;
            all.append(&mut muts);
            if !list.has_more_patches {
                break;
            }
        }
        Ok(all)
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait AppStateSyncDriver {
    async fn fetch_collection(&self, name: WAPatchName, after_version: u64) -> Result<Node>;
}
