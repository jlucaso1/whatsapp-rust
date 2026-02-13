use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use prost::Message;
use tokio::sync::Mutex;
use wacore::appstate::hash::HashState;
use wacore::appstate::keys::ExpandedAppStateKeys;
use wacore::appstate::patch_decode::{PatchList, WAPatchName, parse_patch_list};
use wacore::appstate::{
    collect_key_ids_from_patch_list, expand_app_state_keys, process_patch, process_snapshot,
};
use wacore::store::traits::Backend;
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

// Re-export Mutation from wacore for backwards compatibility
pub use wacore::appstate::Mutation;

#[derive(Clone)]
pub struct AppStateProcessor {
    backend: Arc<dyn Backend>,
    key_cache: Arc<Mutex<HashMap<String, ExpandedAppStateKeys>>>,
}

impl AppStateProcessor {
    pub fn new(backend: Arc<dyn Backend>) -> Self {
        Self {
            backend,
            key_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    async fn get_app_state_key(&self, key_id: &[u8]) -> Result<ExpandedAppStateKeys> {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        let id_b64 = STANDARD_NO_PAD.encode(key_id);
        if let Some(cached) = self.key_cache.lock().await.get(&id_b64).cloned() {
            return Ok(cached);
        }
        let key_opt = self.backend.get_sync_key(key_id).await?;
        let key = key_opt.ok_or_else(|| anyhow!("app state key not found"))?;
        let expanded: ExpandedAppStateKeys = expand_app_state_keys(&key.key_data);
        self.key_cache.lock().await.insert(id_b64, expanded.clone());
        Ok(expanded)
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
            let result = tokio::task::spawn_blocking(move || {
                let get_keys = |key_id: &[u8]| -> Result<
                    ExpandedAppStateKeys,
                    wacore::appstate::AppStateError,
                > {
                    use base64::Engine;
                    use base64::engine::general_purpose::STANDARD_NO_PAD;
                    let id_b64 = STANDARD_NO_PAD.encode(key_id);
                    keys_map
                        .get(&id_b64)
                        .cloned()
                        .ok_or(wacore::appstate::AppStateError::KeyNotFound)
                };

                let mut snapshot_state = HashState::default();
                let result = process_snapshot(
                    &snapshot_clone,
                    &mut snapshot_state,
                    get_keys,
                    validate_macs,
                    &collection_name_owned,
                )?;
                Ok::<_, wacore::appstate::AppStateError>((result, snapshot_state))
            })
            .await
            .map_err(|e| anyhow!("Blocking task failed: {}", e))?
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
            let result = tokio::task::spawn_blocking(move || {
                let get_keys = |key_id: &[u8]| -> Result<
                    ExpandedAppStateKeys,
                    wacore::appstate::AppStateError,
                > {
                    use base64::Engine;
                    use base64::engine::general_purpose::STANDARD_NO_PAD;
                    let id_b64 = STANDARD_NO_PAD.encode(key_id);
                    keys.get(&id_b64)
                        .cloned()
                        .ok_or(wacore::appstate::AppStateError::KeyNotFound)
                };

                let get_prev_value_mac = |index_mac: &[u8]| -> Result<
                    Option<Vec<u8>>,
                    wacore::appstate::AppStateError,
                > { Ok(db_prev.get(index_mac).cloned()) };

                let mut state = state_clone;
                process_patch(
                    &patch_clone,
                    &mut state,
                    get_keys,
                    get_prev_value_mac,
                    validate_macs,
                    &coll,
                )
            })
            .await
            .map_err(|e| anyhow!("Blocking task failed: {}", e))?
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

#[async_trait]
pub trait AppStateSyncDriver {
    async fn fetch_collection(&self, name: WAPatchName, after_version: u64) -> Result<Node>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;
    use std::collections::HashMap;
    use wacore::appstate::WAPATCH_INTEGRITY;
    use wacore::appstate::hash::HashState;
    use wacore::appstate::hash::generate_content_mac;
    use wacore::appstate::keys::expand_app_state_keys;
    use wacore::appstate::processor::AppStateMutationMAC;
    use wacore::libsignal::crypto::aes_256_cbc_encrypt_into;
    use wacore::store::error::Result as StoreResult;
    use wacore::store::traits::{
        AppStateSyncKey, AppSyncStore, DeviceListRecord, DeviceStore, LidPnMappingEntry,
        ProtocolStore, SignalStore,
    };
    use wacore_binary::jid::Jid;

    type MockMacMap = Arc<Mutex<HashMap<(String, Vec<u8>), Vec<u8>>>>;

    #[derive(Default, Clone)]
    struct MockBackend {
        versions: Arc<Mutex<HashMap<String, HashState>>>,
        macs: MockMacMap,
        keys: Arc<Mutex<HashMap<Vec<u8>, AppStateSyncKey>>>,
    }

    // Implement SignalStore - Signal protocol cryptographic operations
    #[async_trait]
    impl SignalStore for MockBackend {
        async fn put_identity(&self, _: &str, _: [u8; 32]) -> StoreResult<()> {
            Ok(())
        }
        async fn load_identity(&self, _: &str) -> StoreResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn delete_identity(&self, _: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn get_session(&self, _: &str) -> StoreResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn put_session(&self, _: &str, _: &[u8]) -> StoreResult<()> {
            Ok(())
        }
        async fn delete_session(&self, _: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn store_prekey(&self, _: u32, _: &[u8], _: bool) -> StoreResult<()> {
            Ok(())
        }
        async fn load_prekey(&self, _: u32) -> StoreResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn remove_prekey(&self, _: u32) -> StoreResult<()> {
            Ok(())
        }
        async fn store_signed_prekey(&self, _: u32, _: &[u8]) -> StoreResult<()> {
            Ok(())
        }
        async fn load_signed_prekey(&self, _: u32) -> StoreResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn load_all_signed_prekeys(&self) -> StoreResult<Vec<(u32, Vec<u8>)>> {
            Ok(vec![])
        }
        async fn remove_signed_prekey(&self, _: u32) -> StoreResult<()> {
            Ok(())
        }
        async fn put_sender_key(&self, _: &str, _: &[u8]) -> StoreResult<()> {
            Ok(())
        }
        async fn get_sender_key(&self, _: &str) -> StoreResult<Option<Vec<u8>>> {
            Ok(None)
        }
        async fn delete_sender_key(&self, _: &str) -> StoreResult<()> {
            Ok(())
        }
    }

    // Implement AppSyncStore - WhatsApp app state synchronization
    #[async_trait]
    impl AppSyncStore for MockBackend {
        async fn get_sync_key(&self, key_id: &[u8]) -> StoreResult<Option<AppStateSyncKey>> {
            Ok(self.keys.lock().await.get(key_id).cloned())
        }
        async fn set_sync_key(&self, key_id: &[u8], key: AppStateSyncKey) -> StoreResult<()> {
            self.keys.lock().await.insert(key_id.to_vec(), key);
            Ok(())
        }
        async fn get_version(&self, name: &str) -> StoreResult<HashState> {
            Ok(self
                .versions
                .lock()
                .await
                .get(name)
                .cloned()
                .unwrap_or_default())
        }
        async fn set_version(&self, name: &str, state: HashState) -> StoreResult<()> {
            self.versions.lock().await.insert(name.to_string(), state);
            Ok(())
        }
        async fn put_mutation_macs(
            &self,
            name: &str,
            _version: u64,
            mutations: &[AppStateMutationMAC],
        ) -> StoreResult<()> {
            let mut macs = self.macs.lock().await;
            for m in mutations {
                macs.insert((name.to_string(), m.index_mac.clone()), m.value_mac.clone());
            }
            Ok(())
        }
        async fn get_mutation_mac(
            &self,
            name: &str,
            index_mac: &[u8],
        ) -> StoreResult<Option<Vec<u8>>> {
            Ok(self
                .macs
                .lock()
                .await
                .get(&(name.to_string(), index_mac.to_vec()))
                .cloned())
        }
        async fn delete_mutation_macs(&self, _: &str, _: &[Vec<u8>]) -> StoreResult<()> {
            Ok(())
        }
    }

    // Implement ProtocolStore - WhatsApp Web protocol alignment
    #[async_trait]
    impl ProtocolStore for MockBackend {
        async fn get_skdm_recipients(&self, _: &str) -> StoreResult<Vec<Jid>> {
            Ok(vec![])
        }
        async fn add_skdm_recipients(&self, _: &str, _: &[Jid]) -> StoreResult<()> {
            Ok(())
        }
        async fn clear_skdm_recipients(&self, _: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn get_lid_mapping(&self, _: &str) -> StoreResult<Option<LidPnMappingEntry>> {
            Ok(None)
        }
        async fn get_pn_mapping(&self, _: &str) -> StoreResult<Option<LidPnMappingEntry>> {
            Ok(None)
        }
        async fn put_lid_mapping(&self, _: &LidPnMappingEntry) -> StoreResult<()> {
            Ok(())
        }
        async fn get_all_lid_mappings(&self) -> StoreResult<Vec<LidPnMappingEntry>> {
            Ok(vec![])
        }
        async fn save_base_key(&self, _: &str, _: &str, _: &[u8]) -> StoreResult<()> {
            Ok(())
        }
        async fn has_same_base_key(&self, _: &str, _: &str, _: &[u8]) -> StoreResult<bool> {
            Ok(false)
        }
        async fn delete_base_key(&self, _: &str, _: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn update_device_list(&self, _: DeviceListRecord) -> StoreResult<()> {
            Ok(())
        }
        async fn get_devices(&self, _: &str) -> StoreResult<Option<DeviceListRecord>> {
            Ok(None)
        }
        async fn mark_forget_sender_key(&self, _: &str, _: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn consume_forget_marks(&self, _: &str) -> StoreResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_tc_token(
            &self,
            _: &str,
        ) -> StoreResult<Option<wacore::store::traits::TcTokenEntry>> {
            Ok(None)
        }
        async fn put_tc_token(
            &self,
            _: &str,
            _: &wacore::store::traits::TcTokenEntry,
        ) -> StoreResult<()> {
            Ok(())
        }
        async fn delete_tc_token(&self, _: &str) -> StoreResult<()> {
            Ok(())
        }
        async fn get_all_tc_token_jids(&self) -> StoreResult<Vec<String>> {
            Ok(vec![])
        }
        async fn delete_expired_tc_tokens(&self, _: i64) -> StoreResult<u32> {
            Ok(0)
        }
    }

    // Implement DeviceStore - Device persistence
    #[async_trait]
    impl DeviceStore for MockBackend {
        async fn save(&self, _: &wacore::store::Device) -> StoreResult<()> {
            Ok(())
        }
        async fn load(&self) -> StoreResult<Option<wacore::store::Device>> {
            Ok(Some(wacore::store::Device::new()))
        }
        async fn exists(&self) -> StoreResult<bool> {
            Ok(true)
        }
        async fn create(&self) -> StoreResult<i32> {
            Ok(1)
        }
    }

    fn create_encrypted_mutation(
        op: wa::syncd_mutation::SyncdOperation,
        index_mac: &[u8],
        plaintext: &[u8],
        keys: &wacore::appstate::keys::ExpandedAppStateKeys,
        key_id_bytes: &[u8],
    ) -> wa::SyncdMutation {
        let iv = vec![0u8; 16];

        let mut ciphertext = Vec::new();
        aes_256_cbc_encrypt_into(plaintext, &keys.value_encryption, &iv, &mut ciphertext)
            .expect("AES-CBC encryption should succeed with valid inputs");
        let mut value_with_iv = iv;
        value_with_iv.extend_from_slice(&ciphertext);
        let value_mac = generate_content_mac(op, &value_with_iv, key_id_bytes, &keys.value_mac);
        let mut value_blob = value_with_iv;
        value_blob.extend_from_slice(&value_mac);

        wa::SyncdMutation {
            operation: Some(op as i32),
            record: Some(wa::SyncdRecord {
                index: Some(wa::SyncdIndex {
                    blob: Some(index_mac.to_vec()),
                }),
                value: Some(wa::SyncdValue {
                    blob: Some(value_blob),
                }),
                key_id: Some(wa::KeyId {
                    id: Some(key_id_bytes.to_vec()),
                }),
            }),
        }
    }

    #[tokio::test]
    async fn test_process_patch_list_handles_set_overwrite_correctly() {
        let backend = Arc::new(MockBackend::default());
        let processor = AppStateProcessor::new(backend.clone());
        let collection_name = WAPatchName::Regular;
        let index_mac = vec![1; 32];
        let key_id_bytes = b"test_key_id".to_vec();
        let master_key = [7u8; 32];
        let keys = expand_app_state_keys(&master_key);

        let sync_key = AppStateSyncKey {
            key_data: master_key.to_vec(),
            ..Default::default()
        };
        backend
            .set_sync_key(&key_id_bytes, sync_key)
            .await
            .expect("test backend should accept sync key");

        let original_plaintext = wa::SyncActionData {
            value: Some(wa::SyncActionValue {
                timestamp: Some(1000),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        let original_mutation = create_encrypted_mutation(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &original_plaintext,
            &keys,
            &key_id_bytes,
        );

        let mut initial_state = HashState {
            version: 1,
            ..Default::default()
        };
        let (hash_result, res) =
            initial_state.update_hash(std::slice::from_ref(&original_mutation), |_, _| Ok(None));
        assert!(res.is_ok() && !hash_result.has_missing_remove);
        backend
            .set_version(collection_name.as_str(), initial_state.clone())
            .await
            .expect("test backend should accept app state version");

        let original_value_blob = original_mutation
            .record
            .expect("mutation should have record")
            .value
            .expect("record should have value")
            .blob
            .expect("value should have blob");
        let original_value_mac = original_value_blob[original_value_blob.len() - 32..].to_vec();
        backend
            .put_mutation_macs(
                collection_name.as_str(),
                1,
                &[AppStateMutationMAC {
                    index_mac: index_mac.clone(),
                    value_mac: original_value_mac.clone(),
                }],
            )
            .await
            .expect("test backend should accept mutation MACs");

        let new_plaintext = wa::SyncActionData {
            value: Some(wa::SyncActionValue {
                timestamp: Some(2000),
                ..Default::default()
            }),
            ..Default::default()
        }
        .encode_to_vec();
        let overwrite_mutation = create_encrypted_mutation(
            wa::syncd_mutation::SyncdOperation::Set,
            &index_mac,
            &new_plaintext,
            &keys,
            &key_id_bytes,
        );

        let patch_list = PatchList {
            name: collection_name,
            has_more_patches: false,
            patches: vec![wa::SyncdPatch {
                mutations: vec![overwrite_mutation.clone()],
                version: Some(wa::SyncdVersion { version: Some(2) }),
                key_id: Some(wa::KeyId {
                    id: Some(key_id_bytes),
                }),
                ..Default::default()
            }],
            snapshot: None,
            snapshot_ref: None,
        };

        let result = processor.process_patch_list(patch_list, false).await;

        assert!(
            result.is_ok(),
            "Processing the patch should succeed, but it failed: {:?}",
            result.err()
        );
        let (_, final_state, _) = result.expect("process_patch_list should succeed");

        let mut expected_state = initial_state.clone();
        let new_value_blob = overwrite_mutation
            .record
            .expect("mutation should have record")
            .value
            .expect("record should have value")
            .blob
            .expect("value should have blob");
        let new_value_mac = new_value_blob[new_value_blob.len() - 32..].to_vec();

        WAPATCH_INTEGRITY.subtract_then_add_in_place(
            &mut expected_state.hash,
            &[original_value_mac],
            &[new_value_mac],
        );

        assert_eq!(
            final_state.hash, expected_state.hash,
            "The final LTHash is incorrect, meaning the overwrite was not handled properly."
        );
        assert_eq!(
            final_state.version, 2,
            "The version should be updated to that of the patch."
        );
    }
}
