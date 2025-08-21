use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use async_trait::async_trait;
use prost::Message;
use tokio::sync::Mutex;
use wacore::appstate::expand_app_state_keys;
use wacore::appstate::hash::{HashState, generate_content_mac, generate_patch_mac};
use wacore::appstate::keys::ExpandedAppStateKeys;
use wacore::appstate::patch_decode::{PatchList, WAPatchName, parse_patch_list};
use wacore::libsignal::crypto::aes_256_cbc_decrypt;
use wacore::store::traits::Backend;
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

#[derive(Clone)]
pub struct AppStateProcessor<B: Backend> {
    backend: Arc<B>,
    key_cache: Arc<Mutex<HashMap<String, ExpandedAppStateKeys>>>,
}

impl<B: Backend> AppStateProcessor<B> {
    pub fn new(backend: Arc<B>) -> Self {
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
        let key_opt = self.backend.get_app_state_sync_key(key_id).await?;
        let key = key_opt.ok_or_else(|| anyhow!("app state key not found"))?;
        let expanded: ExpandedAppStateKeys = expand_app_state_keys(&key.key_data);
        self.key_cache.lock().await.insert(id_b64, expanded.clone());
        Ok(expanded)
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
        if pl.snapshot.is_none()
            && let Some(ext) = &pl.snapshot_ref
            && let Ok(data) = download(ext)
            && let Ok(snapshot) = wa::SyncdSnapshot::decode(data.as_slice())
        {
            pl.snapshot = Some(snapshot);
        }
        self.process_patch_list(pl, validate_macs).await
    }

    pub async fn process_patch_list(
        &self,
        pl: PatchList,
        validate_macs: bool,
    ) -> Result<(Vec<Mutation>, HashState, PatchList)> {
        let mut state = self.backend.get_app_state_version(pl.name.as_str()).await?;
        let mut new_mutations: Vec<Mutation> = Vec::new();

        if let Some(snapshot) = &pl.snapshot {
            let version = snapshot
                .version
                .as_ref()
                .and_then(|v| v.version)
                .unwrap_or(0);
            state.version = version;

            let encrypted: Vec<wa::SyncdMutation> = snapshot
                .records
                .iter()
                .map(|rec| wa::SyncdMutation {
                    operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32),
                    record: Some(rec.clone()),
                })
                .collect();

            let (_warn, res) = state.update_hash(&encrypted, |_index_mac, _i| Ok(None));
            res?;

            if validate_macs
                && let (Some(mac_expected), Some(key_id)) = (
                    snapshot.mac.as_ref(),
                    snapshot.key_id.as_ref().and_then(|k| k.id.as_ref()),
                )
            {
                let keys = self.get_app_state_key(key_id).await?;
                let computed = state.generate_snapshot_mac(pl.name.as_str(), &keys.snapshot_mac);
                if computed != *mac_expected {
                    return Err(anyhow!("snapshot MAC mismatch"));
                }
            }

            let mut added = Vec::new();
            for rec in &snapshot.records {
                let mut out = Vec::new();
                self.decode_record(
                    wa::syncd_mutation::SyncdOperation::Set,
                    rec,
                    &mut out,
                    validate_macs,
                )
                .await?;
                if let Some(m) = out.last() {
                    added.push(wacore::store::traits::AppStateMutationMAC {
                        index_mac: m.index_mac.clone(),
                        value_mac: m.value_mac.clone(),
                    });
                }
                new_mutations.extend(out);
            }

            self.backend
                .set_app_state_version(pl.name.as_str(), state.clone())
                .await?;
            if !added.is_empty() {
                self.backend
                    .put_app_state_mutation_macs(pl.name.as_str(), state.version, &added)
                    .await?;
            }
        }

        for patch in &pl.patches {
            state.version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);

            use std::collections::HashMap as StdHashMap;
            let mut need_db_lookup: Vec<Vec<u8>> = Vec::new();
            for m in &patch.mutations {
                if let Some(rec) = &m.record
                    && let Some(ind) = &rec.index
                    && let Some(index_mac) = &ind.blob
                    && !need_db_lookup.iter().any(|v| v == index_mac)
                {
                    need_db_lookup.push(index_mac.clone());
                }
            }

            let mut db_prev: StdHashMap<Vec<u8>, Vec<u8>> = StdHashMap::new();
            for index_mac in need_db_lookup {
                if let Some(mac) = self
                    .backend
                    .get_app_state_mutation_mac(pl.name.as_str(), &index_mac)
                    .await?
                {
                    db_prev.insert(index_mac, mac);
                }
            }

            let (_warn, res) = state.update_hash(&patch.mutations, |index_mac, idx| {
                for prev in patch.mutations[..idx].iter().rev() {
                    if let Some(rec) = &prev.record
                        && let Some(ind) = &rec.index
                        && let Some(b) = &ind.blob
                        && b == index_mac
                        && let Some(val) = &rec.value
                        && let Some(vb) = &val.blob
                        && vb.len() >= 32
                    {
                        return Ok(Some(vb[vb.len() - 32..].to_vec()));
                    }
                }
                if let Some(prev_mac) = db_prev.get(index_mac) {
                    return Ok(Some(prev_mac.clone()));
                }

                Ok(None)
            });
            res?;

            if validate_macs && let Some(key_id) = patch.key_id.as_ref().and_then(|k| k.id.as_ref())
            {
                let keys = self.get_app_state_key(key_id).await?;
                if let Some(snap_mac) = patch.snapshot_mac.as_ref() {
                    let computed_snap =
                        state.generate_snapshot_mac(pl.name.as_str(), &keys.snapshot_mac);
                    if computed_snap != *snap_mac {
                        return Err(anyhow!("patch snapshot MAC mismatch"));
                    }
                }
                if let Some(patch_mac) = patch.patch_mac.as_ref() {
                    let version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0);
                    let computed_patch =
                        generate_patch_mac(patch, pl.name.as_str(), &keys.patch_mac, version);
                    if computed_patch != *patch_mac {
                        return Err(anyhow!("patch MAC mismatch"));
                    }
                }
            }

            let mut added = Vec::new();
            let mut removed: Vec<Vec<u8>> = Vec::new();
            for m in &patch.mutations {
                if let Some(rec) = &m.record {
                    let mut out = Vec::new();
                    let op = wa::syncd_mutation::SyncdOperation::try_from(m.operation.unwrap_or(0))
                        .unwrap_or(wa::syncd_mutation::SyncdOperation::Set);

                    self.decode_record(op, rec, &mut out, validate_macs).await?;
                    if let Some(mdec) = out.last() {
                        match op {
                            wa::syncd_mutation::SyncdOperation::Set => {
                                added.push(wacore::store::traits::AppStateMutationMAC {
                                    index_mac: mdec.index_mac.clone(),
                                    value_mac: mdec.value_mac.clone(),
                                })
                            }
                            wa::syncd_mutation::SyncdOperation::Remove => {
                                removed.push(mdec.index_mac.clone())
                            }
                        }
                    }
                    new_mutations.extend(out);
                }
            }

            self.backend
                .set_app_state_version(pl.name.as_str(), state.clone())
                .await?;
            if !removed.is_empty() {
                self.backend
                    .delete_app_state_mutation_macs(pl.name.as_str(), &removed)
                    .await?;
            }
            if !added.is_empty() {
                self.backend
                    .put_app_state_mutation_macs(pl.name.as_str(), state.version, &added)
                    .await?;
            }
        }

        if pl.patches.is_empty() && pl.snapshot.is_some() {
            self.backend
                .set_app_state_version(pl.name.as_str(), state.clone())
                .await?;
        }

        Ok((new_mutations, state, pl))
    }

    pub async fn get_missing_key_ids(&self, pl: &PatchList) -> Result<Vec<Vec<u8>>> {
        use std::collections::HashSet;
        let mut seen = HashSet::new();
        let mut missing = Vec::new();
        let mut check = |key_id: Option<&Vec<u8>>| {
            if let Some(k) = key_id
                && seen.insert(k.clone())
            {
                missing.push(k.clone());
            }
        };
        if let Some(snapshot) = &pl.snapshot {
            check(snapshot.key_id.as_ref().and_then(|k| k.id.as_ref()));
            for rec in &snapshot.records {
                check(rec.key_id.as_ref().and_then(|k| k.id.as_ref()));
            }
        }
        for patch in &pl.patches {
            check(patch.key_id.as_ref().and_then(|k| k.id.as_ref()));
        }
        let mut out = Vec::new();
        for id in missing {
            if self.backend.get_app_state_sync_key(&id).await?.is_none() {
                out.push(id);
            }
        }
        Ok(out)
    }

    async fn decode_record(
        &self,
        operation: wa::syncd_mutation::SyncdOperation,
        record: &wa::SyncdRecord,
        out: &mut Vec<Mutation>,
        validate_macs: bool,
    ) -> Result<()> {
        let key_id = record
            .key_id
            .as_ref()
            .and_then(|k| k.id.as_ref())
            .ok_or_else(|| anyhow!("missing key id"))?;
        let keys = self.get_app_state_key(key_id).await?;
        let value_blob = record
            .value
            .as_ref()
            .and_then(|v| v.blob.as_ref())
            .ok_or_else(|| anyhow!("missing value blob"))?;
        if value_blob.len() < 16 + 32 {
            return Err(anyhow!("value blob too short"));
        }
        let (iv, rest) = value_blob.split_at(16);
        let (ciphertext, value_mac) = rest.split_at(rest.len() - 32);
        if validate_macs {
            let expected = generate_content_mac(
                operation,
                &value_blob[..value_blob.len() - 32],
                key_id,
                &keys.value_mac,
            );
            if expected != value_mac {
                return Err(anyhow!("content MAC mismatch"));
            }
        }
        let plaintext = aes_256_cbc_decrypt(ciphertext, &keys.value_encryption, iv)?;
        let action = wa::SyncActionData::decode(plaintext.as_slice())?;
        let mut index_list: Vec<String> = Vec::new();
        if let Some(idx_bytes) = action.index.as_ref() {
            if validate_macs {
                let stored = record
                    .index
                    .as_ref()
                    .and_then(|i| i.blob.as_ref())
                    .ok_or_else(|| anyhow!("missing index mac"))?;
                wacore::appstate::hash::validate_index_mac(idx_bytes, stored, &keys.index)?;
            }
            if let Ok(parsed) = serde_json::from_slice::<Vec<String>>(idx_bytes) {
                index_list = parsed;
            }
        }
        out.push(Mutation {
            action_value: action.value.clone(),
            index_mac: record
                .index
                .as_ref()
                .and_then(|i| i.blob.clone())
                .unwrap_or_default(),
            value_mac: value_mac.to_vec(),
            index: index_list,
            operation,
        });
        Ok(())
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
            let state = self.backend.get_app_state_version(name.as_str()).await?;
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

#[derive(Debug, Clone)]
pub struct Mutation {
    pub action_value: Option<wa::SyncActionValue>,
    pub index_mac: Vec<u8>,
    pub value_mac: Vec<u8>,
    pub index: Vec<String>,
    pub operation: wa::syncd_mutation::SyncdOperation,
}

#[async_trait]
pub trait AppStateSyncDriver {
    async fn fetch_collection(&self, name: WAPatchName, after_version: u64) -> Result<Node>;
}
