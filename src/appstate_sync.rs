//! App state synchronization orchestrator (port of whatsmeow appstate logic)
//! High-level (runtime + I/O) portion lives in root crate; cryptographic primitives in wacore.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use prost::Message;
use tokio::sync::Mutex;
use wacore::appstate::{expand_app_state_keys};
use wacore::appstate::hash::{generate_content_mac, generate_patch_mac, HashState};
use wacore::appstate::patch_decode::{parse_patch_list, PatchList, WAPatchName};
use wacore::libsignal::crypto::aes_256_cbc_decrypt;
use wacore::store::traits::Backend;
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

#[derive(Clone)]
pub struct AppStateProcessor<B: Backend> {
    backend: Arc<B>,
    key_cache: Arc<Mutex<HashMap<String, ExpandedKeys>>>,
}

#[derive(Debug, Clone)]
struct ExpandedKeys {
    index: [u8; 32],
    value_encryption: [u8; 32],
    value_mac: [u8; 32],
    snapshot_mac: [u8; 32],
    patch_mac: [u8; 32],
}

impl From<wacore::appstate::ExpandedAppStateKeys> for ExpandedKeys {
    fn from(v: wacore::appstate::ExpandedAppStateKeys) -> Self {
        Self {
            index: v.index,
            value_encryption: v.value_encryption,
            value_mac: v.value_mac,
            snapshot_mac: v.snapshot_mac,
            patch_mac: v.patch_mac,
        }
    }
}

impl<B: Backend> AppStateProcessor<B> {
    pub fn new(backend: Arc<B>) -> Self {
        Self { backend, key_cache: Arc::new(Mutex::new(HashMap::new())) }
    }

    async fn get_app_state_key(&self, key_id: &[u8]) -> Result<ExpandedKeys> {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        use base64::Engine;
        let id_b64 = STANDARD_NO_PAD.encode(key_id);
        if let Some(cached) = self.key_cache.lock().await.get(&id_b64).cloned() {
            return Ok(cached);
        }
        let key_opt = self.backend.get_app_state_sync_key(key_id).await?;
        let key = key_opt.ok_or_else(|| anyhow!("app state key not found"))?;
    let expanded: ExpandedKeys = expand_app_state_keys(&key.key_data).into();
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
        let mut pl = parse_patch_list(stanza_root, Some(&|r| download(r)))?; // may contain snapshot_ref
        let mut state = self.backend.get_app_state_version(pl.name.as_str()).await?;
        let mut new_mutations: Vec<Mutation> = Vec::new();
        // Fetch snapshot if reference present
        if pl.snapshot.is_none() && pl.snapshot_ref.is_some() {
            if let Some(ext) = &pl.snapshot_ref {
                let data = download(ext)?;
                let snapshot = wa::SyncdSnapshot::decode(data.as_slice())?;
                pl.snapshot = Some(snapshot);
            }
        }

    if let Some(snapshot) = &pl.snapshot {
            let version = snapshot.version.as_ref().and_then(|v| v.version).unwrap_or(0) as u64;
            state.version = version;
            let encrypted: Vec<wa::SyncdMutation> = snapshot.records.iter().map(|rec| wa::SyncdMutation { operation: Some(wa::syncd_mutation::SyncdOperation::Set as i32), record: Some(rec.clone()) }).collect();
            let (_warn, res) = state.update_hash(&encrypted, |_index_mac,_i| Ok(None));
            res?;
            if validate_macs {
                // Validate snapshot MAC
                if let (Some(mac_expected), Some(key_id)) = (snapshot.mac.as_ref(), snapshot.key_id.as_ref().and_then(|k| k.id.as_ref())) {
                    let keys = self.get_app_state_key(key_id).await?;
                    let computed = state.generate_snapshot_mac(pl.name.as_str(), &keys.snapshot_mac);
                    if computed != *mac_expected { return Err(anyhow!("snapshot MAC mismatch")); }
                }
            }
            let mut added = Vec::new();
            // Snapshot is all SETs
            for rec in &snapshot.records {
                let mut out = Vec::new();
                self.decode_record(
                    wa::syncd_mutation::SyncdOperation::Set,
                    rec,
                    &mut out,
                    validate_macs,
                ).await?;
                // record value_mac/index_mac for persistence
                if let Some(m) = out.last() {
                    added.push(wacore::store::traits::AppStateMutationMAC { index_mac: m.index_mac.clone(), value_mac: m.value_mac.clone() });
                }
                new_mutations.extend(out);
            }
            // Persist version + added MACs
            self.backend.set_app_state_version(pl.name.as_str(), state.clone()).await?;
            if !added.is_empty() {
                self.backend.put_app_state_mutation_macs(pl.name.as_str(), state.version, &added).await?;
            }
        }

        for patch in &pl.patches {
            state.version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0) as u64;
            let (_warn, res) = state.update_hash(&patch.mutations, |index_mac, idx| {
                for prev in patch.mutations[..idx].iter().rev() {
                    if let Some(rec) = &prev.record {
                        if let Some(ind) = &rec.index {
                            if let Some(b) = &ind.blob {
                                if b == index_mac {
                                    if let Some(val) = &rec.value {
                                        if let Some(vb) = &val.blob {
                                            if vb.len() >= 32 {
                                                return Ok(Some(vb[vb.len() - 32..].to_vec()));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(None)
            });
            res?;
            if validate_macs {
                if let Some(key_id) = patch.key_id.as_ref().and_then(|k| k.id.as_ref()) {
                    let keys = self.get_app_state_key(key_id).await?;
                    // Check snapshot MAC for this patch's version
                    if let Some(snap_mac) = patch.snapshot_mac.as_ref() {
                        let computed_snap = state.generate_snapshot_mac(pl.name.as_str(), &keys.snapshot_mac);
                        if computed_snap != *snap_mac { return Err(anyhow!("patch snapshot MAC mismatch")); }
                    }
                    if let Some(patch_mac) = patch.patch_mac.as_ref() {
                        let version = patch.version.as_ref().and_then(|v| v.version).unwrap_or(0) as u64;
                        let computed_patch = generate_patch_mac(patch, pl.name.as_str(), &keys.patch_mac, version);
                        if computed_patch != *patch_mac { return Err(anyhow!("patch MAC mismatch")); }
                    }
                }
            }
            let mut added = Vec::new();
            let mut removed: Vec<Vec<u8>> = Vec::new();
            for m in &patch.mutations {
                if let Some(rec) = &m.record {
                    let mut out = Vec::new();
                    let op = match m.operation.unwrap_or(0) {
                        0 => wa::syncd_mutation::SyncdOperation::Set,
                        1 => wa::syncd_mutation::SyncdOperation::Remove,
                        _ => wa::syncd_mutation::SyncdOperation::Set,
                    };
                    self.decode_record(op, rec, &mut out, validate_macs).await?;
                    if let Some(mdec) = out.last() {
                        match op {
                            wa::syncd_mutation::SyncdOperation::Set => added.push(wacore::store::traits::AppStateMutationMAC { index_mac: mdec.index_mac.clone(), value_mac: mdec.value_mac.clone() }),
                            wa::syncd_mutation::SyncdOperation::Remove => removed.push(mdec.index_mac.clone()),
                        }
                    }
                    new_mutations.extend(out);
                }
            }
            // Persist after each patch
            self.backend.set_app_state_version(pl.name.as_str(), state.clone()).await?;
            if !removed.is_empty() { self.backend.delete_app_state_mutation_macs(pl.name.as_str(), &removed).await?; }
            if !added.is_empty() { self.backend.put_app_state_mutation_macs(pl.name.as_str(), state.version, &added).await?; }
        }
        // Final version already persisted after patches; ensure latest persisted even if no patches
        if pl.patches.is_empty() {
            self.backend.set_app_state_version(pl.name.as_str(), state.clone()).await?;
        }
        Ok((new_mutations, state, pl))
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
            let expected = generate_content_mac(operation, &value_blob[..value_blob.len() - 32], key_id, &keys.value_mac);
            if expected != value_mac {
                return Err(anyhow!("content MAC mismatch"));
            }
        }
        let plaintext = aes_256_cbc_decrypt(ciphertext, &keys.value_encryption, iv)?;
        let action = wa::SyncActionData::decode(plaintext.as_slice())?;
        // Index MAC validation + JSON parse
        let mut index_list: Vec<String> = Vec::new();
        if let Some(idx_bytes) = action.index.as_ref() {
            if validate_macs {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                let mut h = Hmac::<Sha256>::new_from_slice(&keys.index).expect("hmac key");
                h.update(idx_bytes);
                let expected_index_mac = h.finalize().into_bytes();
                let stored = record.index.as_ref().and_then(|i| i.blob.as_ref()).ok_or_else(|| anyhow!("missing index mac"))?;
                if expected_index_mac.as_slice() != stored { return Err(anyhow!("index MAC mismatch")); }
            }
            if let Ok(parsed) = serde_json::from_slice::<Vec<String>>(idx_bytes) { index_list = parsed; }
        }
        out.push(Mutation {
            action_value: action.value.clone(),
            index_mac: record.index.as_ref().and_then(|i| i.blob.clone()).unwrap_or_default(),
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
            let (mut muts, _new_state, list) = self.decode_patch_list(&node, &download, validate_macs).await?;
            all.append(&mut muts);
            if !list.has_more_patches { break; }
        }
        Ok(all)
    }

    // Collect key IDs referenced in snapshot and patches that are missing locally.
    pub async fn get_missing_key_ids(&self, pl: &PatchList) -> Result<Vec<Vec<u8>>> {
        use base64::engine::general_purpose::STANDARD_NO_PAD;
        use base64::Engine;
        let mut cache: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
        let mut missing: Vec<Vec<u8>> = Vec::new();
        let mut check = |key_id: Option<&[u8]>| {
            if let Some(k) = key_id {
                let id_b64 = STANDARD_NO_PAD.encode(k);
                if !cache.contains_key(&id_b64) {
                    cache.insert(id_b64.clone(), false);
                    // We'll mark missing later after async fetch
                }
            }
        };
        if let Some(snap) = &pl.snapshot {
            check(snap.key_id.as_ref().and_then(|k| k.id.as_deref()));
            for rec in &snap.records { check(rec.key_id.as_ref().and_then(|k| k.id.as_deref())); }
        }
        for patch in &pl.patches { check(patch.key_id.as_ref().and_then(|k| k.id.as_deref())); }
        // Now evaluate each key asynchronously
        for (id_b64, _) in cache.clone() {
            if let Ok(raw) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(&id_b64) {
                if self.backend.get_app_state_sync_key(&raw).await?.is_none() {
                    missing.push(raw);
                }
            }
        }
        Ok(missing)
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
