use super::errors::{AppStateError, Result};
use super::hash::HashState;
use super::keys;
use crate::crypto::cbc;
use crate::crypto::hmac_sha512;
use whatsapp_proto::whatsapp as wa;
use crate::store::traits::{AppStateKeyStore, AppStateStore};
use prost::Message;
use std::sync::Arc;

pub struct Processor {
    #[allow(dead_code)] // TODO: This will be used when hash calculation is implemented
    store: Arc<dyn AppStateStore>,
    key_store: Arc<dyn AppStateKeyStore>,
}

#[derive(Debug, Clone)]
pub struct Mutation {
    pub operation: wa::syncd_mutation::SyncdOperation,
    pub action: wa::SyncActionValue,
    pub index: Vec<String>,
    pub index_mac: Vec<u8>,
    pub value_mac: Vec<u8>,
}

pub struct PatchList {
    pub name: String,
    pub has_more_patches: bool,
    pub patches: Vec<wa::SyncdPatch>,
    pub snapshot: Option<wa::SyncdSnapshot>,
}

impl Processor {
    pub fn new(store: Arc<dyn AppStateStore>, key_store: Arc<dyn AppStateKeyStore>) -> Self {
        Self { store, key_store }
    }

    pub async fn decode_patches(
        &self,
        list: &PatchList,
        initial_state: HashState,
    ) -> Result<(Vec<Mutation>, HashState)> {
        let mut current_state = initial_state;
        let mut new_mutations: Vec<Mutation> = Vec::new();
        let missing_keys: Vec<Vec<u8>> = Vec::new();

        if let Some(snapshot) = &list.snapshot {
            // TODO: Implement snapshot decoding. This involves:
            // 1. Verifying snapshot.mac
            // 2. Updating the hash state
            // 3. Decoding all mutations within the snapshot
            // For now, we'll just log and move to patches.
            log::info!(target: "AppState", "Snapshot decoding not yet implemented. Skipping.");
            current_state.version = snapshot.version.as_ref().map_or(0, |v| v.version());
        }

        for patch in &list.patches {
            let version = patch.version.as_ref().map_or(0, |v| v.version());
            current_state.version = version;

            // TODO: Verify patch.snapshot_mac and patch.patch_mac
            // For now, we will proceed directly to mutation decoding.

            let key_id = patch
                .key_id
                .as_ref()
                .and_then(|k| k.id.as_ref())
                .map_or(&[][..], |v| &v[..]);

            // Fetch the real key from the key store
            let key_struct = match self.key_store.get_app_state_sync_key(key_id).await {
                Ok(Some(k)) => k,
                Ok(None) => {
                    log::warn!(target: "AppState", "No app state sync key found for key_id: {:?}", hex::encode(key_id));
                    continue;
                }
                Err(e) => {
                    log::warn!(target: "AppState", "Failed to fetch app state sync key: {:?}", e);
                    continue;
                }
            };
            let keys = keys::expand_app_state_keys(&key_struct.key_data);

            for mutation in &patch.mutations {
                if let Err(e) = self
                    .decode_mutation(&keys, mutation, &mut new_mutations)
                    .await
                {
                    log::warn!(target: "AppState", "Failed to decode one mutation, skipping: {:?}", e);
                }
            }
        }

        if !missing_keys.is_empty() {
            return Err(AppStateError::KeysNotFound(missing_keys));
        }

        Ok((new_mutations, current_state))
    }

    async fn decode_mutation(
        &self,
        keys: &keys::ExpandedAppStateKeys,
        mutation: &wa::SyncdMutation,
        out: &mut Vec<Mutation>,
    ) -> Result<()> {
        let record = mutation
            .record
            .as_ref()
            .ok_or(AppStateError::KeysNotFound(vec![]))?;
        let key_id_bytes = record
            .key_id
            .as_ref()
            .and_then(|k| k.id.as_deref())
            .ok_or(AppStateError::KeysNotFound(vec![]))?;

        let value_blob = record
            .value
            .as_ref()
            .and_then(|v| v.blob.as_deref())
            .ok_or(AppStateError::KeysNotFound(vec![]))?;
        if value_blob.len() < 32 {
            return Err(AppStateError::KeysNotFound(vec![]));
        }
        let (content, value_mac) = value_blob.split_at(value_blob.len() - 32);

        // Verify the content MAC before attempting decryption.
        let expected_value_mac = hmac_sha512::generate_content_mac(
            mutation.operation(),
            content,
            key_id_bytes,
            &keys.value_mac,
        );

        if &expected_value_mac != value_mac {
            return Err(AppStateError::MismatchingContentMAC);
        }

        if content.len() < 16 {
            return Err(AppStateError::KeysNotFound(vec![]));
        }
        let (iv, ciphertext) = content.split_at(16);

        let plaintext = cbc::decrypt(&keys.value_encryption, iv, ciphertext)?;

        let mut sync_action =
            wa::SyncActionData::decode(plaintext.as_slice()).map_err(AppStateError::Unmarshal)?;

        let index_mac = record
            .index
            .as_ref()
            .and_then(|i| i.blob.as_deref())
            .ok_or(AppStateError::KeysNotFound(vec![]))?;
        // TODO: Verify index_mac with `hash::concat_and_hmac`

        let index_json = sync_action
            .index
            .as_deref()
            .ok_or(AppStateError::KeysNotFound(vec![]))?;
        let index: Vec<String> = serde_json::from_slice(&index_json)?;

        let new_mutation = Mutation {
            operation: wa::syncd_mutation::SyncdOperation::try_from(mutation.operation()).unwrap(),
            action: sync_action.value.take().unwrap(),
            index,
            index_mac: index_mac.to_vec(),
            value_mac: value_mac.to_vec(),
        };

        out.push(new_mutation);
        Ok(())
    }
}
