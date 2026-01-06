//! Sync action pusher - handles encoding and sending sync actions to the server.

use super::traits::SyncAction;
use super::types::{SyncCollection, SyncError};
use crate::client::Client;
use crate::request::InfoQuery;
use prost::Message;
use wacore::appstate::hash::HashState;
use wacore::appstate::{
    ExpandedAppStateKeys, build_patch, encrypt_mutation, expand_app_state_keys,
};
use wacore::request::InfoQueryType;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, SERVER_JID};
use wacore_binary::node::NodeContent;
use waproto::whatsapp as wa;

impl Client {
    /// Push a single sync action to the server.
    ///
    /// This is the main entry point for pushing sync actions. It handles:
    /// - Encoding the action into a SyncActionValue
    /// - Encrypting the mutation
    /// - Building the SyncdPatch
    /// - Sending the IQ stanza
    /// - Updating local state on success
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use whatsapp_rust::sync_actions::actions::StarMessageAction;
    ///
    /// let action = StarMessageAction::for_dm(
    ///     chat_jid,
    ///     message_id,
    ///     true, // from_me
    ///     true, // starred
    /// );
    ///
    /// client.push_sync_action(action).await?;
    /// ```
    pub async fn push_sync_action<A: SyncAction>(&self, action: A) -> Result<(), SyncError> {
        self.push_sync_actions_impl(&[&action]).await
    }

    /// Push multiple sync actions in a single batch.
    ///
    /// This is more efficient than pushing actions one by one when you have
    /// multiple actions to push at once, as they're all included in a single
    /// network request.
    ///
    /// Note: All actions must belong to the same collection.
    pub async fn push_sync_actions(&self, actions: &[&dyn SyncAction]) -> Result<(), SyncError> {
        if actions.is_empty() {
            return Ok(());
        }

        // Verify all actions are in the same collection
        let collection = actions[0].collection();
        for action in actions.iter().skip(1) {
            if action.collection() != collection {
                return Err(SyncError::Network(anyhow::anyhow!(
                    "All actions must be in the same collection"
                )));
            }
        }

        self.push_sync_actions_impl(actions).await
    }

    async fn push_sync_actions_impl(&self, actions: &[&dyn SyncAction]) -> Result<(), SyncError> {
        if actions.is_empty() {
            return Ok(());
        }

        let collection = actions[0].collection();
        let collection_name = collection.as_str().to_string();

        // Check if initial app state sync has completed
        // This ensures we have the correct hash state before pushing
        if self
            .needs_initial_full_sync
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            log::warn!(
                target: "Client/SyncAction",
                "Initial app state sync not completed yet, cannot push to {} collection",
                collection_name
            );
            return Err(SyncError::Network(anyhow::anyhow!(
                "Initial app state sync not completed. Please wait for sync to finish before performing sync actions."
            )));
        }

        // Get the current app state version and key
        let (key_id, keys) = self.get_app_state_key_for_push(collection).await?;
        let current_state = self.get_app_state_version(collection).await?;

        // Extract action data before moving to blocking task
        let action_data: Vec<_> = actions
            .iter()
            .map(|action| {
                let index = action.build_index();
                let value = action.build_value();
                let operation = action.operation();
                let version = action.version();
                log::debug!(
                    target: "Client/SyncAction",
                    "Building sync action - index: {:?}, operation: {:?}, version: {}",
                    index, operation, version
                );
                (index, value, operation, version)
            })
            .collect();

        log::debug!(
            target: "Client/SyncAction",
            "Pushing {} action(s) to collection {} (version {})",
            action_data.len(),
            collection_name,
            current_state.version
        );
        log::debug!(
            target: "Client/SyncAction",
            "Current hash state (first 16 bytes): {:02x?}",
            &current_state.hash[..16]
        );
        log::debug!(
            target: "Client/SyncAction",
            "Key ID: {:02x?}",
            &key_id
        );

        // Perform CPU-bound encryption in a blocking task
        let (encrypted_mutations, index_macs) = {
            let key_id_clone = key_id.clone();
            let keys_clone = keys.clone();
            tokio::task::spawn_blocking(move || {
                encrypt_mutations(action_data, key_id_clone, keys_clone)
            })
            .await
            .map_err(|e| SyncError::Network(anyhow::anyhow!("Task join error: {}", e)))??
        };

        // Look up previous value MACs from database for each index MAC
        // This is needed because index_value_map in HashState is not populated
        // when processing incoming patches (MACs are stored in a separate table)
        let mut current_state = current_state;
        for index_mac in &index_macs {
            let index_mac_hex = hex::encode(index_mac);
            if let Some(prev_mac) = self
                .persistence_manager
                .backend()
                .get_mutation_mac(collection.as_str(), index_mac)
                .await
                .map_err(|e| SyncError::Network(anyhow::anyhow!("{}", e)))?
            {
                current_state
                    .index_value_map
                    .insert(index_mac_hex, prev_mac);
            }
        }

        // Collect mutation MACs for storage after successful push
        let mutation_macs: Vec<wacore::appstate::processor::AppStateMutationMAC> =
            encrypted_mutations
                .iter()
                .map(|m| wacore::appstate::processor::AppStateMutationMAC {
                    index_mac: m.index_mac.clone(),
                    value_mac: m.value_mac.clone(),
                })
                .collect();

        // Build patch with populated index_value_map
        let collection_name_clone = collection_name.clone();
        let (patch_bytes, new_state, request_version) = tokio::task::spawn_blocking(move || {
            build_patch_from_encrypted(
                encrypted_mutations,
                key_id,
                keys,
                current_state,
                &collection_name_clone,
            )
        })
        .await
        .map_err(|e| SyncError::Network(anyhow::anyhow!("Task join error: {}", e)))??;

        log::debug!(
            target: "Client/SyncAction",
            "Patch bytes ({} bytes): {:02x?}",
            patch_bytes.len(),
            &patch_bytes[..std::cmp::min(100, patch_bytes.len())]
        );

        let collection_node = NodeBuilder::new("collection")
            .attr("name", &collection_name)
            .attr("version", request_version.to_string())
            .attr("return_snapshot", "false")
            .children([NodeBuilder::new("patch")
                .apply_content(Some(NodeContent::Bytes(patch_bytes)))
                .build()])
            .build();

        let sync_node = NodeBuilder::new("sync").children([collection_node]).build();

        let query = InfoQuery {
            query_type: InfoQueryType::Set,
            namespace: "w:sync:app:state",
            to: Jid::new("", SERVER_JID),
            target: None,
            content: Some(NodeContent::Nodes(vec![sync_node])),
            id: None,
            timeout: None,
        };

        self.send_iq(query)
            .await
            .map_err(|e| SyncError::IqError(e.to_string()))?;

        // Update local state on success
        self.update_app_state_version(collection, new_state.clone())
            .await?;

        // Store mutation MACs for future lookups
        // This is important for when we need to update/overwrite existing entries
        if !mutation_macs.is_empty() {
            self.persistence_manager
                .backend()
                .put_mutation_macs(collection.as_str(), new_state.version, &mutation_macs)
                .await
                .map_err(|e| SyncError::Network(anyhow::anyhow!("{}", e)))?;
        }

        Ok(())
    }

    /// Get the app state key for pushing mutations.
    async fn get_app_state_key_for_push(
        &self,
        _collection: SyncCollection,
    ) -> Result<(Vec<u8>, ExpandedAppStateKeys), SyncError> {
        // Find the most recent sync key
        let key_data = self
            .persistence_manager
            .backend()
            .get_latest_sync_key()
            .await
            .map_err(|e| SyncError::Network(anyhow::anyhow!("{}", e)))?
            .ok_or(SyncError::KeyNotFound)?;

        let keys = expand_app_state_keys(&key_data.key_data);
        let key_id = key_data
            .key_id
            .ok_or_else(|| SyncError::Network(anyhow::anyhow!("Key ID not found")))?;

        Ok((key_id, keys))
    }

    /// Get the current app state version for a collection.
    async fn get_app_state_version(
        &self,
        collection: SyncCollection,
    ) -> Result<HashState, SyncError> {
        let state = self
            .persistence_manager
            .backend()
            .get_version(collection.as_str())
            .await
            .map_err(|e| SyncError::Network(anyhow::anyhow!("{}", e)))?;

        Ok(state)
    }

    /// Update the local app state version after a successful push.
    async fn update_app_state_version(
        &self,
        collection: SyncCollection,
        state: HashState,
    ) -> Result<(), SyncError> {
        self.persistence_manager
            .backend()
            .set_version(collection.as_str(), state)
            .await
            .map_err(|e| SyncError::Network(anyhow::anyhow!("{}", e)))?;

        Ok(())
    }
}

/// CPU-bound encryption, designed to run in spawn_blocking.
/// Returns encrypted mutations and their index MACs (for database lookup).
fn encrypt_mutations(
    action_data: Vec<(
        Vec<String>,
        wa::SyncActionValue,
        wa::syncd_mutation::SyncdOperation,
        i32, // version
    )>,
    key_id: Vec<u8>,
    keys: ExpandedAppStateKeys,
) -> Result<(Vec<wacore::appstate::EncryptedMutation>, Vec<Vec<u8>>), SyncError> {
    let mut encrypted_mutations = Vec::with_capacity(action_data.len());
    let mut index_macs = Vec::with_capacity(action_data.len());

    for (index, value, operation, version) in &action_data {
        let encrypted = encrypt_mutation(index, value, &keys, &key_id, *operation, *version)
            .map_err(|e| SyncError::EncryptionFailed(e.to_string()))?;
        index_macs.push(encrypted.index_mac.clone());
        encrypted_mutations.push(encrypted);
    }

    Ok((encrypted_mutations, index_macs))
}

/// CPU-bound patch building from pre-encrypted mutations.
fn build_patch_from_encrypted(
    encrypted_mutations: Vec<wacore::appstate::EncryptedMutation>,
    key_id: Vec<u8>,
    keys: ExpandedAppStateKeys,
    current_state: HashState,
    collection_name: &str,
) -> Result<(Vec<u8>, HashState, u64), SyncError> {
    let (patch, new_state) = build_patch(
        &encrypted_mutations,
        &key_id,
        &keys,
        &current_state,
        collection_name,
    );

    let patch_bytes = patch.encode_to_vec();
    let request_version = current_state.version;

    Ok((patch_bytes, new_state, request_version))
}
