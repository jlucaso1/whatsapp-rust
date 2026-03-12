//! Pre-key management for Signal Protocol.
//!
//! Pre-key IDs use a persistent monotonic counter (Device::next_pre_key_id)
//! matching WhatsApp Web's NEXT_PK_ID pattern. IDs only increase to prevent
//! collisions when prekeys are consumed non-sequentially from the store.

use crate::client::Client;
use anyhow;
use log;
use rand::TryRngCore;
use wacore::iq::prekeys::{PreKeyCountSpec, PreKeyFetchSpec, PreKeyUploadSpec};
use wacore::libsignal::protocol::{KeyPair, PreKeyBundle, PublicKey};
use wacore::libsignal::store::record_helpers::new_pre_key_record;
use wacore::store::commands::DeviceCommand;
use wacore_binary::jid::Jid;

pub use wacore::prekeys::PreKeyUtils;

const WANTED_PRE_KEY_COUNT: usize = 50;
const MIN_PRE_KEY_COUNT: usize = 5;

impl Client {
    pub(crate) async fn fetch_pre_keys(
        &self,
        jids: &[Jid],
        reason: Option<&str>,
    ) -> Result<std::collections::HashMap<Jid, PreKeyBundle>, anyhow::Error> {
        let spec = match reason {
            Some(r) => PreKeyFetchSpec::with_reason(jids.to_vec(), r),
            None => PreKeyFetchSpec::new(jids.to_vec()),
        };

        let bundles = self.execute(spec).await?;

        for jid in bundles.keys() {
            log::debug!("Successfully parsed pre-key bundle for {jid}");
        }

        Ok(bundles)
    }

    /// Query the WhatsApp server for how many pre-keys it currently has for this device.
    pub(crate) async fn get_server_pre_key_count(&self) -> Result<usize, crate::request::IqError> {
        let response = self.execute(PreKeyCountSpec::new()).await?;
        Ok(response.count)
    }

    /// Ensure the server has at least MIN_PRE_KEY_COUNT pre-keys, and upload a batch of
    /// WANTED_PRE_KEY_COUNT new pre-keys. Uses a persistent monotonic counter
    /// (Device::next_pre_key_id) to avoid ID collisions — matching WhatsApp Web's
    /// NEXT_PK_ID / FIRST_UNUPLOAD_PK_ID pattern from WAWebSignalStoreApi.
    pub(crate) async fn upload_pre_keys(&self) -> Result<(), anyhow::Error> {
        let server_count = match self.get_server_pre_key_count().await {
            Ok(c) => c,
            Err(e) => return Err(anyhow::anyhow!(e)),
        };

        if server_count >= MIN_PRE_KEY_COUNT {
            log::debug!("Server has {} pre-keys, no upload needed.", server_count);
            return Ok(());
        }

        log::debug!("Server has {} pre-keys, uploading more.", server_count);

        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let device_store = self.persistence_manager.get_device_arc().await;

        let backend = {
            let device_guard = device_store.read().await;
            device_guard.backend.clone()
        };

        // Determine the starting ID using both the persistent counter AND the store max.
        // Using max(counter, max_id+1) guards against crash-after-upload-before-persist:
        // the counter would be stale, but the store already has the generated keys.
        let max_id = backend.get_max_prekey_id().await?;
        let start_id = if device_snapshot.next_pre_key_id > 0 {
            std::cmp::max(device_snapshot.next_pre_key_id, max_id + 1)
        } else {
            log::info!(
                "Migrating pre-key counter: MAX(key_id) in store = {}, starting from {}",
                max_id,
                max_id + 1
            );
            max_id + 1
        };

        let mut keys_to_upload = Vec::with_capacity(WANTED_PRE_KEY_COUNT);
        let mut key_pairs_to_upload = Vec::with_capacity(WANTED_PRE_KEY_COUNT);

        for i in 0..WANTED_PRE_KEY_COUNT {
            let pre_key_id = start_id + i as u32;

            if pre_key_id > 16777215 {
                log::warn!(
                    "Pre-key ID {} exceeds maximum range, wrapping around",
                    pre_key_id
                );
                break;
            }

            let key_pair = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
            let pre_key_record = new_pre_key_record(pre_key_id, &key_pair);

            keys_to_upload.push((pre_key_id, pre_key_record));
            key_pairs_to_upload.push((pre_key_id, key_pair));
        }

        if keys_to_upload.is_empty() {
            log::warn!("No pre-keys available to upload");
            return Ok(());
        }

        // Persist the freshly generated prekeys before uploading them so they are
        // already available for local decryption if the server starts sending
        // pkmsg traffic immediately after accepting the upload.
        // Propagate errors — uploading a key we can't store locally would cause
        // decryption failures when the server hands it out.
        for (id, record) in &keys_to_upload {
            use prost::Message;
            let record_bytes = record.encode_to_vec();
            backend.store_prekey(*id, &record_bytes, false).await?;
        }

        let pre_key_pairs: Vec<(u32, PublicKey)> = key_pairs_to_upload
            .iter()
            .map(|(id, key_pair)| (*id, key_pair.public_key))
            .collect();

        let spec = PreKeyUploadSpec::new(
            device_snapshot.registration_id,
            device_snapshot.identity_key.public_key,
            device_snapshot.signed_pre_key_id,
            device_snapshot.signed_pre_key.public_key,
            device_snapshot.signed_pre_key_signature.to_vec(),
            pre_key_pairs,
        );

        self.execute(spec).await?;

        // Mark the uploaded prekeys as server-synced
        for (id, record) in keys_to_upload {
            use prost::Message;
            let record_bytes = record.encode_to_vec();
            if let Err(e) = backend.store_prekey(id, &record_bytes, true).await {
                log::warn!("Failed to store prekey id {}: {:?}", id, e);
            }
        }

        // Update the persistent counter so future uploads never reuse these IDs.
        let next_id = start_id + key_pairs_to_upload.len() as u32;
        self.persistence_manager
            .process_command(DeviceCommand::SetNextPreKeyId(next_id))
            .await;

        log::debug!(
            "Successfully uploaded {} new pre-keys with sequential IDs starting from {}.",
            key_pairs_to_upload.len(),
            start_id
        );

        Ok(())
    }
}
