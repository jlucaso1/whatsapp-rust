//! Pre-key management for Signal Protocol.
//!
//! Pre-key IDs use a persistent monotonic counter (Device::next_pre_key_id)
//! matching WhatsApp Web's NEXT_PK_ID pattern. IDs only increase to prevent
//! collisions when prekeys are consumed non-sequentially from the store.

use crate::client::Client;
use anyhow;
use log;
use rand::TryRngCore;
use std::sync::atomic::Ordering;
use wacore::iq::prekeys::{
    DigestKeyBundleSpec, PreKeyCountSpec, PreKeyFetchSpec, PreKeyUploadSpec,
};
use wacore::libsignal::protocol::{KeyPair, PreKeyBundle, PublicKey};
use wacore::libsignal::store::record_helpers::new_pre_key_record;
use wacore::store::commands::DeviceCommand;
use wacore_binary::jid::Jid;

pub use wacore::prekeys::PreKeyUtils;

/// Matches WA Web's UPLOAD_KEYS_COUNT from WAWebSignalStoreApi.
const WANTED_PRE_KEY_COUNT: usize = 812;
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
        {
            use prost::Message;
            let batch: Vec<(u32, Vec<u8>)> = keys_to_upload
                .iter()
                .map(|(id, record)| (*id, record.encode_to_vec()))
                .collect();
            backend.store_prekeys_batch(&batch, false).await?;
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
        {
            use prost::Message;
            let batch: Vec<(u32, Vec<u8>)> = keys_to_upload
                .iter()
                .map(|(id, record)| (*id, record.encode_to_vec()))
                .collect();
            if let Err(e) = backend.store_prekeys_batch(&batch, true).await {
                log::warn!("Failed to mark prekeys as uploaded: {:?}", e);
            }
        }

        // Update the persistent counter so future uploads never reuse these IDs.
        let next_id = start_id + key_pairs_to_upload.len() as u32;
        self.persistence_manager
            .process_command(DeviceCommand::SetNextPreKeyId(next_id))
            .await;

        self.server_has_prekeys.store(true, Ordering::Relaxed);

        log::debug!(
            "Successfully uploaded {} new pre-keys with sequential IDs starting from {}.",
            key_pairs_to_upload.len(),
            start_id
        );

        Ok(())
    }

    /// Upload pre-keys with Fibonacci retry backoff matching WA Web's `PromiseRetryLoop`.
    ///
    /// Retry schedule: 1s, 2s, 3s, 5s, 8s, 13s, ... capped at 610s.
    /// Verified against WA Web JS: `{ algo: { type: "fibonacci", first: 1e3, second: 2e3 }, max: 61e4 }`
    pub(crate) async fn upload_pre_keys_with_retry(&self) -> Result<(), anyhow::Error> {
        let mut delay_a: u64 = 1;
        let mut delay_b: u64 = 2;
        const MAX_DELAY_SECS: u64 = 610;

        loop {
            match self.upload_pre_keys().await {
                Ok(()) => {
                    log::info!("Pre-key upload succeeded");
                    return Ok(());
                }
                Err(e) => {
                    let delay = delay_a.min(MAX_DELAY_SECS);
                    log::warn!("Pre-key upload failed, retrying in {}s: {:?}", delay, e);

                    tokio::time::sleep(std::time::Duration::from_secs(delay)).await;

                    // Bail if disconnected during retry wait
                    if !self.is_logged_in.load(Ordering::Relaxed) {
                        return Err(anyhow::anyhow!(
                            "Connection lost during pre-key upload retry"
                        ));
                    }

                    let next = delay_a + delay_b;
                    delay_a = delay_b;
                    delay_b = next;
                }
            }
        }
    }

    /// Validate server key bundle digest and re-upload if mismatched.
    ///
    /// Matches WA Web's `WAWebDigestKeyJob.digestKey()`:
    /// 1. Queries server for key bundle digest (identity + signed prekey + prekey IDs + SHA-1 hash)
    /// 2. Loads local keys and computes SHA-1 over the same material
    /// 3. If hash mismatch or server returns 404: triggers `upload_pre_keys_with_retry()`
    /// 4. If server returns 406/503/other: logs and does nothing
    pub(crate) async fn validate_digest_key(&self) -> Result<(), anyhow::Error> {
        let response = match self.execute(DigestKeyBundleSpec::new()).await {
            Ok(resp) => resp,
            Err(e) => {
                let error_str = format!("{e:?}");
                // Match WA Web's error code handling
                if error_str.contains("404") {
                    log::warn!("digestKey: no record found for current user, re-uploading");
                    return self.upload_pre_keys_with_retry().await;
                } else if error_str.contains("406") {
                    log::warn!("digestKey: malformed request");
                    return Ok(());
                } else if error_str.contains("503") {
                    log::warn!("digestKey: service unavailable");
                    return Ok(());
                }
                log::warn!("digestKey: server error: {:?}", e);
                return Ok(());
            }
        };

        // Validate registration ID matches local
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        if response.reg_id != device_snapshot.registration_id {
            log::warn!(
                "digestKey: registration ID mismatch (server={}, local={}), re-uploading",
                response.reg_id,
                device_snapshot.registration_id
            );
            return self.upload_pre_keys_with_retry().await;
        }

        // Compute local SHA-1 digest over the same material as WA Web's validateLocalKeyBundle:
        // identity_pub_key + signed_prekey_pub + signed_prekey_signature + (for each prekey ID: load 32-byte pubkey)
        let identity_bytes = device_snapshot.identity_key.public_key.public_key_bytes();
        let skey_pub_bytes = device_snapshot.signed_pre_key.public_key.public_key_bytes();
        let skey_sig_bytes = &device_snapshot.signed_pre_key_signature;

        let device_store = self.persistence_manager.get_device_arc().await;
        let backend = {
            let guard = device_store.read().await;
            guard.backend.clone()
        };

        // Load each prekey referenced by the server digest and extract its public key
        let mut prekey_pubkeys = Vec::with_capacity(response.prekey_ids.len());
        for prekey_id in &response.prekey_ids {
            match backend.load_prekey(*prekey_id).await {
                Ok(Some(record_bytes)) => {
                    use prost::Message;
                    match waproto::whatsapp::PreKeyRecordStructure::decode(record_bytes.as_slice())
                    {
                        Ok(record) => {
                            if let Some(pk) = record.public_key {
                                prekey_pubkeys.push(pk);
                            } else {
                                log::warn!(
                                    "digestKey: prekey {} has no public key, re-uploading",
                                    prekey_id
                                );
                                return self.upload_pre_keys_with_retry().await;
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "digestKey: failed to decode prekey {}: {}, re-uploading",
                                prekey_id,
                                e
                            );
                            return self.upload_pre_keys_with_retry().await;
                        }
                    }
                }
                Ok(None) => {
                    log::warn!(
                        "digestKey: missing local prekey {}, re-uploading",
                        prekey_id
                    );
                    return self.upload_pre_keys_with_retry().await;
                }
                Err(e) => {
                    log::warn!(
                        "digestKey: failed to load prekey {}: {:?}, re-uploading",
                        prekey_id,
                        e
                    );
                    return self.upload_pre_keys_with_retry().await;
                }
            }
        }

        // Compute local SHA-1 digest matching WA Web's validateLocalKeyBundle
        let local_hash = wacore::prekeys::compute_key_bundle_digest(
            identity_bytes,
            skey_pub_bytes,
            skey_sig_bytes,
            &prekey_pubkeys,
        );

        if local_hash.as_slice() != response.hash.as_slice() {
            log::warn!(
                "digestKey: hash mismatch (server={}, local={}), re-uploading",
                hex::encode(&response.hash),
                hex::encode(local_hash)
            );
            return self.upload_pre_keys_with_retry().await;
        }

        log::debug!("digestKey: key bundle validation successful");
        Ok(())
    }
}
