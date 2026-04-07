//! Pre-key management for Signal Protocol.
//!
//! Pre-key IDs use a persistent monotonic counter (Device::next_pre_key_id)
//! matching WhatsApp Web's NEXT_PK_ID pattern. IDs only increase to prevent
//! collisions when prekeys are consumed non-sequentially from the store.

use crate::client::Client;
use anyhow;
use log;

use std::sync::atomic::Ordering;
use wacore::iq::prekeys::{
    DigestKeyBundleSpec, PreKeyCountSpec, PreKeyFetchReason, PreKeyFetchSpec, PreKeyUploadSpec,
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
        reason: Option<PreKeyFetchReason>,
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

    /// Upload prekeys at login if the persisted flag indicates they're needed.
    /// Matches WA Web's PassiveTasks.js:30 which checks `getServerHasPreKeys()`.
    pub(crate) async fn upload_pre_keys_at_login(&self) -> Result<(), anyhow::Error> {
        let has_prekeys = self
            .persistence_manager
            .get_device_snapshot()
            .await
            .server_has_prekeys;

        if has_prekeys {
            log::debug!("Server has prekeys (persisted flag), skipping login upload.");
            return Ok(());
        }

        // Serialize with prekey-low/digest paths to avoid duplicate uploads
        let _guard = self.prekey_upload_lock.lock().await;

        // Re-check after acquiring lock (another task may have uploaded)
        if self
            .persistence_manager
            .get_device_snapshot()
            .await
            .server_has_prekeys
        {
            return Ok(());
        }

        log::info!("Server missing prekeys (persisted flag), uploading.");
        self.upload_pre_keys_inner().await
    }

    /// Ensure the server has enough pre-keys, uploading if below threshold.
    /// When `force` is true, skips the count guard (used by digest key repair).
    pub(crate) async fn upload_pre_keys(&self, force: bool) -> Result<(), anyhow::Error> {
        let server_count = self
            .get_server_pre_key_count()
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        if !force && server_count >= MIN_PRE_KEY_COUNT {
            log::debug!("Server has {server_count} pre-keys, no upload needed.");
            return Ok(());
        }

        log::debug!("Server has {server_count} pre-keys, uploading.");
        self.upload_pre_keys_inner().await
    }

    /// Generate and upload WANTED_PRE_KEY_COUNT pre-keys. Shared by
    /// `upload_pre_keys` and `upload_pre_keys_at_login` to avoid
    /// redundant server count queries.
    async fn upload_pre_keys_inner(&self) -> Result<(), anyhow::Error> {
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        let device_store = self.persistence_manager.get_device_arc().await;

        let backend = {
            let device_guard = device_store.read().await;
            device_guard.backend.clone()
        };

        // Use the persistent counter, falling back to max(store_id)+1 for migration.
        // The counter is the source of truth after the first upload.
        let max_id = backend.get_max_prekey_id().await?;
        let raw_start = if device_snapshot.next_pre_key_id > 0 {
            std::cmp::max(device_snapshot.next_pre_key_id, max_id + 1)
        } else {
            log::info!(
                "Migrating pre-key counter: MAX(key_id) in store = {}, starting from {}",
                max_id,
                max_id + 1
            );
            max_id + 1
        };

        // WA Web uses 24-bit PreKey IDs (max 2^24 - 1 = 16777215).
        // Wrap into valid range so lingering high-ID rows don't pin start_id
        // above the boundary and cause repeated overwrites of low IDs.
        const MAX_PREKEY_ID: u32 = 16777215;
        let start_id = ((raw_start as u64 - 1) % MAX_PREKEY_ID as u64) as u32 + 1;

        let mut keys_to_upload = Vec::with_capacity(WANTED_PRE_KEY_COUNT);
        let mut key_pairs_to_upload = Vec::with_capacity(WANTED_PRE_KEY_COUNT);

        for i in 0..WANTED_PRE_KEY_COUNT {
            let pre_key_id =
                (((start_id as u64 - 1) + i as u64) % (MAX_PREKEY_ID as u64)) as u32 + 1;

            let key_pair = KeyPair::generate(&mut rand::make_rng::<rand::rngs::StdRng>());
            let pre_key_record = new_pre_key_record(pre_key_id, &key_pair);

            keys_to_upload.push((pre_key_id, pre_key_record));
            key_pairs_to_upload.push((pre_key_id, key_pair));
        }

        // Encode once — reused for both pre-upload store and post-upload mark.
        let encoded_batch: Vec<(u32, Vec<u8>)> = {
            use prost::Message;
            keys_to_upload
                .iter()
                .map(|(id, record)| (*id, record.encode_to_vec()))
                .collect()
        };

        // Persist the freshly generated prekeys before uploading them so they are
        // already available for local decryption if the server starts sending
        // pkmsg traffic immediately after accepting the upload.
        // Propagate errors — uploading a key we can't store locally would cause
        // decryption failures when the server hands it out.
        backend.store_prekeys_batch(&encoded_batch, false).await?;

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

        // Mark the uploaded prekeys as server-synced (reuse encoded batch)
        if let Err(e) = backend.store_prekeys_batch(&encoded_batch, true).await {
            log::warn!("Failed to mark prekeys as uploaded: {:?}", e);
        }

        // IDs wrap modulo MAX_PREKEY_ID. If the counter wraps while unconsumed
        // high-ID prekeys still exist, the upsert (.on_conflict.do_update)
        // silently overwrites them. Acceptable: the server consumes keys well
        // before a full 16M cycle completes.
        let next_id = (((start_id as u64 - 1) + key_pairs_to_upload.len() as u64)
            % (MAX_PREKEY_ID as u64)) as u32
            + 1;
        self.persistence_manager
            .process_command(DeviceCommand::SetNextPreKeyId(next_id))
            .await;

        // Persist flag matching WA Web's setServerHasPreKeys(true) (PreKeysJob.js:79)
        self.persistence_manager
            .modify_device(|d| d.server_has_prekeys = true)
            .await;

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
    ///
    /// When `force` is true, bypasses the count guard (used by digest repair path).
    pub(crate) async fn upload_pre_keys_with_retry(
        &self,
        force: bool,
    ) -> Result<(), anyhow::Error> {
        let mut delay_a: u64 = 1;
        let mut delay_b: u64 = 2;
        const MAX_DELAY_SECS: u64 = 610;

        loop {
            match self.upload_pre_keys(force).await {
                Ok(()) => {
                    log::info!("Pre-key upload succeeded");
                    return Ok(());
                }
                Err(e) => {
                    let delay = delay_a.min(MAX_DELAY_SECS);
                    log::warn!("Pre-key upload failed, retrying in {}s: {:?}", delay, e);

                    self.runtime
                        .sleep(std::time::Duration::from_secs(delay))
                        .await;

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

    /// Validate server key bundle digest, re-uploading only when the server has no record.
    ///
    /// Matches WA Web's `WAWebDigestKeyJob.digestKey()`:
    /// 1. Queries server for key bundle digest (identity + signed prekey + prekey IDs + SHA-1 hash)
    /// 2. If server returns 404 (no record): triggers `upload_pre_keys_with_retry()`
    /// 3. If server returns 406/503/other error: logs and does nothing
    /// 4. On success: loads local keys and computes SHA-1 over the same material
    /// 5. If validation fails (regId mismatch, missing prekey, hash mismatch): logs warning,
    ///    does NOT re-upload — WA Web catches all `validateLocalKeyBundle` exceptions without
    ///    re-uploading; the normal `RotateKeyJob` will eventually refresh keys
    pub(crate) async fn validate_digest_key(&self) -> Result<(), anyhow::Error> {
        let response = match self.execute(DigestKeyBundleSpec::new()).await {
            Ok(resp) => resp,
            Err(crate::request::IqError::ServerError { code: 404, .. }) => {
                log::warn!("digestKey: no record found for current user, re-uploading");
                return self.upload_pre_keys_with_retry(true).await;
            }
            Err(crate::request::IqError::ServerError { code: 406, .. }) => {
                log::warn!("digestKey: malformed request");
                return Ok(());
            }
            Err(crate::request::IqError::ServerError { code: 503, .. }) => {
                log::warn!("digestKey: service unavailable");
                return Ok(());
            }
            Err(crate::request::IqError::ParseError(e)) => {
                // WA Web catches parse failures without re-uploading
                log::debug!("digestKey: unparseable digest response ({e}), skipping");
                return Ok(());
            }
            Err(e) => {
                if !self.is_shutting_down() {
                    log::warn!("digestKey: server error: {:?}", e);
                }
                return Ok(());
            }
        };

        // WA Web's validateLocalKeyBundle validates but catches ALL exceptions without
        // re-uploading. The catch block in digestKey() sets a=false for any throw from y(),
        // meaning only 404 triggers re-upload. We match that: log warnings, return Ok(()).
        let device_snapshot = self.persistence_manager.get_device_snapshot().await;
        if response.reg_id != device_snapshot.registration_id {
            log::warn!(
                "digestKey: registration ID mismatch (server={}, local={}), skipping",
                response.reg_id,
                device_snapshot.registration_id
            );
            return Ok(());
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
                                    "digestKey: prekey {} has no public key, skipping",
                                    prekey_id
                                );
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            log::warn!(
                                "digestKey: failed to decode prekey {}: {}, skipping",
                                prekey_id,
                                e
                            );
                            return Ok(());
                        }
                    }
                }
                Ok(None) => {
                    log::warn!("digestKey: missing local prekey {}, skipping", prekey_id);
                    return Ok(());
                }
                Err(e) => {
                    log::warn!(
                        "digestKey: failed to load prekey {}: {:?}, skipping",
                        prekey_id,
                        e
                    );
                    return Ok(());
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
                "digestKey: hash mismatch (server={}, local={}), skipping",
                hex::encode(&response.hash),
                hex::encode(local_hash)
            );
            return Ok(());
        }

        log::debug!("digestKey: key bundle validation successful");
        Ok(())
    }
}
