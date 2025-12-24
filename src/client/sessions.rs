//! E2E Session management methods for Client.
//!
//! This module contains methods for managing Signal protocol sessions,
//! including establishing new sessions and ensuring sessions exist before sending.
//!
//! Key features:
//! - Wait for offline delivery to complete before session establishment
//! - Resolve LID mappings before session establishment
//! - Batch prekey fetching and session establishment

use anyhow::Result;
use wacore_binary::jid::Jid;

use super::Client;

impl Client {
    /// Wait for offline message delivery to complete.
    /// Matches WhatsApp Web's WAWebEventsWaitForOfflineDeliveryEnd.waitForOfflineDeliveryEnd().
    /// Should be called before establishing new E2E sessions to avoid conflicts.
    pub(crate) async fn wait_for_offline_delivery_end(&self) {
        use std::sync::atomic::Ordering;

        if self.offline_sync_completed.load(Ordering::Relaxed) {
            return;
        }

        // Wait with a reasonable timeout to avoid blocking forever
        const TIMEOUT_SECS: u64 = 10;
        let _ = tokio::time::timeout(
            std::time::Duration::from_secs(TIMEOUT_SECS),
            self.offline_sync_notifier.notified(),
        )
        .await;
    }

    /// Ensure E2E sessions exist for the given device JIDs.
    /// Matches WhatsApp Web's `ensureE2ESessions` behavior.
    /// - Waits for offline delivery to complete
    /// - Resolves phone-to-LID mappings
    /// - Uses SessionManager for deduplication and batching
    pub(crate) async fn ensure_e2e_sessions(&self, device_jids: Vec<Jid>) -> Result<()> {
        use wacore::libsignal::store::SessionStore;
        use wacore::types::jid::JidExt;

        if device_jids.is_empty() {
            return Ok(());
        }

        // 1. Wait for offline sync (matches WhatsApp Web)
        self.wait_for_offline_delivery_end().await;

        // 2. Resolve LID mappings (matches WhatsApp Web)
        let resolved_jids = self.resolve_lid_mappings(&device_jids).await;

        // 3. Filter to JIDs that need sessions (inline has_session check)
        let device_store = self.persistence_manager.get_device_arc().await;
        let mut jids_needing_sessions = Vec::new();

        {
            let device_guard = device_store.read().await;
            for jid in resolved_jids {
                let signal_addr = jid.to_protocol_address();
                if device_guard.load_session(&signal_addr).await.is_err() {
                    jids_needing_sessions.push(jid);
                }
            }
        }

        if jids_needing_sessions.is_empty() {
            return Ok(());
        }

        // 4. Fetch and establish sessions (with batching)
        for batch in jids_needing_sessions.chunks(crate::session::SESSION_CHECK_BATCH_SIZE) {
            self.fetch_and_establish_sessions(batch.to_vec()).await?;
        }

        Ok(())
    }

    /// Fetch prekeys and establish sessions for a batch of JIDs.
    async fn fetch_and_establish_sessions(&self, jids: Vec<Jid>) -> Result<(), anyhow::Error> {
        use rand::TryRngCore;
        use wacore::libsignal::protocol::{UsePQRatchet, process_prekey_bundle};
        use wacore::types::jid::JidExt;

        if jids.is_empty() {
            return Ok(());
        }

        let prekey_bundles = self.fetch_pre_keys(&jids, Some("identity")).await?;

        let device_store = self.persistence_manager.get_device_arc().await;
        let mut adapter =
            crate::store::signal_adapter::SignalProtocolStoreAdapter::new(device_store);

        for jid in &jids {
            if let Some(bundle) = prekey_bundles.get(jid) {
                let signal_addr = jid.to_protocol_address();
                if let Err(e) = process_prekey_bundle(
                    &signal_addr,
                    &mut adapter.session_store,
                    &mut adapter.identity_store,
                    bundle,
                    &mut rand::rngs::OsRng.unwrap_err(),
                    UsePQRatchet::No,
                )
                .await
                {
                    log::warn!("Failed to establish session with {}: {}", jid, e);
                }
            }
        }
        Ok(())
    }
}
