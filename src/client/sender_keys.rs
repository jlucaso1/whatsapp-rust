//! Sender Key and message cache methods for Client.
//!
//! This module contains methods for managing sender keys (SKDM) for group messaging
//! and caching recent messages for retry handling.
//!
//! Key features:
//! - Mark participants for fresh SKDM on retry
//! - Consume forget marks when sending group messages
//! - Cache recent messages for retry handling

use anyhow::Result;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;

use super::Client;

impl Client {
    /// Mark device JIDs as needing fresh SKDM (has_key = false).
    /// Filters out our own devices (WA Web: `!isMeDevice(e)` check).
    /// Called from handle_retry_receipt for group/status messages.
    pub(crate) async fn mark_forget_sender_key(
        &self,
        group_jid: &str,
        device_jids: &[Jid],
    ) -> Result<()> {
        use anyhow::anyhow;

        let device_store = self.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        let own_lid_user = device_guard
            .lid
            .as_ref()
            .map(|j| j.user.as_str().to_owned());
        let own_pn_user = device_guard.pn.as_ref().map(|j| j.user.as_str().to_owned());
        drop(device_guard);

        // Filter out own devices using Jid user comparison (no string prefix hacks)
        let filtered: Vec<String> = device_jids
            .iter()
            .filter(|jid| {
                let is_own = own_lid_user.as_deref().is_some_and(|u| u == jid.user)
                    || own_pn_user.as_deref().is_some_and(|u| u == jid.user);
                !is_own
            })
            .map(|jid| jid.to_string())
            .collect();

        if filtered.is_empty() {
            return Ok(());
        }

        let entries: Vec<(&str, bool)> = filtered.iter().map(|s| (s.as_str(), false)).collect();
        self.persistence_manager
            .backend()
            .set_sender_key_status(group_jid, &entries)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Take a sent message for retry handling. Checks L1 cache first (if enabled),
    /// then falls back to DB. Matches WA Web's getMessageTable().get() pattern.
    pub(crate) async fn take_recent_message(&self, to: Jid, id: String) -> Option<wa::Message> {
        use prost::Message;
        let key = self.make_stanza_key(to.clone(), id.clone()).await;
        let chat_str = key.chat.to_string();
        let has_l1_cache = self.cache_config.recent_messages.capacity > 0;

        // L1 cache check (if capacity > 0)
        if has_l1_cache && let Some(bytes) = self.recent_messages.remove(&key).await {
            if let Ok(msg) = wa::Message::decode(bytes.as_slice()) {
                // Cache hit — consume the DB row in the background to avoid orphans.
                // Note: if the background DB write from add_recent_message hasn't completed
                // yet, this delete may run first and the write creates an orphan. This is
                // harmless — periodic cleanup (sent_message_ttl_secs) purges it. The race
                // window is negligible since retry receipts arrive seconds after send.
                let backend = self.persistence_manager.backend();
                let cs = chat_str.clone();
                let mid = key.id.clone();
                self.runtime
                    .spawn(Box::pin(async move {
                        let _ = backend.take_sent_message(&cs, &mid).await;
                    }))
                    .detach();
                return Some(msg);
            }
            // Cache decode failed — fall through to DB
            log::warn!(
                "Failed to decode cached message for {}:{}, trying DB",
                to,
                id
            );
        }

        // DB path (primary when cache capacity = 0, fallback when cache misses)
        match self
            .persistence_manager
            .backend()
            .take_sent_message(&chat_str, &key.id)
            .await
        {
            Ok(Some(bytes)) => match wa::Message::decode(bytes.as_slice()) {
                Ok(msg) => Some(msg),
                Err(e) => {
                    log::warn!("Failed to decode DB message for {}:{}: {}", to, id, e);
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                log::warn!(
                    "Failed to read sent message from DB for {}:{}: {}",
                    to,
                    id,
                    e
                );
                None
            }
        }
    }

    /// Store a sent message for retry handling. Always writes to DB; when L1 cache
    /// is enabled (capacity > 0) also stores in-memory for fast retrieval.
    /// In DB-only mode (capacity = 0), the DB write is awaited to guarantee persistence.
    /// With L1 cache, the DB write is backgrounded since the cache serves reads immediately.
    pub(crate) async fn add_recent_message(&self, to: Jid, id: String, msg: &wa::Message) {
        use prost::Message;
        let key = self.make_stanza_key(to, id).await;
        let bytes = msg.encode_to_vec();
        let has_l1_cache = self.cache_config.recent_messages.capacity > 0;

        if has_l1_cache {
            // L1 cache serves reads immediately; DB write can be backgrounded
            self.recent_messages
                .insert(key.clone(), bytes.clone())
                .await;
            let backend = self.persistence_manager.backend();
            let chat_str = key.chat.to_string();
            let msg_id = key.id.clone();
            self.runtime
                .spawn(Box::pin(async move {
                    if let Err(e) = backend.store_sent_message(&chat_str, &msg_id, &bytes).await {
                        log::warn!("Failed to store sent message to DB: {e}");
                    }
                }))
                .detach();
        } else {
            // DB-only mode: await to guarantee the row exists before returning
            let chat_str = key.chat.to_string();
            if let Err(e) = self
                .persistence_manager
                .backend()
                .store_sent_message(&chat_str, &key.id, &bytes)
                .await
            {
                log::warn!("Failed to store sent message to DB: {e}");
            }
        }
    }
}
