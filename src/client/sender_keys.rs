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
    /// Mark participants for fresh SKDM on next group send.
    /// Filters out our own devices (we don't need to send SKDM to ourselves).
    /// Matches WhatsApp Web's WAWebApiParticipantStore.markForgetSenderKey behavior.
    /// Called from handle_retry_receipt for group/status messages.
    pub(crate) async fn mark_forget_sender_key(
        &self,
        group_jid: &str,
        participants: &[String],
    ) -> Result<()> {
        use anyhow::anyhow;

        // Get our own user ID to filter out (WhatsApp Web: isMeDevice check)
        let device_store = self.persistence_manager.get_device_arc().await;
        let device_guard = device_store.read().await;
        let own_lid_user = device_guard.lid.as_ref().map(|j| j.user.clone());
        let own_pn_user = device_guard.pn.as_ref().map(|j| j.user.clone());
        drop(device_guard);

        // Pre-compute prefix strings outside the filter loop to avoid repeated allocations
        // Include exact match string in tuple to avoid repeated Option lookups
        let lid_prefixes = own_lid_user
            .as_ref()
            .map(|lid| (format!("{lid}:"), format!("{lid}@"), lid.as_str()));
        let pn_prefixes = own_pn_user
            .as_ref()
            .map(|pn| (format!("{pn}:"), format!("{pn}@"), pn.as_str()));

        // Filter out own devices (WhatsApp Web: !isMeDevice(e))
        let filtered: Vec<String> = participants
            .iter()
            .filter(|p| {
                // Parse participant JID and check if it's our own
                let is_own_lid = lid_prefixes.as_ref().is_some_and(|(colon, at, exact)| {
                    p.starts_with(colon) || p.starts_with(at) || p.as_str() == *exact
                });
                let is_own_pn = pn_prefixes.as_ref().is_some_and(|(colon, at, exact)| {
                    p.starts_with(colon) || p.starts_with(at) || p.as_str() == *exact
                });
                !is_own_lid && !is_own_pn
            })
            .cloned()
            .collect();

        if filtered.is_empty() {
            return Ok(());
        }

        let backend = self.persistence_manager.backend();
        for participant in &filtered {
            backend
                .mark_forget_sender_key(group_jid, participant)
                .await
                .map_err(|e| anyhow!("{e}"))?;
        }
        Ok(())
    }

    /// Get participants marked for fresh SKDM and consume the marks.
    /// Matches WhatsApp Web's getGroupSenderKeyList pattern.
    pub(crate) async fn consume_forget_marks(&self, group_jid: &str) -> Result<Vec<String>> {
        use anyhow::anyhow;

        let backend = self.persistence_manager.backend();
        backend
            .consume_forget_marks(group_jid)
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Take a sent message for retry handling. Checks L1 cache first (if enabled),
    /// then falls back to DB. Matches WA Web's getMessageTable().get() pattern.
    pub(crate) async fn take_recent_message(&self, to: Jid, id: String) -> Option<wa::Message> {
        use prost::Message;
        let key = self.make_stanza_key(to.clone(), id.clone()).await;
        let chat_str = key.chat.to_string();
        let has_l1_cache = self.recent_messages.policy().max_capacity().unwrap_or(0) > 0;

        // L1 cache check (if capacity > 0)
        if has_l1_cache && let Some(bytes) = self.recent_messages.remove(&key).await {
            if let Ok(msg) = wa::Message::decode(bytes.as_slice()) {
                // Cache hit — also consume the DB row in the background to avoid orphans
                let backend = self.persistence_manager.backend();
                let cs = chat_str.clone();
                let mid = key.id.clone();
                tokio::spawn(async move {
                    let _ = backend.take_sent_message(&cs, &mid).await;
                });
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
        let has_l1_cache = self.recent_messages.policy().max_capacity().unwrap_or(0) > 0;

        if has_l1_cache {
            // L1 cache serves reads immediately; DB write can be backgrounded
            self.recent_messages
                .insert(key.clone(), bytes.clone())
                .await;
            let backend = self.persistence_manager.backend();
            let chat_str = key.chat.to_string();
            let msg_id = key.id.clone();
            tokio::spawn(async move {
                if let Err(e) = backend.store_sent_message(&chat_str, &msg_id, &bytes).await {
                    log::warn!("Failed to store sent message to DB: {e}");
                }
            });
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
