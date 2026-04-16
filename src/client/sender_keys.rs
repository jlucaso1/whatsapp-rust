//! Sender key tracking and message cache methods for Client.

use anyhow::Result;
use wacore::types::message::ChatMessageId;
use wacore_binary::Jid;
use waproto::whatsapp as wa;

use super::Client;

impl Client {
    pub(crate) async fn set_sender_key_status_for_devices(
        &self,
        group_jid: &str,
        device_jids: &[Jid],
        has_key: bool,
        exclude_own_devices: bool,
    ) -> Result<()> {
        let (own_lid_user, own_pn_user) = if exclude_own_devices {
            let snapshot = self.persistence_manager.get_device_snapshot().await;
            (
                snapshot.lid.as_ref().map(|j| j.user.clone()),
                snapshot.pn.as_ref().map(|j| j.user.clone()),
            )
        } else {
            (None, None)
        };

        let device_ids: Vec<String> = device_jids
            .iter()
            .filter(|jid| {
                !exclude_own_devices
                    || !(own_lid_user.as_deref().is_some_and(|u| u == jid.user)
                        || own_pn_user.as_deref().is_some_and(|u| u == jid.user))
            })
            .map(ToString::to_string)
            .collect();

        if device_ids.is_empty() {
            return Ok(());
        }

        let entries: Vec<(&str, bool)> = device_ids
            .iter()
            .map(|jid| (jid.as_str(), has_key))
            .collect();
        self.persistence_manager
            .set_sender_key_status(group_jid, &entries)
            .await?;
        self.sender_key_device_cache.invalidate(group_jid).await;
        Ok(())
    }

    /// Mark device JIDs as needing fresh SKDM (has_key = false).
    /// Filters out our own devices (WA Web: `!isMeDevice(e)` check).
    /// Called from handle_retry_receipt for group/status messages.
    pub(crate) async fn mark_forget_sender_key(
        &self,
        group_jid: &str,
        device_jids: &[Jid],
    ) -> Result<()> {
        self.set_sender_key_status_for_devices(group_jid, device_jids, false, true)
            .await?;
        Ok(())
    }

    /// Take a sent message for retry handling. Checks L1 cache first (if enabled),
    /// then falls back to DB. On miss, tries an alternate PN/LID key to handle
    /// mapping changes between send time and retry time (WAWebLidMigrationUtils
    /// `getAlternateMsgKey`).
    /// Returns `(message, alternate_chat)`. When the message was found via the
    /// alternate PN/LID key, `alternate_chat` contains the namespace that
    /// matched -- the caller should use it for session operations instead of
    /// `resolve_encryption_jid` (which would map back to the primary).
    pub(crate) async fn take_recent_message(
        &self,
        to: &Jid,
        id: &str,
    ) -> Option<(wa::Message, Option<Jid>)> {
        let primary_key = self.make_chat_message_id(to, id).await;
        if let Some(msg) = self.try_take_by_key(&primary_key).await {
            return Some((msg, None));
        }

        // Primary miss -- try alternate PN<->LID key.
        // If resolve_encryption_jid changed the namespace (PN→LID), the
        // original `to` is already the alternate -- skip the cache lookup.
        // Otherwise (LID input), swap via cache to try the PN form.
        let alt_chat = if primary_key.chat.server != to.server {
            Some(to.clone())
        } else {
            self.swap_pn_lid_namespace(&primary_key.chat).await
        };

        if let Some(alt_chat) = alt_chat {
            log::debug!(
                "Primary key miss for {}:{}, trying alternate {}",
                primary_key.chat,
                id,
                alt_chat
            );
            let alt_key = ChatMessageId {
                chat: alt_chat,
                id: primary_key.id,
            };
            if let Some(msg) = self.try_take_by_key(&alt_key).await {
                return Some((msg, Some(alt_key.chat)));
            }
        }

        None
    }

    /// Look up and consume a message by exact `ChatMessageId` (L1 cache then DB).
    async fn try_take_by_key(&self, key: &ChatMessageId) -> Option<wa::Message> {
        use buffa::Message;
        let chat_str = key.chat.to_string();
        let has_l1_cache = self.cache_config.recent_messages.capacity > 0;

        // L1 cache check (if capacity > 0)
        if has_l1_cache && let Some(bytes) = self.recent_messages.remove(key).await {
            if let Ok(msg) = wa::Message::decode_from_slice(bytes.as_slice()) {
                // Cache hit — consume the DB row in the background to avoid orphans.
                let backend = self.persistence_manager.backend();
                let mid = key.id.clone();
                self.runtime
                    .spawn(Box::pin(async move {
                        if let Err(e) = backend.take_sent_message(&chat_str, &mid).await {
                            log::warn!("Failed to clean up sent message {chat_str}:{mid}: {e}");
                        }
                    }))
                    .detach();
                return Some(msg);
            }
            log::warn!(
                "Failed to decode cached message for {}:{}, trying DB",
                key.chat,
                key.id
            );
        }

        // DB path (primary when cache capacity = 0, fallback when cache misses)
        match self
            .persistence_manager
            .backend()
            .take_sent_message(&chat_str, &key.id)
            .await
        {
            Ok(Some(bytes)) => match wa::Message::decode_from_slice(bytes.as_slice()) {
                Ok(msg) => Some(msg),
                Err(e) => {
                    log::warn!(
                        "Failed to decode DB message for {}:{}: {}",
                        key.chat,
                        key.id,
                        e
                    );
                    None
                }
            },
            Ok(None) => None,
            Err(e) => {
                log::warn!(
                    "Failed to read sent message from DB for {}:{}: {}",
                    key.chat,
                    key.id,
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
    pub(crate) async fn add_recent_message(&self, to: &Jid, id: &str, msg: &wa::Message) {
        use buffa::Message;
        let key = self.make_chat_message_id(to, id).await;
        let bytes = msg.encode_to_vec();
        let has_l1_cache = self.cache_config.recent_messages.capacity > 0;

        if has_l1_cache {
            // L1 cache serves reads immediately; DB write can be backgrounded
            let chat_str = key.chat.to_string();
            let msg_id = key.id.clone();
            self.recent_messages.insert(key, bytes.clone()).await;
            let backend = self.persistence_manager.backend();
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
