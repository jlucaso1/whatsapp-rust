//! Chat management actions: archive, pin, mute, and starred messages.
//!
//! These features work through WhatsApp's app state sync mechanism (syncd).
//! Each action is encoded as a mutation and sent to the appropriate collection.
//!
//! ## Collections (from WhatsApp Web JS)
//! - Archive: `regular_low` (WAWebArchiveChatSync)
//! - Pin: `regular_low` (WAWebPinChatSync)
//! - Mute: `regular_high` (WAWebMuteChatSync)
//! - Star: `regular_high` (WAWebStarMessageSync)
//!
//! ## Wire format (app state mutation)
//! - Index: JSON array, e.g. `["pin_v1", "jid@s.whatsapp.net"]`
//! - Value: protobuf `SyncActionValue` with the corresponding action field
//! - Operation: `SET`

use crate::appstate_sync::Mutation;
use crate::client::Client;
use anyhow::Result;
use chrono::DateTime;
use log::debug;
use std::sync::Arc;
use wacore::appstate::patch_decode::WAPatchName;
use wacore::types::events::{
    ArchiveUpdate, ContactUpdate, Event, MarkChatAsReadUpdate, MuteUpdate, PinUpdate, StarUpdate,
};
use wacore_binary::jid::{Jid, JidExt};
use waproto::whatsapp as wa;

/// Mute end timestamp value for indefinite mute (matches WhatsApp Web's `-1` sentinel).
const MUTE_INDEFINITE: i64 = -1;

// ── Event dispatch from incoming app state mutations ─────────────────

/// Dispatch events for chat-related app state mutations.
///
/// Handles: mute, pin, pin_v1, archive, star, contact, mark_chat_as_read.
/// Returns `true` if the mutation was handled, `false` if unknown.
pub(crate) fn dispatch_chat_mutation(
    event_bus: &wacore::types::events::CoreEventBus,
    m: &Mutation,
    full_sync: bool,
) -> bool {
    if m.operation != wa::syncd_mutation::SyncdOperation::Set || m.index.is_empty() {
        return false;
    }

    let kind = &m.index[0];

    // Only handle known chat mutation types. Return false for unknown kinds
    // so other handlers (e.g. setting_pushName) can process them.
    if !matches!(
        kind.as_str(),
        "mute"
            | "pin"
            | "pin_v1"
            | "archive"
            | "star"
            | "contact"
            | "mark_chat_as_read"
            | "markChatAsRead"
    ) {
        return false;
    }

    let ts = m
        .action_value
        .as_ref()
        .and_then(|v| v.timestamp)
        .unwrap_or(0);
    let time = DateTime::from_timestamp_millis(ts).unwrap_or_else(wacore::time::now_utc);
    let jid: Jid = if m.index.len() > 1 {
        match m.index[1].parse() {
            Ok(j) => j,
            Err(_) => {
                log::warn!(
                    "Skipping chat mutation '{}': malformed JID '{}'",
                    kind,
                    m.index[1]
                );
                return true; // consumed but not dispatched
            }
        }
    } else {
        log::warn!("Skipping chat mutation '{}': missing JID in index", kind);
        return true;
    };

    match kind.as_str() {
        "mute" => {
            if let Some(val) = &m.action_value
                && let Some(act) = &val.mute_action
            {
                event_bus.dispatch(&Event::MuteUpdate(MuteUpdate {
                    jid,
                    timestamp: time,
                    action: Box::new(*act),
                    from_full_sync: full_sync,
                }));
            }
            true
        }
        "pin" | "pin_v1" => {
            if let Some(val) = &m.action_value
                && let Some(act) = &val.pin_action
            {
                event_bus.dispatch(&Event::PinUpdate(PinUpdate {
                    jid,
                    timestamp: time,
                    action: Box::new(*act),
                    from_full_sync: full_sync,
                }));
            }
            true
        }
        "archive" => {
            if let Some(val) = &m.action_value
                && let Some(act) = &val.archive_chat_action
            {
                event_bus.dispatch(&Event::ArchiveUpdate(ArchiveUpdate {
                    jid,
                    timestamp: time,
                    action: Box::new(act.clone()),
                    from_full_sync: full_sync,
                }));
            }
            true
        }
        "star" => {
            // Star index: ["star", chatJid, messageId, fromMe, participant]
            // See WAWebSyncdUtils.constructMsgKeySegmentsFromMsgKey
            if let Some(val) = &m.action_value
                && let Some(act) = &val.star_action
                && m.index.len() >= 5
            {
                let chat_jid: Jid = match m.index[1].parse() {
                    Ok(j) => j,
                    Err(_) => {
                        log::warn!(
                            "Skipping star mutation: malformed chat JID '{}'",
                            m.index[1]
                        );
                        return true;
                    }
                };
                let message_id = m.index[2].clone();
                let from_me = m.index[3] == "1";
                // Participant is the actual sender for group messages from others.
                // "0" means self-authored or 1-on-1 → None.
                let participant_jid: Option<Jid> = if m.index[4] != "0" {
                    match m.index[4].parse() {
                        Ok(j) => Some(j),
                        Err(_) => {
                            log::warn!(
                                "Skipping star mutation: malformed participant JID '{}'",
                                m.index[4]
                            );
                            return true;
                        }
                    }
                } else {
                    None
                };

                event_bus.dispatch(&Event::StarUpdate(StarUpdate {
                    chat_jid,
                    participant_jid,
                    message_id,
                    from_me,
                    timestamp: time,
                    action: Box::new(*act),
                    from_full_sync: full_sync,
                }));
            }
            true
        }
        "contact" => {
            if let Some(val) = &m.action_value
                && let Some(act) = &val.contact_action
            {
                event_bus.dispatch(&Event::ContactUpdate(ContactUpdate {
                    jid,
                    timestamp: time,
                    action: Box::new(act.clone()),
                    from_full_sync: full_sync,
                }));
            }
            true
        }
        "mark_chat_as_read" | "markChatAsRead" => {
            if let Some(val) = &m.action_value
                && let Some(act) = &val.mark_chat_as_read_action
            {
                event_bus.dispatch(&Event::MarkChatAsReadUpdate(MarkChatAsReadUpdate {
                    jid,
                    timestamp: time,
                    action: Box::new(act.clone()),
                    from_full_sync: full_sync,
                }));
            }
            true
        }
        _ => false,
    }
}

// ── Public API ───────────────────────────────────────────────────────

/// Feature handle for chat management actions.
///
/// Access via `client.chat_actions()` (requires `Arc<Client>`).
pub struct ChatActions<'a> {
    client: &'a Arc<Client>,
}

impl<'a> ChatActions<'a> {
    pub(crate) fn new(client: &'a Arc<Client>) -> Self {
        Self { client }
    }

    // ── Archive ──────────────────────────────────────────────────────

    /// Archive a chat.
    pub async fn archive_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Archiving chat {jid}");
        self.send_archive_mutation(jid, true).await
    }

    /// Unarchive a chat.
    pub async fn unarchive_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Unarchiving chat {jid}");
        self.send_archive_mutation(jid, false).await
    }

    // ── Pin ──────────────────────────────────────────────────────────

    /// Pin a chat.
    pub async fn pin_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Pinning chat {jid}");
        self.send_pin_mutation(jid, true).await
    }

    /// Unpin a chat.
    pub async fn unpin_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Unpinning chat {jid}");
        self.send_pin_mutation(jid, false).await
    }

    // ── Mute ─────────────────────────────────────────────────────────

    /// Mute a chat indefinitely.
    pub async fn mute_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Muting chat {jid} indefinitely");
        self.send_mute_mutation(jid, true, MUTE_INDEFINITE).await
    }

    /// Mute a chat until a specific timestamp (Unix milliseconds).
    ///
    /// The timestamp must be in the future. Use [`mute_chat`](Self::mute_chat)
    /// for indefinite muting.
    pub async fn mute_chat_until(&self, jid: &Jid, mute_end_timestamp_ms: i64) -> Result<()> {
        if mute_end_timestamp_ms <= 0 {
            anyhow::bail!(
                "mute_end_timestamp_ms must be a positive future timestamp (use mute_chat() for indefinite)"
            );
        }
        let now_ms = wacore::time::now_millis();
        if mute_end_timestamp_ms <= now_ms {
            anyhow::bail!(
                "mute_end_timestamp_ms is in the past ({mute_end_timestamp_ms} <= {now_ms})"
            );
        }
        debug!("Muting chat {jid} until {mute_end_timestamp_ms}");
        self.send_mute_mutation(jid, true, mute_end_timestamp_ms)
            .await
    }

    /// Unmute a chat.
    pub async fn unmute_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Unmuting chat {jid}");
        self.send_mute_mutation(jid, false, 0).await
    }

    // ── Star ─────────────────────────────────────────────────────────

    /// Star a message.
    ///
    /// - `chat_jid`: The chat containing the message.
    /// - `participant_jid`: For group messages from others, pass `Some(&sender_jid)`.
    ///   For 1-on-1 or own messages, pass `None` (the protocol uses `"0"`).
    /// - `message_id`: The message ID to star.
    /// - `from_me`: Whether the message was sent by us.
    pub async fn star_message(
        &self,
        chat_jid: &Jid,
        participant_jid: Option<&Jid>,
        message_id: &str,
        from_me: bool,
    ) -> Result<()> {
        debug!("Starring message {message_id} in {chat_jid}");
        self.send_star_mutation(chat_jid, participant_jid, message_id, from_me, true)
            .await
    }

    /// Unstar a message.
    ///
    /// Parameters are the same as [`star_message`](Self::star_message).
    pub async fn unstar_message(
        &self,
        chat_jid: &Jid,
        participant_jid: Option<&Jid>,
        message_id: &str,
        from_me: bool,
    ) -> Result<()> {
        debug!("Unstarring message {message_id} in {chat_jid}");
        self.send_star_mutation(chat_jid, participant_jid, message_id, from_me, false)
            .await
    }

    // ── Internal helpers ─────────────────────────────────────────────

    async fn send_archive_mutation(&self, jid: &Jid, archived: bool) -> Result<()> {
        let index = serde_json::to_vec(&["archive", &jid.to_string()])?;
        let value = wa::SyncActionValue {
            archive_chat_action: Some(wa::sync_action_value::ArchiveChatAction {
                archived: Some(archived),
                message_range: None,
            }),
            timestamp: Some(wacore::time::now_millis()),
            ..Default::default()
        };
        self.send_mutation(WAPatchName::RegularLow, &index, &value)
            .await
    }

    async fn send_pin_mutation(&self, jid: &Jid, pinned: bool) -> Result<()> {
        let index = serde_json::to_vec(&["pin_v1", &jid.to_string()])?;
        let value = wa::SyncActionValue {
            pin_action: Some(wa::sync_action_value::PinAction {
                pinned: Some(pinned),
            }),
            timestamp: Some(wacore::time::now_millis()),
            ..Default::default()
        };
        self.send_mutation(WAPatchName::RegularLow, &index, &value)
            .await
    }

    async fn send_mute_mutation(
        &self,
        jid: &Jid,
        muted: bool,
        mute_end_timestamp_ms: i64,
    ) -> Result<()> {
        let index = serde_json::to_vec(&["mute", &jid.to_string()])?;
        // WhatsApp Web requires muteEndTimestamp to always be present when muted=true.
        // -1 means indefinite, 0 means unmuted, positive means expiry in milliseconds.
        let mute_end = if muted {
            Some(mute_end_timestamp_ms)
        } else {
            Some(0)
        };
        let value = wa::SyncActionValue {
            mute_action: Some(wa::sync_action_value::MuteAction {
                muted: Some(muted),
                mute_end_timestamp: mute_end,
                auto_muted: None,
            }),
            timestamp: Some(wacore::time::now_millis()),
            ..Default::default()
        };
        self.send_mutation(WAPatchName::RegularHigh, &index, &value)
            .await
    }

    async fn send_star_mutation(
        &self,
        chat_jid: &Jid,
        participant_jid: Option<&Jid>,
        message_id: &str,
        from_me: bool,
        starred: bool,
    ) -> Result<()> {
        if chat_jid.is_group() && !from_me && participant_jid.is_none() {
            anyhow::bail!(
                "participant_jid is required when starring a group message not sent by us"
            );
        }
        // WhatsApp Web star index order: ["star", chatJid, messageId, fromMe, participant]
        // participant = sender JID for group messages from others, "0" otherwise.
        // See WAWebSyncdUtils.constructMsgKeySegmentsFromMsgKey + extractParticipantForSync
        let from_me_str = if from_me { "1" } else { "0" };
        let participant = participant_jid
            .map(|j| j.to_string())
            .unwrap_or_else(|| "0".to_string());
        let index = serde_json::to_vec(&[
            "star",
            &chat_jid.to_string(),
            message_id,
            from_me_str,
            &participant,
        ])?;
        let value = wa::SyncActionValue {
            star_action: Some(wa::sync_action_value::StarAction {
                starred: Some(starred),
            }),
            timestamp: Some(wacore::time::now_millis()),
            ..Default::default()
        };
        self.send_mutation(WAPatchName::RegularHigh, &index, &value)
            .await
    }

    /// Encode and send an app state mutation to the given collection.
    async fn send_mutation(
        &self,
        collection: WAPatchName,
        index: &[u8],
        value: &wa::SyncActionValue,
    ) -> Result<()> {
        use rand::Rng;
        use wacore::appstate::encode::encode_record;

        let proc = self.client.get_app_state_processor().await;
        let key_id = proc
            .backend
            .get_latest_sync_key_id()
            .await
            .map_err(|e| anyhow::anyhow!(e))?
            .ok_or_else(|| anyhow::anyhow!("No app state sync key available"))?;
        let keys = proc.get_app_state_key(&key_id).await?;

        let mut iv = [0u8; 16];
        rand::make_rng::<rand::rngs::StdRng>().fill_bytes(&mut iv);

        let (mutation, value_mac) = encode_record(
            wa::syncd_mutation::SyncdOperation::Set,
            index,
            value,
            &keys,
            &key_id,
            &iv,
        );

        self.client
            .send_app_state_patch(collection.as_str(), vec![(mutation, value_mac)])
            .await
    }
}

impl Client {
    /// Access chat management actions (archive, pin, mute, star).
    ///
    /// Requires `Arc<Client>` because app state mutations need key access.
    pub fn chat_actions(self: &Arc<Self>) -> ChatActions<'_> {
        ChatActions::new(self)
    }
}
