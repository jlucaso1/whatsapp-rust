//! Chat management via app state sync (syncd).
//!
//! ## Collections (from WhatsApp Web JS)
//! - `regular_low`: archive, pin, markChatAsRead
//! - `regular_high`: mute, star, deleteChat, deleteMessageForMe

use crate::appstate_sync::Mutation;
use crate::client::Client;
use anyhow::Result;
use chrono::DateTime;
use log::debug;
use wacore::appstate::patch_decode::WAPatchName;
use wacore::types::events::{
    ArchiveUpdate, ContactUpdate, DeleteChatUpdate, DeleteMessageForMeUpdate, Event,
    MarkChatAsReadUpdate, MuteUpdate, PinUpdate, StarUpdate,
};
use wacore_binary::jid::{Jid, JidExt};
use waproto::whatsapp as wa;

/// WA Web uses `-1` for indefinite mute.
const MUTE_INDEFINITE: i64 = -1;

pub type SyncActionMessageRange = wa::sync_action_value::SyncActionMessageRange;

/// Enables multi-device conflict resolution. `None` is safe (matches whatsmeow/Baileys).
/// Only WA Web (with a full message DB) populates this.
pub fn message_range(
    last_message_timestamp: i64,
    last_system_message_timestamp: Option<i64>,
    messages: Vec<(wa::MessageKey, i64)>,
) -> SyncActionMessageRange {
    SyncActionMessageRange {
        last_message_timestamp: Some(last_message_timestamp),
        last_system_message_timestamp,
        messages: messages
            .into_iter()
            .map(|(key, ts)| wa::sync_action_value::SyncActionMessage {
                key: Some(key),
                timestamp: Some(ts),
            })
            .collect(),
    }
}

pub fn message_key(
    id: impl Into<String>,
    remote_jid: &Jid,
    from_me: bool,
    participant: Option<&Jid>,
) -> wa::MessageKey {
    wa::MessageKey {
        id: Some(id.into()),
        remote_jid: Some(remote_jid.to_string()),
        from_me: Some(from_me),
        participant: participant.map(|j| j.to_string()),
    }
}

/// Returns `true` if handled, `false` if unknown (so other handlers can try).
pub(crate) fn dispatch_chat_mutation(
    event_bus: &wacore::types::events::CoreEventBus,
    m: &Mutation,
    full_sync: bool,
) -> bool {
    if m.operation != wa::syncd_mutation::SyncdOperation::Set || m.index.is_empty() {
        return false;
    }

    let kind = &m.index[0];

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
            | "deleteChat"
            | "deleteMessageForMe"
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
                return true;
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
            if let Some(val) = &m.action_value
                && let Some(act) = &val.star_action
                && let Some((message_id, from_me, participant_jid)) =
                    parse_message_key_fields(kind, &m.index)
            {
                event_bus.dispatch(&Event::StarUpdate(StarUpdate {
                    chat_jid: jid,
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
        "deleteChat" => {
            if let Some(val) = &m.action_value
                && let Some(act) = &val.delete_chat_action
            {
                // delete_media is in index[2], not in the proto (which only has messageRange)
                let delete_media = m.index.get(2).is_none_or(|v| v != "0");
                event_bus.dispatch(&Event::DeleteChatUpdate(DeleteChatUpdate {
                    jid,
                    delete_media,
                    timestamp: time,
                    action: Box::new(act.clone()),
                    from_full_sync: full_sync,
                }));
            }
            true
        }
        "deleteMessageForMe" => {
            if let Some(val) = &m.action_value
                && let Some(act) = &val.delete_message_for_me_action
                && let Some((message_id, from_me, participant_jid)) =
                    parse_message_key_fields(kind, &m.index)
            {
                event_bus.dispatch(&Event::DeleteMessageForMeUpdate(DeleteMessageForMeUpdate {
                    chat_jid: jid,
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
        _ => false,
    }
}

/// Parse message-key fields (messageId, fromMe, participant) from index positions 2-4.
/// Returns `None` (with a warning log) if the index is too short or participant is malformed.
fn parse_message_key_fields(kind: &str, index: &[String]) -> Option<(String, bool, Option<Jid>)> {
    if index.len() < 5 {
        log::warn!(
            "Skipping {kind} mutation: expected 5 index elements, got {}",
            index.len()
        );
        return None;
    }
    let message_id = index[2].clone();
    let from_me = index[3] == "1";
    let participant_jid = if index[4] != "0" {
        match index[4].parse() {
            Ok(j) => Some(j),
            Err(_) => {
                log::warn!(
                    "Skipping {kind} mutation: malformed participant JID '{}'",
                    index[4]
                );
                return None;
            }
        }
    } else {
        None
    };
    Some((message_id, from_me, participant_jid))
}

/// Mirrors WAWebSyncdActionUtils.buildMessageKey.
fn build_message_key_index(
    action: &str,
    chat_jid: &Jid,
    participant_jid: Option<&Jid>,
    message_id: &str,
    from_me: bool,
) -> Result<Vec<u8>> {
    // syncKeyToMsgKey rejects group non-fromMe without valid participant
    if chat_jid.is_group() && !from_me && participant_jid.is_none() {
        anyhow::bail!(
            "participant_jid is required for group messages not sent by us (action: {action})"
        );
    }
    let from_me_str = if from_me { "1" } else { "0" };
    let participant = participant_jid
        .map(|j| j.to_string())
        .unwrap_or_else(|| "0".to_string());
    Ok(serde_json::to_vec(&[
        action,
        &chat_jid.to_string(),
        message_id,
        from_me_str,
        &participant,
    ])?)
}

/// Access via `client.chat_actions()`.
pub struct ChatActions<'a> {
    client: &'a Client,
}

impl<'a> ChatActions<'a> {
    pub(crate) fn new(client: &'a Client) -> Self {
        Self { client }
    }

    pub async fn archive_chat(
        &self,
        jid: &Jid,
        message_range: Option<SyncActionMessageRange>,
    ) -> Result<()> {
        debug!("Archiving chat {jid}");
        self.send_archive_mutation(jid, true, message_range).await
    }

    pub async fn unarchive_chat(
        &self,
        jid: &Jid,
        message_range: Option<SyncActionMessageRange>,
    ) -> Result<()> {
        debug!("Unarchiving chat {jid}");
        self.send_archive_mutation(jid, false, message_range).await
    }

    pub async fn pin_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Pinning chat {jid}");
        self.send_pin_mutation(jid, true).await
    }

    pub async fn unpin_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Unpinning chat {jid}");
        self.send_pin_mutation(jid, false).await
    }

    pub async fn mute_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Muting chat {jid} indefinitely");
        self.send_mute_mutation(jid, true, MUTE_INDEFINITE).await
    }

    /// Must be in the future. Use [`mute_chat`](Self::mute_chat) for indefinite.
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

    pub async fn unmute_chat(&self, jid: &Jid) -> Result<()> {
        debug!("Unmuting chat {jid}");
        self.send_mute_mutation(jid, false, 0).await
    }

    /// `participant_jid`: required for group messages from others, `None` otherwise.
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

    /// Distinct from `readMessages` IQ receipts — this syncs state across linked devices.
    pub async fn mark_chat_as_read(
        &self,
        jid: &Jid,
        read: bool,
        message_range: Option<SyncActionMessageRange>,
    ) -> Result<()> {
        debug!(
            "Marking chat {jid} as {}",
            if read { "read" } else { "unread" }
        );
        let index = serde_json::to_vec(&["markChatAsRead", &jid.to_string()])?;
        let value = wa::SyncActionValue {
            mark_chat_as_read_action: Some(wa::sync_action_value::MarkChatAsReadAction {
                read: Some(read),
                message_range,
            }),
            timestamp: Some(wacore::time::now_millis()),
            ..Default::default()
        };
        self.send_mutation(WAPatchName::RegularLow, &index, &value)
            .await
    }

    pub async fn delete_chat(
        &self,
        jid: &Jid,
        delete_media: bool,
        message_range: Option<SyncActionMessageRange>,
    ) -> Result<()> {
        debug!("Deleting chat {jid}");
        let delete_media_str = if delete_media { "1" } else { "0" };
        let index = serde_json::to_vec(&["deleteChat", &jid.to_string(), delete_media_str])?;
        let value = wa::SyncActionValue {
            delete_chat_action: Some(wa::sync_action_value::DeleteChatAction { message_range }),
            timestamp: Some(wacore::time::now_millis()),
            ..Default::default()
        };
        self.send_mutation(WAPatchName::RegularHigh, &index, &value)
            .await
    }

    /// Deletes locally only (not for everyone).
    /// `participant_jid`: required for group messages from others, `None` otherwise.
    pub async fn delete_message_for_me(
        &self,
        chat_jid: &Jid,
        participant_jid: Option<&Jid>,
        message_id: &str,
        from_me: bool,
        delete_media: bool,
        message_timestamp: Option<i64>,
    ) -> Result<()> {
        debug!("Deleting message {message_id} for me in {chat_jid}");
        let index = build_message_key_index(
            "deleteMessageForMe",
            chat_jid,
            participant_jid,
            message_id,
            from_me,
        )?;
        let value = wa::SyncActionValue {
            delete_message_for_me_action: Some(wa::sync_action_value::DeleteMessageForMeAction {
                delete_media: Some(delete_media),
                message_timestamp,
            }),
            timestamp: Some(wacore::time::now_millis()),
            ..Default::default()
        };
        self.send_mutation(WAPatchName::RegularHigh, &index, &value)
            .await
    }

    async fn send_archive_mutation(
        &self,
        jid: &Jid,
        archived: bool,
        message_range: Option<SyncActionMessageRange>,
    ) -> Result<()> {
        let index = serde_json::to_vec(&["archive", &jid.to_string()])?;
        let value = wa::SyncActionValue {
            archive_chat_action: Some(wa::sync_action_value::ArchiveChatAction {
                archived: Some(archived),
                message_range,
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
        // -1 = indefinite, 0 = unmuted, positive = expiry ms
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
        let index =
            build_message_key_index("star", chat_jid, participant_jid, message_id, from_me)?;
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

        let (mutation, _) = encode_record(
            wa::syncd_mutation::SyncdOperation::Set,
            index,
            value,
            &keys,
            &key_id,
            &iv,
        );

        self.client
            .send_app_state_patch(collection.as_str(), vec![mutation])
            .await
    }
}

impl Client {
    pub fn chat_actions(&self) -> ChatActions<'_> {
        ChatActions::new(self)
    }
}
