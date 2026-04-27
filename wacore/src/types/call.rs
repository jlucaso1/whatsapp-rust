use chrono::{DateTime, Utc};
use serde::Serialize;
use wacore_binary::Jid;

#[derive(Debug, Clone)]
pub struct BasicCallMeta {
    pub from: Jid,
    pub timestamp: DateTime<Utc>,
    pub call_creator: Jid,
    pub call_id: String,
}

#[derive(Debug, Clone)]
pub struct CallRemoteMeta {
    pub remote_platform: String,
    pub remote_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CallAudioCodec {
    pub enc: String,
    pub rate: u32,
}

/// Fields kept per-variant (not a shared `BasicCallMeta`) so the `serde` shape
/// mirrors the stanza 1:1 for downstream JS consumers.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CallAction {
    Offer {
        call_id: String,
        call_creator: Jid,
        #[serde(skip_serializing_if = "Option::is_none")]
        caller_pn: Option<Jid>,
        #[serde(skip_serializing_if = "Option::is_none")]
        caller_country_code: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        device_class: Option<String>,
        joinable: bool,
        is_video: bool,
        audio: Vec<CallAudioCodec>,
        /// Set on group calls. Primary group signal per `WAWebVoipGatingUtils`.
        #[serde(skip_serializing_if = "Option::is_none")]
        group_jid: Option<Jid>,
    },
    /// Group-call notification fan-out to members. No offer-receipt expected;
    /// the generic call ack is enough (router handles it via `should_ack`).
    OfferNotice {
        call_id: String,
        call_creator: Jid,
        /// `media == "video"` per `WAWebHandleVoipOfferNotice`.
        is_video: bool,
        /// `type == "group"` per `WAWebHandleVoipOfferNotice`.
        is_group: bool,
    },
    PreAccept {
        call_id: String,
        call_creator: Jid,
    },
    Accept {
        call_id: String,
        call_creator: Jid,
    },
    Reject {
        call_id: String,
        call_creator: Jid,
    },
    Terminate {
        call_id: String,
        call_creator: Jid,
        #[serde(skip_serializing_if = "Option::is_none")]
        duration: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        audio_duration: Option<u32>,
    },
}

impl CallAction {
    pub fn call_id(&self) -> &str {
        match self {
            Self::Offer { call_id, .. }
            | Self::OfferNotice { call_id, .. }
            | Self::PreAccept { call_id, .. }
            | Self::Accept { call_id, .. }
            | Self::Reject { call_id, .. }
            | Self::Terminate { call_id, .. } => call_id,
        }
    }

    pub fn call_creator(&self) -> &Jid {
        match self {
            Self::Offer { call_creator, .. }
            | Self::OfferNotice { call_creator, .. }
            | Self::PreAccept { call_creator, .. }
            | Self::Accept { call_creator, .. }
            | Self::Reject { call_creator, .. }
            | Self::Terminate { call_creator, .. } => call_creator,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct IncomingCall {
    pub from: Jid,
    /// Stanza id; distinct from `CallAction::call_id`.
    pub stanza_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notify: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub timestamp: DateTime<Utc>,
    pub offline: bool,
    pub action: CallAction,
}
