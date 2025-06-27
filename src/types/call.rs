use crate::types::jid::Jid;
use chrono::{DateTime, Utc};

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
