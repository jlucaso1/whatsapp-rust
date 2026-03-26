//! In-memory cache for per-group sender key device tracking.
//!
//! Sits between `resolve_skdm_targets` and the DB to avoid a round-trip
//! on every group send. Uses two-level indexing (user → device → has_key)
//! for zero-allocation O(1) lookups.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::cache::Cache;
use crate::cache_config::CacheEntryConfig;
use wacore_binary::jid::Jid;

/// Pre-parsed, pre-indexed sender key device map for one group.
#[derive(Clone, Debug)]
pub(crate) struct SenderKeyDeviceMap {
    /// user → (device_id → has_key)
    devices: HashMap<Arc<str>, HashMap<u16, bool>>,
    /// Users with at least one `has_key=false` device.
    forgotten_users: HashSet<Arc<str>>,
}

impl SenderKeyDeviceMap {
    /// Build from raw DB rows. Parses JID strings once.
    pub fn from_db_rows(rows: &[(String, bool)]) -> Self {
        let mut devices: HashMap<Arc<str>, HashMap<u16, bool>> = HashMap::new();
        let mut forgotten_users = HashSet::new();

        for (jid_str, has_key) in rows {
            if let Ok(jid) = jid_str.parse::<Jid>() {
                let user: Arc<str> = Arc::from(jid.user.as_str());
                devices
                    .entry(user.clone())
                    .or_default()
                    .insert(jid.device, *has_key);
                if !*has_key {
                    forgotten_users.insert(user);
                }
            }
        }

        Self {
            devices,
            forgotten_users,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    /// O(1) lookup: does this specific device have a sender key?
    pub fn device_has_key(&self, user: &str, device: u16) -> Option<bool> {
        self.devices.get(user)?.get(&device).copied()
    }

    /// O(1) lookup: is any device of this user marked as needing SKDM?
    pub fn is_user_forgotten(&self, user: &str) -> bool {
        self.forgotten_users.contains(user)
    }

    /// Apply a single upsert. Used for write-through updates.
    pub fn upsert(&mut self, user: &str, device: u16, has_key: bool) {
        let user_key = if let Some((existing, _)) = self.devices.get_key_value(user) {
            existing.clone()
        } else {
            Arc::from(user)
        };
        self.devices
            .entry(user_key.clone())
            .or_default()
            .insert(device, has_key);
        if !has_key {
            self.forgotten_users.insert(user_key);
        }
    }
}

/// Bounded cache wrapping `SenderKeyDeviceMap` per group.
/// Uses the project's `Cache` type (moka future::Cache or portable fallback).
pub(crate) struct SenderKeyDeviceCache {
    inner: Cache<String, Arc<SenderKeyDeviceMap>>,
}

impl SenderKeyDeviceCache {
    pub fn new(config: &CacheEntryConfig) -> Self {
        Self {
            inner: config.build_with_tti(),
        }
    }

    pub async fn get(&self, group_jid: &str) -> Option<Arc<SenderKeyDeviceMap>> {
        self.inner.get(group_jid).await
    }

    pub async fn insert(&self, group_jid: String, map: Arc<SenderKeyDeviceMap>) {
        self.inner.insert(group_jid, map).await;
    }

    pub async fn invalidate(&self, group_jid: &str) {
        self.inner.invalidate(group_jid).await;
    }

    pub fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}
