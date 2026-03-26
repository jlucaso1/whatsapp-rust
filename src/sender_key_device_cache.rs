//! In-memory cache for per-group sender key device tracking.
//! Avoids DB round-trips on group sends after the first.

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
    pub fn from_db_rows(rows: &[(String, bool)]) -> Self {
        let mut devices: HashMap<Arc<str>, HashMap<u16, bool>> = HashMap::new();
        let mut forgotten_users = HashSet::new();

        for (jid_str, has_key) in rows {
            match jid_str.parse::<Jid>() {
                Ok(jid) => {
                    let user: Arc<str> = Arc::from(jid.user.as_str());
                    devices
                        .entry(user.clone())
                        .or_default()
                        .insert(jid.device, *has_key);
                    if !*has_key {
                        forgotten_users.insert(user);
                    }
                }
                Err(e) => {
                    log::warn!("Skipping malformed device JID '{}': {}", jid_str, e);
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

    pub fn device_has_key(&self, user: &str, device: u16) -> Option<bool> {
        self.devices.get(user)?.get(&device).copied()
    }

    pub fn is_user_forgotten(&self, user: &str) -> bool {
        self.forgotten_users.contains(user)
    }

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
        if has_key {
            if let Some(device_map) = self.devices.get(user_key.as_ref())
                && device_map.values().all(|v| *v)
            {
                self.forgotten_users.remove(&user_key);
            }
        } else {
            self.forgotten_users.insert(user_key);
        }
    }
}

pub(crate) struct SenderKeyDeviceCache {
    inner: Cache<String, Arc<SenderKeyDeviceMap>>,
}

impl SenderKeyDeviceCache {
    pub(crate) fn new(config: &CacheEntryConfig) -> Self {
        Self {
            inner: config.build_with_tti(),
        }
    }

    pub(crate) async fn get(&self, group_jid: &str) -> Option<Arc<SenderKeyDeviceMap>> {
        self.inner.get(group_jid).await
    }

    pub(crate) async fn insert(&self, group_jid: String, map: Arc<SenderKeyDeviceMap>) {
        self.inner.insert(group_jid, map).await;
    }

    pub(crate) async fn invalidate(&self, group_jid: &str) {
        self.inner.invalidate(group_jid).await;
    }

    pub(crate) fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}
