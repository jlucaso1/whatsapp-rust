//! In-memory cache for per-group sender key device tracking.
//! Avoids DB round-trips on group sends after the first.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::cache::Cache;
use crate::cache_config::CacheEntryConfig;
use wacore_binary::Jid;

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
        let mut devices: HashMap<Arc<str>, HashMap<u16, bool>> = HashMap::with_capacity(rows.len());
        let mut forgotten_users = HashSet::with_capacity(rows.len() / 4);

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

    /// Atomically get-or-init: returns cached value or runs `init` once per key.
    /// Concurrent callers for the same key share the single init result.
    pub(crate) async fn get_or_init<F>(&self, group_jid: &str, init: F) -> Arc<SenderKeyDeviceMap>
    where
        F: std::future::Future<Output = Arc<SenderKeyDeviceMap>>,
    {
        self.inner.get_with_by_ref(group_jid, init).await
    }

    pub(crate) async fn invalidate(&self, group_jid: &str) {
        self.inner.invalidate(group_jid).await;
    }

    /// Invalidate all entries. Used on raw_id mismatch (identity change)
    /// to force SKDM redistribution for all groups.
    pub(crate) fn invalidate_all(&self) {
        self.inner.invalidate_all();
    }

    #[cfg(feature = "debug-diagnostics")]
    pub(crate) fn entry_count(&self) -> u64 {
        self.inner.entry_count()
    }
}
