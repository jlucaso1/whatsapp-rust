//! Batches unknown-device users during offline sync for deferred usync.
//! WA Web: `OfflinePendingDeviceCache` + `doPendingDeviceSync()`.

use std::collections::HashSet;
use wacore_binary::jid::Jid;

pub(crate) struct PendingDeviceSync {
    pending: async_lock::Mutex<HashSet<Jid>>,
}

impl PendingDeviceSync {
    pub(crate) fn new() -> Self {
        Self {
            pending: async_lock::Mutex::new(HashSet::new()),
        }
    }

    pub(crate) async fn add(&self, jid: Jid) {
        self.pending.lock().await.insert(jid);
    }

    pub(crate) async fn take_all(&self) -> Vec<Jid> {
        self.pending.lock().await.drain().collect()
    }

    pub(crate) async fn clear(&self) {
        self.pending.lock().await.clear();
    }
}
