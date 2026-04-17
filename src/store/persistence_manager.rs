use super::error::{StoreError, db_err};
use crate::store::Device;
use crate::store::traits::Backend;
use async_lock::RwLock;
use event_listener::Event;
use futures::FutureExt;
use log::{debug, error};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use wacore::runtime::{AbortHandle, Runtime, wait_for_shutdown};

pub struct PersistenceManager {
    device: Arc<RwLock<Device>>,
    backend: Arc<dyn Backend>,
    dirty: Arc<AtomicBool>,
    save_notify: Arc<Event>,
    /// Set to true when the background saver halts due to repeated flush failures.
    saver_halted: Arc<AtomicBool>,
}

impl PersistenceManager {
    /// Create a PersistenceManager with a backend implementation.
    ///
    /// Note: The backend should already be configured with the correct device_id
    /// (via SqliteStore::new_for_device for multi-account scenarios).
    pub async fn new(backend: Arc<dyn Backend>) -> Result<Self, StoreError> {
        debug!("PersistenceManager: Ensuring device row exists.");
        // Ensure a device row exists for this backend's device_id; create it if not.
        let exists = backend.exists().await.map_err(db_err)?;
        if !exists {
            debug!("PersistenceManager: No device row found. Creating new device row.");
            let id = backend.create().await.map_err(db_err)?;
            debug!("PersistenceManager: Created device row with id={id}.");
        }

        debug!("PersistenceManager: Attempting to load device data via Backend.");
        let device_data_opt = backend.load().await.map_err(db_err)?;

        let device = if let Some(serializable_device) = device_data_opt {
            debug!(
                "PersistenceManager: Loaded existing device data (PushName: '{}'). Initializing Device.",
                serializable_device.push_name
            );
            let mut dev = Device::new(backend.clone());
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            debug!("PersistenceManager: No data yet; initializing default Device in memory.");
            Device::new(backend.clone())
        };

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            backend,
            dirty: Arc::new(AtomicBool::new(false)),
            save_notify: Arc::new(Event::new()),
            saver_halted: Arc::new(AtomicBool::new(false)),
        })
    }

    pub async fn get_device_arc(&self) -> Arc<RwLock<Device>> {
        self.device.clone()
    }

    pub async fn get_device_snapshot(&self) -> Device {
        self.device.read().await.clone()
    }

    pub fn backend(&self) -> Arc<dyn Backend> {
        self.backend.clone()
    }

    /// Returns true if the background saver halted due to repeated flush failures.
    pub fn is_saver_halted(&self) -> bool {
        self.saver_halted.load(Ordering::Acquire)
    }

    pub async fn modify_device<F, R>(&self, modifier: F) -> R
    where
        F: FnOnce(&mut Device) -> R,
    {
        let mut device_guard = self.device.write().await;
        let result = modifier(&mut device_guard);

        self.dirty.store(true, Ordering::Relaxed);
        self.save_notify.notify(1);

        result
    }

    /// Flush any dirty device state to the backend immediately.
    pub async fn flush(&self) -> Result<(), StoreError> {
        self.save_to_disk().await
    }

    async fn save_to_disk(&self) -> Result<(), StoreError> {
        if self.dirty.swap(false, Ordering::AcqRel) {
            debug!("Device state is dirty, saving to disk.");
            let device_guard = self.device.read().await;
            let serializable_device = device_guard.to_serializable();
            drop(device_guard);

            if let Err(e) = self.backend.save(&serializable_device).await {
                // Restore dirty flag so the next tick retries the save
                self.dirty.store(true, Ordering::Release);
                return Err(db_err(e));
            }
            debug!("Device state saved successfully.");
        }
        Ok(())
    }

    /// Triggers a snapshot of the underlying storage backend.
    /// Useful for debugging critical errors like crypto state corruption.
    pub async fn create_snapshot(
        &self,
        name: &str,
        extra_content: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        #[cfg(feature = "debug-snapshots")]
        {
            // Ensure pending changes are saved first
            self.save_to_disk().await?;
            self.backend
                .snapshot_db(name, extra_content)
                .await
                .map_err(db_err)
        }
        #[cfg(not(feature = "debug-snapshots"))]
        {
            let _ = name;
            let _ = extra_content;
            log::warn!("Snapshot requested but 'debug-snapshots' feature is disabled");
            Ok(())
        }
    }

    /// Self-terminates on `shutdown.notify(...)` after a final flush.
    /// Caller must keep the returned `AbortHandle` — dropping it aborts the task.
    ///
    /// A notify that fires between `spawn` and the first `listen()` inside the
    /// loop is missed. The worst-case recovery is one interval tick (plus the
    /// `AbortHandle` drop path) so no state is lost.
    pub fn run_background_saver(
        self: Arc<Self>,
        runtime: Arc<dyn Runtime>,
        interval: Duration,
        shutdown: Weak<Event>,
    ) -> AbortHandle {
        const MAX_CONSECUTIVE_FAILURES: u32 = 10;

        let rt = runtime.clone();
        let weak = Arc::downgrade(&self);
        drop(self);
        debug!("Background saver started (interval {interval:?})");
        runtime.spawn(Box::pin(async move {
            let mut consecutive_failures: u32 = 0;

            // Flush any state dirtied during construction before the first wait.
            // The saver is started after Client::new_with_cache_config in bot.rs,
            // so save_notify fires from SetDeviceProps etc. happen before the first
            // listener is registered and would otherwise be missed until the next
            // interval tick.
            if let Some(this) = weak.upgrade()
                && let Err(e) = this.save_to_disk().await
            {
                error!("Background saver: initial flush failed: {e}");
                consecutive_failures = 1;
            }

            loop {
                let Some(this) = weak.upgrade() else {
                    debug!("PersistenceManager dropped, exiting background saver.");
                    return;
                };
                let save_listener = this.save_notify.listen();
                drop(this);

                let should_exit = futures::select! {
                    _ = save_listener.fuse() => false,
                    _ = rt.sleep(interval).fuse() => false,
                    _ = wait_for_shutdown(&shutdown).fuse() => true,
                };

                let Some(this) = weak.upgrade() else {
                    debug!("PersistenceManager dropped, exiting background saver.");
                    return;
                };
                let flush_result = this.save_to_disk().await;

                // On the shutdown path the task is terminating either way; a failed
                // final flush should not permanently flag the store as halted.
                if should_exit {
                    match &flush_result {
                        Err(e) => {
                            error!("Background saver: final flush on shutdown failed: {e}");
                        }
                        Ok(()) => {
                            debug!("Background saver received shutdown; final flush complete.");
                        }
                    }
                    return;
                }

                if let Err(e) = flush_result {
                    consecutive_failures += 1;
                    if consecutive_failures >= MAX_CONSECUTIVE_FAILURES {
                        this.saver_halted.store(true, Ordering::Release);
                        error!(
                            "Background saver: {consecutive_failures} consecutive flush failures, \
                             halting to prevent silent data loss. Last error: {e}"
                        );
                        return;
                    }
                    error!(
                        "Background saver flush failed ({consecutive_failures}/{MAX_CONSECUTIVE_FAILURES}): {e}"
                    );
                } else {
                    consecutive_failures = 0;
                }
            }
        }))
    }
}

use super::commands::{DeviceCommand, apply_command_to_device};

impl PersistenceManager {
    pub async fn process_command(&self, command: DeviceCommand) {
        self.modify_device(|device| {
            apply_command_to_device(device, command);
        })
        .await;
    }
}

impl PersistenceManager {
    pub async fn get_sender_key_devices(
        &self,
        group_jid: &str,
    ) -> Result<Vec<(String, bool)>, StoreError> {
        self.backend
            .get_sender_key_devices(group_jid)
            .await
            .map_err(db_err)
    }

    pub async fn set_sender_key_status(
        &self,
        group_jid: &str,
        entries: &[(&str, bool)],
    ) -> Result<(), StoreError> {
        self.backend
            .set_sender_key_status(group_jid, entries)
            .await
            .map_err(db_err)
    }

    pub async fn clear_sender_key_devices(&self, group_jid: &str) -> Result<(), StoreError> {
        self.backend
            .clear_sender_key_devices(group_jid)
            .await
            .map_err(db_err)
    }
}
