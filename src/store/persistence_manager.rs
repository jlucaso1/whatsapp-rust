use super::error::{StoreError, db_err};
use crate::store::Device;
use crate::store::traits::Backend;
use log::{debug, error};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Notify, RwLock};
use tokio::time::{Duration, sleep};
use wacore_binary::jid::Jid;

pub struct PersistenceManager {
    device: Arc<RwLock<Device>>,
    backend: Arc<dyn Backend>,
    dirty: Arc<AtomicBool>,
    save_notify: Arc<Notify>,
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
            save_notify: Arc::new(Notify::new()),
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

    pub async fn modify_device<F, R>(&self, modifier: F) -> R
    where
        F: FnOnce(&mut Device) -> R,
    {
        let mut device_guard = self.device.write().await;
        let result = modifier(&mut device_guard);

        self.dirty.store(true, Ordering::Relaxed);
        self.save_notify.notify_one();

        result
    }

    async fn save_to_disk(&self) -> Result<(), StoreError> {
        if self.dirty.swap(false, Ordering::AcqRel) {
            debug!("Device state is dirty, saving to disk.");
            let device_guard = self.device.read().await;
            let serializable_device = device_guard.to_serializable();
            drop(device_guard);

            self.backend
                .save(&serializable_device)
                .await
                .map_err(db_err)?;
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

    pub fn run_background_saver(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = self.save_notify.notified() => {
                        debug!("Save notification received.");
                    }
                    _ = sleep(interval) => {}
                }

                if let Err(e) = self.save_to_disk().await {
                    error!("Error saving device state in background: {e}");
                }
            }
        });
        debug!("Background saver task started with interval {interval:?}");
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
    pub async fn get_skdm_recipients(&self, group_jid: &str) -> Result<Vec<Jid>, StoreError> {
        self.backend
            .get_skdm_recipients(group_jid)
            .await
            .map_err(db_err)
    }

    pub async fn add_skdm_recipients(
        &self,
        group_jid: &str,
        device_jids: &[Jid],
    ) -> Result<(), StoreError> {
        self.backend
            .add_skdm_recipients(group_jid, device_jids)
            .await
            .map_err(db_err)
    }

    pub async fn clear_skdm_recipients(&self, group_jid: &str) -> Result<(), StoreError> {
        self.backend
            .clear_skdm_recipients(group_jid)
            .await
            .map_err(db_err)
    }
}
