use super::error::StoreError;
use crate::store::Device;
use crate::store::filestore::FileStore;
use crate::store::traits::Backend;
use log::{debug, error, info};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex, Notify};
use tokio::time::{Duration, sleep};

pub struct PersistenceManager {
    device: Arc<RwLock<Device>>,
    filestore: Option<Arc<FileStore>>,
    dirty: Arc<Mutex<bool>>,
    save_notify: Arc<Notify>,
}

impl PersistenceManager {
    pub async fn new(store_path: impl Into<std::path::PathBuf>) -> Result<Self, StoreError> {
        let filestore = Arc::new(FileStore::new(store_path).await.map_err(StoreError::Io)?);

        info!("PersistenceManager: Attempting to load device data via FileStore.");
        let device_data_opt = filestore.load_device_data().await?;

        let device = if let Some(serializable_device) = device_data_opt {
            info!(
                "PersistenceManager: Loaded existing device data (PushName: '{}'). Initializing Device.",
                serializable_device.push_name
            );
            let mut dev = Device::new(filestore.clone() as Arc<dyn Backend>);
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            info!("PersistenceManager: No existing device data found. Creating a new Device.");
            Device::new(filestore.clone() as Arc<dyn Backend>)
        };

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            filestore: Some(filestore),
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
        })
    }

    pub async fn new_in_memory() -> Result<Self, StoreError> {
        info!("PersistenceManager: Initializing in-memory store.");
        let memory_store = Arc::new(crate::store::memory::MemoryStore::new());
        let device = Device::new(memory_store as Arc<dyn Backend>);
        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            filestore: None,
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
        })
    }

    pub async fn get_device_arc(&self) -> Arc<RwLock<Device>> {
        self.device.clone()
    }

    pub async fn get_device_snapshot(&self) -> Device {
        self.device.read().await.clone()
    }

    pub async fn modify_device<F, R>(&self, modifier: F) -> R
    where
        F: FnOnce(&mut Device) -> R,
    {
        let mut device_guard = self.device.write().await;
        let result = modifier(&mut device_guard);
        if self.filestore.is_some() {
            let mut dirty_guard = self.dirty.lock().await;
            *dirty_guard = true;
            self.save_notify.notify_one();
        }
        result
    }

    async fn save_to_disk(&self) -> Result<(), StoreError> {
        if let Some(filestore) = &self.filestore {
            let mut dirty_guard = self.dirty.lock().await;
            if *dirty_guard {
                debug!("Device state is dirty, saving to disk.");
                let device_guard = self.device.read().await;
                let serializable_device = device_guard.to_serializable();
                drop(device_guard);

                filestore.save_device_data(&serializable_device).await?;
                *dirty_guard = false;
                debug!("Device state saved successfully.");
            }
        }
        Ok(())
    }

    pub fn run_background_saver(self: Arc<Self>, interval: Duration) {
        if self.filestore.is_some() {
            tokio::task::spawn_local(async move {
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
            info!("Background saver task started with interval {interval:?}");
        } else {
            info!("PersistenceManager is in-memory; background saver is disabled.");
        }
    }
}

use super::commands::{DeviceCommand, apply_command_to_device};

impl PersistenceManager {
    pub async fn process_command(&self, command: DeviceCommand) {
        debug!("Processing command: {command:?}");
        self.modify_device(|device| {
            apply_command_to_device(device, command);
        })
        .await;
    }

    pub async fn save_now(&self) -> Result<(), StoreError> {
        if let Some(filestore) = &self.filestore {
            debug!("PersistenceManager: Forcing save_now.");
            let device_guard = self.device.read().await;
            let serializable_device = device_guard.to_serializable();
            drop(device_guard);

            match filestore.save_device_data(&serializable_device).await {
                Ok(_) => {
                    let mut dirty_guard = self.dirty.lock().await;
                    *dirty_guard = false;
                    debug!("PersistenceManager: Forced save_now successful.");
                    Ok(())
                }
                Err(e) => {
                    error!("PersistenceManager: Forced save_now failed: {e}");
                    Err(e)
                }
            }
        } else {
            debug!("PersistenceManager: save_now called on in-memory store, no action taken.");
            Ok(())
        }
    }
}
