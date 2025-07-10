use super::error::StoreError;
use crate::store::filestore::FileStore;
use crate::store::traits::Backend;
use crate::store::Device; // Removed SerializableDevice
use log::{error, info}; // Removed warn
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};
use tokio::time::{sleep, Duration}; // Assuming StoreError is pub in store/error.rs

pub struct PersistenceManager {
    device: Arc<Mutex<Device>>,
    filestore: Arc<FileStore>,
    dirty: Arc<Mutex<bool>>,
    save_notify: Arc<Notify>,
}

impl PersistenceManager {
    pub async fn new(store_path: impl Into<std::path::PathBuf>) -> Result<Self, StoreError> {
        let filestore = Arc::new(FileStore::new(store_path).await.map_err(StoreError::Io)?);

        info!("PersistenceManager: Attempting to load device data via FileStore.");
        let device_data_opt = filestore.load_device_data().await?;

        let device = if let Some(serializable_device) = device_data_opt {
            info!("PersistenceManager: Loaded existing device data (PushName: '{}'). Initializing Device.", serializable_device.push_name);
            let mut dev = Device::new(filestore.clone() as Arc<dyn Backend>);
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            info!("PersistenceManager: No existing device data found. Creating a new Device.");
            Device::new(filestore.clone() as Arc<dyn Backend>)
        };

        Ok(Self {
            device: Arc::new(Mutex::new(device)),
            filestore,
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
        })
    }

    pub async fn get_device_arc(&self) -> Arc<Mutex<Device>> {
        self.device.clone()
    }

    // Provides locked access to the device for reading.
    // The returned guard allows multiple reads simultaneously if needed,
    // but for simplicity, we'll keep it as a direct owned Device clone for now
    // if the full device state is small enough and cloning is not too expensive.
    // For more complex scenarios, returning a guard or specific fields would be better.
    pub async fn get_device_snapshot(&self) -> Device {
        self.device.lock().await.clone() // Clone the current state
    }

    // Modifies the device using a closure.
    // The closure receives a mutable reference to the Device.
    pub async fn modify_device<F, R>(&self, modifier: F) -> R
    where
        F: FnOnce(&mut Device) -> R,
    {
        let mut device_guard = self.device.lock().await;
        let result = modifier(&mut device_guard);
        let mut dirty_guard = self.dirty.lock().await;
        *dirty_guard = true;
        self.save_notify.notify_one(); // Notify the saver task that there's something to save
        result
    }

    // Saves the device state to disk if it's dirty.
    async fn save_to_disk(&self) -> Result<(), StoreError> {
        let mut dirty_guard = self.dirty.lock().await;
        if *dirty_guard {
            info!("Device state is dirty, saving to disk.");
            let device_guard = self.device.lock().await;
            let serializable_device = device_guard.to_serializable();
            drop(device_guard); // Release lock on device before I/O

            self.filestore
                .save_device_data(&serializable_device)
                .await?;
            *dirty_guard = false;
            info!("Device state saved successfully.");
        }
        Ok(())
    }

    // Runs a background task that periodically saves the device state.
    pub fn run_background_saver(self: Arc<Self>, interval: Duration) {
        tokio::spawn(async move {
            loop {
                // Wait for either a notification or the interval to pass
                tokio::select! {
                    _ = self.save_notify.notified() => {
                        info!("Save notification received.");
                    }
                    _ = sleep(interval) => {
                        // Interval elapsed, proceed to check dirty flag
                    }
                }

                // Attempt to save, but don't let save errors crash the loop
                if let Err(e) = self.save_to_disk().await {
                    error!("Error saving device state in background: {}", e);
                }
            }
        });
        info!("Background saver task started with interval {:?}", interval);
    }

    // Graceful shutdown for the saver (optional, depending on requirements)
    // This might involve signaling the background task to stop and waiting for it.
    // For simplicity, we'll omit this unless specifically requested.
}

use super::commands::{apply_command_to_device, DeviceCommand};

impl PersistenceManager {
    pub async fn process_command(&self, command: DeviceCommand) {
        info!("Processing command: {:?}", command);
        self.modify_device(|device| {
            apply_command_to_device(device, command);
        })
        .await;
    }

    // Method to force save, useful for testing.
    pub async fn save_now(&self) -> Result<(), StoreError> {
        info!("PersistenceManager: Forcing save_now.");
        let device_guard = self.device.lock().await;
        let serializable_device = device_guard.to_serializable();
        drop(device_guard);

        match self.filestore.save_device_data(&serializable_device).await {
            Ok(_) => {
                let mut dirty_guard = self.dirty.lock().await;
                *dirty_guard = false; // Reset dirty flag after forced save
                info!("PersistenceManager: Forced save_now successful.");
                Ok(())
            }
            Err(e) => {
                error!("PersistenceManager: Forced save_now failed: {}", e);
                Err(e)
            }
        }
    }
}
