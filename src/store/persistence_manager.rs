use super::error::StoreError;
use crate::store::Device;
use crate::store::traits::Backend;
use log::{debug, error};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Notify, RwLock};
use tokio::time::{Duration, sleep};

pub struct PersistenceManager {
    device: Arc<RwLock<Device>>,
    backend: Arc<dyn Backend>,
    dirty: Arc<AtomicBool>,
    save_notify: Arc<Notify>,
    device_id: Option<i32>, // None for single device mode, Some(id) for multi-account
}

impl PersistenceManager {
    /// Create a PersistenceManager with a backend implementation (single device mode)
    pub async fn new(backend: Arc<dyn Backend>) -> Result<Self, StoreError> {
        debug!("PersistenceManager: Ensuring device row exists (single-device mode).");
        // Ensure a device row with id=1 exists; create it if not.
        let exists = backend
            .device_exists(1)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;
        if !exists {
            debug!("PersistenceManager: No device row found. Creating new device row.");
            let id = backend
                .create_new_device()
                .await
                .map_err(|e| StoreError::Database(e.to_string()))?;
            debug!("PersistenceManager: Created device row with id={id}.");
        }

        debug!("PersistenceManager: Attempting to load device data via Backend.");
        let device_data_opt = backend
            .load_device_data()
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

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
            device_id: None, // Single device mode
        })
    }

    /// Create a PersistenceManager for a specific device ID (multi-account mode)
    pub async fn new_for_device(
        device_id: i32,
        backend: Arc<dyn Backend>,
    ) -> Result<Self, StoreError> {
        debug!(
            "PersistenceManager: Loading device data for device ID {}",
            device_id
        );

        // Load device data for this specific device
        let device_data_opt = backend
            .load_device_data_for_device(device_id)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))?;

        let device = if let Some(serializable_device) = device_data_opt {
            debug!(
                "PersistenceManager: Loaded existing device data for device {} (PushName: '{}'). Initializing Device.",
                device_id, serializable_device.push_name
            );
            let mut dev = Device::new(backend.clone());
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            // This shouldn't happen if the device was just created by StoreManager
            return Err(StoreError::DeviceNotFound(device_id));
        };

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            backend,
            dirty: Arc::new(AtomicBool::new(false)),
            save_notify: Arc::new(Notify::new()),
            device_id: Some(device_id),
        })
    }

    /// Get the device ID for this manager (if in multi-account mode)
    pub fn device_id(&self) -> i32 {
        self.device_id.unwrap_or(1) // Default to 1 for single device mode
    }

    /// Check if this manager is in multi-account mode
    pub fn is_multi_account(&self) -> bool {
        self.device_id.is_some()
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

            // If this PersistenceManager is associated with a specific device_id,
            // use the device-aware save path to ensure we update the correct row.
            if let Some(device_id) = self.device_id {
                self.backend
                    .save_device_data_for_device(device_id, &serializable_device)
                    .await
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            } else {
                self.backend
                    .save_device_data(&serializable_device)
                    .await
                    .map_err(|e| StoreError::Database(e.to_string()))?;
            }
            debug!("Device state saved successfully.");
        }
        Ok(())
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

// SKDM recipient tracking methods
impl PersistenceManager {
    /// Get the list of device JIDs that have already received SKDM for a group
    pub async fn get_skdm_recipients(&self, group_jid: &str) -> Result<Vec<String>, StoreError> {
        self.backend
            .get_skdm_recipients(group_jid)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    /// Mark devices as having received SKDM for a group
    pub async fn add_skdm_recipients(
        &self,
        group_jid: &str,
        device_jids: &[String],
    ) -> Result<(), StoreError> {
        self.backend
            .add_skdm_recipients(group_jid, device_jids)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }

    /// Clear all SKDM recipients for a group (used when sender key is rotated)
    pub async fn clear_skdm_recipients(&self, group_jid: &str) -> Result<(), StoreError> {
        self.backend
            .clear_skdm_recipients(group_jid)
            .await
            .map_err(|e| StoreError::Database(e.to_string()))
    }
}
