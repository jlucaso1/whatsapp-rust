use super::device_aware_store::DeviceAwareSqliteStore;
use super::error::StoreError;
use crate::store::Device;
use crate::store::sqlite_store::SqliteStore;
use crate::store::traits::Backend;
use log::{debug, error};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::time::{Duration, sleep};

pub enum StoreBackend {
    Sqlite(Arc<SqliteStore>),
}

impl StoreBackend {
    pub async fn save_device_data(
        &self,
        device_data: &wacore::store::Device,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(store) => store.save_device_data(device_data).await,
        }
    }

    pub async fn save_device_data_for_device(
        &self,
        device_id: i32,
        device_data: &wacore::store::Device,
    ) -> Result<(), StoreError> {
        match self {
            StoreBackend::Sqlite(store) => {
                store
                    .save_device_data_for_device(device_id, device_data)
                    .await
            }
        }
    }

    pub async fn load_device_data(&self) -> Result<Option<wacore::store::Device>, StoreError> {
        match self {
            StoreBackend::Sqlite(store) => store.load_device_data().await,
        }
    }

    pub fn as_backend(&self) -> Arc<dyn Backend> {
        match self {
            StoreBackend::Sqlite(store) => store.clone() as Arc<dyn Backend>,
        }
    }

    pub fn as_device_aware_backend(&self, device_id: i32) -> Arc<dyn Backend> {
        match self {
            StoreBackend::Sqlite(store) => {
                Arc::new(DeviceAwareSqliteStore::new(store.clone(), device_id)) as Arc<dyn Backend>
            }
        }
    }
}

pub struct PersistenceManager {
    device: Arc<RwLock<Device>>,
    backend: Option<StoreBackend>,
    dirty: Arc<Mutex<bool>>,
    save_notify: Arc<Notify>,
    device_id: Option<i32>, // None for backward compatibility, Some(id) for multi-account
}

impl PersistenceManager {
    /// Create a PersistenceManager for backward compatibility (loads first/only device)
    /// DEPRECATED: Use StoreManager::get_persistence_manager or create_new_device instead
    pub async fn new(database_url: &str) -> Result<Self, StoreError> {
        let sqlite_store = Arc::new(SqliteStore::new(database_url).await?);
        let backend = StoreBackend::Sqlite(sqlite_store);

        debug!("PersistenceManager: Attempting to load device data via SqliteStore.");
        let device_data_opt = backend.load_device_data().await?;

        let device = if let Some(serializable_device) = device_data_opt {
            debug!(
                "PersistenceManager: Loaded existing device data (PushName: '{}'). Initializing Device.",
                serializable_device.push_name
            );
            let mut dev = Device::new(backend.as_backend());
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            debug!("PersistenceManager: No existing device data found. Creating a new Device.");
            Device::new(backend.as_backend())
        };

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            backend: Some(backend),
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
            device_id: None, // Backward compatibility mode
        })
    }

    /// Create a PersistenceManager for a specific device ID (multi-account mode)
    pub async fn new_for_device(device_id: i32, backend: StoreBackend) -> Result<Self, StoreError> {
        debug!(
            "PersistenceManager: Loading device data for device ID {}",
            device_id
        );

        // Load device data for this specific device
        let device_data_opt = match &backend {
            StoreBackend::Sqlite(store) => store.load_device_data_for_device(device_id).await?,
        };

        let device = if let Some(serializable_device) = device_data_opt {
            debug!(
                "PersistenceManager: Loaded existing device data for device {} (PushName: '{}'). Initializing Device.",
                device_id, serializable_device.push_name
            );
            let mut dev = Device::new(backend.as_device_aware_backend(device_id));
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            // This shouldn't happen if the device was just created by StoreManager
            return Err(StoreError::DeviceNotFound(device_id));
        };

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            backend: Some(backend),
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
            device_id: Some(device_id),
        })
    }

    /// Get the device ID for this manager (if in multi-account mode)
    pub fn device_id(&self) -> i32 {
        self.device_id.unwrap_or(1) // Default to 1 for backward compatibility
    }

    /// Check if this manager is in multi-account mode
    pub fn is_multi_account(&self) -> bool {
        self.device_id.is_some()
    }

    pub async fn get_device_arc(&self) -> Arc<RwLock<Device>> {
        self.device.clone()
    }

    pub fn sqlite_store(&self) -> Option<Arc<SqliteStore>> {
        match &self.backend {
            Some(StoreBackend::Sqlite(s)) => Some(s.clone()),
            _ => None,
        }
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
        if self.backend.is_some() {
            let mut dirty_guard = self.dirty.lock().await;
            *dirty_guard = true;
            self.save_notify.notify_one();
        }
        result
    }

    async fn save_to_disk(&self) -> Result<(), StoreError> {
        if let Some(backend) = &self.backend {
            let mut dirty_guard = self.dirty.lock().await;
            if *dirty_guard {
                debug!("Device state is dirty, saving to disk.");
                let device_guard = self.device.read().await;
                let serializable_device = device_guard.to_serializable();
                drop(device_guard);

                // If this PersistenceManager is associated with a specific device_id,
                // use the device-aware save path to ensure we update the correct row.
                if let Some(device_id) = self.device_id {
                    backend
                        .save_device_data_for_device(device_id, &serializable_device)
                        .await?;
                } else {
                    backend.save_device_data(&serializable_device).await?;
                }
                *dirty_guard = false;
                debug!("Device state saved successfully.");
            }
        }
        Ok(())
    }

    pub fn run_background_saver(self: Arc<Self>, interval: Duration) {
        if self.backend.is_some() {
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
        } else {
            debug!("PersistenceManager is in-memory; background saver is disabled.");
        }
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
