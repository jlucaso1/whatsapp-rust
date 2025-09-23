use super::device_aware_store::DeviceAwareSqliteStore;
use super::error::StoreError;
use crate::store::Device;
use crate::store::sqlite_store::SqliteStore;
use crate::store::traits::Backend;
use async_trait::async_trait;
use log::{debug, error};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify, RwLock};
use tokio::time::{Duration, sleep};

/// Trait for persisting device data. This is separate from the Backend trait
/// to maintain compatibility while allowing storage backends to handle device persistence.
#[async_trait]
pub trait DevicePersistence: Send + Sync {
    /// Save device data (backward compatibility mode)
    async fn save_device_data(&self, device_data: &wacore::store::Device)
    -> Result<(), StoreError>;

    /// Save device data for a specific device ID (multi-account mode)
    async fn save_device_data_for_device(
        &self,
        device_id: i32,
        device_data: &wacore::store::Device,
    ) -> Result<(), StoreError>;

    /// Load device data (backward compatibility mode)
    async fn load_device_data(&self) -> Result<Option<wacore::store::Device>, StoreError>;

    /// Load device data for a specific device ID (multi-account mode)
    async fn load_device_data_for_device(
        &self,
        device_id: i32,
    ) -> Result<Option<wacore::store::Device>, StoreError>;

    /// Allow downcasting to concrete types for backward compatibility
    fn as_any(&self) -> &dyn std::any::Any;
}

/// Implementation of DevicePersistence for SqliteStore
#[async_trait]
impl DevicePersistence for SqliteStore {
    async fn save_device_data(
        &self,
        device_data: &wacore::store::Device,
    ) -> Result<(), StoreError> {
        self.save_device_data(device_data).await
    }

    async fn save_device_data_for_device(
        &self,
        device_id: i32,
        device_data: &wacore::store::Device,
    ) -> Result<(), StoreError> {
        self.save_device_data_for_device(device_id, device_data)
            .await
    }

    async fn load_device_data(&self) -> Result<Option<wacore::store::Device>, StoreError> {
        self.load_device_data().await
    }

    async fn load_device_data_for_device(
        &self,
        device_id: i32,
    ) -> Result<Option<wacore::store::Device>, StoreError> {
        self.load_device_data_for_device(device_id).await
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

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
    backend: Option<Arc<dyn Backend>>,
    device_persistence: Option<Arc<dyn DevicePersistence>>,
    // Keep a reference to SqliteStore for backward compatibility
    sqlite_store_ref: Option<Arc<SqliteStore>>,
    dirty: Arc<Mutex<bool>>,
    save_notify: Arc<Notify>,
    device_id: Option<i32>, // None for backward compatibility, Some(id) for multi-account
}

impl PersistenceManager {
    /// Create a PersistenceManager from a backend and device persistence implementation
    /// This is the new generic way to create a PersistenceManager
    pub async fn new_with_backend(
        backend: Arc<dyn Backend>,
        device_persistence: Arc<dyn DevicePersistence>,
    ) -> Result<Self, StoreError> {
        debug!("PersistenceManager: Attempting to load device data via DevicePersistence.");
        let device_data_opt = device_persistence.load_device_data().await?;

        let device = if let Some(serializable_device) = device_data_opt {
            debug!(
                "PersistenceManager: Loaded existing device data (PushName: '{}'). Initializing Device.",
                serializable_device.push_name
            );
            let mut dev = Device::new(backend.clone());
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            debug!("PersistenceManager: No existing device data found. Creating a new Device.");
            Device::new(backend.clone())
        };

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            backend: Some(backend),
            device_persistence: Some(device_persistence),
            sqlite_store_ref: None, // No SqliteStore reference for generic backends
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
            device_id: None, // Backward compatibility mode
        })
    }

    /// Create a PersistenceManager with a SqliteStore
    /// This is a convenience method that maintains the SqliteStore reference
    pub async fn new_with_sqlite_store(sqlite_store: Arc<SqliteStore>) -> Result<Self, StoreError> {
        let backend = sqlite_store.clone() as Arc<dyn Backend>;
        let device_persistence = sqlite_store.clone() as Arc<dyn DevicePersistence>;

        debug!("PersistenceManager: Attempting to load device data via SqliteStore.");
        let device_data_opt = device_persistence.load_device_data().await?;

        let device = if let Some(serializable_device) = device_data_opt {
            debug!(
                "PersistenceManager: Loaded existing device data (PushName: '{}'). Initializing Device.",
                serializable_device.push_name
            );
            let mut dev = Device::new(backend.clone());
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            debug!("PersistenceManager: No existing device data found. Creating a new Device.");
            Device::new(backend.clone())
        };

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            backend: Some(backend),
            device_persistence: Some(device_persistence),
            sqlite_store_ref: Some(sqlite_store),
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
            device_id: None, // Backward compatibility mode
        })
    }

    /// Create a PersistenceManager for a specific device ID using generic backend
    /// This is the new generic way for multi-account mode
    pub async fn new_for_device_with_backend(
        device_id: i32,
        backend: Arc<dyn Backend>,
        device_persistence: Arc<dyn DevicePersistence>,
    ) -> Result<Self, StoreError> {
        debug!(
            "PersistenceManager: Loading device data for device ID {}",
            device_id
        );

        // Load device data for this specific device
        let device_data_opt = device_persistence
            .load_device_data_for_device(device_id)
            .await?;

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
            backend: Some(backend),
            device_persistence: Some(device_persistence),
            sqlite_store_ref: None, // No SqliteStore reference for generic backends
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
            device_id: Some(device_id),
        })
    }

    /// Create a PersistenceManager for a specific device ID with SqliteStore
    /// This is a convenience method for multi-account mode that maintains the SqliteStore reference
    pub async fn new_for_device_with_sqlite_store(
        device_id: i32,
        sqlite_store: Arc<SqliteStore>,
    ) -> Result<Self, StoreError> {
        debug!(
            "PersistenceManager: Loading device data for device ID {}",
            device_id
        );

        let device_persistence = sqlite_store.clone() as Arc<dyn DevicePersistence>;
        // Load device data for this specific device
        let device_data_opt = device_persistence
            .load_device_data_for_device(device_id)
            .await?;

        let device = if let Some(serializable_device) = device_data_opt {
            debug!(
                "PersistenceManager: Loaded existing device data for device {} (PushName: '{}'). Initializing Device.",
                device_id, serializable_device.push_name
            );
            // Create device-aware backend
            let backend = Arc::new(DeviceAwareSqliteStore::new(sqlite_store.clone(), device_id))
                as Arc<dyn Backend>;
            let mut dev = Device::new(backend);
            dev.load_from_serializable(serializable_device);
            dev
        } else {
            // This shouldn't happen if the device was just created by StoreManager
            return Err(StoreError::DeviceNotFound(device_id));
        };

        // Create device-aware backend for the struct
        let backend = Arc::new(DeviceAwareSqliteStore::new(sqlite_store.clone(), device_id))
            as Arc<dyn Backend>;

        Ok(Self {
            device: Arc::new(RwLock::new(device)),
            backend: Some(backend),
            device_persistence: Some(device_persistence),
            sqlite_store_ref: Some(sqlite_store),
            dirty: Arc::new(Mutex::new(false)),
            save_notify: Arc::new(Notify::new()),
            device_id: Some(device_id),
        })
    }

    /// Create a PersistenceManager for backward compatibility (loads first/only device)
    /// DEPRECATED: Use new_with_backend or StoreManager::get_persistence_manager instead
    pub async fn new(database_url: &str) -> Result<Self, StoreError> {
        let sqlite_store = Arc::new(SqliteStore::new(database_url).await?);
        Self::new_with_sqlite_store(sqlite_store).await
    }

    /// Create a PersistenceManager for a specific device ID (multi-account mode)
    /// DEPRECATED: Use new_for_device_with_backend for new implementations
    pub async fn new_for_device(device_id: i32, backend: StoreBackend) -> Result<Self, StoreError> {
        // Extract the underlying SqliteStore
        let sqlite_store = match backend {
            StoreBackend::Sqlite(store) => store,
        };

        Self::new_for_device_with_sqlite_store(device_id, sqlite_store).await
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
        self.sqlite_store_ref.clone()
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
        if let Some(device_persistence) = &self.device_persistence {
            let mut dirty_guard = self.dirty.lock().await;
            if *dirty_guard {
                debug!("Device state is dirty, saving to disk.");
                let device_guard = self.device.read().await;
                let serializable_device = device_guard.to_serializable();
                drop(device_guard);

                // If this PersistenceManager is associated with a specific device_id,
                // use the device-aware save path to ensure we update the correct row.
                if let Some(device_id) = self.device_id {
                    device_persistence
                        .save_device_data_for_device(device_id, &serializable_device)
                        .await?;
                } else {
                    device_persistence
                        .save_device_data(&serializable_device)
                        .await?;
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
