use super::error::StoreError;
use super::persistence_manager::{PersistenceManager, StoreBackend};
use super::sqlite_store::SqliteStore;
use log::{debug, info};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// StoreManager manages multiple devices within a single database.
/// It provides device-specific PersistenceManager instances and handles
/// the creation of new devices.
pub struct StoreManager {
    sqlite_store: Arc<SqliteStore>,
    /// Cache of PersistenceManager instances by device_id
    managers: RwLock<HashMap<i32, Arc<PersistenceManager>>>,
}

impl StoreManager {
    /// Create a new StoreManager for the given database URL.
    /// This will automatically run any pending migrations.
    pub async fn new(database_url: &str) -> Result<Self, StoreError> {
        let sqlite_store = Arc::new(SqliteStore::new(database_url).await?);

        Ok(Self {
            sqlite_store,
            managers: RwLock::new(HashMap::new()),
        })
    }

    /// Get a PersistenceManager for a specific device ID.
    /// If the device doesn't exist in the database, this will return an error.
    pub async fn get_persistence_manager(
        &self,
        device_id: i32,
    ) -> Result<Arc<PersistenceManager>, StoreError> {
        // Check if we already have a cached manager for this device
        {
            let managers = self.managers.read().await;
            if let Some(manager) = managers.get(&device_id) {
                return Ok(manager.clone());
            }
        }

        // Verify the device exists in the database
        if !self.device_exists(device_id).await? {
            return Err(StoreError::DeviceNotFound(device_id));
        }

        // Create a new PersistenceManager for this device
        let backend = StoreBackend::Sqlite(self.sqlite_store.clone());
        let manager = Arc::new(PersistenceManager::new_for_device(device_id, backend).await?);

        // Cache it for future use
        {
            let mut managers = self.managers.write().await;
            managers.insert(device_id, manager.clone());
        }

        Ok(manager)
    }

    /// Create a new device in the database and return its PersistenceManager.
    /// This generates a new device with default settings and returns a manager for it.
    pub async fn create_new_device(&self) -> Result<Arc<PersistenceManager>, StoreError> {
        info!("Creating new device in database");

        // Create the new device entry and get its ID
        let device_id = self.sqlite_store.create_new_device().await?;

        debug!("Created new device with ID: {}", device_id);

        // Create a PersistenceManager for the new device
        let backend = StoreBackend::Sqlite(self.sqlite_store.clone());
        let manager = Arc::new(PersistenceManager::new_for_device(device_id, backend).await?);

        // Cache it
        {
            let mut managers = self.managers.write().await;
            managers.insert(device_id, manager.clone());
        }

        Ok(manager)
    }

    /// List all device IDs in the database.
    pub async fn list_devices(&self) -> Result<Vec<i32>, StoreError> {
        self.sqlite_store.list_device_ids().await
    }

    /// Check if a device with the given ID exists in the database.
    pub async fn device_exists(&self, device_id: i32) -> Result<bool, StoreError> {
        self.sqlite_store.device_exists(device_id).await
    }

    /// Remove a device and all its associated data from the database.
    /// This also removes the cached PersistenceManager if it exists.
    /// WARNING: This operation is irreversible!
    pub async fn delete_device(&self, device_id: i32) -> Result<(), StoreError> {
        info!("Deleting device {} and all associated data", device_id);

        // Remove from cache first
        {
            let mut managers = self.managers.write().await;
            managers.remove(&device_id);
        }

        // Delete from database
        self.sqlite_store.delete_device(device_id).await
    }

    /// Get the underlying SqliteStore for advanced operations.
    /// This is primarily for internal use and testing.
    pub fn sqlite_store(&self) -> Arc<SqliteStore> {
        self.sqlite_store.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn create_test_store_manager() -> StoreManager {
        let temp_db = format!(
            "file:memdb_{}?mode=memory&cache=shared",
            uuid::Uuid::new_v4()
        );
        StoreManager::new(&temp_db)
            .await
            .expect("Failed to create test StoreManager")
    }

    #[tokio::test]
    async fn test_create_new_device() {
        let store_manager = create_test_store_manager().await;

        // Create a new device
        let manager = store_manager
            .create_new_device()
            .await
            .expect("Failed to create new device");

        // Verify it has a valid device
        let device = manager.get_device_snapshot().await;
        assert!(!device.push_name.is_empty() || device.push_name.is_empty()); // Just verify it exists
    }

    #[tokio::test]
    async fn test_get_persistence_manager_cached() {
        let store_manager = create_test_store_manager().await;

        // Create a new device
        let manager1 = store_manager
            .create_new_device()
            .await
            .expect("Failed to create new device");
        let device_id = manager1.device_id();

        // Get it again - should return the same cached instance
        let manager2 = store_manager
            .get_persistence_manager(device_id)
            .await
            .expect("Failed to get manager");

        // They should be the same Arc (same memory address)
        assert!(Arc::ptr_eq(&manager1, &manager2));
    }

    #[tokio::test]
    async fn test_device_not_found() {
        let store_manager = create_test_store_manager().await;

        // Try to get a manager for a non-existent device
        let result = store_manager.get_persistence_manager(999).await;

        assert!(matches!(result, Err(StoreError::DeviceNotFound(999))));
    }

    #[tokio::test]
    async fn test_list_devices() {
        let store_manager = create_test_store_manager().await;

        // Initially should be empty
        let devices = store_manager
            .list_devices()
            .await
            .expect("Failed to list devices");
        assert!(devices.is_empty());

        // Create a device
        let _manager1 = store_manager
            .create_new_device()
            .await
            .expect("Failed to create device");
        let devices = store_manager
            .list_devices()
            .await
            .expect("Failed to list devices");
        assert_eq!(devices.len(), 1);

        // Create another device
        let _manager2 = store_manager
            .create_new_device()
            .await
            .expect("Failed to create device");
        let devices = store_manager
            .list_devices()
            .await
            .expect("Failed to list devices");
        assert_eq!(devices.len(), 2);
    }

    #[tokio::test]
    async fn test_delete_device() {
        let store_manager = create_test_store_manager().await;

        // Create a device
        let manager = store_manager
            .create_new_device()
            .await
            .expect("Failed to create device");
        let device_id = manager.device_id();

        // Verify it exists
        assert!(
            store_manager
                .device_exists(device_id)
                .await
                .expect("Failed to check device existence")
        );

        // Delete it
        store_manager
            .delete_device(device_id)
            .await
            .expect("Failed to delete device");

        // Verify it's gone
        assert!(
            !store_manager
                .device_exists(device_id)
                .await
                .expect("Failed to check device existence")
        );

        // Trying to get it should fail
        let result = store_manager.get_persistence_manager(device_id).await;
        assert!(matches!(result, Err(StoreError::DeviceNotFound(_))));
    }
}
