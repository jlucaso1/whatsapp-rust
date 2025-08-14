use std::sync::Arc;
use whatsapp_rust::store::persistence_manager::PersistenceManager;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use whatsapp_rust::store::traits::*;

#[tokio::test]
async fn test_sqlite_store_basic_operations() {
    // Test basic SQLite store operations
    let db_path = "/tmp/test_whatsapp.db";

    // Clean up any existing test database
    let _ = std::fs::remove_file(db_path);

    // Create a SQLite store
    let store = SqliteStore::new(db_path)
        .await
        .expect("Failed to create SqliteStore");

    // Test identity store operations
    let address = "test@example.com";
    let key = [1u8; 32];

    // Put identity
    store
        .put_identity(address, key)
        .await
        .expect("Failed to put identity");

    // Load identity
    let loaded_identity = store
        .load_identity(address)
        .await
        .expect("Failed to load identity");
    assert!(loaded_identity.is_some());
    assert_eq!(loaded_identity.unwrap(), key.to_vec());

    // Test session store operations
    let session_data = vec![1, 2, 3, 4, 5];
    store
        .put_session(address, &session_data)
        .await
        .expect("Failed to put session");

    let loaded_session = store
        .get_session(address)
        .await
        .expect("Failed to get session");
    assert!(loaded_session.is_some());
    assert_eq!(loaded_session.unwrap(), session_data);

    // Test has_session
    let has_session = store
        .has_session(address)
        .await
        .expect("Failed to check has_session");
    assert!(has_session);

    // Test sender key operations
    let sender_key_data = vec![6, 7, 8, 9, 10];
    store
        .put_sender_key(address, &sender_key_data)
        .await
        .expect("Failed to put sender key");

    let loaded_sender_key = store
        .get_sender_key(address)
        .await
        .expect("Failed to get sender key");
    assert!(loaded_sender_key.is_some());
    assert_eq!(loaded_sender_key.unwrap(), sender_key_data);

    // Test app state key operations
    let key_id = vec![11, 12, 13, 14];
    let app_state_key = AppStateSyncKey {
        key_data: vec![15, 16, 17, 18],
        fingerprint: vec![19, 20, 21, 22],
        timestamp: 1234567890,
    };

    store
        .set_app_state_sync_key(&key_id, app_state_key.clone())
        .await
        .expect("Failed to set app state key");

    let loaded_app_state_key = store
        .get_app_state_sync_key(&key_id)
        .await
        .expect("Failed to get app state key");
    assert!(loaded_app_state_key.is_some());
    let loaded_key = loaded_app_state_key.unwrap();
    assert_eq!(loaded_key.key_data, app_state_key.key_data);
    assert_eq!(loaded_key.fingerprint, app_state_key.fingerprint);
    assert_eq!(loaded_key.timestamp, app_state_key.timestamp);

    // Clean up
    let _ = std::fs::remove_file(db_path);
}

#[tokio::test]
async fn test_persistence_manager_with_sqlite() {
    // Test PersistenceManager using SQLite backend
    let db_path = "/tmp/test_pm_whatsapp.db";

    // Clean up any existing test database
    let _ = std::fs::remove_file(db_path);

    // Create PersistenceManager with SQLite backend
    let pm = Arc::new(
        PersistenceManager::new_sqlite(db_path)
            .await
            .expect("Failed to create PersistenceManager with SQLite"),
    );

    // Test that we can get device snapshot without errors
    let device = pm.get_device_snapshot().await;
    // Default device starts with empty push name
    assert_eq!(device.push_name, String::new());

    // Test device modification
    let new_push_name = "Test SQLite Device".to_string();
    pm.modify_device(|device| {
        device.push_name = new_push_name.clone();
    })
    .await;

    // Verify the change
    let device = pm.get_device_snapshot().await;
    assert_eq!(device.push_name, new_push_name);

    // Force save and verify persistence
    pm.save_now().await.expect("Failed to save device data");

    // Create a new PersistenceManager and verify data persisted
    let pm2 = Arc::new(
        PersistenceManager::new_sqlite(db_path)
            .await
            .expect("Failed to create second PersistenceManager"),
    );
    let device2 = pm2.get_device_snapshot().await;
    assert_eq!(device2.push_name, new_push_name);

    // Clean up
    let _ = std::fs::remove_file(db_path);
}

#[tokio::test]
async fn test_sqlite_store_vs_memory_store() {
    // Compare SQLite store with in-memory store to ensure same interface
    let db_path = "/tmp/test_comparison_whatsapp.db";

    // Clean up any existing test database
    let _ = std::fs::remove_file(db_path);

    // Test with SQLite backend using in-memory database for testing
    let pm_sqlite = Arc::new(
        PersistenceManager::new_sqlite(":memory:")
            .await
            .expect("Failed to create SQLite PM"),
    );

    // Test with in-memory backend
    let pm_memory = Arc::new(
        PersistenceManager::new_in_memory()
            .await
            .expect("Failed to create memory PM"),
    );

    // Both should support the same operations
    let test_push_name = "Test Device".to_string();

    pm_sqlite
        .modify_device(|device| {
            device.push_name = test_push_name.clone();
        })
        .await;

    pm_memory
        .modify_device(|device| {
            device.push_name = test_push_name.clone();
        })
        .await;

    // Both should return the same value
    let device_sqlite = pm_sqlite.get_device_snapshot().await;
    let device_memory = pm_memory.get_device_snapshot().await;

    assert_eq!(device_sqlite.push_name, device_memory.push_name);

    // Clean up
    let _ = std::fs::remove_file(db_path);
}
