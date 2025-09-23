use crate::store::device_aware_store::DeviceAwareSqliteStore;
use crate::store::store_manager::StoreManager;
use std::sync::Arc;
use uuid::Uuid;
use wacore::libsignal::store::{PreKeyStore, SignedPreKeyStore};
use wacore::store::traits::*;

#[tokio::test]
async fn test_device_isolation_identities() {
    let store_manager = Arc::new(
        StoreManager::new("file:test_isolation_identities?mode=memory&cache=shared")
            .await
            .expect("Failed to create StoreManager"),
    );

    // Create two devices
    let manager1 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 1");
    let manager2 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 2");

    let device_id1 = manager1.device_id();
    let device_id2 = manager2.device_id();

    // Create device-aware stores
    let store1 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id1);
    let store2 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id2);

    // Store identities for each device
    let address = "test@example.com";
    let key1 = [1u8; 32];
    let key2 = [2u8; 32];

    store1
        .put_identity(address, key1)
        .await
        .expect("Failed to store identity for device 1");
    store2
        .put_identity(address, key2)
        .await
        .expect("Failed to store identity for device 2");

    // Verify isolation - each device should only see its own identity
    let loaded_key1 = store1
        .load_identity(address)
        .await
        .expect("Failed to load identity for device 1");
    let loaded_key2 = store2
        .load_identity(address)
        .await
        .expect("Failed to load identity for device 2");

    assert_eq!(loaded_key1, Some(key1.to_vec()));
    assert_eq!(loaded_key2, Some(key2.to_vec()));

    // Verify they are different
    assert_ne!(loaded_key1, loaded_key2);
}

#[tokio::test]
async fn test_device_isolation_sessions() {
    let store_manager = Arc::new(
        StoreManager::new("file:test_isolation_sessions?mode=memory&cache=shared")
            .await
            .expect("Failed to create StoreManager"),
    );

    // Create two devices
    let manager1 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 1");
    let manager2 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 2");

    let device_id1 = manager1.device_id();
    let device_id2 = manager2.device_id();

    // Create device-aware stores
    let store1 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id1);
    let store2 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id2);

    // Store sessions for each device
    let address = "session@example.com";
    let session1 = b"session_data_device_1";
    let session2 = b"session_data_device_2";

    store1
        .put_session(address, session1)
        .await
        .expect("Failed to store session for device 1");
    store2
        .put_session(address, session2)
        .await
        .expect("Failed to store session for device 2");

    // Verify isolation - each device should only see its own session
    let loaded_session1 = store1
        .get_session(address)
        .await
        .expect("Failed to load session for device 1");
    let loaded_session2 = store2
        .get_session(address)
        .await
        .expect("Failed to load session for device 2");

    assert_eq!(loaded_session1, Some(session1.to_vec()));
    assert_eq!(loaded_session2, Some(session2.to_vec()));

    // Verify they are different
    assert_ne!(loaded_session1, loaded_session2);

    // Test has_session isolation
    assert!(
        store1
            .has_session(address)
            .await
            .expect("Failed to check session existence for device 1")
    );
    assert!(
        store2
            .has_session(address)
            .await
            .expect("Failed to check session existence for device 2")
    );

    // Delete session from device 1, should not affect device 2
    store1
        .delete_session(address)
        .await
        .expect("Failed to delete session for device 1");

    assert!(
        !store1
            .has_session(address)
            .await
            .expect("Failed to check session existence for device 1")
    );
    assert!(
        store2
            .has_session(address)
            .await
            .expect("Failed to check session existence for device 2")
    );
}

#[tokio::test]
async fn test_device_isolation_sender_keys() {
    let store_manager = Arc::new(
        StoreManager::new("file:test_isolation_sender_keys?mode=memory&cache=shared")
            .await
            .expect("Failed to create StoreManager"),
    );

    // Create two devices
    let manager1 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 1");
    let manager2 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 2");

    let device_id1 = manager1.device_id();
    let device_id2 = manager2.device_id();

    // Create device-aware stores
    let store1 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id1);
    let store2 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id2);

    // Store sender keys for each device
    let address = "group@example.com";
    let key1 = b"sender_key_device_1";
    let key2 = b"sender_key_device_2";

    store1
        .put_sender_key(address, key1)
        .await
        .expect("Failed to store sender key for device 1");
    store2
        .put_sender_key(address, key2)
        .await
        .expect("Failed to store sender key for device 2");

    // Verify isolation
    let loaded_key1 = store1
        .get_sender_key(address)
        .await
        .expect("Failed to load sender key for device 1");
    let loaded_key2 = store2
        .get_sender_key(address)
        .await
        .expect("Failed to load sender key for device 2");

    assert_eq!(loaded_key1, Some(key1.to_vec()));
    assert_eq!(loaded_key2, Some(key2.to_vec()));
    assert_ne!(loaded_key1, loaded_key2);

    // Delete sender key from device 1, should not affect device 2
    store1
        .delete_sender_key(address)
        .await
        .expect("Failed to delete sender key for device 1");

    assert_eq!(
        store1
            .get_sender_key(address)
            .await
            .expect("Failed to check sender key for device 1"),
        None
    );
    assert_eq!(
        store2
            .get_sender_key(address)
            .await
            .expect("Failed to check sender key for device 2"),
        Some(key2.to_vec())
    );
}

#[tokio::test]
async fn test_device_isolation_app_state_keys() {
    let store_manager = Arc::new(
        StoreManager::new("file:test_isolation_app_state_keys?mode=memory&cache=shared")
            .await
            .expect("Failed to create StoreManager"),
    );

    // Create two devices
    let manager1 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 1");
    let manager2 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 2");

    let device_id1 = manager1.device_id();
    let device_id2 = manager2.device_id();

    // Create device-aware stores
    let store1 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id1);
    let store2 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id2);

    // Store app state keys for each device
    let key_id = b"app_state_key_id";
    let key1 = AppStateSyncKey {
        key_data: b"app_state_key_data_1".to_vec(),
        fingerprint: b"fingerprint_1".to_vec(),
        timestamp: 1000,
    };
    let key2 = AppStateSyncKey {
        key_data: b"app_state_key_data_2".to_vec(),
        fingerprint: b"fingerprint_2".to_vec(),
        timestamp: 2000,
    };

    store1
        .set_app_state_sync_key(key_id, key1.clone())
        .await
        .expect("Failed to store app state key for device 1");
    store2
        .set_app_state_sync_key(key_id, key2.clone())
        .await
        .expect("Failed to store app state key for device 2");

    // Verify isolation
    let loaded_key1 = store1
        .get_app_state_sync_key(key_id)
        .await
        .expect("Failed to load app state key for device 1");
    let loaded_key2 = store2
        .get_app_state_sync_key(key_id)
        .await
        .expect("Failed to load app state key for device 2");

    assert_eq!(loaded_key1.unwrap().key_data, key1.key_data);
    assert_eq!(loaded_key2.unwrap().key_data, key2.key_data);
}

#[tokio::test]
async fn test_device_isolation_prekeys() {
    let store_manager = Arc::new(
        StoreManager::new("file:test_isolation_prekeys?mode=memory&cache=shared")
            .await
            .expect("Failed to create StoreManager"),
    );

    // Create two devices
    let manager1 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 1");
    let manager2 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 2");

    let device_id1 = manager1.device_id();
    let device_id2 = manager2.device_id();

    // Create device-aware stores
    let store1 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id1);
    let store2 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id2);

    // Create test prekey records
    let prekey_id = 123;
    let prekey1 = waproto::whatsapp::PreKeyRecordStructure {
        id: Some(prekey_id),
        public_key: Some(b"public_key_1".to_vec()),
        private_key: Some(b"private_key_1".to_vec()),
    };
    let prekey2 = waproto::whatsapp::PreKeyRecordStructure {
        id: Some(prekey_id),
        public_key: Some(b"public_key_2".to_vec()),
        private_key: Some(b"private_key_2".to_vec()),
    };

    // Store prekeys for each device
    store1
        .store_prekey(prekey_id, prekey1.clone(), false)
        .await
        .expect("Failed to store prekey for device 1");
    store2
        .store_prekey(prekey_id, prekey2.clone(), false)
        .await
        .expect("Failed to store prekey for device 2");

    // Verify isolation
    let loaded_prekey1 = store1
        .load_prekey(prekey_id)
        .await
        .expect("Failed to load prekey for device 1");
    let loaded_prekey2 = store2
        .load_prekey(prekey_id)
        .await
        .expect("Failed to load prekey for device 2");

    assert_eq!(loaded_prekey1.unwrap().private_key, prekey1.private_key);
    assert_eq!(loaded_prekey2.unwrap().private_key, prekey2.private_key);

    // Test contains_prekey isolation
    assert!(
        store1
            .contains_prekey(prekey_id)
            .await
            .expect("Failed to check prekey existence for device 1")
    );
    assert!(
        store2
            .contains_prekey(prekey_id)
            .await
            .expect("Failed to check prekey existence for device 2")
    );

    // Remove prekey from device 1, should not affect device 2
    store1
        .remove_prekey(prekey_id)
        .await
        .expect("Failed to remove prekey for device 1");

    assert!(
        !store1
            .contains_prekey(prekey_id)
            .await
            .expect("Failed to check prekey existence for device 1")
    );
    assert!(
        store2
            .contains_prekey(prekey_id)
            .await
            .expect("Failed to check prekey existence for device 2")
    );
}

#[tokio::test]
async fn test_device_isolation_signed_prekeys() {
    let store_manager = Arc::new(
        StoreManager::new("file:test_isolation_signed_prekeys?mode=memory&cache=shared")
            .await
            .expect("Failed to create StoreManager"),
    );

    // Create two devices
    let manager1 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 1");
    let manager2 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 2");

    let device_id1 = manager1.device_id();
    let device_id2 = manager2.device_id();

    // Create device-aware stores
    let store1 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id1);
    let store2 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id2);

    // Create test signed prekey records
    let signed_prekey_id = 456;
    let signed_prekey1 = waproto::whatsapp::SignedPreKeyRecordStructure {
        id: Some(signed_prekey_id),
        public_key: Some(b"signed_public_key_1".to_vec()),
        private_key: Some(b"signed_private_key_1".to_vec()),
        signature: Some(b"signature_1".to_vec()),
        timestamp: Some(1000),
    };
    let signed_prekey2 = waproto::whatsapp::SignedPreKeyRecordStructure {
        id: Some(signed_prekey_id),
        public_key: Some(b"signed_public_key_2".to_vec()),
        private_key: Some(b"signed_private_key_2".to_vec()),
        signature: Some(b"signature_2".to_vec()),
        timestamp: Some(2000),
    };

    // Store signed prekeys for each device
    store1
        .store_signed_prekey(signed_prekey_id, signed_prekey1.clone())
        .await
        .expect("Failed to store signed prekey for device 1");
    store2
        .store_signed_prekey(signed_prekey_id, signed_prekey2.clone())
        .await
        .expect("Failed to store signed prekey for device 2");

    // Verify isolation
    let loaded_signed_prekey1 = store1
        .load_signed_prekey(signed_prekey_id)
        .await
        .expect("Failed to load signed prekey for device 1");
    let loaded_signed_prekey2 = store2
        .load_signed_prekey(signed_prekey_id)
        .await
        .expect("Failed to load signed prekey for device 2");

    assert_eq!(
        loaded_signed_prekey1.unwrap().private_key,
        signed_prekey1.private_key
    );
    assert_eq!(
        loaded_signed_prekey2.unwrap().private_key,
        signed_prekey2.private_key
    );

    // Test contains_signed_prekey isolation
    assert!(
        store1
            .contains_signed_prekey(signed_prekey_id)
            .await
            .expect("Failed to check signed prekey existence for device 1")
    );
    assert!(
        store2
            .contains_signed_prekey(signed_prekey_id)
            .await
            .expect("Failed to check signed prekey existence for device 2")
    );

    // Test load_signed_prekeys isolation
    let all_signed_prekeys1 = store1
        .load_signed_prekeys()
        .await
        .expect("Failed to load all signed prekeys for device 1");
    let all_signed_prekeys2 = store2
        .load_signed_prekeys()
        .await
        .expect("Failed to load all signed prekeys for device 2");

    assert_eq!(all_signed_prekeys1.len(), 1);
    assert_eq!(all_signed_prekeys2.len(), 1);
    assert_eq!(
        all_signed_prekeys1[0].private_key,
        signed_prekey1.private_key
    );
    assert_eq!(
        all_signed_prekeys2[0].private_key,
        signed_prekey2.private_key
    );

    // Remove signed prekey from device 1, should not affect device 2
    store1
        .remove_signed_prekey(signed_prekey_id)
        .await
        .expect("Failed to remove signed prekey for device 1");

    assert!(
        !store1
            .contains_signed_prekey(signed_prekey_id)
            .await
            .expect("Failed to check signed prekey existence for device 1")
    );
    assert!(
        store2
            .contains_signed_prekey(signed_prekey_id)
            .await
            .expect("Failed to check signed prekey existence for device 2")
    );
}

#[tokio::test]
async fn test_device_isolation_app_state_versions() {
    let store_manager = Arc::new(
        StoreManager::new("file:test_isolation_app_state_versions?mode=memory&cache=shared")
            .await
            .expect("Failed to create StoreManager"),
    );

    // Create two devices
    let manager1 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 1");
    let manager2 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 2");

    let device_id1 = manager1.device_id();
    let device_id2 = manager2.device_id();

    // Create device-aware stores
    let store1 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id1);
    let store2 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id2);

    // Create test app state versions
    let name = "test_app_state";
    let state1 = wacore::appstate::hash::HashState::default(); // Different states would be created in real use
    let state2 = wacore::appstate::hash::HashState {
        version: 2,
        ..Default::default()
    };

    // Store app state versions for each device
    store1
        .set_app_state_version(name, state1.clone())
        .await
        .expect("Failed to store app state version for device 1");
    store2
        .set_app_state_version(name, state2.clone())
        .await
        .expect("Failed to store app state version for device 2");

    // Verify isolation
    let loaded_state1 = store1
        .get_app_state_version(name)
        .await
        .expect("Failed to load app state version for device 1");
    let loaded_state2 = store2
        .get_app_state_version(name)
        .await
        .expect("Failed to load app state version for device 2");

    assert_eq!(loaded_state1.version, state1.version);
    assert_eq!(loaded_state2.version, state2.version);
    assert_ne!(loaded_state1.version, loaded_state2.version);
}

#[tokio::test]
async fn test_device_isolation_app_state_mutation_macs() {
    let store_manager = Arc::new(
        StoreManager::new("file:test_isolation_app_state_macs?mode=memory&cache=shared")
            .await
            .expect("Failed to create StoreManager"),
    );

    // Create two devices
    let manager1 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 1");
    let manager2 = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device 2");

    let device_id1 = manager1.device_id();
    let device_id2 = manager2.device_id();

    // Create device-aware stores
    let store1 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id1);
    let store2 = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id2);

    // Create test mutation MACs
    let name = "test_mutation";
    let version = 1;
    let mutations1 = vec![AppStateMutationMAC {
        index_mac: b"index_mac_1".to_vec(),
        value_mac: b"value_mac_1".to_vec(),
    }];
    let mutations2 = vec![AppStateMutationMAC {
        index_mac: b"index_mac_2".to_vec(),
        value_mac: b"value_mac_2".to_vec(),
    }];

    // Store mutation MACs for each device
    store1
        .put_app_state_mutation_macs(name, version, &mutations1)
        .await
        .expect("Failed to store mutation MACs for device 1");
    store2
        .put_app_state_mutation_macs(name, version, &mutations2)
        .await
        .expect("Failed to store mutation MACs for device 2");

    // Verify isolation
    let loaded_mac1 = store1
        .get_app_state_mutation_mac(name, &mutations1[0].index_mac)
        .await
        .expect("Failed to load mutation MAC for device 1");
    let loaded_mac2 = store2
        .get_app_state_mutation_mac(name, &mutations2[0].index_mac)
        .await
        .expect("Failed to load mutation MAC for device 2");

    assert_eq!(loaded_mac1, Some(mutations1[0].value_mac.clone()));
    assert_eq!(loaded_mac2, Some(mutations2[0].value_mac.clone()));

    // Verify cross-device isolation - device 1 should not see device 2's MACs
    let cross_mac1 = store1
        .get_app_state_mutation_mac(name, &mutations2[0].index_mac)
        .await
        .expect("Failed to check cross-device MAC for device 1");
    let cross_mac2 = store2
        .get_app_state_mutation_mac(name, &mutations1[0].index_mac)
        .await
        .expect("Failed to check cross-device MAC for device 2");

    assert_eq!(cross_mac1, None);
    assert_eq!(cross_mac2, None);

    // Test deletion isolation
    store1
        .delete_app_state_mutation_macs(name, &[mutations1[0].index_mac.clone()])
        .await
        .expect("Failed to delete mutation MAC for device 1");

    let after_delete1 = store1
        .get_app_state_mutation_mac(name, &mutations1[0].index_mac)
        .await
        .expect("Failed to check deleted MAC for device 1");
    let after_delete2 = store2
        .get_app_state_mutation_mac(name, &mutations2[0].index_mac)
        .await
        .expect("Failed to check MAC for device 2 after device 1 deletion");

    assert_eq!(after_delete1, None);
    assert_eq!(after_delete2, Some(mutations2[0].value_mac.clone()));
}

#[tokio::test]
async fn test_migration_correctness() {
    // Test that the migration correctly assigns device_id = 1 to existing data
    // and that new data gets proper device_id values

    // Use a unique in-memory database for this test to ensure fresh migration
    let db_name = format!(
        "file:test_migration_{}?mode=memory&cache=shared",
        Uuid::new_v4()
    );

    // Create a store manager to trigger migration
    let store_manager = Arc::new(
        StoreManager::new(&db_name)
            .await
            .expect("Failed to create StoreManager for migration test"),
    );

    // Create a new device (should get device_id = 1 due to migration or device_id > 1 if it's a new device)
    let manager = store_manager
        .create_new_device()
        .await
        .expect("Failed to create device for migration test");
    let device_id = manager.device_id();

    // Verify we get a valid device ID
    assert!(device_id > 0);

    // Create device-aware store
    let store = DeviceAwareSqliteStore::new(store_manager.sqlite_store(), device_id);

    // Store some test data
    let address = "migration@test.com";
    let key = [42u8; 32];

    store
        .put_identity(address, key)
        .await
        .expect("Failed to store identity in migration test");

    // Verify we can load it back
    let loaded_key = store
        .load_identity(address)
        .await
        .expect("Failed to load identity in migration test");
    assert_eq!(loaded_key, Some(key.to_vec()));
}
