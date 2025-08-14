use std::sync::Arc;
use tokio;
use whatsapp_rust::store::persistence_manager::PersistenceManager;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use whatsapp_rust::store::traits::*;
use wacore::signal::store::{PreKeyStore, SignedPreKeyStore};
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

#[tokio::test]
async fn test_sqlite_store_comprehensive() {
    // Create an in-memory SQLite database for testing
    let store = Arc::new(SqliteStore::new(":memory:").await.expect("Failed to create SQLite store"));

    // Test IdentityStore
    let address = "test@example.com";
    let key = [1u8; 32];

    // Should trust identity when none exists
    assert!(store.is_trusted_identity(address, &key, libsignal_protocol::Direction::Sending).await.unwrap());

    // Store identity
    store.put_identity(address, key).await.unwrap();
    
    // Should load the stored identity
    let loaded = store.load_identity(address).await.unwrap().unwrap();
    assert_eq!(loaded, key);

    // Should trust same identity
    assert!(store.is_trusted_identity(address, &key, libsignal_protocol::Direction::Sending).await.unwrap());

    // Should not trust different identity
    let different_key = [2u8; 32];
    assert!(!store.is_trusted_identity(address, &different_key, libsignal_protocol::Direction::Sending).await.unwrap());

    // Test SessionStore
    let session_address = "session@test.com";
    let session_data = b"session_data";
    
    assert!(!store.has_session(session_address).await.unwrap());
    store.put_session(session_address, session_data).await.unwrap();
    assert!(store.has_session(session_address).await.unwrap());
    
    let loaded_session = store.get_session(session_address).await.unwrap().unwrap();
    assert_eq!(loaded_session, session_data);

    // Test PreKeyStore - create a minimal PreKeyRecordStructure
    let prekey_id = 123u32;
    let prekey_record = PreKeyRecordStructure {
        id: Some(prekey_id),
        public_key: Some(vec![0x05; 33]), // Minimal public key
        private_key: Some(vec![0x42; 32]), // Minimal private key
    };

    assert!(!store.contains_prekey(prekey_id).await.unwrap());
    store.store_prekey(prekey_id, prekey_record.clone()).await.unwrap();
    assert!(store.contains_prekey(prekey_id).await.unwrap());
    
    let loaded_prekey = store.load_prekey(prekey_id).await.unwrap().unwrap();
    assert_eq!(loaded_prekey.id, prekey_record.id);

    // Test SignedPreKeyStore - create a minimal SignedPreKeyRecordStructure  
    let signed_prekey_id = 456u32;
    let signed_prekey_record = SignedPreKeyRecordStructure {
        id: Some(signed_prekey_id),
        public_key: Some(vec![0x05; 33]), // Minimal public key
        private_key: Some(vec![0x42; 32]), // Minimal private key
        signature: Some(vec![0x99; 64]), // Minimal signature
        timestamp: Some(1234567890),
    };

    assert!(!store.contains_signed_prekey(signed_prekey_id).await.unwrap());
    store.store_signed_prekey(signed_prekey_id, signed_prekey_record.clone()).await.unwrap();
    assert!(store.contains_signed_prekey(signed_prekey_id).await.unwrap());
    
    let loaded_signed_prekey = store.load_signed_prekey(signed_prekey_id).await.unwrap().unwrap();
    assert_eq!(loaded_signed_prekey.id, signed_prekey_record.id);

    // Test loading all signed prekeys
    let all_signed_prekeys = store.load_signed_prekeys().await.unwrap();
    assert_eq!(all_signed_prekeys.len(), 1);
    assert_eq!(all_signed_prekeys[0].id, signed_prekey_record.id);

    // Test SenderKeyStoreHelper
    let sender_address = "sender@test.com";
    let sender_record = b"sender_key_record";
    
    store.put_sender_key(sender_address, sender_record).await.unwrap();
    let loaded_sender_key = store.get_sender_key(sender_address).await.unwrap().unwrap();
    assert_eq!(loaded_sender_key, sender_record);

    println!("✅ All SQLite store tests passed!");
}

#[tokio::test]
async fn test_sqlite_persistence_manager() {
    // Test that PersistenceManager works with SQLite backend
    let pm = PersistenceManager::new_sqlite(":memory:").await.expect("Failed to create SQLite PersistenceManager");
    
    // Test device modification
    pm.modify_device(|device| {
        device.push_name = "Test Device".to_string();
    }).await;
    
    let device = pm.get_device_snapshot().await;
    assert_eq!(device.push_name, "Test Device");
    
    println!("✅ SQLite PersistenceManager test passed!");
}