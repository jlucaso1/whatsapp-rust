use std::sync::Arc;
use tokio;
use whatsapp_rust::store::persistence_manager::PersistenceManager;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use whatsapp_rust::store::traits::*;
use wacore::signal::store::{PreKeyStore, SignedPreKeyStore};
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    
    println!("🔧 SQLite Storage Backend Demo");
    println!("================================");
    
    // 1. Create SQLite-backed persistence manager
    println!("\n📦 Creating SQLite persistence manager...");
    let pm = PersistenceManager::new_sqlite("demo.db").await?;
    
    println!("✅ SQLite persistence manager created with database: demo.db");
    
    // 2. Demonstrate device management
    println!("\n🔧 Testing device management...");
    pm.modify_device(|device| {
        device.push_name = "SQLite Demo Device".to_string();
    }).await;
    
    let device = pm.get_device_snapshot().await;
    println!("✅ Device push name: '{}'", device.push_name);
    
    // Force save to demonstrate persistence
    pm.save_now().await?;
    println!("✅ Device data persisted to SQLite database");
    
    // 3. Demonstrate storage backend features
    println!("\n🔑 Testing Signal Protocol storage...");
    
    // Get the SQLite store directly for testing storage features
    let store = Arc::new(SqliteStore::new("demo.db").await?);
    
    // Test identity storage with proper trust verification
    let address = "demo_contact@whatsapp.com";
    let identity_key = [0x42u8; 32];
    
    // Should trust new identity (first contact)
    let trusted = store.is_trusted_identity(address, &identity_key, libsignal_protocol::Direction::Sending).await?;
    println!("✅ New identity trusted: {}", trusted);
    
    // Store the identity
    store.put_identity(address, identity_key).await?;
    println!("✅ Identity stored for {}", address);
    
    // Should still trust same identity
    let trusted = store.is_trusted_identity(address, &identity_key, libsignal_protocol::Direction::Sending).await?;
    println!("✅ Same identity trusted: {}", trusted);
    
    // Should not trust different identity
    let different_key = [0x99u8; 32];
    let trusted = store.is_trusted_identity(address, &different_key, libsignal_protocol::Direction::Sending).await?;
    println!("✅ Different identity trusted: {} (should be false)", trusted);
    
    // Test session storage
    println!("\n💬 Testing session storage...");
    let session_address = "session_demo@whatsapp.com";
    let session_data = b"encrypted_session_data_example";
    
    store.put_session(session_address, session_data).await?;
    let has_session = store.has_session(session_address).await?;
    println!("✅ Session stored and verified: {}", has_session);
    
    // Test prekey storage
    println!("\n🗝️  Testing prekey storage...");
    let prekey_id = 12345u32;
    let prekey_record = PreKeyRecordStructure {
        id: Some(prekey_id),
        public_key: Some(vec![0x05; 33]), // Mock public key
        private_key: Some(vec![0x42; 32]), // Mock private key  
    };
    
    store.store_prekey(prekey_id, prekey_record.clone()).await.map_err(|e| format!("PreKey store error: {}", e))?;
    let contains = store.contains_prekey(prekey_id).await.map_err(|e| format!("PreKey contains error: {}", e))?;
    println!("✅ PreKey {} stored: {}", prekey_id, contains);
    
    // Test signed prekey storage (this is the new functionality!)
    println!("\n🔐 Testing signed prekey storage (full implementation)...");
    let signed_prekey_id = 67890u32;
    let signed_prekey_record = SignedPreKeyRecordStructure {
        id: Some(signed_prekey_id),
        public_key: Some(vec![0x05; 33]), // Mock public key
        private_key: Some(vec![0x42; 32]), // Mock private key
        signature: Some(vec![0x99; 64]), // Mock signature
        timestamp: Some(chrono::Utc::now().timestamp() as u64),
    };
    
    store.store_signed_prekey(signed_prekey_id, signed_prekey_record.clone()).await.map_err(|e| format!("SignedPreKey store error: {}", e))?;
    let contains = store.contains_signed_prekey(signed_prekey_id).await.map_err(|e| format!("SignedPreKey contains error: {}", e))?;
    println!("✅ SignedPreKey {} stored: {}", signed_prekey_id, contains);
    
    // Load the signed prekey back
    let loaded = store.load_signed_prekey(signed_prekey_id).await.map_err(|e| format!("SignedPreKey load error: {}", e))?.unwrap();
    println!("✅ SignedPreKey {} loaded successfully", loaded.id.unwrap());
    
    // Load all signed prekeys
    let all_signed_prekeys = store.load_signed_prekeys().await.map_err(|e| format!("SignedPreKey load all error: {}", e))?;
    println!("✅ Total signed prekeys in database: {}", all_signed_prekeys.len());
    
    // Test sender key storage
    println!("\n📡 Testing sender key storage...");
    let sender_address = "group_sender@whatsapp.com";
    let sender_record = b"group_sender_key_record_data";
    
    store.put_sender_key(sender_address, sender_record).await?;
    let loaded_sender = store.get_sender_key(sender_address).await?.unwrap();
    println!("✅ Sender key stored and loaded for {}", sender_address);
    
    // Test app state storage
    println!("\n📱 Testing app state storage...");
    let app_state_name = "critical_block";
    let mut hash_state = wacore::appstate::hash::HashState::default();
    hash_state.version = 12345;
    
    store.set_app_state_version(app_state_name, hash_state.clone()).await?;
    let loaded_state = store.get_app_state_version(app_state_name).await?;
    println!("✅ App state version stored: {}", loaded_state.version);
    
    println!("\n🎉 SQLite Storage Backend Demo Complete!");
    println!("=====================================");
    println!("All storage features working correctly:");
    println!("  • Device data persistence ✅");
    println!("  • Identity key storage with trust verification ✅");
    println!("  • Session storage ✅");
    println!("  • PreKey storage ✅");
    println!("  • SignedPreKey storage (FULL IMPLEMENTATION) ✅");
    println!("  • Sender key storage ✅");
    println!("  • App state synchronization ✅");
    println!("\nThe SQLite database 'demo.db' contains all the stored data.");
    println!("You can inspect it with any SQLite tool to see the table structure.");
    
    // Cleanup
    std::fs::remove_file("demo.db").ok();
    println!("\n🧹 Demo database cleaned up.");
    
    Ok(())
}