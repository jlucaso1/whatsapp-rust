/**
 * Test to prevent regressions in Signal Protocol identity trust handling.
 *
 * This test ensures that the "Untrusted identity key" error does not occur during
 * normal message encryption and decryption flows, as experienced in issue #15.
 */
use std::sync::Arc;
use tokio::sync::RwLock;
use whatsapp_rust::signal::{address::SignalAddress, store::IdentityKeyStore};
use whatsapp_rust::store::{Device, memory::MemoryStore, signal::DeviceRwLockWrapper};

#[tokio::test]
async fn test_signal_identity_trust_always_returns_true() {
    // Setup device using the same pattern as other tests
    let device = {
        let store_backend = Arc::new(MemoryStore::new());
        let device = Device::new(store_backend);
        Arc::new(RwLock::new(device))
    };

    let device_store = DeviceRwLockWrapper::new(device);

    // Create a test address
    let test_address = SignalAddress::new("test_user".to_string(), 1);

    // Generate identity key from the device itself
    let identity_key_pair = device_store.get_identity_key_pair().await.unwrap();
    let identity_key = identity_key_pair.public_key();

    // Save the identity key - this should work
    let save_result = device_store
        .save_identity(&test_address, identity_key)
        .await;
    assert!(
        save_result.is_ok(),
        "Saving identity should succeed: {:?}",
        save_result
    );

    // Check if the key is trusted - should ALWAYS return true in our implementation
    // This is the key fix that prevents the "Untrusted identity key" error
    let is_trusted = device_store
        .is_trusted_identity(&test_address, identity_key)
        .await
        .unwrap();
    assert!(
        is_trusted,
        "Identity should be trusted - our implementation trusts all identities to prevent regression"
    );

    // Test with a different identity key - should also be trusted
    let different_device = {
        let store_backend = Arc::new(MemoryStore::new());
        let device = Device::new(store_backend);
        Arc::new(RwLock::new(device))
    };
    let different_device_store = DeviceRwLockWrapper::new(different_device);
    let different_identity_key_pair = different_device_store
        .get_identity_key_pair()
        .await
        .unwrap();
    let different_identity_key = different_identity_key_pair.public_key();

    let is_different_trusted = device_store
        .is_trusted_identity(&test_address, different_identity_key)
        .await
        .unwrap();
    assert!(
        is_different_trusted,
        "Even different identity keys should be trusted to prevent the regression"
    );

    println!("✅ Signal identity trust test passed - all identities are trusted by default");
}

#[tokio::test]
async fn test_identity_key_operations_complete_successfully() {
    let device = {
        let store_backend = Arc::new(MemoryStore::new());
        let device = Device::new(store_backend);
        Arc::new(RwLock::new(device))
    };
    let device_store = DeviceRwLockWrapper::new(device);

    let test_address1 = SignalAddress::new("user1".to_string(), 1);
    let test_address2 = SignalAddress::new("user2".to_string(), 1);

    // Get device's own identity key
    let identity_key_pair = device_store.get_identity_key_pair().await.unwrap();
    let identity_key = identity_key_pair.public_key();
    let registration_id = device_store.get_local_registration_id().await.unwrap();

    // Basic operations should all succeed
    assert!(
        device_store
            .save_identity(&test_address1, identity_key)
            .await
            .is_ok()
    );
    assert!(
        device_store
            .save_identity(&test_address2, identity_key)
            .await
            .is_ok()
    );

    // All trust checks should return true
    assert!(
        device_store
            .is_trusted_identity(&test_address1, identity_key)
            .await
            .unwrap()
    );
    assert!(
        device_store
            .is_trusted_identity(&test_address2, identity_key)
            .await
            .unwrap()
    );

    // Registration ID should be consistent
    assert!(
        registration_id > 0,
        "Registration ID should be a positive number"
    );

    println!("✅ Identity key operations test passed - all operations completed successfully");
}
