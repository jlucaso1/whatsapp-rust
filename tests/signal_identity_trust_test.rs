use wacore::libsignal::protocol::Direction;
use wacore::libsignal::protocol::IdentityKeyStore;
use wacore::libsignal::protocol::ProtocolAddress;
use std::sync::Arc;
use tokio::sync::RwLock;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use whatsapp_rust::store::{Device, signal::DeviceRwLockWrapper};

#[tokio::test]
async fn test_signal_identity_trust_returns_true() {
    let device = {
        let store_backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
        let device = Device::new(store_backend);
        Arc::new(RwLock::new(device))
    };

    let mut device_store = DeviceRwLockWrapper::new(device);

    let test_address = ProtocolAddress::new("test_user".to_string(), 1.into());

    let identity_key_pair = device_store.get_identity_key_pair().await.unwrap();
    let identity_key = identity_key_pair.identity_key();

    let save_result = device_store
        .save_identity(&test_address, identity_key)
        .await;
    assert!(
        save_result.is_ok(),
        "Saving identity should succeed: {save_result:?}"
    );

    let is_trusted = device_store
        .is_trusted_identity(&test_address, identity_key, Direction::Receiving)
        .await
        .unwrap();
    assert!(
        is_trusted,
        "Identity should be trusted - our implementation trusts all identities to prevent regression"
    );

    // let different_device = {
    //     let store_backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
    //     let device = Device::new(store_backend);
    //     Arc::new(RwLock::new(device))
    // };
    // let different_device_store = DeviceRwLockWrapper::new(different_device);
    // let different_identity_key_pair = different_device_store
    //     .get_identity_key_pair()
    //     .await
    //     .unwrap();
    // let different_identity_key = different_identity_key_pair.identity_key();

    // let is_different_trusted = device_store
    //     .is_trusted_identity(&test_address, different_identity_key, Direction::Receiving)
    //     .await
    //     .unwrap();
    // assert!(
    //     is_different_trusted,
    //     "Even different identity keys should not be trusted to prevent the regression"
    // );
}

#[tokio::test]
async fn test_identity_key_operations_complete_successfully() {
    let device = {
        let store_backend = Arc::new(SqliteStore::new(":memory:").await.unwrap());
        let device = Device::new(store_backend);
        Arc::new(RwLock::new(device))
    };
    let mut device_store = DeviceRwLockWrapper::new(device);

    let test_address1 = ProtocolAddress::new("user1".to_string(), 1.into());
    let test_address2 = ProtocolAddress::new("user2".to_string(), 1.into());

    let identity_key_pair = device_store.get_identity_key_pair().await.unwrap();
    let identity_key = identity_key_pair.identity_key();
    let registration_id = device_store.get_local_registration_id().await.unwrap();

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

    assert!(
        device_store
            .is_trusted_identity(&test_address1, identity_key, Direction::Receiving)
            .await
            .unwrap()
    );
    assert!(
        device_store
            .is_trusted_identity(&test_address2, identity_key, Direction::Receiving)
            .await
            .unwrap()
    );

    assert!(
        registration_id > 0,
        "Registration ID should be a positive number"
    );

    println!("✅ Identity key operations test passed - all operations completed successfully");
}
