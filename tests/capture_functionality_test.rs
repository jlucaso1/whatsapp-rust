use std::sync::Arc;
use tempfile::TempDir;
use tokio::fs;
use wacore::signal::identity::IdentityKeyPair;
use whatsapp_rust::{client::Client, store::persistence_manager::PersistenceManager};

#[tokio::test]
async fn test_capture_mode_functionality() {
    // Initialize logging for debugging
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .try_init();

    // Create a temporary directory for the client store
    let temp_store = TempDir::new().unwrap();
    let store_path = temp_store.path().join("capture_test_store");

    // Create a temporary directory for capture output
    let temp_capture = TempDir::new().unwrap();
    let capture_path = temp_capture.path().join("captured_bundles");

    // Create client
    let pm = Arc::new(
        PersistenceManager::new(store_path)
            .await
            .expect("Failed to create PersistenceManager"),
    );
    let client = Arc::new(Client::new(pm).await);

    // Test capture mode activation
    assert!(
        !client.is_capture_enabled(),
        "Capture should be disabled by default"
    );

    client.enable_capture_mode(&capture_path).await;
    assert!(
        client.is_capture_enabled(),
        "Capture should be enabled after activation"
    );

    // Test that capture directory is set up correctly
    // Since we can't easily trigger actual message capture without a full connection,
    // we'll just verify the basic functionality works
    client.disable_capture_mode();
    assert!(
        !client.is_capture_enabled(),
        "Capture should be disabled after deactivation"
    );

    println!("✅ Capture mode functionality test passed");
}

#[tokio::test]
async fn test_capture_manager_bundle_creation() {
    use wacore::signal::state::session_record::SessionRecord;
    use whatsapp_rust::capture::{CaptureManager, DirectMessageBundle};

    let temp_dir = TempDir::new().unwrap();
    let capture_path = temp_dir.path().join("test_bundles");

    let manager = CaptureManager::new();
    manager.set_capture_path(&capture_path).await;

    // Create a test bundle with mock data
    let test_bundle = DirectMessageBundle {
        message_bin: b"mock_encrypted_message".to_vec(),
        sender_identity_key_bin: b"mock_sender_key".to_vec(),
        recipient_session: SessionRecord::new(),
        recipient_identity_keys: create_mock_identity_key_pair(),
        recipient_prekey: None,
        recipient_signed_prekey: None,
        expected_plaintext: "Test message content".to_string(),
    };

    // Capture the bundle
    manager
        .capture_direct_message_bundle("test_message_001", test_bundle)
        .await
        .expect("Failed to capture bundle");

    // Verify files were created
    let bundle_dir = capture_path.join("test_message_001");
    assert!(bundle_dir.exists(), "Bundle directory should be created");

    let expected_files = [
        "message.bin",
        "sender_identity_key.bin",
        "recipient_session.json",
        "recipient_identity_keys.json",
        "expected_plaintext.txt",
    ];

    for file in &expected_files {
        let file_path = bundle_dir.join(file);
        assert!(file_path.exists(), "File {file} should exist");
    }

    // Verify content of one file
    let plaintext_content = fs::read_to_string(bundle_dir.join("expected_plaintext.txt"))
        .await
        .expect("Failed to read plaintext file");
    assert_eq!(plaintext_content, "Test message content");

    println!("✅ Bundle creation test passed");
}

fn create_mock_identity_key_pair() -> IdentityKeyPair {
    use wacore::signal::ecc::{
        key_pair::EcKeyPair,
        keys::{DjbEcPrivateKey, DjbEcPublicKey},
    };
    use wacore::signal::identity::{IdentityKey, IdentityKeyPair};

    // Create mock 32-byte keys (in real usage these would be proper Ed25519 keys)
    let private_bytes = [1u8; 32];
    let public_bytes = [2u8; 32];

    let public_key = DjbEcPublicKey::new(public_bytes);
    let private_key = DjbEcPrivateKey::new(private_bytes);
    let identity_key = IdentityKey::new(public_key.clone());
    let key_pair = EcKeyPair::new(public_key, private_key);

    IdentityKeyPair::new(identity_key, key_pair)
}
