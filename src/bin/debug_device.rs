use log::info;
use prost::Message;
use std::sync::Arc;
use whatsapp_proto::whatsapp as wa; // Added import
use whatsapp_rust::store::persistence_manager::PersistenceManager; // Added for decode

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=== WhatsApp Rust Device Debug Utility ===");
    info!("----------------------------------------");

    let store_path = "./whatsapp_store"; // Default store path
    info!("Attempting to load device using PersistenceManager from path: {store_path}");

    let persistence_manager = match PersistenceManager::new(store_path).await {
        Ok(pm) => Arc::new(pm),
        Err(e) => {
            info!("❌ Failed to initialize PersistenceManager: {e}. Cannot display info.");
            info!("   Ensure the store path is correct and accessible.");
            return Ok(());
        }
    };

    let device_snapshot = persistence_manager.get_device_snapshot().await;

    if device_snapshot.id.is_none() && device_snapshot.noise_key.public_key == [0; 32] {
        info!("❌ No significant device data found (no JID or default noise key).");
        info!("   The device may need to be paired first using the main application.");
        return Ok(());
    }

    info!("✅ Device data loaded via PersistenceManager.");
    info!("\nDevice Information (from snapshot):");
    info!("----------------------------------------");
    info!("  JID: {:?}", device_snapshot.id);
    info!("  LID: {:?}", device_snapshot.lid);
    info!("  Push Name: '{}'", device_snapshot.push_name);
    info!("  Has Account (ADV): {}", device_snapshot.account.is_some());
    info!("  Registration ID: {}", device_snapshot.registration_id);
    info!(
        "  Identity Key (Public): {}",
        hex::encode(device_snapshot.identity_key.public_key)
    );
    info!(
        "  Signed PreKey ID: {}",
        device_snapshot.signed_pre_key.key_id
    );
    info!(
        "  ADV Secret Key: {}",
        hex::encode(device_snapshot.adv_secret_key)
    );

    if let Some(account_details) = &device_snapshot.account {
        info!("  Account Details (ADV):");
        info!(
            "    - Account Signature Key: {}",
            hex::encode(account_details.account_signature_key())
        );
        // info!("    - Account Signature: {}", hex::encode(&account_details.account_signature())); // This field might not be directly on AdvSignedDeviceIdentity
        info!(
            "    - Device Signature: {}",
            hex::encode(account_details.device_signature())
        );
        if let Some(details_bytes) = &account_details.details {
            match wa::AdvDeviceIdentity::decode(details_bytes.as_slice()) {
                // Corrected type to AdvDeviceIdentity
                Ok(details_struct) => {
                    info!("    - Device Type: {:?}", details_struct.device_type); // Use device_type field
                    info!("    - Key Index: {:?}", details_struct.key_index); // Access field directly
                }
                Err(e) => {
                    info!("    - Could not decode ADV Details: {e}");
                }
            }
        }
    }

    // Check readiness for presence (simulating client logic)
    let is_ready_for_presence =
        device_snapshot.id.is_some() && !device_snapshot.push_name.is_empty();
    if is_ready_for_presence {
        info!("✅ Device appears ready for presence announcements (JID and Push Name are set).");
    } else {
        info!("❌ Device is NOT ready for presence announcements.");
        if device_snapshot.id.is_none() {
            info!("   Reason: JID is missing.");
        }
        if device_snapshot.push_name.is_empty() {
            info!("   Reason: Push Name is empty.");
        }
    }

    info!("----------------------------------------");
    info!("Debug information complete.");

    Ok(())
}
