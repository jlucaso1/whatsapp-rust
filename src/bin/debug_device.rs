use log::info;
use std::sync::Arc;
use whatsapp_rust::client::Client;
use whatsapp_rust::store;
use whatsapp_rust::store::filestore::FileStore;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=== WhatsApp Rust Device Debug Utility ===");

    let store_backend = Arc::new(FileStore::new("./whatsapp_store").await?);

    // Try to load existing device data
    if let Some(loaded_data) = store_backend.load_device_data().await? {
        info!("✅ Found existing device data");

        let mut device = store::Device::new(store_backend.clone());
        device.load_from_serializable(loaded_data);

        let client = Arc::new(Client::new(device));

        // Print debug information
        info!("Device Information:");
        info!("  JID: {:?}", client.store.read().await.id);
        info!("  Push Name: '{}'", client.store.read().await.push_name);
        info!(
            "  Has Account: {}",
            client.store.read().await.account.is_some()
        );
        info!(
            "  Registration ID: {}",
            client.store.read().await.registration_id
        );

        // Check readiness for presence
        if client.is_ready_for_presence().await {
            info!("✅ Device is ready for presence announcements");
        } else {
            info!("❌ Device is NOT ready for presence announcements");
        }

        // Print detailed debug info
        info!("\n{}", client.get_device_debug_info().await);

        // Test push name methods
        info!("\nTesting push name methods:");
        let current_name = client.get_push_name().await;
        info!("  Current push name: '{}'", current_name);

        if current_name.is_empty() {
            info!("  ⚠️  Push name is empty - this will prevent presence announcements!");
        }
    } else {
        info!("❌ No existing device data found");
        info!("   The device needs to be paired first using the main application.");
    }

    Ok(())
}
