use chrono::Local;
use log::{debug, error, info};
use std::sync::Arc;
use wacore::types::events::Event;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::store_manager::StoreManager;

/// This example demonstrates the new multi-account capabilities of whatsapp-rust.
/// It shows how to:
/// 1. Create a StoreManager for managing multiple accounts in one database
/// 2. Create multiple bots using the same StoreManager  
/// 3. Handle events from multiple accounts
/// 4. List and manage devices

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} [{:<5}] [{}] - {}",
                Local::now().format("%H:%M:%S"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();

    info!("🚀 Starting Multi-Account WhatsApp Bot Example");

    // Step 1: Create a StoreManager 
    // This manages multiple WhatsApp accounts in a single database
    let store_manager = Arc::new(
        StoreManager::new("multi_account.db")
            .await
            .expect("Failed to create StoreManager")
    );

    info!("📊 StoreManager created successfully");

    // Step 2: List existing devices (if any)
    let existing_devices = store_manager
        .list_devices()
        .await
        .expect("Failed to list devices");
    
    info!("📱 Found {} existing devices: {:?}", existing_devices.len(), existing_devices);

    // Step 3: Create multiple bots using the same StoreManager
    
    // Bot 1: Create a new device automatically
    info!("🤖 Creating Bot 1 (new device)...");
    let mut bot1 = Bot::builder()
        .with_store_manager(store_manager.clone())
        .on_event(|event, client| {
            async move {
                let device_id = client.persistence_manager().device_id();
                match event {
                    Event::PairingQrCode { code, timeout } => {
                        info!("📱 [Device {}] New pairing QR code (valid for {}s):", device_id, timeout.as_secs());
                        info!("\n{}\n", code);
                    }
                    Event::Connected(_) => {
                        info!("✅ [Device {}] Connected successfully!", device_id);
                    }
                    Event::Message(msg, _info) => {
                        if let Some(text) = msg.conversation.as_ref() {
                            info!("💬 [Device {}] Received message: {}", device_id, text);
                        }
                    }
                    Event::LoggedOut(_) => {
                        error!("❌ [Device {}] Logged out!", device_id);
                    }
                    _ => {
                        debug!("📨 [Device {}] Received event: {:?}", device_id, event);
                    }
                }
            }
        })
        .build()
        .await
        .expect("Failed to create Bot 1");

    let bot1_device_id = bot1.client().persistence_manager().device_id();
    info!("🤖 Bot 1 created with device ID: {}", bot1_device_id);

    // Bot 2: Create another new device
    info!("🤖 Creating Bot 2 (new device)...");
    let mut bot2 = Bot::builder()
        .with_store_manager(store_manager.clone())
        .on_event(|event, client| {
            async move {
                let device_id = client.persistence_manager().device_id();
                match event {
                    Event::PairingQrCode { code, timeout } => {
                        info!("📱 [Device {}] New pairing QR code (valid for {}s):", device_id, timeout.as_secs());
                        info!("\n{}\n", code);
                    }
                    Event::Connected(_) => {
                        info!("✅ [Device {}] Connected successfully!", device_id);
                    }
                    Event::Message(msg, _info) => {
                        if let Some(text) = msg.conversation.as_ref() {
                            info!("💬 [Device {}] Received message: {}", device_id, text);
                        }
                    }
                    Event::LoggedOut(_) => {
                        error!("❌ [Device {}] Logged out!", device_id);
                    }
                    _ => {
                        debug!("📨 [Device {}] Received event: {:?}", device_id, event);
                    }
                }
            }
        })
        .build()
        .await
        .expect("Failed to create Bot 2");

    let bot2_device_id = bot2.client().persistence_manager().device_id();
    info!("🤖 Bot 2 created with device ID: {}", bot2_device_id);

    // Step 4: Demonstrate working with existing device
    // If you already have devices, you can create a bot for a specific device:
    if !existing_devices.is_empty() {
        let existing_device_id = existing_devices[0];
        info!("🔄 Creating Bot 3 for existing device ID: {}", existing_device_id);
        
        let _bot3 = Bot::builder()
            .with_store_manager(store_manager.clone())
            .for_device(existing_device_id) // Use specific device ID
            .on_event(|event, client| {
                async move {
                    let device_id = client.persistence_manager().device_id();
                    info!("📨 [Device {}] Event: {:?}", device_id, event);
                }
            })
            .build()
            .await
            .expect("Failed to create Bot 3");
        
        info!("🤖 Bot 3 created for existing device");
    }

    // Step 5: List all devices again to see what we have
    let all_devices = store_manager
        .list_devices()
        .await
        .expect("Failed to list devices");
    
    info!("📊 Total devices now: {} - {:?}", all_devices.len(), all_devices);

    // Step 6: Start the bots
    info!("🚀 Starting all bots...");
    
    let bot1_handle = bot1.run().await.expect("Failed to start Bot 1");
    info!("✅ Bot 1 started");
    
    let bot2_handle = bot2.run().await.expect("Failed to start Bot 2");
    info!("✅ Bot 2 started");

    info!("🎯 All bots are running. They will display QR codes for pairing.");
    info!("💡 Each device will get its own QR code - scan them with different WhatsApp accounts.");
    info!("🔄 Press Ctrl+C to stop.");

    // Step 7: Wait for the bots to finish (they run indefinitely)
    tokio::select! {
        result1 = bot1_handle => {
            if let Err(e) = result1 {
                error!("Bot 1 ended with error: {}", e);
            } else {
                info!("Bot 1 ended gracefully");
            }
        }
        result2 = bot2_handle => {
            if let Err(e) = result2 {
                error!("Bot 2 ended with error: {}", e);
            } else {
                info!("Bot 2 ended gracefully");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Received Ctrl+C, shutting down...");
        }
    }

    info!("👋 Multi-account bot example finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_multi_account_creation() {
        // This test demonstrates how to programmatically work with multiple accounts
        let store_manager = Arc::new(
            StoreManager::new("test_multi.db")
                .await
                .expect("Failed to create test StoreManager")
        );

        // Create first account
        let manager1 = store_manager
            .create_new_device()
            .await
            .expect("Failed to create device 1");
        
        // Create second account  
        let manager2 = store_manager
            .create_new_device()
            .await
            .expect("Failed to create device 2");

        // Verify they have different device IDs
        assert_ne!(manager1.device_id(), manager2.device_id());

        // Verify both exist in the store
        let devices = store_manager
            .list_devices()
            .await
            .expect("Failed to list devices");
        
        assert_eq!(devices.len(), 2);
        assert!(devices.contains(&manager1.device_id()));
        assert!(devices.contains(&manager2.device_id()));

        // Clean up
        store_manager
            .delete_device(manager1.device_id())
            .await
            .expect("Failed to delete device 1");
        
        store_manager
            .delete_device(manager2.device_id())
            .await
            .expect("Failed to delete device 2");

        // Verify cleanup
        let devices_after = store_manager
            .list_devices()
            .await
            .expect("Failed to list devices after cleanup");
        
        assert!(devices_after.is_empty());
    }

    #[tokio::test] 
    async fn test_backward_compatibility() {
        // Test that the old single-account API still works
        let bot = Bot::builder()
            .build()
            .await
            .expect("Failed to create bot with backward compatibility");

        // Should work with default device ID
        let device_id = bot.client().persistence_manager().device_id();
        assert!(device_id > 0);
    }
}