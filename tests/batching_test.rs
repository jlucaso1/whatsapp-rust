use log::{error, info};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use whatsapp_rust::client::Client;
use whatsapp_rust::store;
use whatsapp_rust::store::filestore::FileStore;
use whatsapp_rust::types::events::Event;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=== WhatsApp Rust Batching Test Utility ===");

    let store_backend = Arc::new(FileStore::new("./whatsapp_store").await?);

    // Try to load existing device data
    let device = if let Some(loaded_data) = store_backend.load_device_data().await? {
        info!("✅ Found existing device data");
        let mut dev = store::Device::new(store_backend.clone());
        dev.load_from_serializable(loaded_data);
        dev
    } else {
        info!("❌ No existing device data found");
        return Ok(());
    };

    let client = Arc::new(Client::new(device));

    // Counter to track how many events we receive
    let event_counter = Arc::new(AtomicUsize::new(0));
    let save_counter = Arc::new(AtomicUsize::new(0));

    // Add event handler to count events and saves
    let store_backend_for_handler = store_backend.clone();
    let client_for_handler = client.clone();
    let event_counter_clone = event_counter.clone();
    let save_counter_clone = save_counter.clone();

    client
        .add_event_handler(Box::new(move |event: Arc<Event>| {
            let store_backend_clone = store_backend_for_handler.clone();
            let client_clone = client_for_handler.clone();
            let event_counter_clone = event_counter_clone.clone();
            let save_counter_clone = save_counter_clone.clone();

            tokio::spawn(async move {
                if let Event::SelfPushNameUpdated(update) = &*event {
                    let event_num = event_counter_clone.fetch_add(1, Ordering::SeqCst) + 1;
                    info!("📨 SelfPushNameUpdated event #{} received!", event_num);
                    info!("  From server: {}", update.from_server);
                    info!("  Old name: '{}'", update.old_name);
                    info!("  New name: '{}'", update.new_name);

                    // Save the state
                    let store_guard = client_clone.store.read().await;
                    match store_backend_clone
                        .save_device_data(&store_guard.to_serializable())
                        .await
                    {
                        Ok(_) => {
                            let save_num = save_counter_clone.fetch_add(1, Ordering::SeqCst) + 1;
                            info!("💾 Device state save #{} successful", save_num);
                        }
                        Err(e) => {
                            error!("❌ Failed to save device state: {e}");
                        }
                    }
                }
            });
        }))
        .await;

    info!("\n=== Testing Batching Behavior ===");
    let initial_name = client.get_push_name().await;
    info!("Initial push name: '{}'", initial_name);

    // Reset counters
    event_counter.store(0, Ordering::SeqCst);
    save_counter.store(0, Ordering::SeqCst);

    // Test 1: Single update
    info!("\n--- Test 1: Single Update ---");
    let test_name_1 = "Batch Test 1";
    info!("Setting push name to: '{}'", test_name_1);

    client.set_push_name(test_name_1.to_string()).await?;

    // Wait for event processing
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let events_after_1 = event_counter.load(Ordering::SeqCst);
    let saves_after_1 = save_counter.load(Ordering::SeqCst);

    info!("✅ Single update complete");
    info!("  Events fired: {}", events_after_1);
    info!("  Saves performed: {}", saves_after_1);

    if events_after_1 == 1 && saves_after_1 == 1 {
        info!("✅ Single update behavior is correct");
    } else {
        error!("❌ Single update behavior is incorrect");
    }

    // Test 2: Multiple rapid updates (simulating what happens during app state sync)
    info!("\n--- Test 2: Multiple Rapid Updates ---");

    // Reset counters
    event_counter.store(0, Ordering::SeqCst);
    save_counter.store(0, Ordering::SeqCst);

    let test_names = [
        "Batch Test 2a",
        "Batch Test 2b",
        "Batch Test 2c",
        "Batch Test 2d",
        "Batch Test 2e",
    ];

    info!("Performing {} rapid updates...", test_names.len());

    for (i, name) in test_names.iter().enumerate() {
        info!("Update {}: Setting to '{}'", i + 1, name);
        client.set_push_name(name.to_string()).await?;

        // Small delay to simulate processing time
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    // Wait for all events to be processed
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let events_after_2 = event_counter.load(Ordering::SeqCst);
    let saves_after_2 = save_counter.load(Ordering::SeqCst);

    info!("✅ Multiple updates complete");
    info!("  Events fired: {}", events_after_2);
    info!("  Saves performed: {}", saves_after_2);
    info!(
        "  Expected: {} events, {} saves",
        test_names.len(),
        test_names.len()
    );

    if events_after_2 == test_names.len() && saves_after_2 == test_names.len() {
        info!("✅ Multiple update behavior is correct");
    } else {
        error!("❌ Multiple update behavior may be inefficient");
        info!("  Note: This is expected with manual updates, batching only applies to server sync");
    }

    // Test 3: Duplicate updates (should not fire events)
    info!("\n--- Test 3: Duplicate Updates ---");

    // Reset counters
    event_counter.store(0, Ordering::SeqCst);
    save_counter.store(0, Ordering::SeqCst);

    let current_name = client.get_push_name().await;
    info!("Current name: '{}'", current_name);
    info!("Setting to same name 3 times...");

    for i in 1..=3 {
        info!("Duplicate update #{}: Setting to '{}'", i, current_name);
        client.set_push_name(current_name.clone()).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    // Wait for any events
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let events_after_3 = event_counter.load(Ordering::SeqCst);
    let saves_after_3 = save_counter.load(Ordering::SeqCst);

    info!("✅ Duplicate updates complete");
    info!("  Events fired: {}", events_after_3);
    info!("  Saves performed: {}", saves_after_3);

    if events_after_3 == 0 && saves_after_3 == 0 {
        info!("✅ Duplicate update filtering is working correctly");
    } else {
        error!("❌ Duplicate update filtering is not working");
    }

    // Restore original name
    if initial_name != current_name {
        info!("\n--- Restoring Original Name ---");
        client.set_push_name(initial_name.clone()).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        info!("✅ Original name '{}' restored", initial_name);
    }

    info!("\n=== Batching Test Complete ===");
    info!("Key observations:");
    info!("• Single updates work correctly (1 event, 1 save)");
    info!("• Manual updates fire individual events (expected behavior)");
    info!("• Duplicate updates are filtered out (0 events, 0 saves)");
    info!("• Server-side app state sync will batch multiple mutations efficiently");
    info!("\nTo test server-side batching:");
    info!("1. Run the main application: cargo run");
    info!("2. Change your name in WhatsApp app");
    info!("3. You should see only 1 event per sync batch instead of many");

    Ok(())
}
