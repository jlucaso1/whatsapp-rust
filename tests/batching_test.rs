use log::{error, info};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::persistence_manager::PersistenceManager; // Use PersistenceManager
                                                                   // use whatsapp_rust::store; // Not needed directly
                                                                   // use whatsapp_rust::store::filestore::FileStore; // Handled by PM
use std::time::Duration;
use whatsapp_rust::types::events::Event;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=== WhatsApp Rust Batching Test Utility (with PersistenceManager) ===");

    let pm = match PersistenceManager::new("./whatsapp_store_batch_test").await {
        Ok(manager) => Arc::new(manager),
        Err(e) => {
            error!("Failed to initialize PersistenceManager: {}", e);
            return Err(e.into());
        }
    };
    // Start background saver for PM, with a short interval for testing if desired,
    // but the test mainly focuses on event counts now.
    let pm_clone_for_saver = pm.clone();
    tokio::spawn(async move {
        pm_clone_for_saver.run_background_saver(Duration::from_secs(5));
    });

    let client = Arc::new(Client::new(pm.clone()));

    // Counter to track how many events we receive
    let event_counter = Arc::new(AtomicUsize::new(0));
    // let save_counter = Arc::new(AtomicUsize::new(0)); // PersistenceManager handles saves

    // Add event handler to count events
    let event_counter_clone = event_counter.clone();
    // let save_counter_clone = save_counter.clone(); // Not needed

    client
        .add_event_handler(Box::new(move |event: Arc<Event>| {
            let event_counter_clone = event_counter_clone.clone();
            // let save_counter_clone = save_counter_clone.clone(); // Not needed

            tokio::spawn(async move {
                if let Event::SelfPushNameUpdated(update) = &*event {
                    let event_num = event_counter_clone.fetch_add(1, Ordering::SeqCst) + 1;
                    info!("📨 SelfPushNameUpdated event #{} received!", event_num);
                    info!("  From server: {}", update.from_server);
                    info!("  Old name: '{}'", update.old_name);
                    info!("  New name: '{}'", update.new_name);

                    // PersistenceManager handles saving automatically.
                    // We could log when the PM saves if needed for debugging, but not counting manual saves here.
                    // info!("💾 PM will handle saving if state is dirty.");
                }
            });
        }))
        .await;

    info!("\n=== Testing Batching Behavior (Event Counts with PersistenceManager) ===");
    let initial_name = client.get_push_name().await;
    info!("Initial push name: '{}'", initial_name);

    // Reset counters
    event_counter.store(0, Ordering::SeqCst);
    // save_counter.store(0, Ordering::SeqCst); // Removed

    // Test 1: Single update
    info!("\n--- Test 1: Single Update ---");
    let test_name_1 = "Batch Test 1";
    info!("Setting push name to: '{}'", test_name_1);

    client.set_push_name(test_name_1.to_string()).await?;

    // Wait for event processing & potential save by PM
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await; // Increased delay slightly

    let events_after_1 = event_counter.load(Ordering::SeqCst);
    // let saves_after_1 = save_counter.load(Ordering::SeqCst); // Removed

    info!("✅ Single update complete");
    info!("  Events fired: {}", events_after_1);
    // info!("  Saves performed by PM: (background task, not directly counted)"); // Adjusted log

    if events_after_1 == 1 {
        // Check only events
        info!("✅ Single update event behavior is correct");
    } else {
        error!(
            "❌ Single update event behavior is incorrect (expected 1 event, got {})",
            events_after_1
        );
    }

    // Test 2: Multiple rapid updates (simulating what happens during app state sync)
    info!("\n--- Test 2: Multiple Rapid Updates ---");

    // Reset counters
    event_counter.store(0, Ordering::SeqCst);
    // save_counter.store(0, Ordering::SeqCst); // Removed

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
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await; // Increased delay slightly

    let events_after_2 = event_counter.load(Ordering::SeqCst);
    // let saves_after_2 = save_counter.load(Ordering::SeqCst); // Removed

    info!("✅ Multiple updates complete");
    info!("  Events fired: {}", events_after_2);
    // info!("  Saves performed by PM: (background task, not directly counted)"); // Adjusted log
    info!(
        "  Expected: {} events", // Removed saves from expected log
        test_names.len()
    );

    if events_after_2 == test_names.len() {
        // Check only events
        info!("✅ Multiple update event behavior is correct");
    } else {
        error!(
            "❌ Multiple update event behavior is incorrect (expected {} events, got {})",
            test_names.len(),
            events_after_2
        );
        info!("  Note: This is expected with manual updates, batching only applies to server sync");
    }

    // Test 3: Duplicate updates (should not fire events)
    info!("\n--- Test 3: Duplicate Updates ---");

    // Reset counters
    event_counter.store(0, Ordering::SeqCst);
    // save_counter.store(0, Ordering::SeqCst); // Removed

    let current_name = client.get_push_name().await;
    info!("Current name: '{}'", current_name);
    info!("Setting to same name 3 times...");

    for i in 1..=3 {
        info!("Duplicate update #{}: Setting to '{}'", i, current_name);
        client.set_push_name(current_name.clone()).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    // Wait for any events
    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await; // Increased delay slightly

    let events_after_3 = event_counter.load(Ordering::SeqCst);
    // let saves_after_3 = save_counter.load(Ordering::SeqCst); // Removed

    info!("✅ Duplicate updates complete");
    info!("  Events fired: {}", events_after_3);
    // info!("  Saves performed by PM: (background task, not directly counted)"); // Adjusted log

    if events_after_3 == 0 {
        // Check only events
        info!("✅ Duplicate update filtering is working correctly (0 events fired)");
    } else {
        error!(
            "❌ Duplicate update filtering is not working (expected 0 events, got {})",
            events_after_3
        );
    }

    // Restore original name
    if initial_name != current_name {
        info!("\n--- Restoring Original Name ---");
        client.set_push_name(initial_name.clone()).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await; // Increased delay
        info!("✅ Original name '{}' restored", initial_name);
    }

    info!("\n=== Batching Test Complete (with PersistenceManager) ===");
    info!("Key observations:");
    info!("• Single updates fire 1 event (saves handled by PM).");
    info!("• Manual updates fire individual events (expected behavior, saves by PM).");
    info!("• Duplicate updates are filtered out (0 events fired, saves by PM if initial state was different).");
    info!("• Server-side app state sync will batch multiple mutations efficiently");
    info!("\nTo test server-side batching:");
    info!("1. Run the main application: cargo run");
    info!("2. Change your name in WhatsApp app");
    info!("3. You should see only 1 event per sync batch instead of many");

    Ok(())
}
