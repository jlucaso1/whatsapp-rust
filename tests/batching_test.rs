use log::{error, info};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use whatsapp_rust::client::Client;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

#[tokio::test]
async fn batching_test() -> Result<(), anyhow::Error> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    info!("=== WhatsApp Rust Batching Test Utility (with PersistenceManager) ===");

    let pm = match PersistenceManager::new_in_memory().await {
        Ok(manager) => Arc::new(manager),
        Err(e) => {
            error!("Failed to initialize PersistenceManager: {e}");
            return Err(e.into());
        }
    };
    let pm_clone_for_saver = pm.clone();
    tokio::spawn(async move {
        pm_clone_for_saver.run_background_saver(Duration::from_secs(5));
    });

    let client = Arc::new(Client::new(pm.clone()).await);

    let event_counter = Arc::new(AtomicUsize::new(0));

    let event_counter_clone = event_counter.clone();
    let mut self_push_name_rx = client.subscribe_to_self_push_name_updated();
    tokio::spawn(async move {
        while let Ok(update) = self_push_name_rx.recv().await {
            let event_num = event_counter_clone.fetch_add(1, Ordering::SeqCst) + 1;
            info!("📨 SelfPushNameUpdated event #{event_num} received!");
            info!("  From server: {}", update.from_server);
            info!("  Old name: '{}'", update.old_name);
            info!("  New name: '{}'", update.new_name);
        }
    });

    info!("\n=== Testing Batching Behavior (Event Counts with PersistenceManager) ===");
    let initial_name = client.get_push_name().await;
    info!("Initial push name: '{initial_name}'");

    event_counter.store(0, Ordering::SeqCst);

    info!("\n--- Test 1: Single Update ---");
    let test_name_1 = "Batch Test 1";
    info!("Setting push name to: '{test_name_1}'");

    client.set_push_name(test_name_1.to_string()).await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let events_after_1 = event_counter.load(Ordering::SeqCst);

    info!("✅ Single update complete");
    info!("  Events fired: {events_after_1}");

    if events_after_1 == 1 {
        info!("✅ Single update event behavior is correct");
    } else {
        error!(
            "❌ Single update event behavior is incorrect (expected 1 event, got {events_after_1})"
        );
    }

    info!("\n--- Test 2: Multiple Rapid Updates ---");

    event_counter.store(0, Ordering::SeqCst);

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

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;

    let events_after_2 = event_counter.load(Ordering::SeqCst);

    info!("✅ Multiple updates complete");
    info!("  Events fired: {events_after_2}");
    info!("  Expected: {} events", test_names.len());

    if events_after_2 == test_names.len() {
        info!("✅ Multiple update event behavior is correct");
    } else {
        error!(
            "❌ Multiple update event behavior is incorrect (expected {} events, got {})",
            test_names.len(),
            events_after_2
        );
        info!("  Note: This is expected with manual updates, batching only applies to server sync");
    }

    info!("\n--- Test 3: Duplicate Updates ---");

    event_counter.store(0, Ordering::SeqCst);

    let current_name = client.get_push_name().await;
    info!("Current name: '{current_name}'");
    info!("Setting to same name 3 times...");

    for i in 1..=3 {
        info!("Duplicate update #{i}: Setting to '{current_name}'");
        client.set_push_name(current_name.clone()).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
    }

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

    let events_after_3 = event_counter.load(Ordering::SeqCst);

    info!("✅ Duplicate updates complete");
    info!("  Events fired: {events_after_3}");

    if events_after_3 == 0 {
        info!("✅ Duplicate update filtering is working correctly (0 events fired)");
    } else {
        error!(
            "❌ Duplicate update filtering is not working (expected 0 events, got {events_after_3})"
        );
    }

    if initial_name != current_name {
        info!("\n--- Restoring Original Name ---");
        client.set_push_name(initial_name.clone()).await?;
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        info!("✅ Original name '{initial_name}' restored");
    }

    info!("\n=== Batching Test Complete (with PersistenceManager) ===");
    info!("Key observations:");
    info!("• Single updates fire 1 event (saves handled by PM).");
    info!("• Manual updates fire individual events (expected behavior, saves by PM).");
    info!(
        "• Duplicate updates are filtered out (0 events fired, saves by PM if initial state was different)."
    );
    info!("• Server-side app state sync will batch multiple mutations efficiently");
    info!("\nTo test server-side batching:");
    info!("1. Run the main application: cargo run");
    info!("2. Change your name in WhatsApp app");
    info!("3. You should see only 1 event per sync batch instead of many");

    Ok(())
}
