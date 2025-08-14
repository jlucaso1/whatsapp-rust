// Example demonstrating SQLite backend usage
use std::sync::Arc;
use whatsapp_rust::store::persistence_manager::PersistenceManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    println!("WhatsApp-Rust SQLite Backend Demo");
    println!("=================================");

    // Example 1: Using SQLite backend
    println!("\n1. Creating PersistenceManager with SQLite backend...");
    let pm_sqlite = Arc::new(
        PersistenceManager::new_sqlite("demo.db")
            .await
            .expect("Failed to create SQLite PersistenceManager"),
    );

    // Modify device data
    pm_sqlite
        .modify_device(|device| {
            device.push_name = "SQLite Demo Device".to_string();
        })
        .await;

    // Save the changes
    pm_sqlite
        .save_now()
        .await
        .expect("Failed to save device data");

    let device = pm_sqlite.get_device_snapshot().await;
    println!("SQLite device push_name: '{}'", device.push_name);

    // Example 2: Using FileStore backend (existing functionality)
    println!("\n2. Creating PersistenceManager with FileStore backend...");
    let pm_file = Arc::new(
        PersistenceManager::new("./demo_filestore")
            .await
            .expect("Failed to create FileStore PersistenceManager"),
    );

    pm_file
        .modify_device(|device| {
            device.push_name = "FileStore Demo Device".to_string();
        })
        .await;

    pm_file
        .save_now()
        .await
        .expect("Failed to save device data");

    let device_file = pm_file.get_device_snapshot().await;
    println!("FileStore device push_name: '{}'", device_file.push_name);

    // Example 3: In-memory backend (no persistence)
    println!("\n3. Creating PersistenceManager with in-memory backend...");
    let pm_memory = Arc::new(
        PersistenceManager::new_in_memory()
            .await
            .expect("Failed to create in-memory PersistenceManager"),
    );

    pm_memory
        .modify_device(|device| {
            device.push_name = "Memory Demo Device".to_string();
        })
        .await;

    let device_memory = pm_memory.get_device_snapshot().await;
    println!("Memory device push_name: '{}'", device_memory.push_name);

    // Example 4: Demonstrate persistence across sessions
    println!("\n4. Testing persistence across sessions...");

    // Create new SQLite manager with same database
    let pm_sqlite2 = Arc::new(
        PersistenceManager::new_sqlite("demo.db")
            .await
            .expect("Failed to create second SQLite PersistenceManager"),
    );

    let persisted_device = pm_sqlite2.get_device_snapshot().await;
    println!(
        "Persisted device push_name from previous session: '{}'",
        persisted_device.push_name
    );

    if persisted_device.push_name == "SQLite Demo Device" {
        println!("✅ Data successfully persisted in SQLite database!");
    } else {
        println!("❌ Data persistence failed");
    }

    println!("\nDemo completed successfully!");
    println!("Files created:");
    println!("  - demo.db (SQLite database)");
    println!("  - demo_filestore/ (FileStore directory)");

    Ok(())
}
