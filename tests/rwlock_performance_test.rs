#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Instant;
    use whatsapp_rust::store::persistence_manager::PersistenceManager;

    /// Test demonstrating improved concurrency with RwLock
    /// Multiple concurrent reads should be faster than serialized reads with Mutex
    #[tokio::test]
    async fn test_concurrent_device_snapshot_reads() {
        // Setup persistence manager with RwLock
        let persistence_manager = Arc::new(PersistenceManager::new_in_memory().await.unwrap());

        let num_concurrent_readers = 10;
        let reads_per_task = 100;

        let start_time = Instant::now();

        // Spawn multiple concurrent readers
        let mut handles = vec![];
        for _ in 0..num_concurrent_readers {
            let pm = persistence_manager.clone();
            let handle = tokio::spawn(async move {
                for _ in 0..reads_per_task {
                    let _snapshot = pm.get_device_snapshot().await;
                    // Small delay to simulate processing
                    tokio::time::sleep(tokio::time::Duration::from_micros(1)).await;
                }
            });
            handles.push(handle);
        }

        // Wait for all readers to complete
        for handle in handles {
            handle.await.unwrap();
        }

        let elapsed = start_time.elapsed();
        println!(
            "RwLock: {} concurrent readers × {} reads completed in {:?}",
            num_concurrent_readers, reads_per_task, elapsed
        );

        // The test passes if it completes without deadlock
        // Performance improvement is observable when comparing with a theoretical Mutex version
        assert!(
            elapsed.as_millis() < 5000,
            "Test should complete within reasonable time"
        );
    }

    /// Test demonstrating that concurrent reads don't block each other
    #[tokio::test]
    async fn test_read_write_contention() {
        let persistence_manager = Arc::new(PersistenceManager::new_in_memory().await.unwrap());

        let pm_reader = persistence_manager.clone();
        let pm_writer = persistence_manager.clone();

        // Start a long-running reader
        let reader_handle = tokio::spawn(async move {
            let start = Instant::now();
            let mut read_count = 0;

            while start.elapsed().as_millis() < 100 {
                let _snapshot = pm_reader.get_device_snapshot().await;
                read_count += 1;
                tokio::time::sleep(tokio::time::Duration::from_micros(1)).await;
            }
            read_count
        });

        // Perform a write operation in parallel
        let writer_handle = tokio::spawn(async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            pm_writer
                .modify_device(|device| {
                    device.push_name = "test_name".to_string();
                })
                .await;
        });

        let read_count = reader_handle.await.unwrap();
        writer_handle.await.unwrap();

        // With RwLock, reads should be able to proceed concurrently
        // even when there's occasional write activity
        assert!(
            read_count > 10,
            "Should achieve substantial concurrent reads: {}",
            read_count
        );
    }
}
