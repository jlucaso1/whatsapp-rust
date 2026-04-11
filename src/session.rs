// Re-export from wacore — the canonical implementation lives there now.
pub use wacore::session::{SESSION_CHECK_BATCH_SIZE, SessionError, SessionManager, SessionResult};

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use wacore_binary::jid::Jid;

    fn make_jid(user: &str) -> Jid {
        Jid::pn(user)
    }

    #[tokio::test]
    async fn test_ensure_sessions_empty_list() {
        let manager = SessionManager::new();
        let result = manager
            .ensure_sessions(vec![], |_| false, |_| async { Ok(()) })
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ensure_sessions_all_have_sessions() {
        let manager = SessionManager::new();
        let jids = vec![make_jid("123"), make_jid("456")];

        let result = manager
            .ensure_sessions(
                jids,
                |_| true, // All have sessions
                |_| async { panic!("Should not fetch") },
            )
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_ensure_sessions_fetches_for_missing() {
        let manager = SessionManager::new();
        let jids = vec![make_jid("123"), make_jid("456")];
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fetch_count_clone = fetch_count.clone();

        let result = manager
            .ensure_sessions(
                jids,
                |_| false, // None have sessions
                move |batch| {
                    let count = fetch_count_clone.clone();
                    async move {
                        count.fetch_add(batch.len(), Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(fetch_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_concurrent_requests_deduplicated() {
        let manager = Arc::new(SessionManager::new());
        let fetch_count = Arc::new(AtomicUsize::new(0));

        // Spawn two concurrent ensure_sessions calls for the same JID
        let jid = make_jid("123");

        let manager1 = manager.clone();
        let manager2 = manager.clone();
        let fetch_count1 = fetch_count.clone();
        let fetch_count2 = fetch_count.clone();
        let jid1 = jid.clone();
        let jid2 = jid.clone();

        let handle1 = tokio::spawn(async move {
            manager1
                .ensure_sessions(
                    vec![jid1],
                    |_| false,
                    move |batch| {
                        let count = fetch_count1.clone();
                        async move {
                            // Simulate some processing time
                            tokio::time::sleep(Duration::from_millis(50)).await;
                            count.fetch_add(batch.len(), Ordering::SeqCst);
                            Ok(())
                        }
                    },
                )
                .await
        });

        // Small delay to ensure the first call starts processing
        tokio::time::sleep(Duration::from_millis(10)).await;

        let handle2 = tokio::spawn(async move {
            manager2
                .ensure_sessions(
                    vec![jid2],
                    |_| false,
                    move |batch| {
                        let count = fetch_count2.clone();
                        async move {
                            count.fetch_add(batch.len(), Ordering::SeqCst);
                            Ok(())
                        }
                    },
                )
                .await
        });

        let (r1, r2) = tokio::join!(handle1, handle2);
        assert!(r1.unwrap().is_ok());
        assert!(r2.unwrap().is_ok());

        // Only one fetch should have happened due to deduplication
        assert_eq!(fetch_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_batching() {
        let manager = SessionManager::new();

        // Create more JIDs than the batch size
        let jids: Vec<Jid> = (0..75).map(|i| make_jid(&i.to_string())).collect();
        let batch_count = Arc::new(AtomicUsize::new(0));
        let batch_count_clone = batch_count.clone();

        let result = manager
            .ensure_sessions(
                jids,
                |_| false,
                move |_batch| {
                    let count = batch_count_clone.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await;

        assert!(result.is_ok());
        // 75 JIDs should be processed in 2 batches (50 + 25)
        assert_eq!(batch_count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_error_propagation() {
        let manager = SessionManager::new();
        let jids = vec![make_jid("123")];

        let result = manager
            .ensure_sessions(
                jids,
                |_| false,
                |_| async { Err(anyhow::anyhow!("fetch failed")) },
            )
            .await;

        assert!(result.is_err());
        match result {
            Err(SessionError::FetchFailed(msg)) => {
                assert!(msg.contains("fetch failed"));
            }
            _ => panic!("Expected FetchFailed error"),
        }
    }

    /// Test: When session exists, it should NOT call the fetch function.
    /// This matches WhatsApp Web's behavior where existing sessions are skipped.
    #[tokio::test]
    async fn test_existing_session_prevents_fetch_whatsapp_web_compliant() {
        let manager = SessionManager::new();
        let jids = vec![make_jid("existing_session_user")];
        let fetch_called = Arc::new(AtomicUsize::new(0));
        let fetch_called_clone = fetch_called.clone();

        let result = manager
            .ensure_sessions(
                jids,
                |_| true, // Session exists - should skip
                move |_batch| {
                    let count = fetch_called_clone.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        panic!("Fetch should NOT be called when session exists!");
                    }
                },
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(
            fetch_called.load(Ordering::SeqCst),
            0,
            "Fetch should never be called for existing sessions"
        );
    }

    /// Test: Mixed scenario - only devices WITHOUT sessions get fetched.
    /// This matches WhatsApp Web's filtering logic.
    #[tokio::test]
    async fn test_mixed_sessions_only_fetches_missing_whatsapp_web_compliant() {
        let manager = SessionManager::new();
        let jids = vec![
            make_jid("has_session"),
            make_jid("no_session_1"),
            make_jid("no_session_2"),
        ];
        let fetched_jids = Arc::new(std::sync::Mutex::new(Vec::new()));
        let fetched_jids_clone = fetched_jids.clone();

        let result = manager
            .ensure_sessions(
                jids,
                |jid| jid.user == "has_session", // Only "has_session" has a session
                move |batch| {
                    let jids = fetched_jids_clone.clone();
                    let batch_users: Vec<String> =
                        batch.iter().map(|j| j.user.to_string()).collect();
                    async move {
                        jids.lock().unwrap().extend(batch_users);
                        Ok(())
                    }
                },
            )
            .await;

        assert!(result.is_ok());
        let fetched = fetched_jids.lock().unwrap();
        assert_eq!(
            fetched.len(),
            2,
            "Only 2 JIDs without sessions should be fetched"
        );
        assert!(
            fetched.contains(&"no_session_1".to_string()),
            "no_session_1 should be fetched"
        );
        assert!(
            fetched.contains(&"no_session_2".to_string()),
            "no_session_2 should be fetched"
        );
        assert!(
            !fetched.contains(&"has_session".to_string()),
            "has_session should NOT be fetched"
        );
    }

    /// Test: Primary device (device 0) session establishment behavior.
    /// Simulates the establish_primary_phone_session_immediate scenario.
    #[tokio::test]
    async fn test_primary_device_session_establishment_pattern() {
        let manager = SessionManager::new();

        // Case 1: Session already exists - should not fetch
        let primary_jid = Jid::pn("559999999999").with_device(0);
        let fetch_count = Arc::new(AtomicUsize::new(0));
        let fetch_count_clone = fetch_count.clone();

        let result = manager
            .ensure_sessions(
                vec![primary_jid.clone()],
                |_| true, // Session exists
                move |_| {
                    let count = fetch_count_clone.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await;

        assert!(result.is_ok());
        assert_eq!(
            fetch_count.load(Ordering::SeqCst),
            0,
            "Should not fetch when primary device session exists"
        );

        // Case 2: No session exists - should fetch
        let fetch_count2 = Arc::new(AtomicUsize::new(0));
        let fetch_count2_clone = fetch_count2.clone();

        let result2 = manager
            .ensure_sessions(
                vec![primary_jid],
                |_| false, // No session
                move |_| {
                    let count = fetch_count2_clone.clone();
                    async move {
                        count.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    }
                },
            )
            .await;

        assert!(result2.is_ok());
        assert_eq!(
            fetch_count2.load(Ordering::SeqCst),
            1,
            "Should fetch when primary device session does not exist"
        );
    }

    /// Test: Device 0 (primary phone) should always be device 0 after with_device(0)
    #[test]
    fn test_primary_phone_jid_always_device_zero() {
        // Phone number JID with device 0
        let pn = Jid::pn("559999999999");
        let primary = pn.with_device(0);
        assert_eq!(primary.device, 0, "Primary phone should have device 0");

        // Even if we start with a different device, with_device(0) should give device 0
        let companion = Jid::pn_device("559999999999", 33);
        let primary_from_companion = companion.with_device(0);
        assert_eq!(
            primary_from_companion.device, 0,
            "with_device(0) should always result in device 0"
        );

        // LID should work the same way
        let lid = Jid::lid("100000000000001");
        let lid_primary = lid.with_device(0);
        assert_eq!(lid_primary.device, 0, "LID primary should have device 0");
    }
}
