//! Tests for message handling functionality.
//!
//! This module contains comprehensive tests for:
//! - Message parsing
//! - Session decryption
//! - Sender key handling
//! - Retry logic
//! - LID-PN cache behavior

use crate::client::Client;
use crate::store::SqliteStore;
use crate::store::persistence_manager::PersistenceManager;
use crate::test_utils::MockHttpClient;
use crate::types::message::MessageInfo;
use rand::TryRngCore;
use std::sync::Arc;
use wacore::types::message::{HIGH_RETRY_COUNT_THRESHOLD, MAX_DECRYPT_RETRIES};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::{Jid, JidExt};

fn mock_transport() -> Arc<dyn crate::transport::TransportFactory> {
    Arc::new(crate::transport::mock::MockTransportFactory::new())
}

fn mock_http_client() -> Arc<dyn crate::http::HttpClient> {
    Arc::new(MockHttpClient)
}

#[tokio::test]
async fn test_parse_message_info_for_status_broadcast() {
    // 1. Setup
    let backend = Arc::new(
        SqliteStore::new("file:memdb_status_test?mode=memory&cache=shared")
            .await
            .expect("Failed to create test backend"),
    );
    let pm = Arc::new(
        PersistenceManager::new(backend)
            .await
            .expect("test backend should initialize"),
    );
    let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

    let participant_jid_str = "556899336555:42@s.whatsapp.net";
    let status_broadcast_jid_str = "status@broadcast";

    // 2. Create the test node mirroring the logs
    let node = NodeBuilder::new("message")
        .attr("from", status_broadcast_jid_str)
        .attr("id", "8A8CCCC7E6E466D9EE8CA11A967E485A")
        .attr("participant", participant_jid_str)
        .attr("t", "1759295366")
        .attr("type", "media")
        .build();

    // 3. Run the function under test
    let info = client
        .parse_message_info(&node)
        .await
        .expect("parse_message_info should not fail");

    // 4. Assert the correct behavior
    let expected_sender: Jid = participant_jid_str
        .parse()
        .expect("test JID should be valid");
    let expected_chat: Jid = status_broadcast_jid_str
        .parse()
        .expect("test JID should be valid");

    assert_eq!(
        info.source.sender, expected_sender,
        "The sender should be the 'participant' JID, not 'status@broadcast'"
    );
    assert_eq!(
        info.source.chat, expected_chat,
        "The chat should be 'status@broadcast'"
    );
    assert!(
        info.source.is_group,
        "Broadcast messages should be treated as group-like"
    );
}

#[tokio::test]
async fn test_process_session_enc_batch_handles_session_not_found_gracefully() {
    use wacore::libsignal::protocol::{IdentityKeyPair, KeyPair, SignalMessage};

    // 1. Setup
    let backend = Arc::new(
        SqliteStore::new("file:memdb_graceful_fail?mode=memory&cache=shared")
            .await
            .expect("Failed to create test backend"),
    );
    let pm = Arc::new(
        PersistenceManager::new(backend)
            .await
            .expect("test backend should initialize"),
    );
    let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;

    let sender_jid: Jid = "1234567890@s.whatsapp.net"
        .parse()
        .expect("test JID should be valid");
    let info = MessageInfo {
        source: crate::types::message::MessageSource {
            sender: sender_jid.clone(),
            chat: sender_jid.clone(),
            ..Default::default()
        },
        ..Default::default()
    };

    // 2. Create a valid but undecryptable SignalMessage (encrypted with a dummy key)
    let dummy_key = [0u8; 32];
    let sender_ratchet = KeyPair::generate(&mut rand::rngs::OsRng.unwrap_err()).public_key;
    let sender_identity_pair = IdentityKeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
    let receiver_identity_pair = IdentityKeyPair::generate(&mut rand::rngs::OsRng.unwrap_err());
    let signal_message = SignalMessage::new(
        4,
        &dummy_key,
        sender_ratchet,
        0,
        0,
        b"test",
        sender_identity_pair.identity_key(),
        receiver_identity_pair.identity_key(),
    )
    .expect("SignalMessage::new should succeed with valid inputs");

    let enc_node = NodeBuilder::new("enc")
        .attr("type", "msg")
        .bytes(signal_message.serialized().to_vec())
        .build();
    let enc_nodes = vec![&enc_node];

    // 3. Run the function under test
    // The function now returns (any_success, any_duplicate, dispatched_undecryptable).
    // With a SessionNotFound error, it should return (false, false, true) since it dispatches an event.
    let (success, had_duplicates, dispatched) = client
        .process_session_enc_batch(&enc_nodes, &info, &sender_jid)
        .await;

    // 4. Assert the desired behavior: the function continues gracefully
    // The function should return (false, false, true) (no successful decryption, no duplicates, but dispatched event)
    assert!(
        !success && !had_duplicates && dispatched,
        "process_session_enc_batch should return (false, false, true) when SessionNotFound occurs and dispatches event"
    );

    // Note: Verifying event dispatch would require adding a test event handler.
    // For this test, we're just ensuring the function doesn't panic and returns the correct status.
}

// ==================== RETRY LOGIC TESTS ====================

/// Helper to create a test MessageInfo with customizable fields
fn create_test_message_info(chat: &str, msg_id: &str, sender: &str) -> MessageInfo {
    use wacore::types::message::{EditAttribute, MessageSource, MsgMetaInfo};

    let chat_jid: Jid = chat.parse().expect("valid chat JID");
    let sender_jid: Jid = sender.parse().expect("valid sender JID");

    MessageInfo {
        id: msg_id.to_string(),
        server_id: 0,
        r#type: "text".to_string(),
        source: MessageSource {
            chat: chat_jid.clone(),
            sender: sender_jid,
            sender_alt: None,
            recipient_alt: None,
            is_from_me: false,
            is_group: chat_jid.is_group(),
            addressing_mode: None,
            broadcast_list_owner: None,
            recipient: None,
        },
        timestamp: chrono::Utc::now(),
        push_name: "Test User".to_string(),
        category: "".to_string(),
        multicast: false,
        media_type: "".to_string(),
        edit: EditAttribute::default(),
        bot_info: None,
        meta_info: MsgMetaInfo::default(),
        verified_name: None,
        device_sent_meta: None,
    }
}

/// Helper to create a test client for retry tests with a unique database
async fn create_test_client_for_retry_with_id(test_id: &str) -> Arc<Client> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let unique_id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let db_name = format!(
        "file:memdb_retry_{}_{}_{}?mode=memory&cache=shared",
        test_id,
        unique_id,
        std::process::id()
    );

    let backend = Arc::new(
        SqliteStore::new(&db_name)
            .await
            .expect("Failed to create test backend"),
    );
    let pm = Arc::new(
        PersistenceManager::new(backend)
            .await
            .expect("test backend should initialize"),
    );
    let (client, _sync_rx) = Client::new(pm, mock_transport(), mock_http_client(), None).await;
    client
}

#[tokio::test]
async fn test_increment_retry_count_starts_at_one() {
    let client = create_test_client_for_retry_with_id("starts_at_one").await;

    let cache_key = "test_chat:msg123:sender456";

    // First increment should return 1
    let count = client.increment_retry_count(cache_key).await;
    assert_eq!(count, Some(1), "First retry should be count 1");

    // Verify it's stored in cache
    let stored = client.message_retry_counts.get(cache_key).await;
    assert_eq!(stored, Some(1), "Cache should store count 1");
}

#[tokio::test]
async fn test_increment_retry_count_increments_correctly() {
    let client = create_test_client_for_retry_with_id("increments").await;

    let cache_key = "test_chat:msg456:sender789";

    // Simulate multiple retries
    let count1 = client.increment_retry_count(cache_key).await;
    let count2 = client.increment_retry_count(cache_key).await;
    let count3 = client.increment_retry_count(cache_key).await;

    assert_eq!(count1, Some(1), "First retry should be 1");
    assert_eq!(count2, Some(2), "Second retry should be 2");
    assert_eq!(count3, Some(3), "Third retry should be 3");
}

#[tokio::test]
async fn test_increment_retry_count_respects_max_retries() {
    let client = create_test_client_for_retry_with_id("max_retries").await;

    let cache_key = "test_chat:msg_max:sender_max";

    // Exhaust all retries (MAX_DECRYPT_RETRIES = 5)
    for i in 1..=5 {
        let count = client.increment_retry_count(cache_key).await;
        assert_eq!(count, Some(i), "Retry {} should return {}", i, i);
    }

    // 6th attempt should return None (max reached)
    let count_after_max = client.increment_retry_count(cache_key).await;
    assert_eq!(
        count_after_max, None,
        "After max retries, should return None"
    );

    // Verify cache still has max value
    let stored = client.message_retry_counts.get(cache_key).await;
    assert_eq!(stored, Some(5), "Cache should retain max count");
}

#[tokio::test]
async fn test_retry_count_different_messages_are_independent() {
    let client = create_test_client_for_retry_with_id("independent").await;

    let key1 = "chat1:msg1:sender1";
    let key2 = "chat1:msg2:sender1"; // Same chat and sender, different message
    let key3 = "chat2:msg1:sender2"; // Different chat and sender

    // Increment each independently
    let _ = client.increment_retry_count(key1).await;
    let _ = client.increment_retry_count(key1).await;
    let _ = client.increment_retry_count(key1).await; // key1 = 3

    let _ = client.increment_retry_count(key2).await; // key2 = 1

    let _ = client.increment_retry_count(key3).await;
    let _ = client.increment_retry_count(key3).await; // key3 = 2

    // Verify each has independent counts
    assert_eq!(client.message_retry_counts.get(key1).await, Some(3));
    assert_eq!(client.message_retry_counts.get(key2).await, Some(1));
    assert_eq!(client.message_retry_counts.get(key3).await, Some(2));
}

#[tokio::test]
async fn test_retry_cache_key_format() {
    // Verify the cache key format is consistent
    let info = create_test_message_info(
        "120363021033254949@g.us",
        "3EB0ABCD1234",
        "5511999998888@s.whatsapp.net",
    );

    let expected_key = format!("{}:{}:{}", info.source.chat, info.id, info.source.sender);
    assert_eq!(
        expected_key,
        "120363021033254949@g.us:3EB0ABCD1234:5511999998888@s.whatsapp.net"
    );

    // Verify key uniqueness for different senders in same group
    let info2 = create_test_message_info(
        "120363021033254949@g.us",
        "3EB0ABCD1234",                 // Same message ID
        "5511888887777@s.whatsapp.net", // Different sender
    );

    let key2 = format!("{}:{}:{}", info2.source.chat, info2.id, info2.source.sender);
    assert_ne!(
        expected_key, key2,
        "Different senders should have different keys"
    );
}

#[tokio::test]
async fn test_high_retry_count_threshold() {
    // Verify HIGH_RETRY_COUNT_THRESHOLD is set correctly
    assert_eq!(
        HIGH_RETRY_COUNT_THRESHOLD, 3,
        "High retry threshold should be 3"
    );
    assert_eq!(MAX_DECRYPT_RETRIES, 5, "Max retries should be 5");
    // Compile-time assertion that threshold < max (avoids clippy warning)
    const _: () = assert!(HIGH_RETRY_COUNT_THRESHOLD < MAX_DECRYPT_RETRIES);
}

/// Test: Status broadcast messages should always try skmsg even if pkmsg fails
#[test]
fn test_status_broadcast_should_always_process_skmsg() {
    // status@broadcast JID
    let status_jid: Jid = "status@broadcast".parse().expect("status JID should parse");
    assert!(
        status_jid.is_status_broadcast(),
        "status@broadcast should be recognized as status broadcast"
    );

    // Regular broadcast list should NOT be status broadcast
    let broadcast_list: Jid = "123456789@broadcast"
        .parse()
        .expect("broadcast JID should parse");
    assert!(
        !broadcast_list.is_status_broadcast(),
        "Regular broadcast list should not be status broadcast"
    );
    assert!(
        broadcast_list.is_broadcast_list(),
        "123456789@broadcast should be broadcast list"
    );

    // Group JID should NOT be status broadcast
    let group_jid: Jid = "120363021033254949@g.us"
        .parse()
        .expect("group JID should parse");
    assert!(
        !group_jid.is_status_broadcast(),
        "Group JID should not be status broadcast"
    );

    // 1:1 JID should NOT be status broadcast
    let user_jid: Jid = "15551234567@s.whatsapp.net"
        .parse()
        .expect("user JID should parse");
    assert!(
        !user_jid.is_status_broadcast(),
        "User JID should not be status broadcast"
    );
}

/// Test: Verify should_process_skmsg logic for status broadcast
#[test]
fn test_should_process_skmsg_logic_for_status_broadcast() {
    // Test cases: (chat_jid, session_empty, session_success, session_dupe, expected)
    let test_cases = [
        // Status broadcast: always process skmsg
        ("status@broadcast", false, false, false, true),
        ("status@broadcast", false, false, true, true),
        ("status@broadcast", false, true, false, true),
        ("status@broadcast", true, false, false, true),
        // Regular group: only process if session ok or empty
        ("120363021033254949@g.us", false, false, false, false), // Fail: session failed
        ("120363021033254949@g.us", false, false, true, true),   // OK: duplicate
        ("120363021033254949@g.us", false, true, false, true),   // OK: success
        ("120363021033254949@g.us", true, false, false, true),   // OK: no session msgs
        // 1:1 chat: same logic as group
        ("15551234567@s.whatsapp.net", false, false, false, false),
        ("15551234567@s.whatsapp.net", true, false, false, true),
    ];

    for (jid_str, session_empty, session_success, session_dupe, expected) in test_cases {
        let chat_jid: Jid = jid_str.parse().expect("JID should parse");

        // Recreate the should_process_skmsg logic from handle_encrypted_message
        let should_process_skmsg =
            session_empty || session_success || session_dupe || chat_jid.is_status_broadcast();

        assert_eq!(
            should_process_skmsg,
            expected,
            "For chat {} with session_empty={}, session_success={}, session_dupe={}: \
             expected should_process_skmsg={}, got {}",
            jid_str,
            session_empty,
            session_success,
            session_dupe,
            expected,
            should_process_skmsg
        );
    }
}
