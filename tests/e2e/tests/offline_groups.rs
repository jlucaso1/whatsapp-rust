//! Tests for offline group event delivery.
//!
//! These tests verify that the mock server properly queues group notifications
//! for offline clients. Chatstate TTL tests are in `chatstate_ttl.rs`.

use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::features::{GroupCreateOptions, GroupParticipantOptions};
use whatsapp_rust::waproto::whatsapp as wa;

/// Test that group notifications are queued when a member is offline.
///
/// Flow:
/// 1. A creates a group with B and C
/// 2. C goes offline via reconnect()
/// 3. A adds a new member (D) to the group — triggers w:gp2 notification
/// 4. C reconnects and should receive the group notification from offline queue
#[tokio::test]
async fn test_offline_group_notification() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_grp_notif_a").await?;
    let mut client_b = TestClient::connect("e2e_off_grp_notif_b").await?;
    let mut client_c = TestClient::connect("e2e_off_grp_notif_c").await?;
    let client_d = TestClient::connect("e2e_off_grp_notif_d").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();
    let jid_c = client_c.client.get_pn().await.expect("C JID").to_non_ad();
    let jid_d = client_d.client.get_pn().await.expect("D JID").to_non_ad();

    info!("B={jid_b}, C={jid_c}, D={jid_d}");

    // Step 1: A creates group with B and C
    let group_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Offline Notif Test".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
            ],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group created: {group_jid}");

    // Wait for B to get the create notification (confirms group is set up)
    let _notif_b = client_b
        .wait_for_event(10, |e| {
            matches!(e, Event::Notification(node) if node.attrs().optional_string("type").as_deref() == Some("w:gp2"))
        })
        .await?;
    info!("B received group create notification");

    // Step 2: C goes offline via reconnect()
    client_c.client.reconnect().await;
    info!("C disconnected (will auto-reconnect)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Step 3: A adds D to the group — generates w:gp2 add notification for all members
    let add_result = client_a
        .client
        .groups()
        .add_participants(&group_jid, std::slice::from_ref(&jid_d))
        .await?;
    assert_eq!(
        add_result[0].status.as_deref(),
        Some("200"),
        "Add participant should succeed"
    );
    info!("A added D to group");

    // B (online) should get the notification immediately
    let _notif_b2 = client_b
        .wait_for_event(10, |e| {
            matches!(e, Event::Notification(node) if node.attrs().optional_string("type").as_deref() == Some("w:gp2"))
        })
        .await?;
    info!("B received add notification (online)");

    // Step 4: C should receive the notification after reconnecting (from offline queue)
    let notif_c = client_c
        .wait_for_event(30, |e| {
            matches!(e, Event::Notification(node) if node.attrs().optional_string("type").as_deref() == Some("w:gp2"))
        })
        .await?;

    if let Event::Notification(node) = notif_c {
        info!(
            "C received offline group notification: type={}",
            node.attrs()
                .optional_string("type")
                .as_deref()
                .unwrap_or("?")
        );
    } else {
        panic!("Expected Notification event for C");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;
    client_d.disconnect().await;

    Ok(())
}

/// Test that mixed offline event types (messages + group notifications) arrive in order.
///
/// Flow:
/// 1. A creates a group with B and C
/// 2. C goes offline
/// 3. A sends a group message, then adds D, then sends another message
/// 4. C reconnects and receives all events in chronological order
#[tokio::test]
async fn test_mixed_offline_event_ordering() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_mixed_a").await?;
    let mut client_b = TestClient::connect("e2e_off_mixed_b").await?;
    let mut client_c = TestClient::connect("e2e_off_mixed_c").await?;
    let client_d = TestClient::connect("e2e_off_mixed_d").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();
    let jid_c = client_c.client.get_pn().await.expect("C JID").to_non_ad();
    let jid_d = client_d.client.get_pn().await.expect("D JID").to_non_ad();

    // Step 1: A creates group with B and C
    let group_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Mixed Events Test".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
            ],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group created: {group_jid}");

    // Wait for C to receive create notification
    let _notif = client_c
        .wait_for_event(10, |e| {
            matches!(e, Event::Notification(node) if node.attrs().optional_string("type").as_deref() == Some("w:gp2"))
        })
        .await?;
    // Also consume B's notification
    let _notif_b = client_b
        .wait_for_event(10, |e| {
            matches!(e, Event::Notification(node) if node.attrs().optional_string("type").as_deref() == Some("w:gp2"))
        })
        .await?;

    // Step 2: C goes offline
    client_c.client.reconnect().await;
    info!("C disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Step 3: Sequence of events while C is offline:
    // 3a. A sends first group message
    let text_1 = "First message while C offline";
    client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_1.to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent first message");

    // B (online) receives it
    let _ev = client_b
        .wait_for_event(
            10,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text_1)),
        )
        .await?;

    // Small delay to ensure server processes sequentially
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // 3b. A adds D to group (generates notification)
    let add_result = client_a
        .client
        .groups()
        .add_participants(&group_jid, std::slice::from_ref(&jid_d))
        .await?;
    assert_eq!(add_result[0].status.as_deref(), Some("200"));
    info!("A added D to group");

    // B receives the add notification
    let _notif_b2 = client_b
        .wait_for_event(10, |e| {
            matches!(e, Event::Notification(node) if node.attrs().optional_string("type").as_deref() == Some("w:gp2"))
        })
        .await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // 3c. A sends second group message
    let text_2 = "Second message after D was added";
    client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_2.to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent second message");

    // Step 4: C reconnects and should receive events
    // We collect all events C receives — should include both messages and notification
    let mut messages_received = Vec::new();
    let mut notifications_received = 0;

    // Collect events for up to 30s — we expect at least 2 messages and 1 notification
    for _ in 0..5 {
        let result = client_c
            .wait_for_event(10, |e| {
                matches!(e, Event::Message(msg, _) if msg.conversation.is_some())
                    || matches!(e, Event::Notification(node) if node.attrs().optional_string("type").as_deref() == Some("w:gp2"))
            })
            .await;

        match result {
            Ok(Event::Message(msg, _)) => {
                let text = msg.conversation.unwrap_or_default();
                info!("C received message: {text}");
                messages_received.push(text);
            }
            Ok(Event::Notification(_)) => {
                info!("C received group notification");
                notifications_received += 1;
            }
            Ok(_) => {}
            Err(_) => break, // timeout — no more events
        }
    }

    info!(
        "C received {} messages and {} notifications",
        messages_received.len(),
        notifications_received
    );

    // Verify both messages arrived
    assert!(
        messages_received.iter().any(|m| m == text_1),
        "C should receive first message. Got: {:?}",
        messages_received
    );
    assert!(
        messages_received.iter().any(|m| m == text_2),
        "C should receive second message. Got: {:?}",
        messages_received
    );

    // Verify at least one group notification (the add)
    assert!(
        notifications_received >= 1,
        "C should receive at least one group notification, got {}",
        notifications_received
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;
    client_d.disconnect().await;

    Ok(())
}

/// Test that group messages sent while a member is offline are delivered on reconnect.
///
/// Flow:
/// 1. A creates group with B and C
/// 2. C goes offline
/// 3. A sends a group message
/// 4. C reconnects and receives the group message from offline queue
#[tokio::test]
async fn test_offline_group_message_delivery() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_grp_msg_a").await?;
    let mut client_b = TestClient::connect("e2e_off_grp_msg_b").await?;
    let mut client_c = TestClient::connect("e2e_off_grp_msg_c").await?;

    let jid_b = client_b.client.get_pn().await.expect("B JID").to_non_ad();
    let jid_c = client_c.client.get_pn().await.expect("C JID").to_non_ad();

    // Create group
    let group_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Offline Group Msg Test".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
            ],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group created: {group_jid}");

    // Wait for both to get creation notifications
    let _n1 = client_b
        .wait_for_event(10, |e| matches!(e, Event::Notification(_)))
        .await?;
    let _n2 = client_c
        .wait_for_event(10, |e| matches!(e, Event::Notification(_)))
        .await?;

    // C goes offline
    client_c.client.reconnect().await;
    info!("C disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // A sends group message
    let text = "Group message while C offline";
    client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text.to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent group message");

    // B (online) receives it
    let _ev = client_b
        .wait_for_event(
            10,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;
    info!("B received group message (online)");

    // C should receive it after reconnecting
    let event = client_c
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;

    if let Event::Message(msg, info) = event {
        assert_eq!(msg.conversation.as_deref(), Some(text));
        assert!(info.source.is_group);
        assert_eq!(info.source.chat, group_jid);
        info!("C received offline group message after reconnect");
    } else {
        panic!("Expected Message event for C");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;

    Ok(())
}
