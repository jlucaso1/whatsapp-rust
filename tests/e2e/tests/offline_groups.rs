use e2e_tests::{TestClient, text_msg};
use log::info;
use std::collections::HashSet;
use wacore::types::events::Event;
use whatsapp_rust::features::{GroupCreateOptions, GroupParticipantOptions};

#[tokio::test]
async fn test_offline_group_notification() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_grp_notif_a").await?;
    let mut client_b = TestClient::connect("e2e_off_grp_notif_b").await?;
    let mut client_c = TestClient::connect("e2e_off_grp_notif_c").await?;
    let client_d = TestClient::connect("e2e_off_grp_notif_d").await?;

    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;
    let jid_d = client_d.jid().await;

    info!("B={jid_b}, C={jid_c}, D={jid_d}");

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

    // Drain create notifications before testing offline delivery
    client_b.wait_for_group_notification(10).await?;
    client_c.wait_for_group_notification(10).await?;
    info!("B and C received group create notification");

    client_c.client.reconnect().await;
    info!("C disconnected (will auto-reconnect)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

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

    client_b.wait_for_group_notification(10).await?;
    info!("B received add notification (online)");

    // C should receive the notification after reconnecting (from offline queue)
    client_c.wait_for_group_notification(30).await?;
    info!("C received offline group notification");

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;
    client_d.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_mixed_offline_event_ordering() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_mixed_a").await?;
    let mut client_b = TestClient::connect("e2e_off_mixed_b").await?;
    let mut client_c = TestClient::connect("e2e_off_mixed_c").await?;
    let client_d = TestClient::connect("e2e_off_mixed_d").await?;

    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;
    let jid_d = client_d.jid().await;

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

    client_c.wait_for_group_notification(10).await?;
    client_b.wait_for_group_notification(10).await?;

    client_c.client.reconnect().await;
    info!("C disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let text_1 = "First message while C offline";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_1))
        .await?;
    info!("A sent first message");

    client_b.wait_for_text(text_1, 10).await?;

    // Small delay to ensure server processes sequentially
    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    // A adds D to group
    let add_result = client_a
        .client
        .groups()
        .add_participants(&group_jid, std::slice::from_ref(&jid_d))
        .await?;
    assert_eq!(add_result[0].status.as_deref(), Some("200"));
    info!("A added D to group");

    client_b.wait_for_group_notification(10).await?;

    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

    let text_2 = "Second message after D was added";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_2))
        .await?;
    info!("A sent second message");

    // Collect all events C receives after reconnecting
    let mut messages_received = Vec::new();
    let mut notifications_received = 0;
    for _ in 0..5 {
        let result = client_c
            .wait_for_event(10, |e| {
                matches!(e, Event::Message(msg, _) if msg.conversation.is_some())
                    || matches!(e, Event::Notification(node) if node.get_attr("type").is_some_and(|v| v.as_str() == "w:gp2"))
            })
            .await;

        match result {
            Ok(ref event) if let Some((msg, _)) = event.as_message() => {
                let text = msg.conversation.clone().unwrap_or_default();
                info!("C received message: {text}");
                messages_received.push(text);
            }
            Ok(ref event) if matches!(**event, Event::Notification(_)) => {
                info!("C received group notification");
                notifications_received += 1;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    info!(
        "C received {} messages and {} notifications",
        messages_received.len(),
        notifications_received
    );

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

#[tokio::test]
async fn test_offline_group_message_delivery() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_off_grp_msg_a").await?;
    let mut client_b = TestClient::connect("e2e_off_grp_msg_b").await?;
    let mut client_c = TestClient::connect("e2e_off_grp_msg_c").await?;

    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;

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

    client_b.wait_for_group_notification(10).await?;
    client_c.wait_for_group_notification(10).await?;

    client_c.client.reconnect().await;
    info!("C disconnected");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    let text = "Group message while C offline";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text))
        .await?;
    info!("A sent group message");

    client_b.wait_for_text(text, 10).await?;
    info!("B received group message (online)");

    // C should receive it after reconnecting (from offline queue)
    let event = client_c.wait_for_text(text, 30).await?;
    if let Event::Message(msg, info) = &*event {
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

/// Regression test for the semaphore transition bug during offline→online sync.
///
/// When a device comes back online, the message processing semaphore transitions from
/// 1 permit (sequential) to 64 permits (concurrent). Messages that were waiting on
/// the old semaphore used to be silently dropped. If the dropped message was a pkmsg
/// carrying a sender key distribution message (SKDM), ALL subsequent group messages
/// from that sender would fail with "No sender key state".
///
/// This test reproduces the scenario:
/// 1. Multiple senders send messages across multiple groups while a device is offline
/// 2. The first message from each new sender contains pkmsg+skmsg (SKDM + content)
/// 3. Subsequent messages from the same sender contain only skmsg
/// 4. After reconnection, ALL messages must be decrypted — none silently dropped
#[tokio::test]
async fn test_offline_multi_sender_group_messages() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Create 3 senders (A, D, E) and 1 receiver (C), plus an online observer (B)
    let client_a = TestClient::connect("e2e_off_multi_a").await?;
    let mut client_b = TestClient::connect("e2e_off_multi_b").await?;
    let mut client_c = TestClient::connect("e2e_off_multi_c").await?;
    let client_d = TestClient::connect("e2e_off_multi_d").await?;
    let client_e = TestClient::connect("e2e_off_multi_e").await?;

    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;
    let jid_d = client_d.jid().await;
    let jid_e = client_e.jid().await;

    info!("B={jid_b}, C={jid_c}, D={jid_d}, E={jid_e}");

    // Create two groups to increase message volume during offline sync
    let group1_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Multi-Sender Group 1".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
                GroupParticipantOptions::new(jid_d.clone()),
                GroupParticipantOptions::new(jid_e.clone()),
            ],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group 1 created: {group1_jid}");

    let group2_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Multi-Sender Group 2".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
                GroupParticipantOptions::new(jid_d.clone()),
            ],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group 2 created: {group2_jid}");

    // Drain group creation notifications for all participants
    for _ in 0..2 {
        client_b.wait_for_group_notification(10).await?;
    }
    for _ in 0..2 {
        client_c.wait_for_group_notification(10).await?;
    }
    info!("All participants received group creation notifications");

    // Take C offline. We use reconnect() (NOT reconnect_and_wait()) because we
    // need C to be offline while messages are sent. reconnect() triggers a
    // disconnect + background auto-reconnect; the 100ms sleep gives the server
    // time to detect the TCP close and start queuing messages for C.
    // This is the standard offline simulation pattern used by all offline tests.
    client_c.client.reconnect().await;
    info!("C disconnected (will auto-reconnect)");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    // Send multiple messages from multiple senders across both groups while C is offline.
    // This creates the conditions for the semaphore transition bug:
    // - Multiple groups → multiple per-chat queues
    // - Multiple senders → pkmsg required for first message from each sender to C
    // - The pkmsg carries the SKDM; if dropped, all subsequent skmsg from that sender fail

    let mut expected_messages = Vec::new();

    // A sends 3 messages to group 1
    for i in 1..=3 {
        let text = format!("A-g1-msg{i}");
        client_a
            .client
            .send_message(group1_jid.clone(), text_msg(&text))
            .await?;
        expected_messages.push(text);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }

    // D sends 3 messages to group 1
    for i in 1..=3 {
        let text = format!("D-g1-msg{i}");
        client_d
            .client
            .send_message(group1_jid.clone(), text_msg(&text))
            .await?;
        expected_messages.push(text);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }

    // A sends 2 messages to group 2
    for i in 1..=2 {
        let text = format!("A-g2-msg{i}");
        client_a
            .client
            .send_message(group2_jid.clone(), text_msg(&text))
            .await?;
        expected_messages.push(text);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }

    // D sends 2 messages to group 2
    for i in 1..=2 {
        let text = format!("D-g2-msg{i}");
        client_d
            .client
            .send_message(group2_jid.clone(), text_msg(&text))
            .await?;
        expected_messages.push(text);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }

    // E sends 2 messages to group 1
    for i in 1..=2 {
        let text = format!("E-g1-msg{i}");
        client_e
            .client
            .send_message(group1_jid.clone(), text_msg(&text))
            .await?;
        expected_messages.push(text);
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;
    }

    info!("Sent {} messages while C offline", expected_messages.len());

    // Verify B receives all messages (sanity check that sends worked)
    let mut b_received = 0;
    for _ in 0..expected_messages.len() {
        if client_b
            .wait_for_event(
                10,
                |e| matches!(e, Event::Message(msg, _) if msg.conversation.is_some()),
            )
            .await
            .is_ok()
        {
            b_received += 1;
        }
    }
    info!("B received {b_received} messages (online observer)");

    // Wait for C to reconnect and receive ALL messages from the offline queue.
    // Use an overall deadline rather than fixed attempt count to tolerate
    // duplicate deliveries, extra notifications, and variable reconnect time.
    let mut received_texts: HashSet<String> = HashSet::new();
    let total_expected = expected_messages.len();
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_secs(60);

    while tokio::time::Instant::now() < deadline {
        let remaining = deadline - tokio::time::Instant::now();
        let timeout_secs = remaining.as_secs().max(1);

        let result = client_c
            .wait_for_event(timeout_secs, |e| {
                matches!(e, Event::Message(msg, _) if msg.conversation.is_some())
                    || matches!(e, Event::Notification(node) if node.get_attr("type").is_some_and(|v| v.as_str() == "w:gp2"))
            })
            .await;

        match result {
            Ok(ref event) if let Some((msg, _)) = event.as_message() => {
                if let Some(text) = &msg.conversation {
                    info!("C received: {text}");
                    received_texts.insert(text.clone());
                }
            }
            Ok(ref event) if matches!(**event, Event::Notification(_)) => {}
            Ok(_) => {}
            Err(_) => break,
        }

        // Early exit once all expected messages are collected
        if received_texts.len() >= total_expected {
            break;
        }
    }

    info!(
        "C received {}/{} messages after reconnect",
        received_texts.len(),
        total_expected
    );

    // Assert ALL messages were received — the critical assertion.
    // If the semaphore transition bug is present, messages from one or more senders
    // will be missing because their pkmsg (carrying the SKDM) was silently dropped.
    let mut missing = Vec::new();
    for expected in &expected_messages {
        if !received_texts.contains(expected) {
            missing.push(expected.clone());
        }
    }

    assert!(
        missing.is_empty(),
        "C is missing {} messages after offline sync: {:?}\nReceived: {:?}",
        missing.len(),
        missing,
        received_texts
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;
    client_d.disconnect().await;
    client_e.disconnect().await;

    Ok(())
}
