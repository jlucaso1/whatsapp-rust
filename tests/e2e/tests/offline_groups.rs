use e2e_tests::{TestClient, text_msg};
use log::info;
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
                    || matches!(e, Event::Notification(node) if node.attrs.get("type").is_some_and(|v| v == "w:gp2"))
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
