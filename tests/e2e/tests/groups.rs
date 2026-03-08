use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::features::{GroupCreateOptions, GroupParticipantOptions};
use whatsapp_rust::waproto::whatsapp as wa;

#[tokio::test]
async fn test_group_create_send_message_and_add_member() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Connect three clients
    let mut client_a = TestClient::connect("e2e_group_a").await?;
    let mut client_b = TestClient::connect("e2e_group_b").await?;
    let mut client_c = TestClient::connect("e2e_group_c").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("Client A should have a JID")
        .to_non_ad();
    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();
    let jid_c = client_c
        .client
        .get_pn()
        .await
        .expect("Client C should have a JID")
        .to_non_ad();

    info!("A={jid_a}, B={jid_b}, C={jid_c}");

    // Step 1: Client A creates a group with only B
    let create_result = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "E2E Test Group".to_string(),
            participants: vec![GroupParticipantOptions::new(jid_b.clone())],
            ..Default::default()
        })
        .await?;

    let group_jid = create_result.gid;
    info!("Group created: {group_jid}");

    // Step 2: Client A sends a message to the group
    let text_1 = "Hello group from A!";
    let msg_id = client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_1.to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent group message: {msg_id}");

    // Step 3: Client B should receive the group message
    let event = client_b
        .wait_for_event(30, |e| matches!(e, Event::Message(_, _)))
        .await?;
    if let Event::Message(msg, msg_info) = event {
        info!("B received group message from {:?}", msg_info.source);
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text_1),
            "B should receive the correct message text"
        );
        assert!(
            msg_info.source.is_group,
            "Message should be marked as group message"
        );
        assert_eq!(
            msg_info.source.chat, group_jid,
            "Message chat should be the group JID"
        );
    } else {
        panic!("Expected Message event, got: {:?}", event);
    }

    // Step 4: Client A adds Client C to the group
    let add_result = client_a
        .client
        .groups()
        .add_participants(&group_jid, std::slice::from_ref(&jid_c))
        .await?;
    info!("Add participants result: {:?}", add_result);
    assert!(
        !add_result.is_empty(),
        "Add participants should return results"
    );
    assert_eq!(
        add_result[0].status.as_deref(),
        Some("200"),
        "Add participant should succeed with status 200"
    );

    // Give a moment for notifications to propagate to all clients
    tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

    // Step 5: Client A sends a message after adding C
    let text_2 = "Welcome C to the group!";
    let msg_id_2 = client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_2.to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("A sent second group message: {msg_id_2}");

    // Step 6: Both B and C should receive the second message
    let event_b = client_b
        .wait_for_event(30, |e| matches!(e, Event::Message(_, _)))
        .await?;
    if let Event::Message(msg, _) = event_b {
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text_2),
            "B should receive the second group message"
        );
    } else {
        panic!("Expected Message event for B, got: {:?}", event_b);
    }

    let event_c = client_c
        .wait_for_event(30, |e| matches!(e, Event::Message(_, _)))
        .await?;
    if let Event::Message(msg, msg_info) = event_c {
        info!("C received group message from {:?}", msg_info.source);
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text_2),
            "C should receive the second group message"
        );
        assert!(
            msg_info.source.is_group,
            "C's message should be marked as group message"
        );
        assert_eq!(
            msg_info.source.chat, group_jid,
            "C's message chat should be the group JID"
        );
    } else {
        panic!("Expected Message event for C, got: {:?}", event_c);
    }

    // Step 7: Client B sends a message — all participants (A and C) should receive it
    let text_3 = "B says hi to everyone!";
    client_b
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_3.to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("B sent group message");

    let event_a = client_a
        .wait_for_event(30, |e| matches!(e, Event::Message(_, _)))
        .await?;
    if let Event::Message(msg, _) = event_a {
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text_3),
            "A should receive B's group message"
        );
    } else {
        panic!("Expected Message event for A, got: {:?}", event_a);
    }

    let event_c2 = client_c
        .wait_for_event(30, |e| matches!(e, Event::Message(_, _)))
        .await?;
    if let Event::Message(msg, _) = event_c2 {
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text_3),
            "C should receive B's group message"
        );
    } else {
        panic!("Expected Message event for C, got: {:?}", event_c2);
    }

    // Cleanup
    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;

    Ok(())
}
