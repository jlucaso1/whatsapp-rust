use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::Jid;
use whatsapp_rust::NodeFilter;
use whatsapp_rust::features::{
    GroupCreateOptions, GroupParticipantOptions, MembershipApprovalMode,
};
use whatsapp_rust::waproto::whatsapp as wa;

/// Wait for a group message with specific text on a specific group.
async fn wait_for_group_message(
    client: &mut TestClient,
    group_jid: &Jid,
    expected_text: &str,
    timeout_secs: u64,
) -> anyhow::Result<Event> {
    let gid = group_jid.clone();
    let text = expected_text.to_string();
    client
        .wait_for_event(timeout_secs, move |e| {
            matches!(
                e,
                Event::Message(msg, info)
                if info.source.chat == gid
                    && msg.conversation.as_deref() == Some(text.as_str())
            )
        })
        .await
}

/// Wait for a w:gp2 notification on the given client.
async fn wait_for_group_notification(
    client: &mut TestClient,
    timeout_secs: u64,
) -> anyhow::Result<Event> {
    client
        .wait_for_event(timeout_secs, |e| {
            matches!(e, Event::Notification(node) if node.attrs.get("type").is_some_and(|v| v == "w:gp2"))
        })
        .await
}

/// Assert that waiting for an event correctly times out (not some other error).
fn assert_timeout_error(result: Result<Event, anyhow::Error>, context: &str) {
    match result {
        Ok(event) => panic!("{context}, but got event: {event:?}"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("Timed out"),
                "{context}: expected timeout error, got: {msg}"
            );
        }
    }
}

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
    let event = wait_for_group_message(&mut client_b, &group_jid, text_1, 30).await?;
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

    // Wait for w:gp2 add notification to propagate to B (invalidates B's cache)
    wait_for_group_notification(&mut client_b, 10).await?;
    info!("B received w:gp2 notification for add");

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
    let event_b = wait_for_group_message(&mut client_b, &group_jid, text_2, 30).await?;
    if let Event::Message(msg, _) = event_b {
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text_2),
            "B should receive the second group message"
        );
    } else {
        panic!("Expected Message event for B, got: {:?}", event_b);
    }

    let event_c = wait_for_group_message(&mut client_c, &group_jid, text_2, 30).await?;
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

    let event_a = wait_for_group_message(&mut client_a, &group_jid, text_3, 30).await?;
    if let Event::Message(msg, _) = event_a {
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text_3),
            "A should receive B's group message"
        );
    } else {
        panic!("Expected Message event for A, got: {:?}", event_a);
    }

    let event_c2 = wait_for_group_message(&mut client_c, &group_jid, text_3, 30).await?;
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

#[tokio::test]
async fn test_group_remove_member() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Connect three clients
    let mut client_a = TestClient::connect("e2e_grp_rm_a").await?;
    let mut client_b = TestClient::connect("e2e_grp_rm_b").await?;
    let mut client_c = TestClient::connect("e2e_grp_rm_c").await?;

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

    info!("B={jid_b}, C={jid_c}");

    // Step 1: A creates a group with B and C
    let create_result = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Remove Test Group".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
            ],
            ..Default::default()
        })
        .await?;

    let group_jid = create_result.gid;
    info!("Group created: {group_jid}");

    // Step 2: A sends a message — both B and C should receive it
    let text_before = "Before removal";
    client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_before.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event_b = wait_for_group_message(&mut client_b, &group_jid, text_before, 30).await?;
    if let Event::Message(msg, _) = event_b {
        assert_eq!(msg.conversation.as_deref(), Some(text_before));
    } else {
        panic!("Expected Message event for B, got: {:?}", event_b);
    }

    let event_c = wait_for_group_message(&mut client_c, &group_jid, text_before, 30).await?;
    if let Event::Message(msg, _) = event_c {
        assert_eq!(msg.conversation.as_deref(), Some(text_before));
    } else {
        panic!("Expected Message event for C, got: {:?}", event_c);
    }

    info!("Both B and C received the pre-removal message");

    // Step 3: A removes B from the group
    let remove_result = client_a
        .client
        .groups()
        .remove_participants(&group_jid, std::slice::from_ref(&jid_b))
        .await?;
    info!("Remove participants result: {:?}", remove_result);
    assert!(
        !remove_result.is_empty(),
        "Remove participants should return results"
    );
    assert_eq!(
        remove_result[0].status.as_deref(),
        Some("200"),
        "Remove participant should succeed with status 200"
    );

    // Wait for w:gp2 remove notification to propagate to C
    wait_for_group_notification(&mut client_c, 10).await?;
    info!("C received w:gp2 notification for remove");

    // Step 4: A sends a message after removing B — only C should receive it
    let text_after = "After B was removed";
    client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_after.to_string()),
                ..Default::default()
            },
        )
        .await?;

    // C should receive the message
    let event_c2 = wait_for_group_message(&mut client_c, &group_jid, text_after, 30).await?;
    if let Event::Message(msg, msg_info) = event_c2 {
        assert_eq!(msg.conversation.as_deref(), Some(text_after));
        assert!(msg_info.source.is_group);
        assert_eq!(msg_info.source.chat, group_jid);
    } else {
        panic!("Expected Message event for C, got: {:?}", event_c2);
    }

    // B should NOT receive the message — expect timeout
    let b_result = client_b
        .wait_for_event(3, |e| matches!(e, Event::Message(_, _)))
        .await;
    assert_timeout_error(
        b_result,
        "B should NOT receive messages after being removed from the group",
    );

    // Step 5: C sends a message — A should receive it, B should NOT
    let text_c = "C says hello after removal";
    client_c
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_c.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event_a = wait_for_group_message(&mut client_a, &group_jid, text_c, 30).await?;
    if let Event::Message(msg, _) = event_a {
        assert_eq!(msg.conversation.as_deref(), Some(text_c));
    } else {
        panic!("Expected Message event for A, got: {:?}", event_a);
    }

    let b_result2 = client_b
        .wait_for_event(3, |e| matches!(e, Event::Message(_, _)))
        .await;
    assert_timeout_error(
        b_result2,
        "B should NOT receive messages sent by C after being removed",
    );

    // Cleanup
    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;

    Ok(())
}

/// Helper to find a participant's admin status in group metadata by matching the user part of their JID.
fn find_participant_admin_status(
    metadata: &whatsapp_rust::features::GroupMetadata,
    target_jid: &Jid,
) -> Option<bool> {
    metadata.participants.iter().find_map(|p| {
        // Match by phone_number if available (LID addressing mode), or by JID user
        let matches = p
            .phone_number
            .as_ref()
            .is_some_and(|pn| pn.user == target_jid.user)
            || p.jid.user == target_jid.user;
        matches.then_some(p.is_admin)
    })
}

#[tokio::test]
async fn test_group_promote_and_demote_admin() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Connect two clients
    let client_a = TestClient::connect("e2e_grp_promo_a").await?;
    let client_b = TestClient::connect("e2e_grp_promo_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    info!("B={jid_b}");

    // Step 1: A creates a group with B
    let create_result = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Promote Test Group".to_string(),
            participants: vec![GroupParticipantOptions::new(jid_b.clone())],
            ..Default::default()
        })
        .await?;

    let group_jid = create_result.gid;
    info!("Group created: {group_jid}");

    // Step 2: Verify B is NOT an admin initially
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    let b_is_admin = find_participant_admin_status(&metadata, &jid_b);
    assert_eq!(
        b_is_admin,
        Some(false),
        "B should not be an admin initially"
    );
    info!("Confirmed B is not admin initially");

    // Step 3: A promotes B to admin
    client_a
        .client
        .groups()
        .promote_participants(&group_jid, std::slice::from_ref(&jid_b))
        .await?;
    info!("Promoted B to admin");

    // Step 4: Verify B is now an admin via metadata query
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    let b_is_admin = find_participant_admin_status(&metadata, &jid_b);
    assert_eq!(
        b_is_admin,
        Some(true),
        "B should be an admin after promotion"
    );
    info!("Confirmed B is admin after promotion");

    // Step 5: A demotes B from admin
    client_a
        .client
        .groups()
        .demote_participants(&group_jid, std::slice::from_ref(&jid_b))
        .await?;
    info!("Demoted B from admin");

    // Step 6: Verify B is no longer an admin
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    let b_is_admin = find_participant_admin_status(&metadata, &jid_b);
    assert_eq!(
        b_is_admin,
        Some(false),
        "B should not be an admin after demotion"
    );
    info!("Confirmed B is not admin after demotion");

    // Cleanup
    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_group_cache_invalidation_on_add() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_grp_cache_a").await?;
    let client_b = TestClient::connect("e2e_grp_cache_b").await?;
    let mut client_c = TestClient::connect("e2e_grp_cache_c").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B JID")
        .to_non_ad();
    let jid_c = client_c
        .client
        .get_pn()
        .await
        .expect("Client C JID")
        .to_non_ad();

    // Step 1: A creates group with B only
    let group_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Cache Invalidation Test".to_string(),
            participants: vec![GroupParticipantOptions::new(jid_b.clone())],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group created: {group_jid}");

    // Step 2: B sends a message to the group — this caches group info for B
    let text_1 = "B's first message";
    client_b
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_1.to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("B sent first message (caching group info)");

    // A receives it
    let event_a = wait_for_group_message(&mut client_a, &group_jid, text_1, 30).await?;
    if let Event::Message(msg, _) = event_a {
        assert_eq!(msg.conversation.as_deref(), Some(text_1));
    } else {
        panic!("Expected Message event for A");
    }

    // Register a node waiter on B BEFORE the add, so no w:gp2 notification is missed.
    let notification_waiter = client_b
        .client
        .wait_for_node(NodeFilter::tag("notification").attr("type", "w:gp2"));

    // Step 3: A adds C to the group
    let add_result = client_a
        .client
        .groups()
        .add_participants(&group_jid, std::slice::from_ref(&jid_c))
        .await?;
    assert_eq!(add_result[0].status.as_deref(), Some("200"));
    info!("A added C to group");

    // Wait for B to receive the w:gp2 add notification (invalidates B's sender key cache)
    let _notification =
        tokio::time::timeout(tokio::time::Duration::from_secs(10), notification_waiter)
            .await
            .map_err(|_| anyhow::anyhow!("Timed out waiting for w:gp2 notification on B"))?
            .map_err(|_| anyhow::anyhow!("Notification waiter channel closed"))?;
    info!("B received w:gp2 notification for add");

    // Step 4: B sends another message — C should receive it
    // This proves B's group cache was invalidated by the add notification
    let text_2 = "B's message after C was added";
    client_b
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_2.to_string()),
                ..Default::default()
            },
        )
        .await?;
    info!("B sent second message");

    // C should receive the message
    let event_c = wait_for_group_message(&mut client_c, &group_jid, text_2, 30).await?;
    if let Event::Message(msg, msg_info) = event_c {
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text_2),
            "C should receive B's message after being added"
        );
        assert!(msg_info.source.is_group);
        assert_eq!(msg_info.source.chat, group_jid);
    } else {
        panic!("Expected Message event for C");
    }

    // A should also receive it
    let event_a2 = wait_for_group_message(&mut client_a, &group_jid, text_2, 30).await?;
    if let Event::Message(msg, _) = event_a2 {
        assert_eq!(msg.conversation.as_deref(), Some(text_2));
    } else {
        panic!("Expected Message event for A");
    }

    // Cleanup
    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_group_settings() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_grp_settings_a").await?;
    let client_b = TestClient::connect("e2e_grp_settings_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B JID")
        .to_non_ad();

    // Create group
    let group_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Settings Test Group".to_string(),
            participants: vec![GroupParticipantOptions::new(jid_b.clone())],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group created: {group_jid}");

    // Verify initial state
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert!(!metadata.is_locked, "Group should not be locked initially");
    assert!(
        !metadata.is_announcement,
        "Announcement should be off initially"
    );
    assert_eq!(
        metadata.ephemeral_expiration, 0,
        "Ephemeral should be disabled initially"
    );
    assert!(
        !metadata.membership_approval,
        "Membership approval should be off initially"
    );
    info!("Verified initial settings");

    // Test locked
    client_a
        .client
        .groups()
        .set_locked(&group_jid, true)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert!(
        metadata.is_locked,
        "Group should be locked after set_locked(true)"
    );
    info!("Group locked - verified");

    client_a
        .client
        .groups()
        .set_locked(&group_jid, false)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert!(
        !metadata.is_locked,
        "Group should be unlocked after set_locked(false)"
    );
    info!("Group unlocked - verified");

    // Test announcement mode
    client_a
        .client
        .groups()
        .set_announce(&group_jid, true)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert!(
        metadata.is_announcement,
        "Announcement should be on after set_announce(true)"
    );
    info!("Announcement mode enabled - verified");

    client_a
        .client
        .groups()
        .set_announce(&group_jid, false)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert!(
        !metadata.is_announcement,
        "Announcement should be off after set_announce(false)"
    );
    info!("Announcement mode disabled - verified");

    // Test ephemeral messages
    client_a
        .client
        .groups()
        .set_ephemeral(&group_jid, 86400)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert_eq!(
        metadata.ephemeral_expiration, 86400,
        "Ephemeral should be 24h after set_ephemeral(86400)"
    );
    info!("Ephemeral set to 24h - verified");

    client_a
        .client
        .groups()
        .set_ephemeral(&group_jid, 604800)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert_eq!(
        metadata.ephemeral_expiration, 604800,
        "Ephemeral should be 7d after set_ephemeral(604800)"
    );
    info!("Ephemeral set to 7d - verified");

    client_a
        .client
        .groups()
        .set_ephemeral(&group_jid, 0)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert_eq!(
        metadata.ephemeral_expiration, 0,
        "Ephemeral should be disabled after set_ephemeral(0)"
    );
    info!("Ephemeral disabled - verified");

    // Test membership approval mode
    client_a
        .client
        .groups()
        .set_membership_approval(&group_jid, MembershipApprovalMode::On)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert!(
        metadata.membership_approval,
        "Membership approval should be on"
    );
    info!("Membership approval enabled - verified");

    client_a
        .client
        .groups()
        .set_membership_approval(&group_jid, MembershipApprovalMode::Off)
        .await?;
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    assert!(
        !metadata.membership_approval,
        "Membership approval should be off"
    );
    info!("Membership approval disabled - verified");

    // Cleanup
    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_group_leave() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Connect three clients
    let mut client_a = TestClient::connect("e2e_grp_leave_a").await?;
    let mut client_b = TestClient::connect("e2e_grp_leave_b").await?;
    let mut client_c = TestClient::connect("e2e_grp_leave_c").await?;

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

    info!("B={jid_b}, C={jid_c}");

    // Step 1: A creates a group with B and C
    let create_result = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Leave Test Group".to_string(),
            participants: vec![
                GroupParticipantOptions::new(jid_b.clone()),
                GroupParticipantOptions::new(jid_c.clone()),
            ],
            ..Default::default()
        })
        .await?;

    let group_jid = create_result.gid;
    info!("Group created: {group_jid}");

    // Step 2: A sends a message — both B and C should receive it
    let text_before = "Before B leaves";
    client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_before.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event_b = wait_for_group_message(&mut client_b, &group_jid, text_before, 30).await?;
    if let Event::Message(msg, _) = event_b {
        assert_eq!(msg.conversation.as_deref(), Some(text_before));
    } else {
        panic!("Expected Message event for B, got: {:?}", event_b);
    }

    let event_c = wait_for_group_message(&mut client_c, &group_jid, text_before, 30).await?;
    if let Event::Message(msg, _) = event_c {
        assert_eq!(msg.conversation.as_deref(), Some(text_before));
    } else {
        panic!("Expected Message event for C, got: {:?}", event_c);
    }

    info!("Both B and C received the pre-leave message");

    // Step 3: B leaves the group
    client_b.client.groups().leave(&group_jid).await?;
    info!("B left the group");

    // Wait for w:gp2 remove notification to propagate to A
    wait_for_group_notification(&mut client_a, 10).await?;
    info!("A received w:gp2 notification for B's leave");

    // Step 4: A sends a message after B left — only C should receive it
    let text_after = "After B left";
    client_a
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_after.to_string()),
                ..Default::default()
            },
        )
        .await?;

    // C should receive the message
    let event_c2 = wait_for_group_message(&mut client_c, &group_jid, text_after, 30).await?;
    if let Event::Message(msg, msg_info) = event_c2 {
        assert_eq!(msg.conversation.as_deref(), Some(text_after));
        assert!(msg_info.source.is_group);
        assert_eq!(msg_info.source.chat, group_jid);
    } else {
        panic!("Expected Message event for C, got: {:?}", event_c2);
    }

    // B should NOT receive the message — expect timeout
    let b_result = client_b
        .wait_for_event(3, |e| matches!(e, Event::Message(_, _)))
        .await;
    assert_timeout_error(
        b_result,
        "B should NOT receive messages after leaving the group",
    );

    // Step 5: C sends a message — A should receive it, B should NOT
    let text_c = "C says hello after B left";
    client_c
        .client
        .send_message(
            group_jid.clone(),
            wa::Message {
                conversation: Some(text_c.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event_a = wait_for_group_message(&mut client_a, &group_jid, text_c, 30).await?;
    if let Event::Message(msg, _) = event_a {
        assert_eq!(msg.conversation.as_deref(), Some(text_c));
    } else {
        panic!("Expected Message event for A, got: {:?}", event_a);
    }

    let b_result2 = client_b
        .wait_for_event(3, |e| matches!(e, Event::Message(_, _)))
        .await;
    assert_timeout_error(
        b_result2,
        "B should NOT receive messages sent by C after leaving",
    );

    // Cleanup
    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;

    Ok(())
}
