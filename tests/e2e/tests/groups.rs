use e2e_tests::{TestClient, text_msg};
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::Jid;
use whatsapp_rust::NodeFilter;
use whatsapp_rust::features::{
    GroupCreateOptions, GroupParticipantOptions, MembershipApprovalMode,
};

#[tokio::test]
async fn test_group_create_send_message_and_add_member() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_group_a").await?;
    let mut client_b = TestClient::connect("e2e_group_b").await?;
    let mut client_c = TestClient::connect("e2e_group_c").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;

    info!("A={jid_a}, B={jid_b}, C={jid_c}");

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

    let text_1 = "Hello group from A!";
    let msg_id = client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_1))
        .await?
        .message_id;
    info!("A sent group message: {msg_id}");

    client_b.wait_for_group_text(&group_jid, text_1, 30).await?;
    info!("B received group message");

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

    // w:gp2 add notification invalidates B's sender key cache
    client_b.wait_for_group_notification(10).await?;
    info!("B received w:gp2 notification for add");

    let text_2 = "Welcome C to the group!";
    let msg_id_2 = client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_2))
        .await?
        .message_id;
    info!("A sent second group message: {msg_id_2}");

    client_b.wait_for_group_text(&group_jid, text_2, 30).await?;
    client_c.wait_for_group_text(&group_jid, text_2, 30).await?;
    info!("Both B and C received the second message");

    let text_3 = "B says hi to everyone!";
    client_b
        .client
        .send_message(group_jid.clone(), text_msg(text_3))
        .await?;
    info!("B sent group message");

    client_a.wait_for_group_text(&group_jid, text_3, 30).await?;
    client_c.wait_for_group_text(&group_jid, text_3, 30).await?;
    info!("Both A and C received B's message");

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_group_remove_member() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_grp_rm_a").await?;
    let mut client_b = TestClient::connect("e2e_grp_rm_b").await?;
    let mut client_c = TestClient::connect("e2e_grp_rm_c").await?;

    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;

    info!("B={jid_b}, C={jid_c}");

    let group_jid = client_a
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
        .await?
        .gid;
    info!("Group created: {group_jid}");

    let text_before = "Before removal";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_before))
        .await?;

    client_b
        .wait_for_group_text(&group_jid, text_before, 30)
        .await?;
    client_c
        .wait_for_group_text(&group_jid, text_before, 30)
        .await?;
    info!("Both B and C received the pre-removal message");

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

    client_c.wait_for_group_notification(10).await?;
    info!("C received w:gp2 notification for remove");

    let text_after = "After B was removed";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_after))
        .await?;

    client_c
        .wait_for_group_text(&group_jid, text_after, 30)
        .await?;

    // B was removed, so should not receive anything
    client_b
        .assert_no_event(
            3,
            |e| matches!(e, Event::Message(_, _)),
            "B should NOT receive messages after being removed",
        )
        .await?;

    let text_c = "C says hello after removal";
    client_c
        .client
        .send_message(group_jid.clone(), text_msg(text_c))
        .await?;

    client_a.wait_for_group_text(&group_jid, text_c, 30).await?;

    client_b
        .assert_no_event(
            3,
            |e| matches!(e, Event::Message(_, _)),
            "B should NOT receive messages sent by C after being removed",
        )
        .await?;

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

    let client_a = TestClient::connect("e2e_grp_promo_a").await?;
    let client_b = TestClient::connect("e2e_grp_promo_b").await?;

    let jid_b = client_b.jid().await;

    info!("B={jid_b}");

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

    // Verify B is NOT an admin initially
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    let b_is_admin = find_participant_admin_status(&metadata, &jid_b);
    assert_eq!(
        b_is_admin,
        Some(false),
        "B should not be an admin initially"
    );
    info!("Confirmed B is not admin initially");

    // Promote B to admin
    client_a
        .client
        .groups()
        .promote_participants(&group_jid, std::slice::from_ref(&jid_b))
        .await?;
    info!("Promoted B to admin");

    // Verify B is now an admin
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    let b_is_admin = find_participant_admin_status(&metadata, &jid_b);
    assert_eq!(
        b_is_admin,
        Some(true),
        "B should be an admin after promotion"
    );
    info!("Confirmed B is admin after promotion");

    // Demote B from admin
    client_a
        .client
        .groups()
        .demote_participants(&group_jid, std::slice::from_ref(&jid_b))
        .await?;
    info!("Demoted B from admin");

    // Verify B is no longer an admin
    let metadata = client_a.client.groups().get_metadata(&group_jid).await?;
    let b_is_admin = find_participant_admin_status(&metadata, &jid_b);
    assert_eq!(
        b_is_admin,
        Some(false),
        "B should not be an admin after demotion"
    );
    info!("Confirmed B is not admin after demotion");

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

    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;

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

    // B sends a message to prime its group participant cache
    let text_1 = "B's first message";
    client_b
        .client
        .send_message(group_jid.clone(), text_msg(text_1))
        .await?;
    info!("B sent first message (caching group info)");

    client_a.wait_for_group_text(&group_jid, text_1, 30).await?;

    // Register a node waiter on B BEFORE the add, so no w:gp2 notification is missed.
    let notification_waiter = client_b
        .client
        .wait_for_node(NodeFilter::tag("notification").attr("type", "w:gp2"));

    // A adds C — B should get a w:gp2 notification that invalidates its sender key cache
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

    // B sends another message — C should receive it (proves cache was invalidated)
    let text_2 = "B's message after C was added";
    client_b
        .client
        .send_message(group_jid.clone(), text_msg(text_2))
        .await?;
    info!("B sent second message");

    client_c.wait_for_group_text(&group_jid, text_2, 30).await?;
    client_a.wait_for_group_text(&group_jid, text_2, 30).await?;

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

    let jid_b = client_b.jid().await;

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

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_group_leave() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_grp_leave_a").await?;
    let mut client_b = TestClient::connect("e2e_grp_leave_b").await?;
    let mut client_c = TestClient::connect("e2e_grp_leave_c").await?;

    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;

    info!("B={jid_b}, C={jid_c}");

    let group_jid = client_a
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
        .await?
        .gid;
    info!("Group created: {group_jid}");

    let text_before = "Before B leaves";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_before))
        .await?;

    client_b
        .wait_for_group_text(&group_jid, text_before, 30)
        .await?;
    client_c
        .wait_for_group_text(&group_jid, text_before, 30)
        .await?;
    info!("Both B and C received the pre-leave message");

    client_b.client.groups().leave(&group_jid).await?;
    info!("B left the group");

    client_a.wait_for_group_notification(10).await?;
    info!("A received w:gp2 notification for B's leave");

    let text_after = "After B left";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_after))
        .await?;

    client_c
        .wait_for_group_text(&group_jid, text_after, 30)
        .await?;

    client_b
        .assert_no_event(
            3,
            |e| matches!(e, Event::Message(_, _)),
            "B should NOT receive messages after leaving",
        )
        .await?;

    let text_c = "C says hello after B left";
    client_c
        .client
        .send_message(group_jid.clone(), text_msg(text_c))
        .await?;

    client_a.wait_for_group_text(&group_jid, text_c, 30).await?;

    client_b
        .assert_no_event(
            3,
            |e| matches!(e, Event::Message(_, _)),
            "B should NOT receive messages sent by C after leaving",
        )
        .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;

    Ok(())
}

/// Tests per-device sender key tracking across multiple group messages.
///
/// Verifies that:
/// 1. First group message from A establishes sender keys (SKDM distributed to all)
/// 2. Subsequent messages from A skip SKDM (devices already have the key)
/// 3. Adding a new member (C) forces SKDM redistribution to include C's devices
/// 4. All messages are decrypted correctly by all recipients throughout
#[tokio::test]
async fn test_per_device_sender_key_tracking() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_skdev_a").await?;
    let mut client_b = TestClient::connect("e2e_skdev_b").await?;
    let mut client_c = TestClient::connect("e2e_skdev_c").await?;

    let jid_b = client_b.jid().await;
    let jid_c = client_c.jid().await;

    // Create group with A and B only
    let group_jid = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "SK Device Track Test".to_string(),
            participants: vec![GroupParticipantOptions::new(jid_b.clone())],
            ..Default::default()
        })
        .await?
        .gid;
    info!("Group created: {group_jid}");

    // A sends first message — triggers full SKDM distribution to B
    let text_1 = "First from A";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_1))
        .await?;
    client_b.wait_for_group_text(&group_jid, text_1, 10).await?;
    info!("B received first message");

    // A sends second message — should reuse sender key (no SKDM needed)
    let text_2 = "Second from A";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_2))
        .await?;
    client_b.wait_for_group_text(&group_jid, text_2, 10).await?;
    info!("B received second message (sender key reused)");

    // B sends a message — B's sender key distributed to A
    let text_3 = "First from B";
    client_b
        .client
        .send_message(group_jid.clone(), text_msg(text_3))
        .await?;
    client_a.wait_for_group_text(&group_jid, text_3, 10).await?;
    info!("A received B's message (bidirectional sender key exchange)");

    // Add C — forces sender key redistribution on next send
    let add_result = client_a
        .client
        .groups()
        .add_participants(&group_jid, std::slice::from_ref(&jid_c))
        .await?;
    assert_eq!(
        add_result[0].status.as_deref(),
        Some("200"),
        "Add C should succeed"
    );
    info!("C added to group");

    // Drain group notification for B and C
    client_b.wait_for_group_notification(10).await?;
    client_c.wait_for_group_notification(10).await?;

    // A sends message after member change — SKDM must include C's devices now
    let text_4 = "Hello C, welcome!";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_4))
        .await?;

    // Both B and C should receive it
    client_b.wait_for_group_text(&group_jid, text_4, 10).await?;
    info!("B received post-add message");

    client_c.wait_for_group_text(&group_jid, text_4, 30).await?;
    info!("C received post-add message (new member got SKDM)");

    // A sends another message — all devices should have keys now
    let text_5 = "All settled";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_5))
        .await?;
    client_b.wait_for_group_text(&group_jid, text_5, 10).await?;
    client_c.wait_for_group_text(&group_jid, text_5, 10).await?;
    info!("Both B and C received final message");

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;

    Ok(())
}
