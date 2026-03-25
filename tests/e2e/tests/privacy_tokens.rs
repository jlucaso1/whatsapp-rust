use e2e_tests::{
    TestClient, restricted_push_name, scenario_push_name, send_and_expect_text, text_msg,
};
use log::info;
use std::sync::Arc;
use wacore::iq::tctoken::tc_token_expiration_cutoff;
use wacore::store::traits::TcTokenEntry;
use wacore::types::events::Event;
use wacore_binary::node::Node;
use whatsapp_rust::{NodeFilter, SendOptions};

fn has_child(node: &Node, tag: &str) -> bool {
    node.children()
        .map(|children| children.iter().any(|child| child.tag == tag))
        .unwrap_or(false)
}

fn has_descendant(node: &Node, tag: &str) -> bool {
    node.children().is_some_and(|children| {
        children
            .iter()
            .any(|child| child.tag == tag || has_descendant(child, tag))
    })
}

async fn send_first_message_and_expect_463(
    sender: &TestClient,
    recipient: &mut TestClient,
    recipient_jid: &whatsapp_rust::Jid,
    text: &str,
) -> anyhow::Result<Arc<Node>> {
    let msg_id = format!("E2E463{}", uuid::Uuid::new_v4().simple());
    send_message_and_expect_463_with_id(sender, recipient, recipient_jid, text, msg_id).await
}

async fn send_message_and_expect_463_with_id(
    sender: &TestClient,
    recipient: &mut TestClient,
    recipient_jid: &whatsapp_rust::Jid,
    text: &str,
    msg_id: String,
) -> anyhow::Result<Arc<Node>> {
    let waiter = sender.client.wait_for_node(
        NodeFilter::tag("ack")
            .attr("id", msg_id.clone())
            .attr("class", "message")
            .attr("from", recipient_jid.to_string())
            .attr("error", "463"),
    );

    let returned_id = sender
        .client
        .send_message_with_options(
            recipient_jid.clone(),
            text_msg(text),
            SendOptions {
                message_id: Some(msg_id.clone()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(returned_id, msg_id);

    let ack = tokio::time::timeout(tokio::time::Duration::from_secs(15), waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for 463 nack"))?
        .map_err(|_| anyhow::anyhow!("463 nack waiter was canceled"))?;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs.get("error").map(|v| v.to_string()),
        Some("463".to_string())
    );

    let expected_text = text.to_string();
    recipient
        .assert_no_event(
            5,
            move |e| matches!(e, wacore::types::events::Event::Message(msg, _) if msg.conversation.as_deref() == Some(expected_text.as_str())),
            "restricted recipient should not receive first-contact message without privacy token",
        )
        .await?;

    Ok(ack)
}

#[tokio::test]
async fn test_tc_token_notification_stores_token_for_sender() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_tctok_store_a").await?;
    let mut client_b = TestClient::connect("e2e_tctok_store_b").await?;

    let jid_b = client_b.jid().await;
    send_and_expect_text(&client_a.client, &mut client_b, &jid_b, "seed tc token", 30).await?;

    let key_a = client_a.tc_token_key().await?;
    let entry = client_b.wait_for_tc_token(&key_a, 10).await?;
    assert!(!entry.token.is_empty(), "tc token should contain bytes");
    assert!(
        entry.token_timestamp > 0,
        "tc token timestamp should be populated"
    );
    assert_eq!(
        entry.sender_timestamp, None,
        "recipient-side storage should not set sender_timestamp yet"
    );
    info!("B stored tc token for key {}", key_a);

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_issue_tokens_api_delivers_notification_and_updates_index() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_tctok_issue_a").await?;
    let client_b = TestClient::connect("e2e_tctok_issue_b").await?;

    let jid_b_lid = client_b
        .client
        .get_lid()
        .await
        .expect("B should have LID after connect");
    let issued = client_a
        .client
        .tc_token()
        .issue_tokens(std::slice::from_ref(&jid_b_lid))
        .await?;
    info!("issue_tokens returned {} token(s)", issued.len());

    let key_a = client_a.tc_token_key().await?;
    let stored = client_b.wait_for_tc_token(&key_a, 10).await?;
    assert!(
        !stored.token.is_empty(),
        "issued tc token should be stored on recipient"
    );

    let all_jids = client_b.client.tc_token().get_all_jids().await?;
    assert!(
        all_jids.contains(&key_a),
        "tc token index should include the sender key after explicit issuance"
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_reply_to_restricted_contact_uses_received_tc_token() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_tctok_reply_a");
    let mut client_a = TestClient::connect_as("e2e_tctok_reply_a", &restricted_name).await?;
    let mut client_b = TestClient::connect("e2e_tctok_reply_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "seed restricted reply path",
        30,
    )
    .await?;

    let key_a = client_a.tc_token_key().await?;
    let initial_entry = client_b.wait_for_tc_token(&key_a, 10).await?;
    assert_eq!(initial_entry.sender_timestamp, None);

    let reply = "reply to restricted A";
    client_b
        .client
        .send_message(jid_a.clone(), text_msg(reply))
        .await?;
    client_a.wait_for_text(reply, 30).await?;

    let updated_entry = client_b.wait_for_tc_token(&key_a, 5).await?;
    assert!(
        updated_entry.sender_timestamp.is_some(),
        "using a valid tc token should set sender_timestamp"
    );
    info!("B replied successfully to restricted A using stored tc token");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_first_message_to_restricted_contact_receives_463_nack() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_tctok_463_a");
    let mut client_a = TestClient::connect_as("e2e_tctok_463_a", &restricted_name).await?;
    let client_b = TestClient::connect("e2e_tctok_463_b").await?;

    let jid_a = client_a.jid().await;
    send_first_message_and_expect_463(
        &client_b,
        &mut client_a,
        &jid_a,
        "first contact to restricted account",
    )
    .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_tc_token_notification_reaches_all_connected_devices() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_tctok_multi_a");
    let shared_b_name = e2e_tests::unique_push_name("e2e_tctok_multi_b");

    let client_a = TestClient::connect_as("e2e_tctok_multi_a", &restricted_name).await?;
    let mut client_b1 = TestClient::connect_as("e2e_tctok_multi_b1", &shared_b_name).await?;
    let client_b2 = TestClient::connect_as("e2e_tctok_multi_b2", &shared_b_name).await?;

    let phone_b1 = client_b1.client.get_pn().await.expect("B1 should have JID");
    let phone_b2 = client_b2.client.get_pn().await.expect("B2 should have JID");
    assert_eq!(
        phone_b1.user, phone_b2.user,
        "B devices should share a phone"
    );
    assert_ne!(
        phone_b1.device, phone_b2.device,
        "B devices should have different device IDs"
    );

    let jid_b = client_b1.jid().await;

    send_and_expect_text(
        &client_a.client,
        &mut client_b1,
        &jid_b,
        "seed multi-device tc token",
        30,
    )
    .await?;

    let key_a = client_a.tc_token_key().await?;
    client_b1.wait_for_tc_token(&key_a, 10).await?;
    client_b2.wait_for_tc_token(&key_a, 10).await?;
    info!("Both connected B devices stored A's tc token");

    client_a.disconnect().await;
    client_b1.disconnect().await;
    client_b2.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_tc_token_survives_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_tctok_recon_a");
    let mut client_a = TestClient::connect_as("e2e_tctok_recon_a", &restricted_name).await?;
    let mut client_b = TestClient::connect("e2e_tctok_recon_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "seed reconnect tc token",
        30,
    )
    .await?;

    let key_a = client_a.tc_token_key().await?;
    let initial_entry = client_b.wait_for_tc_token(&key_a, 10).await?;

    client_b.reconnect_and_wait().await?;

    let after_reconnect = client_b.wait_for_tc_token(&key_a, 5).await?;
    assert_eq!(
        after_reconnect.token, initial_entry.token,
        "tc token bytes should survive reconnect"
    );
    assert_eq!(
        after_reconnect.token_timestamp, initial_entry.token_timestamp,
        "tc token timestamp should survive reconnect"
    );

    let reply = "reply after reconnect";
    client_b
        .client
        .send_message(jid_a.clone(), text_msg(reply))
        .await?;
    client_a.wait_for_text(reply, 30).await?;
    info!("Stored tc token survived reconnect and still works for replies");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_prune_expired_tc_tokens_removes_only_stale_entries() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_tctok_prune").await?;
    let backend = client.client.persistence_manager().backend();
    let cutoff = tc_token_expiration_cutoff();
    let expired_key = format!("expired_{}", uuid::Uuid::new_v4());
    let fresh_key = format!("fresh_{}", uuid::Uuid::new_v4());

    backend
        .put_tc_token(
            &expired_key,
            &TcTokenEntry {
                token: vec![0x01],
                token_timestamp: cutoff - 1,
                sender_timestamp: None,
            },
        )
        .await?;
    backend
        .put_tc_token(
            &fresh_key,
            &TcTokenEntry {
                token: vec![0x02],
                token_timestamp: cutoff,
                sender_timestamp: Some(cutoff),
            },
        )
        .await?;

    let deleted = client.client.tc_token().prune_expired().await?;
    assert_eq!(deleted, 1, "exactly one expired tc token should be pruned");
    assert!(
        client.client.tc_token().get(&expired_key).await?.is_none(),
        "expired tc token should be removed"
    );
    assert!(
        client.client.tc_token().get(&fresh_key).await?.is_some(),
        "fresh tc token should be preserved"
    );

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_only_nct_send_ab_without_salt_still_receives_463() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_cstok_send_only_a");
    let sender_name = scenario_push_name(
        "e2e_cstok_send_only_b",
        &[
            "nct_send_ab=1",
            "nct_history_delivery=0",
            "nct_syncd_delivery=0",
        ],
    );
    let mut client_a = TestClient::connect_as("e2e_cstok_send_only_a", &restricted_name).await?;
    let client_b = TestClient::connect_as("e2e_cstok_send_only_b", &sender_name).await?;

    assert!(
        client_b.nct_salt().await.is_none(),
        "send AB alone should not create NCT salt"
    );

    let key_a = client_a.tc_token_key().await?;
    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "sender should not have a tc token for recipient before first contact"
    );

    let jid_a = client_a.jid().await;
    let msg_id = format!("E2ECSNEG1{}", uuid::Uuid::new_v4().simple());
    let sent_msg_id = msg_id.clone();
    let sent_waiter = client_b.sent_message_waiter(&sent_msg_id);
    send_message_and_expect_463_with_id(
        &client_b,
        &mut client_a,
        &jid_a,
        "send-ab-only first contact",
        msg_id,
    )
    .await?;
    let sent = tokio::time::timeout(tokio::time::Duration::from_secs(10), sent_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for sent message node"))?
        .map_err(|_| anyhow::anyhow!("sent message waiter was canceled"))?;
    assert!(!has_child(&sent, "tctoken"));
    assert!(!has_child(&sent, "cstoken"));

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_send_and_syncd_ab_without_delivery_still_receives_463() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_cstok_ab_only_a");
    let sender_name = scenario_push_name(
        "e2e_cstok_ab_only_b",
        &[
            "nct_send_ab=1",
            "nct_syncd_ab=1",
            "nct_history_delivery=0",
            "nct_syncd_delivery=0",
        ],
    );
    let mut client_a = TestClient::connect_as("e2e_cstok_ab_only_a", &restricted_name).await?;
    let client_b = TestClient::connect_as("e2e_cstok_ab_only_b", &sender_name).await?;

    assert!(
        client_b.nct_salt().await.is_none(),
        "AB props without delivery should still leave NCT salt unset"
    );

    let key_a = client_a.tc_token_key().await?;
    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "sender should not have a tc token for recipient before first contact"
    );

    let jid_a = client_a.jid().await;
    let msg_id = format!("E2ECSNEG2{}", uuid::Uuid::new_v4().simple());
    let sent_msg_id = msg_id.clone();
    let sent_waiter = client_b.sent_message_waiter(&sent_msg_id);
    send_message_and_expect_463_with_id(
        &client_b,
        &mut client_a,
        &jid_a,
        "send-and-syncd-ab first contact",
        msg_id,
    )
    .await?;
    let sent = tokio::time::timeout(tokio::time::Duration::from_secs(10), sent_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for sent message node"))?
        .map_err(|_| anyhow::anyhow!("sent message waiter was canceled"))?;
    assert!(!has_child(&sent, "tctoken"));
    assert!(!has_child(&sent, "cstoken"));

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_history_sync_nct_salt_enables_cstoken_first_contact() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_cstok_hist_a");
    let sender_name = scenario_push_name(
        "e2e_cstok_hist_b",
        &[
            "nct_send_ab=1",
            "nct_history_ab=1",
            "nct_history_delivery=1",
            "nct_syncd_delivery=0",
        ],
    );
    let mut client_a = TestClient::connect_as("e2e_cstok_hist_a", &restricted_name).await?;
    let client_b = TestClient::connect_as("e2e_cstok_hist_b", &sender_name).await?;

    let nct_salt = client_b.wait_for_nct_salt(10).await?;
    assert!(
        !nct_salt.is_empty(),
        "history sync should provision NCT salt"
    );

    let key_a = client_a.tc_token_key().await?;
    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "sender should not have a tc token for recipient before cstoken fallback"
    );

    let jid_a_lid = client_a
        .client
        .get_lid()
        .await
        .expect("restricted recipient should have a LID");
    let sent_waiter = client_b.next_sent_message_waiter();
    client_b
        .client
        .send_message_with_options(
            jid_a_lid,
            text_msg("history-sync cstoken first contact"),
            SendOptions {
                message_id: Some(format!("E2ECSHIST{}", uuid::Uuid::new_v4().simple())),
                ..Default::default()
            },
        )
        .await?;
    let sent = tokio::time::timeout(tokio::time::Duration::from_secs(10), sent_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for next sent message node"))?
        .map_err(|_| anyhow::anyhow!("sent message waiter was canceled"))?;
    assert!(has_child(&sent, "cstoken"));
    assert!(!has_child(&sent, "tctoken"));
    client_a
        .wait_for_text("history-sync cstoken first contact", 30)
        .await?;

    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "cstoken fallback should not materialize a tc token entry for the recipient"
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_cstoken_only_first_contact_succeeds_when_tctoken_disabled() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = scenario_push_name(
        "e2e_cstok_only_a",
        &["restricted", "tc_enabled=0", "cs_enabled=1"],
    );
    let sender_name = scenario_push_name(
        "e2e_cstok_only_b",
        &[
            "nct_send_ab=1",
            "nct_history_ab=1",
            "nct_history_delivery=1",
            "nct_syncd_delivery=0",
        ],
    );
    let mut client_a = TestClient::connect_as("e2e_cstok_only_a", &restricted_name).await?;
    let client_b = TestClient::connect_as("e2e_cstok_only_b", &sender_name).await?;

    let nct_salt = client_b.wait_for_nct_salt(10).await?;
    assert!(
        !nct_salt.is_empty(),
        "history sync should provision NCT salt"
    );

    let key_a = client_a.tc_token_key().await?;
    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "sender should not have a tc token for recipient before first contact"
    );

    let jid_a_lid = client_a
        .client
        .get_lid()
        .await
        .expect("restricted recipient should have a LID");
    let sent_waiter = client_b.next_sent_message_waiter();
    client_b
        .client
        .send_message_with_options(
            jid_a_lid,
            text_msg("cstoken-only first contact"),
            SendOptions {
                message_id: Some(format!("E2ECSONLY{}", uuid::Uuid::new_v4().simple())),
                ..Default::default()
            },
        )
        .await?;
    let sent = tokio::time::timeout(tokio::time::Duration::from_secs(10), sent_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for next sent message node"))?
        .map_err(|_| anyhow::anyhow!("sent message waiter was canceled"))?;
    assert!(has_child(&sent, "cstoken"));
    assert!(!has_child(&sent, "tctoken"));
    client_a
        .wait_for_text("cstoken-only first contact", 30)
        .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_syncd_nct_salt_enables_cstoken_first_contact() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_cstok_syncd_a");
    let sender_name = scenario_push_name(
        "e2e_cstok_syncd_b",
        &[
            "nct_send_ab=1",
            "nct_syncd_ab=1",
            "nct_history_delivery=0",
            "nct_syncd_delivery=1",
        ],
    );
    let mut client_a = TestClient::connect_as("e2e_cstok_syncd_a", &restricted_name).await?;
    let client_b = TestClient::connect_as("e2e_cstok_syncd_b", &sender_name).await?;

    let nct_salt = client_b.wait_for_nct_salt(10).await?;
    assert!(
        !nct_salt.is_empty(),
        "app state sync should provision NCT salt"
    );

    let key_a = client_a.tc_token_key().await?;
    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "sender should not have a tc token for recipient before cstoken fallback"
    );

    let jid_a_lid = client_a
        .client
        .get_lid()
        .await
        .expect("restricted recipient should have a LID");
    let sent_waiter = client_b.next_sent_message_waiter();
    client_b
        .client
        .send_message_with_options(
            jid_a_lid,
            text_msg("syncd cstoken first contact"),
            SendOptions {
                message_id: Some(format!("E2ECSSYN{}", uuid::Uuid::new_v4().simple())),
                ..Default::default()
            },
        )
        .await?;
    let sent = tokio::time::timeout(tokio::time::Duration::from_secs(10), sent_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for next sent message node"))?
        .map_err(|_| anyhow::anyhow!("sent message waiter was canceled"))?;
    assert!(has_child(&sent, "cstoken"));
    assert!(!has_child(&sent, "tctoken"));
    client_a
        .wait_for_text("syncd cstoken first contact", 30)
        .await?;

    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "cstoken fallback should not materialize a tc token entry for the recipient"
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_clearing_nct_salt_locally_makes_first_contact_fail_again() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = scenario_push_name(
        "e2e_cstok_remove_a",
        &["restricted", "tc_enabled=0", "cs_enabled=1"],
    );
    let sender_name = scenario_push_name(
        "e2e_cstok_remove_b",
        &[
            "nct_send_ab=1",
            "nct_syncd_ab=1",
            "nct_history_delivery=0",
            "nct_syncd_delivery=1",
        ],
    );
    let mut client_a = TestClient::connect_as("e2e_cstok_remove_a", &restricted_name).await?;
    let client_b = TestClient::connect_as("e2e_cstok_remove_b", &sender_name).await?;

    let initial_salt = client_b.wait_for_nct_salt(10).await?;
    assert!(!initial_salt.is_empty(), "syncd should provision NCT salt");

    let jid_a_lid = client_a
        .client
        .get_lid()
        .await
        .expect("restricted recipient should have a LID");
    client_b
        .client
        .send_message(jid_a_lid, text_msg("remove-salt initial success"))
        .await?;
    client_a
        .wait_for_text("remove-salt initial success", 30)
        .await?;

    client_b
        .client
        .persistence_manager()
        .process_command(whatsapp_rust::store::commands::DeviceCommand::SetNctSalt(
            None,
        ))
        .await;
    assert!(
        client_b.nct_salt().await.is_none(),
        "NCT salt should be cleared locally"
    );

    let restricted_name_c = scenario_push_name(
        "e2e_cstok_remove_c",
        &["restricted", "tc_enabled=0", "cs_enabled=1"],
    );
    let mut client_c = TestClient::connect_as("e2e_cstok_remove_c", &restricted_name_c).await?;
    let jid_c = client_c.jid().await;
    send_first_message_and_expect_463(
        &client_b,
        &mut client_c,
        &jid_c,
        "remove-salt first contact should fail",
    )
    .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    client_c.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_tctoken_only_reply_succeeds_when_cstoken_disabled() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = scenario_push_name(
        "e2e_tctok_only_a",
        &["restricted", "tc_enabled=1", "cs_enabled=0"],
    );
    let mut client_a = TestClient::connect_as("e2e_tctok_only_a", &restricted_name).await?;
    let mut client_b = TestClient::connect("e2e_tctok_only_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "seed tctoken-only reply path",
        30,
    )
    .await?;

    let key_a = client_a.tc_token_key().await?;
    let initial_entry = client_b.wait_for_tc_token(&key_a, 10).await?;
    assert!(
        !initial_entry.token.is_empty(),
        "sender should have a valid tc token before reply"
    );

    let sent_waiter = client_b.next_sent_message_waiter();
    client_b
        .client
        .send_message_with_options(
            jid_a.clone(),
            text_msg("tctoken-only reply"),
            SendOptions {
                message_id: Some(format!("E2ETCONLY{}", uuid::Uuid::new_v4().simple())),
                ..Default::default()
            },
        )
        .await?;
    let sent = tokio::time::timeout(tokio::time::Duration::from_secs(10), sent_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for next sent message node"))?
        .map_err(|_| anyhow::anyhow!("sent message waiter was canceled"))?;
    assert!(has_child(&sent, "tctoken"));
    assert!(!has_child(&sent, "cstoken"));
    client_a.wait_for_text("tctoken-only reply", 30).await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_nct_salt_survives_reconnect_and_still_allows_first_contact() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_cstok_recon_a");
    let sender_name = scenario_push_name(
        "e2e_cstok_recon_b",
        &[
            "nct_send_ab=1",
            "nct_syncd_ab=1",
            "nct_history_delivery=0",
            "nct_syncd_delivery=1",
        ],
    );
    let mut client_a = TestClient::connect_as("e2e_cstok_recon_a", &restricted_name).await?;
    let mut client_b = TestClient::connect_as("e2e_cstok_recon_b", &sender_name).await?;

    let before_reconnect = client_b.wait_for_nct_salt(10).await?;
    client_b.reconnect_and_wait().await?;
    client_b
        .client
        .wait_for_startup_sync(tokio::time::Duration::from_secs(15))
        .await?;

    let after_reconnect = client_b.wait_for_nct_salt(5).await?;
    assert_eq!(
        after_reconnect, before_reconnect,
        "NCT salt should survive reconnect"
    );

    let key_a = client_a.tc_token_key().await?;
    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "sender should still have no tc token for recipient before first contact"
    );

    let jid_a_lid = client_a
        .client
        .get_lid()
        .await
        .expect("restricted recipient should have a LID");
    let sent_waiter = client_b.next_sent_message_waiter();
    client_b
        .client
        .send_message_with_options(
            jid_a_lid,
            text_msg("reconnect cstoken first contact"),
            SendOptions {
                message_id: Some(format!("E2ECSRECON{}", uuid::Uuid::new_v4().simple())),
                ..Default::default()
            },
        )
        .await?;
    let sent = tokio::time::timeout(tokio::time::Duration::from_secs(10), sent_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for next sent message node"))?
        .map_err(|_| anyhow::anyhow!("sent message waiter was canceled"))?;
    assert!(has_child(&sent, "cstoken"));
    assert!(!has_child(&sent, "tctoken"));
    client_a
        .wait_for_text("reconnect cstoken first contact", 30)
        .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_pn_target_first_contact_uses_cstoken_after_lid_resolution() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = scenario_push_name(
        "e2e_cstok_pn_a",
        &["restricted", "tc_enabled=0", "cs_enabled=1"],
    );
    let sender_name = scenario_push_name(
        "e2e_cstok_pn_b",
        &[
            "nct_send_ab=1",
            "nct_history_ab=1",
            "nct_history_delivery=1",
            "nct_syncd_delivery=0",
        ],
    );
    let mut client_a = TestClient::connect_as("e2e_cstok_pn_a", &restricted_name).await?;
    let client_b = TestClient::connect_as("e2e_cstok_pn_b", &sender_name).await?;

    let nct_salt = client_b.wait_for_nct_salt(10).await?;
    assert!(
        !nct_salt.is_empty(),
        "history sync should provision NCT salt"
    );

    let jid_a_pn = client_a.jid().await;
    let key_a = client_a.tc_token_key().await?;
    assert!(
        client_b.client.tc_token().get(&key_a).await?.is_none(),
        "sender should not have a tc token for recipient before first contact"
    );

    let user_info = client_b
        .client
        .contacts()
        .get_user_info(std::slice::from_ref(&jid_a_pn))
        .await?;
    let resolved = user_info
        .get(&jid_a_pn)
        .expect("PN-target usync info should exist");
    assert!(
        resolved.lid.is_some(),
        "PN-target usync info should carry the recipient account LID"
    );

    let msg_id = format!("E2ECSPN{}", uuid::Uuid::new_v4().simple());
    let sent_waiter = client_b.sent_message_waiter(&msg_id);
    client_b
        .client
        .send_message_with_options(
            jid_a_pn.clone(),
            text_msg("pn-target cstoken first contact"),
            SendOptions {
                message_id: Some(msg_id),
                ..Default::default()
            },
        )
        .await?;
    let sent = tokio::time::timeout(tokio::time::Duration::from_secs(10), sent_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for PN-target sent message node"))?
        .map_err(|_| anyhow::anyhow!("PN-target sent message waiter was canceled"))?;
    assert_eq!(
        sent.attrs.get("to").map(|v| v.to_string()),
        Some(jid_a_pn.to_string())
    );
    assert!(has_child(&sent, "cstoken"));
    assert!(!has_child(&sent, "tctoken"));

    client_a
        .wait_for_text("pn-target cstoken first contact", 30)
        .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_restricted_profile_picture_requires_tctoken() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_ppic_priv_a");
    let client_a = TestClient::connect_as("e2e_ppic_priv_a", &restricted_name).await?;
    let mut client_b = TestClient::connect("e2e_ppic_priv_b").await?;

    client_a
        .client
        .profile()
        .set_profile_picture(vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10])
        .await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;

    let denied_waiter = client_b.client.wait_for_sent_node(
        NodeFilter::tag("iq")
            .attr("type", "get")
            .attr("xmlns", "w:profile:picture")
            .attr("target", jid_a.to_string()),
    );
    let denied = client_b
        .client
        .contacts()
        .get_profile_picture(&jid_a, false)
        .await?;
    let denied_node = tokio::time::timeout(tokio::time::Duration::from_secs(10), denied_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for denied profile picture IQ"))?
        .map_err(|_| anyhow::anyhow!("denied profile picture waiter was canceled"))?;
    assert!(!has_descendant(&denied_node, "tctoken"));
    assert!(
        denied.is_none(),
        "restricted profile picture should be hidden without a tc token"
    );

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "seed profile picture tc token",
        30,
    )
    .await?;
    let key_a = client_a.tc_token_key().await?;
    client_b.wait_for_tc_token(&key_a, 10).await?;

    let allowed_waiter = client_b.client.wait_for_sent_node(
        NodeFilter::tag("iq")
            .attr("type", "get")
            .attr("xmlns", "w:profile:picture")
            .attr("target", jid_a.to_string()),
    );
    let allowed = client_b
        .client
        .contacts()
        .get_profile_picture(&jid_a, false)
        .await?;
    let allowed_node = tokio::time::timeout(tokio::time::Duration::from_secs(10), allowed_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for allowed profile picture IQ"))?
        .map_err(|_| anyhow::anyhow!("allowed profile picture waiter was canceled"))?;
    assert!(has_descendant(&allowed_node, "tctoken"));
    assert!(
        allowed.is_some(),
        "restricted profile picture should be visible once tc token exists"
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_restricted_presence_subscribe_requires_tctoken() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = restricted_push_name("e2e_presence_priv_a");
    let client_a = TestClient::connect_as("e2e_presence_priv_a", &restricted_name).await?;
    let mut client_b = TestClient::connect("e2e_presence_priv_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;

    let denied_waiter = client_b.client.wait_for_sent_node(
        NodeFilter::tag("presence")
            .attr("type", "subscribe")
            .attr("to", jid_a.to_string()),
    );
    client_b.client.presence().subscribe(&jid_a).await?;
    let denied_node = tokio::time::timeout(tokio::time::Duration::from_secs(10), denied_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for denied presence subscribe"))?
        .map_err(|_| anyhow::anyhow!("denied presence subscribe waiter was canceled"))?;
    assert!(!has_child(&denied_node, "tctoken"));

    client_a.client.presence().set_unavailable().await?;
    client_b
        .assert_no_event(
            5,
            |e| matches!(e, Event::Presence(update) if update.from == jid_a && update.unavailable),
            "restricted presence subscribe without tctoken should not deliver updates",
        )
        .await?;

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "seed presence tc token",
        30,
    )
    .await?;
    let key_a = client_a.tc_token_key().await?;
    client_b.wait_for_tc_token(&key_a, 10).await?;

    let allowed_waiter = client_b.client.wait_for_sent_node(
        NodeFilter::tag("presence")
            .attr("type", "subscribe")
            .attr("to", jid_a.to_string()),
    );
    client_b.client.presence().subscribe(&jid_a).await?;
    let allowed_node = tokio::time::timeout(tokio::time::Duration::from_secs(10), allowed_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for allowed presence subscribe"))?
        .map_err(|_| anyhow::anyhow!("allowed presence subscribe waiter was canceled"))?;
    assert!(has_child(&allowed_node, "tctoken"));

    let _ = client_b
        .wait_for_event(
            5,
            |e| matches!(e, Event::Presence(update) if update.from == jid_a && update.unavailable),
        )
        .await?;

    client_a.client.presence().set_available().await?;
    let _ = client_b
        .wait_for_event(
            10,
            |e| matches!(e, Event::Presence(update) if update.from == jid_a && !update.unavailable),
        )
        .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
