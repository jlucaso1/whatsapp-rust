use e2e_tests::{TestClient, send_and_expect_text, text_msg};
use log::info;
use wacore::iq::tctoken::tc_token_expiration_cutoff;
use wacore::store::traits::TcTokenEntry;
use whatsapp_rust::{NodeFilter, SendOptions};

fn unique_push_name(prefix: &str) -> String {
    format!("{}_{}", prefix, uuid::Uuid::new_v4())
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

    let restricted_name = format!("restricted:{}", unique_push_name("e2e_tctok_reply_a"));
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

    let restricted_name = format!("restricted:{}", unique_push_name("e2e_tctok_463_a"));
    let mut client_a = TestClient::connect_as("e2e_tctok_463_a", &restricted_name).await?;
    let client_b = TestClient::connect("e2e_tctok_463_b").await?;

    let jid_a = client_a.jid().await;
    let msg_id = format!("E2E463{}", uuid::Uuid::new_v4().simple());
    let waiter = client_b.client.wait_for_node(
        NodeFilter::tag("ack")
            .attr("id", msg_id.clone())
            .attr("class", "message")
            .attr("from", jid_a.to_string())
            .attr("error", "463"),
    );

    let returned_id = client_b
        .client
        .send_message_with_options(
            jid_a.clone(),
            text_msg("first contact to restricted account"),
            SendOptions {
                message_id: Some(msg_id.clone()),
                ..Default::default()
            },
        )
        .await?;
    assert_eq!(
        returned_id, msg_id,
        "send should preserve caller-provided message ID"
    );

    let ack = tokio::time::timeout(tokio::time::Duration::from_secs(15), waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for 463 nack"))?
        .map_err(|_| anyhow::anyhow!("463 nack waiter was canceled"))?;
    assert_eq!(ack.tag, "ack");
    assert_eq!(
        ack.attrs.get("error").map(|v| v.to_string()),
        Some("463".to_string())
    );

    client_a
        .assert_no_event(
            5,
            |e| matches!(e, wacore::types::events::Event::Message(msg, _) if msg.conversation.as_deref() == Some("first contact to restricted account")),
            "restricted recipient should not receive first-contact message without tcToken",
        )
        .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_tc_token_notification_reaches_all_connected_devices() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let restricted_name = format!("restricted:{}", unique_push_name("e2e_tctok_multi_a"));
    let shared_b_name = unique_push_name("e2e_tctok_multi_b");

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

    let restricted_name = format!("restricted:{}", unique_push_name("e2e_tctok_recon_a"));
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
