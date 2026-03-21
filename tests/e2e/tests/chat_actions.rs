use e2e_tests::TestClient;
use log::info;
use whatsapp_rust::waproto::whatsapp as wa;

// Note: These tests verify the full app state mutation pipeline (encode → encrypt →
// send IQ → server acknowledgement). The mock server cannot decrypt mutations back,
// so we validate success by checking the API returns Ok (server accepted the patch).

// ─── Archive Tests ───────────────────────────────────────────────────

#[tokio::test]
async fn test_archive_chat() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_archive_a").await?;
    let client_b = TestClient::connect("e2e_archive_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    client_a
        .client
        .chat_actions()
        .archive_chat(&jid_b, None)
        .await?;
    info!("Successfully archived chat with {jid_b}");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_unarchive_chat() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_unarchive_a").await?;
    let client_b = TestClient::connect("e2e_unarchive_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // Archive then unarchive
    client_a
        .client
        .chat_actions()
        .archive_chat(&jid_b, None)
        .await?;
    info!("Archived chat with {jid_b}");

    client_a
        .client
        .chat_actions()
        .unarchive_chat(&jid_b, None)
        .await?;
    info!("Successfully unarchived chat with {jid_b}");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Pin Tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn test_pin_chat() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_pin_a").await?;
    let client_b = TestClient::connect("e2e_pin_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    client_a.client.chat_actions().pin_chat(&jid_b).await?;
    info!("Successfully pinned chat with {jid_b}");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_unpin_chat() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_unpin_a").await?;
    let client_b = TestClient::connect("e2e_unpin_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    client_a.client.chat_actions().pin_chat(&jid_b).await?;
    info!("Pinned chat with {jid_b}");

    client_a.client.chat_actions().unpin_chat(&jid_b).await?;
    info!("Successfully unpinned chat with {jid_b}");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Mute Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_mute_chat_indefinite() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_mute_indef_a").await?;
    let client_b = TestClient::connect("e2e_mute_indef_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    client_a.client.chat_actions().mute_chat(&jid_b).await?;
    info!("Successfully muted chat with {jid_b} indefinitely");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_mute_chat_with_expiry() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_mute_expiry_a").await?;
    let client_b = TestClient::connect("e2e_mute_expiry_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // Mute for 8 hours from now
    let mute_end = chrono::Utc::now().timestamp_millis() + (8 * 60 * 60 * 1000);

    client_a
        .client
        .chat_actions()
        .mute_chat_until(&jid_b, mute_end)
        .await?;
    info!("Successfully muted chat with {jid_b} until {mute_end}");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_unmute_chat() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_unmute_a").await?;
    let client_b = TestClient::connect("e2e_unmute_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // Mute then unmute
    client_a.client.chat_actions().mute_chat(&jid_b).await?;
    info!("Muted chat with {jid_b}");

    client_a.client.chat_actions().unmute_chat(&jid_b).await?;
    info!("Successfully unmuted chat with {jid_b}");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Star Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_star_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_star_a").await?;
    let client_b = TestClient::connect("e2e_star_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // A sends a message to B (we only need the msg_id for starring)
    let msg = wa::Message {
        conversation: Some("Star this message!".to_string()),
        ..Default::default()
    };
    let msg_id = client_a.client.send_message(jid_b.clone(), msg).await?;
    info!("A sent message {msg_id} to B");

    // A stars the message (from_me=true since A sent it)
    // Starring is an app state mutation — it only needs the message ID,
    // not confirmation that B received the message.
    client_a
        .client
        .chat_actions()
        .star_message(&jid_b, None, &msg_id, true)
        .await?;
    info!("Successfully starred message {msg_id}");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_unstar_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_unstar_a").await?;
    let client_b = TestClient::connect("e2e_unstar_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // A sends a message
    let msg = wa::Message {
        conversation: Some("Star then unstar".to_string()),
        ..Default::default()
    };
    let msg_id = client_a.client.send_message(jid_b.clone(), msg).await?;
    info!("A sent message {msg_id}");

    // Star then unstar
    client_a
        .client
        .chat_actions()
        .star_message(&jid_b, None, &msg_id, true)
        .await?;
    info!("Starred message {msg_id}");

    client_a
        .client
        .chat_actions()
        .unstar_message(&jid_b, None, &msg_id, true)
        .await?;
    info!("Successfully unstarred message {msg_id}");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Combined Tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_multiple_chat_actions() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_multi_actions_a").await?;
    let client_b = TestClient::connect("e2e_multi_actions_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    client_a.wait_for_app_state_sync().await?;

    // Pin, mute, unpin, unmute — all should succeed
    client_a.client.chat_actions().pin_chat(&jid_b).await?;
    info!("Pinned chat");

    client_a.client.chat_actions().mute_chat(&jid_b).await?;
    info!("Muted chat");

    client_a.client.chat_actions().unpin_chat(&jid_b).await?;
    info!("Unpinned chat");

    client_a.client.chat_actions().unmute_chat(&jid_b).await?;
    info!("Unmuted chat");

    // Archive and unarchive
    client_a
        .client
        .chat_actions()
        .archive_chat(&jid_b, None)
        .await?;
    info!("Archived chat");

    client_a
        .client
        .chat_actions()
        .unarchive_chat(&jid_b, None)
        .await?;
    info!("Unarchived chat");

    info!("All chat actions completed successfully");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
