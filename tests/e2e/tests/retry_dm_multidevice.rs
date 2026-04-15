//! DM retry recovery after session deletion.

use e2e_tests::{TestClient, send_and_expect_text, text_msg};
use log::info;
use wacore::types::events::Event;
use wacore_binary::node::Node;
use whatsapp_rust::{NodeFilter, SendOptions};

fn participant_target_count(message_node: &Node) -> usize {
    message_node
        .get_optional_child("participants")
        .and_then(|participants| participants.children())
        .map(|children| children.iter().filter(|child| child.tag == "to").count())
        .unwrap_or_default()
}

fn retry_enc_count(message_node: &Node) -> Option<String> {
    let participants = message_node.get_optional_child("participants")?;
    let target = participants.children()?.first()?;
    let enc = target.get_optional_child("enc")?;
    enc.attrs().optional_string("count").map(|s| s.into_owned())
}

#[tokio::test]
async fn test_dm_retry_recovers_after_session_deletion() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_retry_dm_a").await?;
    let mut client_b = TestClient::connect("e2e_retry_dm_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;
    assert_ne!(
        jid_a.user, jid_b.user,
        "Clients must use different accounts"
    );

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "retry-setup-a2b",
        30,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "retry-setup-b2a",
        30,
    )
    .await?;
    info!("Baseline roundtrip established sessions");

    client_b
        .client
        .signal()
        .delete_sessions(std::slice::from_ref(&jid_a))
        .await?;

    let message_id = format!("E2ERETRY{}", uuid::Uuid::new_v4().simple());
    let initial_waiter = client_a
        .client
        .wait_for_sent_node(NodeFilter::tag("message").attr("id", &message_id));
    client_a
        .client
        .send_message_with_options(
            jid_b.clone(),
            text_msg("retry-recover"),
            SendOptions {
                message_id: Some(message_id.clone()),
                ..Default::default()
            },
        )
        .await?;

    let initial_node = tokio::time::timeout(tokio::time::Duration::from_secs(10), initial_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for initial DM send node"))?
        .map_err(|_| anyhow::anyhow!("initial DM send waiter was canceled"))?;
    assert!(
        retry_enc_count(&initial_node).is_none(),
        "Initial DM send should not carry a retry count"
    );

    let retry_waiter = client_a
        .client
        .wait_for_sent_node(NodeFilter::tag("message").attr("id", &message_id));

    client_b
        .wait_for_event(30, |e| matches!(e, Event::UndecryptableMessage(_)))
        .await?;
    client_b.wait_for_text("retry-recover", 30).await?;

    let retry_node = tokio::time::timeout(tokio::time::Duration::from_secs(10), retry_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for retry DM send node"))?
        .map_err(|_| anyhow::anyhow!("retry DM send waiter was canceled"))?;
    assert_eq!(
        participant_target_count(&retry_node),
        1,
        "Retry resend should target exactly one device"
    );
    assert_eq!(
        retry_enc_count(&retry_node).as_deref(),
        Some("1"),
        "Retry resend should mark the payload with count=1"
    );
    let jid_b_str = jid_b.to_string();
    assert_eq!(
        retry_node.attrs().optional_string("to").as_deref(),
        Some(jid_b_str.as_str()),
        "Retry resend should keep the user-level chat target"
    );
    info!("Retry recovered after B deleted its session with A");

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "retry-followup-a2b",
        15,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "retry-followup-b2a",
        15,
    )
    .await?;
    info!("Messaging still works after retry recovery");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
