use e2e_tests::{TestClient, text_msg};
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::waproto::whatsapp as wa;

#[tokio::test]
async fn test_send_text_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_msg_a").await?;
    let mut client_b = TestClient::connect("e2e_msg_b").await?;

    let jid_b = client_b.jid().await;
    info!("Client B JID: {jid_b}");

    let text = "Hello from client A!";
    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg(text))
        .await?
        .message_id;
    info!("Client A sent message with id: {msg_id}");

    client_b.wait_for_text(text, 30).await?;

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_send_text_message_bidirectional() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_bidir_a").await?;
    let mut client_b = TestClient::connect("e2e_bidir_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;
    info!("Client A JID: {jid_a}, Client B JID: {jid_b}");

    // A -> B
    let text_a = "Hello B, this is A!";
    client_a
        .client
        .send_message(jid_b.clone(), text_msg(text_a))
        .await?;
    client_b.wait_for_text(text_a, 30).await?;

    // B -> A
    let text_b = "Hello A, this is B!";
    client_b
        .client
        .send_message(jid_a.clone(), text_msg(text_b))
        .await?;
    client_a.wait_for_text(text_b, 30).await?;

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_message_revoke() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_revoke_a").await?;
    let mut client_b = TestClient::connect("e2e_revoke_b").await?;

    let jid_b = client_b.jid().await;

    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), text_msg("This will be revoked"))
        .await?
        .message_id;

    client_b.wait_for_text("This will be revoked", 30).await?;

    client_a
        .client
        .revoke_message(
            jid_b,
            msg_id.clone(),
            whatsapp_rust::send::RevokeType::Sender,
        )
        .await?;
    info!("Client A revoked message {msg_id}");

    // B should receive the revoke as a protocol message
    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.protocol_message.is_set()),
        )
        .await?;

    if let Event::Message(msg, _) = &*event {
        let proto = msg.protocol_message.as_option().unwrap();
        assert_eq!(
            proto.r#type,
            Some(wa::message::protocol_message::Type::REVOKE),
            "Should be a revoke protocol message"
        );
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

/// Verify that received messages include the sender's push name in MessageInfo.
#[tokio::test]
async fn test_message_has_push_name() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_pushname_msg_a").await?;
    let mut client_b = TestClient::connect("e2e_pushname_msg_b").await?;

    // Wait for app state sync so push name mutations can be sent
    client_a.wait_for_app_state_sync().await?;

    // set_push_name() sends a presence stanza AND an app state mutation IQ.
    // The IQ round-trip ensures the mock server has stored the name before we proceed.
    let push_name = "SenderBot";
    client_a.client.profile().set_push_name(push_name).await?;
    info!("Client A set push name to '{push_name}'");

    let jid_b = client_b.jid().await;

    let text = "Hello with push name!";
    client_a
        .client
        .send_message(jid_b.clone(), text_msg(text))
        .await?;

    // Assert the push_name field on the received event
    let event = client_b.wait_for_text(text, 15).await?;
    if let Event::Message(_, info) = &*event {
        assert_eq!(
            info.push_name, push_name,
            "Received message push_name should match the sender's display name"
        );
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
