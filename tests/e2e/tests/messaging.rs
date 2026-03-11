use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::waproto::whatsapp as wa;

#[tokio::test]
async fn test_send_text_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Connect two clients
    let client_a = TestClient::connect("e2e_msg_a").await?;
    let mut client_b = TestClient::connect("e2e_msg_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    info!("Client B JID: {jid_b}");

    // Client A sends a text message to Client B
    let text = "Hello from client A!";
    let message = wa::Message {
        conversation: Some(text.to_string()),
        ..Default::default()
    };

    let msg_id = client_a.client.send_message(jid_b.clone(), message).await?;
    info!("Client A sent message with id: {msg_id}");

    // Client B should receive the message
    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;

    if let Event::Message(msg, info) = event {
        info!(
            "Client B received message from {:?}: {:?}",
            info.source, msg
        );
        assert_eq!(
            msg.conversation.as_deref(),
            Some(text),
            "Received message text should match sent text"
        );
    } else {
        panic!("Expected Message event");
    }

    // Cleanup
    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_send_text_message_bidirectional() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_bidir_a").await?;
    let mut client_b = TestClient::connect("e2e_bidir_b").await?;

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

    info!("Client A JID: {jid_a}, Client B JID: {jid_b}");

    // A -> B
    let text_a = "Hello B, this is A!";
    client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some(text_a.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text_a)),
        )
        .await?;
    if let Event::Message(msg, _) = event {
        assert_eq!(msg.conversation.as_deref(), Some(text_a));
    } else {
        panic!("Expected Message event, got: {:?}", event);
    }

    // B -> A
    let text_b = "Hello A, this is B!";
    client_b
        .client
        .send_message(
            jid_a.clone(),
            wa::Message {
                conversation: Some(text_b.to_string()),
                ..Default::default()
            },
        )
        .await?;

    let event = client_a
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text_b)),
        )
        .await?;
    if let Event::Message(msg, _) = event {
        assert_eq!(msg.conversation.as_deref(), Some(text_b));
    } else {
        panic!("Expected Message event, got: {:?}", event);
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_message_revoke() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_revoke_a").await?;
    let mut client_b = TestClient::connect("e2e_revoke_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // Send a message
    let msg_id = client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some("This will be revoked".to_string()),
                ..Default::default()
            },
        )
        .await?;

    // Wait for B to receive it
    client_b
        .wait_for_event(30, |e| {
            matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some("This will be revoked"))
        })
        .await?;

    // Revoke the message
    client_a
        .client
        .revoke_message(
            jid_b,
            msg_id.clone(),
            whatsapp_rust::send::RevokeType::Sender,
        )
        .await?;
    info!("Client A revoked message {msg_id}");

    // Client B should receive the revoke as a protocol message
    let event = client_b
        .wait_for_event(30, |e| {
            if let Event::Message(msg, _) = e {
                msg.protocol_message.is_some()
            } else {
                false
            }
        })
        .await?;

    if let Event::Message(msg, _) = event {
        let proto = msg.protocol_message.as_ref().unwrap();
        assert_eq!(
            proto.r#type(),
            wa::message::protocol_message::Type::Revoke,
            "Should be a revoke protocol message"
        );
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

/// Verify that received messages include the sender's push name in MessageInfo.
/// The mock server now populates the `notify` attribute with the sender's display name.
#[tokio::test]
async fn test_message_has_push_name() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_pushname_msg_a").await?;
    let mut client_b = TestClient::connect("e2e_pushname_msg_b").await?;

    // Wait for app state sync so push name mutations can be sent
    client_a.wait_for_app_state_sync().await?;

    // Set a known push name on Client A.
    // set_push_name() sends a presence stanza AND an app state mutation IQ.
    // The IQ round-trip ensures the mock server has stored the name before we proceed.
    let push_name = "SenderBot";
    client_a.client.profile().set_push_name(push_name).await?;
    info!("Client A set push name to '{push_name}'");

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    // Client A sends a message to Client B
    let text = "Hello with push name!";
    client_a
        .client
        .send_message(
            jid_b.clone(),
            wa::Message {
                conversation: Some(text.to_string()),
                ..Default::default()
            },
        )
        .await?;

    // Client B should receive the message with the sender's push name
    let event = client_b
        .wait_for_event(
            15,
            |e| matches!(e, Event::Message(msg, _) if msg.conversation.as_deref() == Some(text)),
        )
        .await?;

    if let Event::Message(_, info) = event {
        info!(
            "Client B received message with push_name: '{}'",
            info.push_name
        );
        assert_eq!(
            info.push_name, push_name,
            "Received message push_name should match the sender's display name"
        );
    } else {
        panic!("Expected Message event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
