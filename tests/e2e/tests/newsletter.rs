use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::waproto::whatsapp as wa;

#[tokio::test]
async fn test_newsletter_create_and_list() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_create").await?;

    // Create a newsletter
    let created = client
        .client
        .newsletter()
        .create("Test Channel", Some("A test newsletter"))
        .await?;

    assert!(
        !created.name.is_empty(),
        "created newsletter should have a name"
    );
    assert_eq!(created.name, "Test Channel");
    assert!(
        created.jid.server == "newsletter",
        "JID should be newsletter: {}",
        created.jid
    );

    info!("Created newsletter: {} ({})", created.name, created.jid);

    // List subscribed — should include the one we just created
    let newsletters = client.client.newsletter().list_subscribed().await?;
    assert!(
        newsletters.iter().any(|n| n.jid == created.jid),
        "created newsletter should appear in subscribed list"
    );

    info!("list_subscribed returned {} newsletters", newsletters.len());

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_newsletter_get_metadata() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_meta").await?;

    // Create a newsletter first
    let created = client
        .client
        .newsletter()
        .create("Metadata Test", None)
        .await?;

    // Fetch metadata by JID
    let metadata = client
        .client
        .newsletter()
        .get_metadata(&created.jid)
        .await?;

    assert_eq!(metadata.jid, created.jid);
    assert_eq!(metadata.name, "Metadata Test");

    info!(
        "Fetched metadata: name='{}', subscribers={}, invite={:?}",
        metadata.name, metadata.subscriber_count, metadata.invite_code
    );

    // Fetch by invite code if available
    if let Some(invite) = &metadata.invite_code {
        let by_invite = client
            .client
            .newsletter()
            .get_metadata_by_invite(invite)
            .await?;
        assert_eq!(by_invite.jid, created.jid);
        info!("Fetched by invite code '{}': OK", invite);
    }

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_newsletter_join() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Client A creates a newsletter
    let client_a = TestClient::connect("e2e_newsletter_join_a").await?;
    let created = client_a
        .client
        .newsletter()
        .create("Join Test Channel", None)
        .await?;

    info!("Client A created newsletter: {}", created.jid);

    // Client B joins the newsletter
    let client_b = TestClient::connect("e2e_newsletter_join_b").await?;
    let joined = client_b.client.newsletter().join(&created.jid).await?;

    assert_eq!(joined.jid, created.jid);
    assert_eq!(joined.name, "Join Test Channel");

    info!(
        "Client B joined newsletter '{}' — role: {:?}",
        joined.name, joined.role
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_newsletter_leave() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_leave").await?;

    // Create and join a newsletter
    let created = client
        .client
        .newsletter()
        .create("Leave Test Channel", None)
        .await?;

    info!("Created newsletter: {}", created.jid);

    // Leave it
    client.client.newsletter().leave(&created.jid).await?;
    info!("Left newsletter: {}", created.jid);

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_newsletter_update() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_update").await?;

    // Create a newsletter
    let created = client
        .client
        .newsletter()
        .create("Original Name", Some("Original description"))
        .await?;

    info!("Created newsletter: {} ({})", created.name, created.jid);

    // Update name and description
    let updated = client
        .client
        .newsletter()
        .update(
            &created.jid,
            Some("Updated Name"),
            Some("Updated description"),
        )
        .await?;

    assert_eq!(updated.jid, created.jid);
    assert_eq!(updated.name, "Updated Name");

    info!(
        "Updated newsletter: name='{}', desc={:?}",
        updated.name, updated.description
    );

    // Verify via metadata fetch
    let metadata = client
        .client
        .newsletter()
        .get_metadata(&created.jid)
        .await?;
    assert_eq!(metadata.name, "Updated Name");

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_newsletter_send_and_get_messages() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_msg").await?;

    // Create a newsletter
    let created = client
        .client
        .newsletter()
        .create("Message Test Channel", None)
        .await?;

    info!("Created newsletter: {}", created.jid);

    // Send a text message
    let message = wa::Message {
        conversation: Some("Hello from newsletter!".to_string()),
        ..Default::default()
    };
    let msg_id = client
        .client
        .newsletter()
        .send_message(&created.jid, &message)
        .await?;

    info!("Sent message with id: {}", msg_id);

    // Fetch message history
    let messages = client
        .client
        .newsletter()
        .get_messages(&created.jid, 50, None)
        .await?;

    assert!(!messages.is_empty(), "should have at least one message");

    let first = &messages[0];
    assert!(first.server_id > 0, "server_id should be assigned");
    assert!(first.timestamp > 0, "timestamp should be set");

    // Verify the plaintext was decoded
    if let Some(ref decoded) = first.message {
        assert_eq!(
            decoded.conversation.as_deref(),
            Some("Hello from newsletter!")
        );
        info!(
            "Message decoded: server_id={}, text={:?}",
            first.server_id,
            decoded.conversation.as_deref()
        );
    }

    info!(
        "Fetched {} messages, first server_id={}",
        messages.len(),
        first.server_id
    );

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_newsletter_message_pagination() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_pag").await?;

    let created = client
        .client
        .newsletter()
        .create("Pagination Test", None)
        .await?;

    // Send multiple messages
    for i in 0..5 {
        let msg = wa::Message {
            conversation: Some(format!("Message {}", i)),
            ..Default::default()
        };
        client
            .client
            .newsletter()
            .send_message(&created.jid, &msg)
            .await?;
    }

    // Fetch all messages
    let all = client
        .client
        .newsletter()
        .get_messages(&created.jid, 50, None)
        .await?;
    assert_eq!(all.len(), 5, "should have 5 messages");

    // Paginate: get messages before the last one
    let last_server_id = all.last().unwrap().server_id;
    let page = client
        .client
        .newsletter()
        .get_messages(&created.jid, 2, Some(last_server_id))
        .await?;

    assert!(
        page.len() <= 4,
        "page before last should have fewer messages"
    );

    info!(
        "Pagination: total={}, page_before_last={}",
        all.len(),
        page.len()
    );

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_newsletter_subscribe_live_updates() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_live").await?;

    let created = client
        .client
        .newsletter()
        .create("Live Updates Test", None)
        .await?;

    let duration = client
        .client
        .newsletter()
        .subscribe_live_updates(&created.jid)
        .await?;

    assert!(duration > 0, "subscription duration should be positive");
    info!(
        "Subscribed to live updates for {} — duration={}s",
        created.jid, duration
    );

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_newsletter_reaction_live_update() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Client A creates a newsletter and sends a message
    let mut client_a = TestClient::connect("e2e_newsletter_react_a").await?;
    let created = client_a
        .client
        .newsletter()
        .create("Reaction Test", None)
        .await?;

    let msg = wa::Message {
        conversation: Some("React to me!".to_string()),
        ..Default::default()
    };
    client_a
        .client
        .newsletter()
        .send_message(&created.jid, &msg)
        .await?;

    // Get the server_id of the message we just sent
    let messages = client_a
        .client
        .newsletter()
        .get_messages(&created.jid, 1, None)
        .await?;
    assert!(!messages.is_empty());
    let server_id = messages[0].server_id;
    info!("Sent message with server_id={}", server_id);

    // Subscribe to live updates
    client_a
        .client
        .newsletter()
        .subscribe_live_updates(&created.jid)
        .await?;

    // Send a reaction (mock server echoes live_updates back to sender)
    client_a
        .client
        .newsletter()
        .send_reaction(&created.jid, server_id, "👍")
        .await?;

    // Wait for the live update notification
    let nl_jid = created.jid.clone();
    let event = client_a
        .wait_for_event(10, move |e| {
            matches!(e, Event::NewsletterLiveUpdate(update) if update.newsletter_jid == nl_jid)
        })
        .await?;

    if let Event::NewsletterLiveUpdate(update) = event {
        info!(
            "Received live update for {} with {} message(s)",
            update.newsletter_jid,
            update.messages.len()
        );
        assert!(!update.messages.is_empty());
        let msg_update = &update.messages[0];
        assert_eq!(msg_update.server_id, server_id);
        assert!(
            msg_update
                .reactions
                .iter()
                .any(|r| r.code == "👍" && r.count > 0),
            "should have thumbs up reaction"
        );
    }

    client_a.disconnect().await;
    Ok(())
}
