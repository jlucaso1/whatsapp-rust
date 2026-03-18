use e2e_tests::TestClient;
use log::info;

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
