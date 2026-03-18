use e2e_tests::TestClient;
use log::info;

#[tokio::test]
async fn test_list_subscribed_newsletters() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_list").await?;

    let newsletters = client.client.newsletter().list_subscribed().await?;
    // Mock server should have at least one newsletter
    assert!(
        !newsletters.is_empty(),
        "should have subscribed newsletters"
    );

    let first = &newsletters[0];
    assert!(!first.name.is_empty(), "newsletter should have a name");
    assert!(
        !first.jid.user.is_empty(),
        "newsletter should have a JID user"
    );

    info!(
        "Listed {} subscribed newsletters, first: {} ({})",
        newsletters.len(),
        first.name,
        first.jid
    );

    client.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_get_newsletter_metadata() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_newsletter_meta").await?;

    // First list to get a known newsletter JID
    let newsletters = client.client.newsletter().list_subscribed().await?;
    assert!(!newsletters.is_empty(), "need at least one newsletter");

    let jid = &newsletters[0].jid;
    let metadata = client.client.newsletter().get_metadata(jid).await?;

    assert_eq!(metadata.jid, *jid);
    assert!(!metadata.name.is_empty(), "newsletter should have a name");
    assert!(
        metadata.subscriber_count > 0,
        "newsletter should have subscribers"
    );

    info!(
        "Fetched metadata for {}: name={}, subscribers={}",
        metadata.jid, metadata.name, metadata.subscriber_count
    );

    client.disconnect().await;

    Ok(())
}
