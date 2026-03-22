use e2e_tests::TestClient;
use log::info;

#[tokio::test]
async fn test_connect_and_pair() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let tc = TestClient::connect("e2e_connect").await?;
    assert!(
        tc.client.is_logged_in(),
        "Client should be logged in after pairing"
    );

    tc.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_reconnect_after_disconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let tc = TestClient::connect("e2e_reconnect").await?;
    info!("First connection established");
    assert!(tc.client.is_logged_in());

    let client = tc.client.clone();
    client.disconnect().await;
    tc.run_handle.abort();

    // Verify the disconnect was clean.
    // A full reconnect test would persist the store and rebuild a new Bot.
    assert!(
        !client.is_logged_in(),
        "Client should not be logged in after disconnect"
    );

    Ok(())
}
