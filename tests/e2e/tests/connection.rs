use std::sync::Arc;

use e2e_tests::{ChannelEventHandler, TestClient, create_test_store, mock_server_url};
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::traits::Backend;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

#[tokio::test]
async fn test_connect_and_pair() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let ws_url = mock_server_url();
    info!("Connecting to mock server at {}", ws_url);

    // Create storage
    let store = create_test_store("e2e_connect").await?;
    let backend = Arc::new(store) as Arc<dyn Backend>;

    // Create transport pointing to mock server (TLS verification is skipped via feature flag)
    let transport_factory = TokioWebSocketTransportFactory::new().with_url(&ws_url);

    // Build bot with event capture
    let (event_handler, mut event_rx) = ChannelEventHandler::new();

    let mut bot = Bot::builder()
        .with_backend(backend)
        .with_transport_factory(transport_factory)
        .with_http_client(UreqHttpClient::new())
        .with_runtime(whatsapp_rust::TokioRuntime)
        .build()
        .await?;

    // Register event handler before running
    let client = bot.client();
    client.register_handler(event_handler);

    // Run bot in background
    let run_handle = bot.run().await?;

    // Wait for PairSuccess and Connected events (mock server auto-pairs after ~2s)
    let timeout = tokio::time::Duration::from_secs(30);
    let mut got_pair_success = false;
    let mut got_connected = false;

    let result = tokio::time::timeout(timeout, async {
        loop {
            match event_rx.recv().await {
                Ok(Event::PairSuccess(ps)) => {
                    info!("Received PairSuccess: {:?}", ps);
                    got_pair_success = true;
                    if got_connected {
                        break;
                    }
                }
                Ok(Event::Connected(_)) => {
                    info!("Received Connected event");
                    got_connected = true;
                    if got_pair_success {
                        break;
                    }
                }
                Ok(event) => {
                    info!("Received event: {:?}", event);
                }
                Err(e) => {
                    panic!("Event channel error: {}", e);
                }
            }
        }
    })
    .await;

    assert!(
        result.is_ok(),
        "Timed out waiting for PairSuccess + Connected events"
    );
    assert!(got_pair_success, "Should have received PairSuccess");
    assert!(got_connected, "Should have received Connected");

    // Verify the client is logged in
    assert!(
        client.is_logged_in(),
        "Client should be logged in after pairing"
    );

    // Cleanup
    client.disconnect().await;
    run_handle.abort();

    Ok(())
}

#[tokio::test]
async fn test_reconnect_after_disconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Connect and pair
    let tc = TestClient::connect("e2e_reconnect").await?;
    info!("First connection established");

    assert!(tc.client.is_logged_in());

    // Keep client and store, disconnect
    let client = tc.client.clone();
    client.disconnect().await;
    tc.run_handle.abort();

    // Reconnect using the same persisted store — should not need re-pairing.
    // We need a new Bot with the same backend. Since TestClient consumed the store,
    // we verify the client was logged in before disconnecting.
    // For a full reconnect test, we'd need to persist the store and rebuild.
    // For now, verify the disconnect was clean.
    assert!(
        !client.is_logged_in(),
        "Client should not be logged in after disconnect"
    );

    Ok(())
}
