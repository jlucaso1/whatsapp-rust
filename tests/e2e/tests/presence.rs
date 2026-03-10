use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::NodeFilter;

#[tokio::test]
async fn test_typing_indicator() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_typing_a").await?;
    let mut client_b = TestClient::connect("e2e_typing_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("Client B should have a JID")
        .to_non_ad();

    info!("Client A sending typing indicator to {jid_b}");

    // Client A starts typing to Client B
    client_a.client.chatstate().send_composing(&jid_b).await?;

    // Client B should receive a ChatPresence event
    let event = client_b
        .wait_for_event(15, |e| matches!(e, Event::ChatPresence(_)))
        .await?;

    if let Event::ChatPresence(presence) = event {
        info!("Client B received chat presence: {:?}", presence);
    } else {
        panic!("Expected ChatPresence event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_presence_available() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_presence_a").await?;
    let client_b = TestClient::connect("e2e_presence_b").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("Client A should have a JID")
        .to_non_ad();

    // Register a node waiter on B BEFORE subscribing, so no presence stanza is missed.
    let presence_waiter = client_b
        .client
        .wait_for_node(NodeFilter::tag("presence").attr("from", jid_a.to_string()));

    // Client A sets available first — presence state is tracked by the server.
    client_a.client.presence().set_available().await?;
    info!("Client A set presence to available");

    // When B subscribes, the server sends A's current presence immediately
    // (no race condition since A's presence state is already recorded).
    client_b.client.presence().subscribe(&jid_a).await?;

    // Wait for the presence node (buffered since before subscribe)
    let node = tokio::time::timeout(tokio::time::Duration::from_secs(15), presence_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for presence node"))?
        .map_err(|_| anyhow::anyhow!("Presence waiter channel closed"))?;
    info!("Client B received presence node: tag={}", node.tag);

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}
