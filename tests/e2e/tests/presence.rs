use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::NodeFilter;

#[tokio::test]
async fn test_typing_indicator() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_typing_a").await?;
    let mut client_b = TestClient::connect("e2e_typing_b").await?;

    let jid_b = client_b.jid().await;

    info!("Client A sending typing indicator to {jid_b}");
    client_a.client.chatstate().send_composing(&jid_b).await?;

    client_b
        .wait_for_event(15, |e| matches!(e, Event::ChatPresence(_)))
        .await?;

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}

#[tokio::test]
async fn test_presence_available() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_presence_a").await?;
    let client_b = TestClient::connect("e2e_presence_b").await?;

    let jid_a = client_a.jid().await;

    // Register waiter BEFORE subscribing so no presence stanza is missed.
    let presence_waiter = client_b
        .client
        .wait_for_node(NodeFilter::tag("presence").attr("from", jid_a.to_string()));

    // A sets available first; the server tracks this state.
    client_a.client.presence().set_available().await?;
    info!("Client A set presence to available");

    // When B subscribes, the server sends A's current presence immediately
    // (no race because A's state is already recorded server-side).
    client_b.client.presence().subscribe(&jid_a).await?;

    let node = tokio::time::timeout(tokio::time::Duration::from_secs(15), presence_waiter)
        .await
        .map_err(|_| anyhow::anyhow!("Timed out waiting for presence node"))?
        .map_err(|_| anyhow::anyhow!("Presence waiter channel closed"))?;
    info!("Client B received presence node: tag={}", node.tag());

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}
