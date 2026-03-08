use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;

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
    let mut client_b = TestClient::connect("e2e_presence_b").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("Client A should have a JID")
        .to_non_ad();

    // Client B subscribes to Client A's presence
    client_b.client.presence().subscribe(&jid_a).await?;

    // Client A sets available
    client_a.client.presence().set_available().await?;
    info!("Client A set presence to available");

    // Client B should receive a Presence event
    let event = client_b
        .wait_for_event(15, |e| matches!(e, Event::Presence(_)))
        .await?;

    if let Event::Presence(presence) = event {
        info!("Client B received presence update: {:?}", presence);
    } else {
        panic!("Expected Presence event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;

    Ok(())
}
