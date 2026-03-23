use e2e_tests::{TestClient, text_msg};
use log::info;
use whatsapp_rust::features::{GroupCreateOptions, GroupParticipantOptions};

/// Verify that group messaging continues to work after a reconnect.
///
/// The first send populates the device registry (moka cache + SQLite DB).
/// After reconnect the moka cache is still warm (same Client object), so
/// this exercises the registry-based resolution path end-to-end. The SQLite
/// DB fallback (cold moka) is covered by unit test
/// `test_device_registry_db_fallback` in `usync.rs`.
#[tokio::test]
async fn test_group_send_uses_registry_cache_after_reconnect() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_devcache_a").await?;
    let mut client_b = TestClient::connect("e2e_devcache_b").await?;

    let jid_b = client_b.jid().await;
    info!("B = {jid_b}");

    let group = client_a
        .client
        .groups()
        .create_group(GroupCreateOptions {
            subject: "Device Cache Test".into(),
            participants: vec![GroupParticipantOptions::new(jid_b.clone())],
            ..Default::default()
        })
        .await?;
    let group_jid = group.gid;
    info!("Group: {group_jid}");

    // First send — populates device registry (in-memory cache + SQLite DB)
    let text_1 = "before reconnect";
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_1))
        .await?;
    client_b.wait_for_group_text(&group_jid, text_1, 30).await?;
    info!("B received pre-reconnect message");

    // Reconnect A — moka cache stays warm (same Client), SQLite DB also persists
    client_a.reconnect_and_wait().await?;
    info!("A reconnected");

    // Second send — exercises registry-based device resolution
    let text_2 = "after reconnect";
    let t = std::time::Instant::now();
    client_a
        .client
        .send_message(group_jid.clone(), text_msg(text_2))
        .await?;
    let send_ms = t.elapsed().as_millis();
    info!("A sent post-reconnect message in {send_ms}ms");

    client_b.wait_for_group_text(&group_jid, text_2, 30).await?;
    info!("B received post-reconnect message");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
