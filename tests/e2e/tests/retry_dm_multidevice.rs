//! DM retry recovery after session deletion.

use e2e_tests::{TestClient, send_and_expect_text};
use log::info;

#[tokio::test]
async fn test_dm_retry_recovers_after_session_deletion() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_retry_dm_a").await?;
    let mut client_b = TestClient::connect("e2e_retry_dm_b").await?;

    let jid_a = client_a.jid().await;
    let jid_b = client_b.jid().await;
    assert_ne!(
        jid_a.user, jid_b.user,
        "Clients must use different accounts"
    );

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "retry-setup-a2b",
        30,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "retry-setup-b2a",
        30,
    )
    .await?;
    info!("Baseline roundtrip established sessions");

    client_b
        .client
        .signal()
        .delete_sessions(std::slice::from_ref(&jid_a))
        .await?;

    send_and_expect_text(&client_a.client, &mut client_b, &jid_b, "retry-recover", 30).await?;
    info!("Retry recovered after B deleted its session with A");

    send_and_expect_text(
        &client_a.client,
        &mut client_b,
        &jid_b,
        "retry-followup-a2b",
        15,
    )
    .await?;
    send_and_expect_text(
        &client_b.client,
        &mut client_a,
        &jid_a,
        "retry-followup-b2a",
        15,
    )
    .await?;
    info!("Messaging still works after retry recovery");

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
