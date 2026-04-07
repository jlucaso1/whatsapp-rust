use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;

#[tokio::test]
async fn test_set_status_text() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_status_text").await?;

    info!("Setting status text...");
    client
        .client
        .profile()
        .set_status_text("Hello from Rust!")
        .await?;
    info!("Status text set successfully");

    // Set it again to verify idempotent behavior
    client
        .client
        .profile()
        .set_status_text("Updated status")
        .await?;
    info!("Status text updated successfully");

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_push_name() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_push_name").await?;

    // Wait for initial app state sync to complete so sync keys are available.
    // The push name mutation requires encryption keys from the critical_block sync.
    client.wait_for_app_state_sync().await?;

    let old_name = client.client.get_push_name().await;
    info!("Current push name: '{}'", old_name);

    let new_name = "TestBot 🤖";
    info!("Setting push name to '{}'...", new_name);
    client.client.profile().set_push_name(new_name).await?;

    // Verify it was updated locally
    let updated_name = client.client.get_push_name().await;
    assert_eq!(
        updated_name, new_name,
        "Push name should be updated locally"
    );
    info!("Push name updated successfully to '{}'", updated_name);

    // Set a different name to verify the app state sync can handle consecutive mutations
    let second_name = "RustBot 🦀";
    info!("Setting push name again to '{}'...", second_name);
    client.client.profile().set_push_name(second_name).await?;

    let final_name = client.client.get_push_name().await;
    assert_eq!(
        final_name, second_name,
        "Push name should be updated to second value"
    );
    info!("Push name updated to '{}' successfully", final_name);

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_push_name_empty_rejected() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_push_name_empty").await?;

    let result = client.client.profile().set_push_name("").await;
    assert!(result.is_err(), "Empty push name should be rejected");
    assert!(
        result.unwrap_err().to_string().contains("cannot be empty"),
        "Error should mention empty push name"
    );

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_status_text_special_characters() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_status_special").await?;

    // Emoji
    info!("Setting status text with emoji...");
    client
        .client
        .profile()
        .set_status_text("Hello 🌍🎉")
        .await?;
    info!("Emoji status set successfully");

    // Arabic (RTL Unicode)
    info!("Setting status text with Arabic...");
    client
        .client
        .profile()
        .set_status_text("مرحبا بالعالم")
        .await?;
    info!("Arabic status set successfully");

    // Multiline
    info!("Setting status text with newlines...");
    client
        .client
        .profile()
        .set_status_text("Line 1\nLine 2")
        .await?;
    info!("Multiline status set successfully");

    // Long text close to WhatsApp's 139 character limit
    let long_status = "a".repeat(139);
    info!(
        "Setting status text with {} characters...",
        long_status.len()
    );
    client
        .client
        .profile()
        .set_status_text(&long_status)
        .await?;
    info!("Long status set successfully");

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_status_text_empty() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_status_empty").await?;

    // WhatsApp allows clearing your status/about text
    info!("Setting empty status text (clearing status)...");
    client.client.profile().set_status_text("").await?;
    info!("Empty status text set successfully");

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_push_name_special_characters() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_push_special").await?;

    // Wait for initial app state sync to complete so sync keys are available.
    client.wait_for_app_state_sync().await?;

    // Emoji
    let name_emoji = "Bot 🤖🦀";
    info!("Setting push name with emoji: '{}'...", name_emoji);
    client.client.profile().set_push_name(name_emoji).await?;
    let result = client.client.get_push_name().await;
    assert_eq!(result, name_emoji, "Push name should support emoji");
    info!("Emoji push name set successfully");

    // Russian (Cyrillic Unicode)
    let name_russian = "Тест";
    info!("Setting push name with Russian: '{}'...", name_russian);
    client.client.profile().set_push_name(name_russian).await?;
    let result = client.client.get_push_name().await;
    assert_eq!(result, name_russian, "Push name should support Cyrillic");
    info!("Russian push name set successfully");

    // Mixed special characters
    let name_mixed = "Test™ User©";
    info!("Setting push name with special chars: '{}'...", name_mixed);
    client.client.profile().set_push_name(name_mixed).await?;
    let result = client.client.get_push_name().await;
    assert_eq!(
        result, name_mixed,
        "Push name should support special characters"
    );
    info!("Mixed special chars push name set successfully");

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_push_name_long() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_push_long").await?;

    // Wait for initial app state sync to complete so sync keys are available.
    client.wait_for_app_state_sync().await?;

    // WhatsApp allows up to 25 characters for push names
    let long_name = "A".repeat(25);
    info!("Setting push name with {} characters...", long_name.len());
    client.client.profile().set_push_name(&long_name).await?;
    let result = client.client.get_push_name().await;
    assert_eq!(result, long_name, "Push name should support 25 characters");
    info!("Long push name set successfully");

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_push_name_whitespace_only() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_push_whitespace").await?;

    // Wait for initial app state sync to complete so sync keys are available.
    client.wait_for_app_state_sync().await?;

    // Whitespace-only push name currently succeeds because we only check for empty string.
    // NOTE: This behavior may need to be revisited — WhatsApp clients may reject or trim
    // whitespace-only names. Documenting current behavior for now.
    let whitespace_name = "   ";
    info!("Setting whitespace-only push name...");
    client
        .client
        .profile()
        .set_push_name(whitespace_name)
        .await?;
    let result = client.client.get_push_name().await;
    assert_eq!(
        result, whitespace_name,
        "Whitespace-only push name should be accepted (only empty is rejected)"
    );
    info!("Whitespace-only push name set successfully");

    client.disconnect().await;
    Ok(())
}

/// Verify that setting status text broadcasts a `UserAboutUpdate` notification
/// to other connected clients. The mock server broadcasts `<notification type="status">`
/// matching real WhatsApp server behavior (WAWebHandleAboutNotification).
#[tokio::test]
async fn test_status_text_notification_received() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_status_notif_a").await?;
    let mut client_b = TestClient::connect("e2e_status_notif_b").await?;

    let new_status = "Testing status notifications!";
    info!("Client A setting status text to: {new_status}");
    client_a
        .client
        .profile()
        .set_status_text(new_status)
        .await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("Client A should have a JID")
        .to_non_ad();

    // Client B should receive a UserAboutUpdate event from Client A
    let event = client_b
        .wait_for_event(
            15,
            |e| matches!(e, Event::UserAboutUpdate(u) if u.jid == jid_a && u.status == new_status),
        )
        .await?;

    if let Event::UserAboutUpdate(update) = event {
        info!(
            "Client B received status update from {} (length={})",
            update.jid,
            update.status.len()
        );
    } else {
        panic!("Expected UserAboutUpdate event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_push_name_persists_across_operations() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_push_persist").await?;

    // Wait for initial app state sync to complete so sync keys are available.
    client.wait_for_app_state_sync().await?;

    // Set push name
    let push_name = "PersistBot";
    info!("Setting push name to '{}'...", push_name);
    client.client.profile().set_push_name(push_name).await?;
    let result = client.client.get_push_name().await;
    assert_eq!(result, push_name);
    info!("Push name set successfully");

    // Perform a different operation (set status text)
    info!("Setting status text (unrelated operation)...");
    client
        .client
        .profile()
        .set_status_text("Some status")
        .await?;
    info!("Status text set successfully");

    // Verify push name is still correct
    let after_status = client.client.get_push_name().await;
    assert_eq!(
        after_status, push_name,
        "Push name should persist after setting status text"
    );
    info!("Push name '{}' persisted across operations", after_status);

    client.disconnect().await;
    Ok(())
}
