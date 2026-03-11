use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;

#[tokio::test]
async fn test_set_profile_picture() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_set_ppic").await?;

    // Create a minimal JPEG-like test image (doesn't need to be valid for the mock server)
    let fake_image = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10]; // JPEG SOI + APP0 marker

    info!("Setting profile picture...");
    let response = client
        .client
        .profile()
        .set_profile_picture(fake_image.clone())
        .await?;
    info!("Profile picture set successfully, id={}", response.id);

    // Verify the picture can be retrieved
    let own_jid = client
        .client
        .get_pn()
        .await
        .expect("should have PN after pairing");
    info!("Fetching profile picture for own JID: {}", own_jid);
    let pic = client
        .client
        .contacts()
        .get_profile_picture(&own_jid, false)
        .await?;
    assert!(
        pic.is_some(),
        "Profile picture should be retrievable after setting"
    );
    let pic = pic.unwrap();
    assert_eq!(
        pic.id, response.id,
        "Retrieved picture ID should match set response"
    );
    info!("Profile picture retrieved: id={}, url={}", pic.id, pic.url);

    // Verify we receive a PictureUpdate event (self-notification from server)
    let event = client
        .wait_for_event(10, |e| matches!(e, Event::PictureUpdate(_)))
        .await?;
    if let Event::PictureUpdate(update) = event {
        info!(
            "Received PictureUpdate event: jid={}, author={:?}, removed={}, pic_id={:?}",
            update.jid, update.author, update.removed, update.picture_id
        );
        assert!(!update.removed, "Should be a set, not a delete");
        assert!(update.picture_id.is_some(), "Should have a picture ID");
    }

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_set_profile_picture_then_update() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_update_ppic").await?;

    // Set first picture
    let image1 = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x01];
    info!("Setting first profile picture...");
    let resp1 = client.client.profile().set_profile_picture(image1).await?;
    info!("First picture set, id={}", resp1.id);

    // Drain the PictureUpdate event from first set
    let _ = client
        .wait_for_event(10, |e| matches!(e, Event::PictureUpdate(_)))
        .await?;

    // Set second picture (update)
    let image2 = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x02];
    info!("Setting second profile picture...");
    let resp2 = client.client.profile().set_profile_picture(image2).await?;
    info!("Second picture set, id={}", resp2.id);

    // IDs should differ since the picture changed
    assert_ne!(resp1.id, resp2.id, "Picture IDs should differ after update");

    // Verify the updated picture is returned
    let own_jid = client
        .client
        .get_pn()
        .await
        .expect("should have PN after pairing");
    let pic = client
        .client
        .contacts()
        .get_profile_picture(&own_jid, false)
        .await?;
    assert!(pic.is_some());
    assert_eq!(
        pic.unwrap().id,
        resp2.id,
        "Should return the latest picture"
    );

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_remove_profile_picture() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_remove_ppic").await?;

    // First set a picture
    let image = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
    info!("Setting profile picture before removal test...");
    client.client.profile().set_profile_picture(image).await?;

    // Drain the PictureUpdate event
    let _ = client
        .wait_for_event(10, |e| matches!(e, Event::PictureUpdate(_)))
        .await?;

    // Now remove it
    info!("Removing profile picture...");
    client.client.profile().remove_profile_picture().await?;
    info!("Profile picture removed successfully");

    // Verify we receive a PictureUpdate event with removed=true
    let event = client
        .wait_for_event(10, |e| matches!(e, Event::PictureUpdate(u) if u.removed))
        .await?;
    if let Event::PictureUpdate(update) = event {
        assert!(update.removed, "Should be a delete");
        assert!(
            update.picture_id.is_none(),
            "Delete should have no picture ID"
        );
        info!("Received PictureUpdate delete event: jid={}", update.jid);
    }

    // Verify the picture is gone
    let own_jid = client
        .client
        .get_pn()
        .await
        .expect("should have PN after pairing");
    let pic = client
        .client
        .contacts()
        .get_profile_picture(&own_jid, false)
        .await?;
    assert!(
        pic.is_none(),
        "Profile picture should be gone after removal"
    );
    info!("Confirmed: no profile picture after removal");

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_get_nonexistent_profile_picture() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_get_no_ppic").await?;

    // Query own picture without ever setting one — should return None
    let own_jid = client
        .client
        .get_pn()
        .await
        .expect("should have PN after pairing");
    let pic = client
        .client
        .contacts()
        .get_profile_picture(&own_jid, true)
        .await?;
    assert!(pic.is_none(), "Should return None for user with no picture");
    info!("Confirmed: no picture for fresh user");

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_get_contact_profile_picture() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_get_contact_ppic_a").await?;
    let mut client_b = TestClient::connect("e2e_get_contact_ppic_b").await?;

    // Client B sets a profile picture
    let image = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x42];
    let set_resp = client_b.client.profile().set_profile_picture(image).await?;
    info!("Client B set picture, id={}", set_resp.id);

    // Drain B's own PictureUpdate event
    let _ = client_b
        .wait_for_event(10, |e| matches!(e, Event::PictureUpdate(_)))
        .await?;

    // Client A fetches Client B's profile picture
    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have PN")
        .to_non_ad();
    let pic = client_a
        .client
        .contacts()
        .get_profile_picture(&jid_b, false)
        .await?;
    assert!(pic.is_some(), "A should see B's profile picture");
    let pic = pic.unwrap();
    assert_eq!(pic.id, set_resp.id, "Picture ID should match what B set");
    assert!(!pic.url.is_empty(), "URL should be non-empty");
    info!(
        "Client A retrieved B's picture: id={}, url={}",
        pic.id, pic.url
    );

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_get_profile_picture_preview_and_full() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client = TestClient::connect("e2e_ppic_types").await?;

    let image = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x99];
    let set_resp = client.client.profile().set_profile_picture(image).await?;
    info!("Picture set, id={}", set_resp.id);

    // Drain PictureUpdate
    let _ = client
        .wait_for_event(10, |e| matches!(e, Event::PictureUpdate(_)))
        .await?;

    let own_jid = client
        .client
        .get_pn()
        .await
        .expect("should have PN after pairing");

    // Fetch preview
    let preview = client
        .client
        .contacts()
        .get_profile_picture(&own_jid, true)
        .await?;
    assert!(preview.is_some(), "Preview should be available");
    let preview = preview.unwrap();
    assert_eq!(preview.id, set_resp.id);
    info!("Preview: id={}, url={}", preview.id, preview.url);

    // Fetch full
    let full = client
        .client
        .contacts()
        .get_profile_picture(&own_jid, false)
        .await?;
    assert!(full.is_some(), "Full picture should be available");
    let full = full.unwrap();
    assert_eq!(full.id, set_resp.id);
    info!("Full: id={}, url={}", full.id, full.url);

    client.disconnect().await;
    Ok(())
}
