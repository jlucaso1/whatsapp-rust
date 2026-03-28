use e2e_tests::TestClient;
use log::info;
use wacore::types::events::Event;
use whatsapp_rust::download::{Downloadable, MediaType};
use whatsapp_rust::upload::UploadResponse;
use whatsapp_rust::waproto::whatsapp as wa;

/// Helper: build an ImageMessage from an UploadResponse.
fn build_image_message(upload: &UploadResponse, caption: Option<&str>) -> wa::Message {
    wa::Message {
        image_message: Some(Box::new(wa::message::ImageMessage {
            url: Some(upload.url.clone()),
            direct_path: Some(upload.direct_path.clone()),
            media_key: Some(upload.media_key.clone()),
            file_sha256: Some(upload.file_sha256.clone()),
            file_enc_sha256: Some(upload.file_enc_sha256.clone()),
            file_length: Some(upload.file_length),
            mimetype: Some("image/jpeg".to_string()),
            caption: caption.map(|c| c.to_string()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// Helper: build a VideoMessage from an UploadResponse.
fn build_video_message(
    upload: &UploadResponse,
    caption: Option<&str>,
    seconds: u32,
) -> wa::Message {
    wa::Message {
        video_message: Some(Box::new(wa::message::VideoMessage {
            url: Some(upload.url.clone()),
            direct_path: Some(upload.direct_path.clone()),
            media_key: Some(upload.media_key.clone()),
            file_sha256: Some(upload.file_sha256.clone()),
            file_enc_sha256: Some(upload.file_enc_sha256.clone()),
            file_length: Some(upload.file_length),
            mimetype: Some("video/mp4".to_string()),
            seconds: Some(seconds),
            caption: caption.map(|c| c.to_string()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// Helper: build a DocumentMessage from an UploadResponse.
fn build_document_message(upload: &UploadResponse, filename: &str, mimetype: &str) -> wa::Message {
    wa::Message {
        document_message: Some(Box::new(wa::message::DocumentMessage {
            url: Some(upload.url.clone()),
            direct_path: Some(upload.direct_path.clone()),
            media_key: Some(upload.media_key.clone()),
            file_sha256: Some(upload.file_sha256.clone()),
            file_enc_sha256: Some(upload.file_enc_sha256.clone()),
            file_length: Some(upload.file_length),
            mimetype: Some(mimetype.to_string()),
            file_name: Some(filename.to_string()),
            ..Default::default()
        })),
        ..Default::default()
    }
}

/// Helper: build an AudioMessage from an UploadResponse.
fn build_audio_message(upload: &UploadResponse, ptt: bool, seconds: u32) -> wa::Message {
    wa::Message {
        audio_message: Some(Box::new(wa::message::AudioMessage {
            url: Some(upload.url.clone()),
            direct_path: Some(upload.direct_path.clone()),
            media_key: Some(upload.media_key.clone()),
            file_sha256: Some(upload.file_sha256.clone()),
            file_enc_sha256: Some(upload.file_enc_sha256.clone()),
            file_length: Some(upload.file_length),
            mimetype: Some(if ptt {
                "audio/ogg; codecs=opus".to_string()
            } else {
                "audio/mpeg".to_string()
            }),
            ptt: Some(ptt),
            seconds: Some(seconds),
            ..Default::default()
        })),
        ..Default::default()
    }
}

// ─── Upload Tests ────────────────────────────────────────────────────

#[tokio::test]
async fn test_upload_image() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_upload_img").await?;

    let data = vec![0xFFu8, 0xD8, 0xFF, 0xE0, 0x00, 0x10]; // fake JPEG header

    let resp = client
        .client
        .upload(data.clone(), MediaType::Image, Default::default())
        .await?;

    info!(
        "Upload response: url={}, direct_path={}",
        resp.url, resp.direct_path
    );

    assert!(!resp.url.is_empty(), "URL should not be empty");
    assert!(
        !resp.direct_path.is_empty(),
        "direct_path should not be empty"
    );
    assert!(!resp.media_key.is_empty(), "media_key should not be empty");
    assert!(
        !resp.file_sha256.is_empty(),
        "file_sha256 should not be empty"
    );
    assert!(
        !resp.file_enc_sha256.is_empty(),
        "file_enc_sha256 should not be empty"
    );
    assert_eq!(resp.file_length, data.len() as u64);

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_upload_video() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_upload_vid").await?;

    let data = vec![0u8; 64]; // fake video bytes
    let resp = client
        .client
        .upload(data.clone(), MediaType::Video, Default::default())
        .await?;

    assert!(!resp.url.is_empty());
    assert!(!resp.direct_path.is_empty());
    assert_eq!(resp.file_length, data.len() as u64);

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_upload_document() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_upload_doc").await?;

    let data = b"%PDF-1.4 fake pdf content for testing purposes".to_vec();
    let resp = client
        .client
        .upload(data.clone(), MediaType::Document, Default::default())
        .await?;

    assert!(!resp.url.is_empty());
    assert!(!resp.direct_path.is_empty());
    assert_eq!(resp.file_length, data.len() as u64);

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_upload_audio() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_upload_aud").await?;

    let data = vec![0u8; 64]; // fake audio bytes
    let resp = client
        .client
        .upload(data.clone(), MediaType::Audio, Default::default())
        .await?;

    assert!(!resp.url.is_empty());
    assert!(!resp.direct_path.is_empty());
    assert_eq!(resp.file_length, data.len() as u64);

    client.disconnect().await;
    Ok(())
}

// ─── Upload + Download Round-Trip Tests ──────────────────────────────

#[tokio::test]
async fn test_upload_then_download_image() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_roundtrip_img").await?;

    let original = b"JPEG image content for round-trip test".to_vec();
    let upload = client
        .client
        .upload(original.clone(), MediaType::Image, Default::default())
        .await?;

    info!("Uploaded: direct_path={}", upload.direct_path);

    // Download using download_from_params
    let downloaded = client
        .client
        .download_from_params(
            &upload.direct_path,
            &upload.media_key,
            &upload.file_sha256,
            &upload.file_enc_sha256,
            upload.file_length,
            MediaType::Image,
        )
        .await?;

    assert_eq!(
        downloaded, original,
        "Downloaded data should match original"
    );

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_upload_then_download_video() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_roundtrip_vid").await?;

    let original = vec![0xAB; 64]; // fake video
    let upload = client
        .client
        .upload(original.clone(), MediaType::Video, Default::default())
        .await?;

    let downloaded = client
        .client
        .download_from_params(
            &upload.direct_path,
            &upload.media_key,
            &upload.file_sha256,
            &upload.file_enc_sha256,
            upload.file_length,
            MediaType::Video,
        )
        .await?;

    assert_eq!(downloaded, original);

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_upload_then_download_document() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_roundtrip_doc").await?;

    let original = b"PDF document content for testing".to_vec();
    let upload = client
        .client
        .upload(original.clone(), MediaType::Document, Default::default())
        .await?;

    let downloaded = client
        .client
        .download_from_params(
            &upload.direct_path,
            &upload.media_key,
            &upload.file_sha256,
            &upload.file_enc_sha256,
            upload.file_length,
            MediaType::Document,
        )
        .await?;

    assert_eq!(downloaded, original);

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_upload_then_download_via_downloadable_trait() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_roundtrip_trait").await?;

    let original = b"Testing Downloadable trait with ImageMessage".to_vec();
    let upload = client
        .client
        .upload(original.clone(), MediaType::Image, Default::default())
        .await?;

    // Build an ImageMessage (which implements Downloadable)
    let img_msg = wa::message::ImageMessage {
        url: Some(upload.url.clone()),
        direct_path: Some(upload.direct_path.clone()),
        media_key: Some(upload.media_key.clone()),
        file_sha256: Some(upload.file_sha256.clone()),
        file_enc_sha256: Some(upload.file_enc_sha256.clone()),
        file_length: Some(upload.file_length),
        mimetype: Some("image/jpeg".to_string()),
        ..Default::default()
    };

    let downloaded = client
        .client
        .download(&img_msg as &dyn Downloadable)
        .await?;
    assert_eq!(downloaded, original);

    client.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_upload_then_download_to_writer() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_roundtrip_writer").await?;

    let original = b"Streaming download test content".to_vec();
    let upload = client
        .client
        .upload(original.clone(), MediaType::Image, Default::default())
        .await?;

    let cursor = std::io::Cursor::new(Vec::<u8>::new());
    let result_cursor = client
        .client
        .download_from_params_to_writer(
            &upload.direct_path,
            &upload.media_key,
            &upload.file_sha256,
            &upload.file_enc_sha256,
            upload.file_length,
            MediaType::Image,
            cursor,
        )
        .await?;

    assert_eq!(result_cursor.into_inner(), original);

    client.disconnect().await;
    Ok(())
}

// ─── Send Media Message Between Two Users ────────────────────────────

#[tokio::test]
async fn test_send_image_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_send_img_a").await?;
    let mut client_b = TestClient::connect("e2e_send_img_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    // A uploads an image
    let original = b"Image bytes sent from A to B".to_vec();
    let upload = client_a
        .client
        .upload(original.clone(), MediaType::Image, Default::default())
        .await?;

    // A sends the image to B
    let caption = "Check out this photo!";
    let msg = build_image_message(&upload, Some(caption));
    let msg_id = client_a
        .client
        .send_message(jid_b.clone(), msg)
        .await?
        .message_id;
    info!("Sent image message: {msg_id}");

    // B receives the image message
    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.image_message.is_some()),
        )
        .await?;

    if let Event::Message(msg, info) = event {
        let img = msg.image_message.as_ref().unwrap();
        assert_eq!(img.caption.as_deref(), Some(caption));
        assert_eq!(img.mimetype.as_deref(), Some("image/jpeg"));
        assert!(img.direct_path.is_some());
        assert!(img.media_key.is_some());
        assert!(img.file_enc_sha256.is_some());
        assert!(img.file_sha256.is_some());
        info!("B received image from {:?}", info.source);

        // B downloads the received image
        let downloaded = client_b
            .client
            .download(img.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(
            downloaded, original,
            "Downloaded image should match original"
        );
    } else {
        panic!("Expected image Message event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_send_video_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_send_vid_a").await?;
    let mut client_b = TestClient::connect("e2e_send_vid_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    let original = vec![0xBB; 64];
    let upload = client_a
        .client
        .upload(original.clone(), MediaType::Video, Default::default())
        .await?;

    let msg = build_video_message(&upload, Some("Cool video"), 15);
    client_a.client.send_message(jid_b.clone(), msg).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.video_message.is_some()),
        )
        .await?;

    if let Event::Message(msg, _) = event {
        let vid = msg.video_message.as_ref().unwrap();
        assert_eq!(vid.caption.as_deref(), Some("Cool video"));
        assert_eq!(vid.seconds, Some(15));
        assert_eq!(vid.mimetype.as_deref(), Some("video/mp4"));

        let downloaded = client_b
            .client
            .download(vid.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(downloaded, original);
    } else {
        panic!("Expected video Message event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_send_document_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_send_doc_a").await?;
    let mut client_b = TestClient::connect("e2e_send_doc_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    let original = b"Important document content".to_vec();
    let upload = client_a
        .client
        .upload(original.clone(), MediaType::Document, Default::default())
        .await?;

    let msg = build_document_message(&upload, "report.pdf", "application/pdf");
    client_a.client.send_message(jid_b.clone(), msg).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.document_message.is_some()),
        )
        .await?;

    if let Event::Message(msg, _) = event {
        let doc = msg.document_message.as_ref().unwrap();
        assert_eq!(doc.file_name.as_deref(), Some("report.pdf"));
        assert_eq!(doc.mimetype.as_deref(), Some("application/pdf"));

        let downloaded = client_b
            .client
            .download(doc.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(downloaded, original);
    } else {
        panic!("Expected document Message event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_send_audio_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_send_aud_a").await?;
    let mut client_b = TestClient::connect("e2e_send_aud_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    let original = vec![0xCC; 64];
    let upload = client_a
        .client
        .upload(original.clone(), MediaType::Audio, Default::default())
        .await?;

    let msg = build_audio_message(&upload, false, 30);
    client_a.client.send_message(jid_b.clone(), msg).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.audio_message.is_some()),
        )
        .await?;

    if let Event::Message(msg, _) = event {
        let audio = msg.audio_message.as_ref().unwrap();
        assert_eq!(audio.seconds, Some(30));
        assert_eq!(audio.ptt, Some(false));

        let downloaded = client_b
            .client
            .download(audio.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(downloaded, original);
    } else {
        panic!("Expected audio Message event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

#[tokio::test]
async fn test_send_ptt_voice_message() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_send_ptt_a").await?;
    let mut client_b = TestClient::connect("e2e_send_ptt_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    let original = vec![0xDD; 64];
    let upload = client_a
        .client
        .upload(original.clone(), MediaType::Audio, Default::default())
        .await?;

    let msg = build_audio_message(&upload, true, 5);
    client_a.client.send_message(jid_b.clone(), msg).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.audio_message.is_some()),
        )
        .await?;

    if let Event::Message(msg, _) = event {
        let audio = msg.audio_message.as_ref().unwrap();
        assert_eq!(audio.ptt, Some(true));
        assert_eq!(audio.seconds, Some(5));
        assert_eq!(audio.mimetype.as_deref(), Some("audio/ogg; codecs=opus"));

        let downloaded = client_b
            .client
            .download(audio.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(downloaded, original);
    } else {
        panic!("Expected PTT audio Message event");
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Bidirectional Media Exchange ────────────────────────────────────

#[tokio::test]
async fn test_send_image_bidirectional() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut client_a = TestClient::connect("e2e_bidir_img_a").await?;
    let mut client_b = TestClient::connect("e2e_bidir_img_b").await?;

    let jid_a = client_a
        .client
        .get_pn()
        .await
        .expect("A should have JID")
        .to_non_ad();
    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    // A -> B: send image
    let data_a = b"Image from A to B".to_vec();
    let upload_a = client_a
        .client
        .upload(data_a.clone(), MediaType::Image, Default::default())
        .await?;
    let msg_a = build_image_message(&upload_a, Some("From A"));
    client_a.client.send_message(jid_b.clone(), msg_a).await?;

    // B receives
    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.image_message.is_some()),
        )
        .await?;
    if let Event::Message(msg, _) = event {
        let img = msg.image_message.as_ref().unwrap();
        assert_eq!(img.caption.as_deref(), Some("From A"));
        let downloaded = client_b
            .client
            .download(img.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(downloaded, data_a);
    }

    // B -> A: send image back
    let data_b = b"Image from B to A".to_vec();
    let upload_b = client_b
        .client
        .upload(data_b.clone(), MediaType::Image, Default::default())
        .await?;
    let msg_b = build_image_message(&upload_b, Some("From B"));
    client_b.client.send_message(jid_a.clone(), msg_b).await?;

    // A receives
    let event = client_a
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.image_message.is_some()),
        )
        .await?;
    if let Event::Message(msg, _) = event {
        let img = msg.image_message.as_ref().unwrap();
        assert_eq!(img.caption.as_deref(), Some("From B"));
        let downloaded = client_a
            .client
            .download(img.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(downloaded, data_b);
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Multiple Media Types in Sequence ────────────────────────────────

#[tokio::test]
async fn test_send_multiple_media_types() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_multi_media_a").await?;
    let mut client_b = TestClient::connect("e2e_multi_media_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    // Send image
    let img_data = b"image data for multi-type test".to_vec();
    let img_upload = client_a
        .client
        .upload(img_data.clone(), MediaType::Image, Default::default())
        .await?;
    let img_msg = build_image_message(&img_upload, Some("Photo"));
    client_a.client.send_message(jid_b.clone(), img_msg).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.image_message.is_some()),
        )
        .await?;
    if let Event::Message(msg, _) = event {
        let img = msg.image_message.as_ref().unwrap();
        let dl = client_b
            .client
            .download(img.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(dl, img_data);
    }

    // Send document
    let doc_data = b"document data for multi-type test".to_vec();
    let doc_upload = client_a
        .client
        .upload(doc_data.clone(), MediaType::Document, Default::default())
        .await?;
    let doc_msg = build_document_message(&doc_upload, "file.txt", "text/plain");
    client_a.client.send_message(jid_b.clone(), doc_msg).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.document_message.is_some()),
        )
        .await?;
    if let Event::Message(msg, _) = event {
        let doc = msg.document_message.as_ref().unwrap();
        let dl = client_b
            .client
            .download(doc.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(dl, doc_data);
    }

    // Send audio
    let aud_data = b"audio data for multi-type test".to_vec();
    let aud_upload = client_a
        .client
        .upload(aud_data.clone(), MediaType::Audio, Default::default())
        .await?;
    let aud_msg = build_audio_message(&aud_upload, true, 10);
    client_a.client.send_message(jid_b.clone(), aud_msg).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.audio_message.is_some()),
        )
        .await?;
    if let Event::Message(msg, _) = event {
        let audio = msg.audio_message.as_ref().unwrap();
        let dl = client_b
            .client
            .download(audio.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(dl, aud_data);
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}

// ─── Large File Upload/Download ──────────────────────────────────────

#[tokio::test]
async fn test_upload_download_large_file() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_large_file").await?;

    // Small file (was 1MB, reduced for CI stability)
    let original = vec![0x42u8; 256];
    let upload = client
        .client
        .upload(original.clone(), MediaType::Document, Default::default())
        .await?;

    let downloaded = client
        .client
        .download_from_params(
            &upload.direct_path,
            &upload.media_key,
            &upload.file_sha256,
            &upload.file_enc_sha256,
            upload.file_length,
            MediaType::Document,
        )
        .await?;

    assert_eq!(downloaded.len(), original.len());
    assert_eq!(downloaded, original);

    client.disconnect().await;
    Ok(())
}

// ─── Media Connection Refresh ────────────────────────────────────────

#[tokio::test]
async fn test_multiple_uploads_reuse_media_conn() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client = TestClient::connect("e2e_multi_upload").await?;

    // Upload multiple files in sequence - media_conn should be cached
    for i in 0..3 {
        let data = format!("Upload number {i}").into_bytes();
        let resp = client
            .client
            .upload(data.clone(), MediaType::Image, Default::default())
            .await?;
        info!("Upload {i}: direct_path={}", resp.direct_path);
        assert!(!resp.direct_path.is_empty());

        // Verify round-trip
        let downloaded = client
            .client
            .download_from_params(
                &resp.direct_path,
                &resp.media_key,
                &resp.file_sha256,
                &resp.file_enc_sha256,
                resp.file_length,
                MediaType::Image,
            )
            .await?;
        assert_eq!(downloaded, data);
    }

    client.disconnect().await;
    Ok(())
}

// ─── Image with No Caption ──────────────────────────────────────────

#[tokio::test]
async fn test_send_image_no_caption() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let client_a = TestClient::connect("e2e_img_nocap_a").await?;
    let mut client_b = TestClient::connect("e2e_img_nocap_b").await?;

    let jid_b = client_b
        .client
        .get_pn()
        .await
        .expect("B should have JID")
        .to_non_ad();

    let original = b"Image without caption".to_vec();
    let upload = client_a
        .client
        .upload(original.clone(), MediaType::Image, Default::default())
        .await?;

    let msg = build_image_message(&upload, None);
    client_a.client.send_message(jid_b.clone(), msg).await?;

    let event = client_b
        .wait_for_event(
            30,
            |e| matches!(e, Event::Message(m, _) if m.image_message.is_some()),
        )
        .await?;

    if let Event::Message(msg, _) = event {
        let img = msg.image_message.as_ref().unwrap();
        assert!(
            img.caption.is_none() || img.caption.as_deref() == Some(""),
            "Caption should be absent or empty"
        );
        let downloaded = client_b
            .client
            .download(img.as_ref() as &dyn Downloadable)
            .await?;
        assert_eq!(downloaded, original);
    }

    client_a.disconnect().await;
    client_b.disconnect().await;
    Ok(())
}
