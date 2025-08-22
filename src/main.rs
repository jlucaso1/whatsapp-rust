use chrono::Local;
use log::{debug, error, info};
use std::io::Cursor;
use tokio::task;
use wacore::download::{Downloadable, MediaType};
use wacore::proto_helpers::MessageExt;
use wacore::types::events::Event;
use waproto::whatsapp as wa;
use whatsapp_rust::bot::{Bot, MessageContext};
use whatsapp_rust::upload::UploadResponse;

// This is a demo of a simple ping-pong bot with every type of media.

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} [{:<5}] [{}] - {}",
                Local::now().format("%H:%M:%S"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let local = task::LocalSet::new();
    local.block_on(&rt, async {
        let mut bot = Bot::builder()
            .on_event(move |event, client| {
                async move {
                    match event {
                        Event::PairingQrCode { code, timeout } => {
                            info!("----------------------------------------");
                            info!(
                                "New pairing code received (valid for {} seconds):",
                                timeout.as_secs()
                            );
                            info!("\n{}\n", code);
                            info!("----------------------------------------");
                        }

                        Event::Message(msg, info) => {
                            let ctx = MessageContext {
                                message: msg,
                                info,
                                client,
                            };

                            if let Some(media_ping_request) = get_pingable_media(&ctx.message) {
                                handle_media_ping(&ctx, media_ping_request).await;
                            }

                            if let Some(text) = ctx.message.text_content()
                                && text == "ping"
                            {
                                debug!("Received text ping, sending pong...");
                                if let Err(e) = ctx
                                    .send_message(wa::Message {
                                        conversation: Some("pong".to_string()),
                                        ..Default::default()
                                    })
                                    .await
                                {
                                    error!("Failed to send text reply: {}", e);
                                }
                            }
                        }
                        Event::Connected(_) => {
                            info!("✅ Bot connected successfully!");
                        }
                        Event::Receipt(receipt) => {
                            info!(
                                "Got receipt for message(s) {:?}, type: {:?}",
                                receipt.message_ids, receipt.r#type
                            );
                        }
                        Event::LoggedOut(_) => {
                            error!("❌ Bot was logged out!");
                        }
                        _ => {
                            // debug!("Received unhandled event: {:?}", event);
                        }
                    }
                }
            })
            .build()
            .await
            .expect("Failed to build bot");

        // If you want and need, you can get the client:
        // let client = bot.client();

        let bot_handle = match bot.run().await {
            Ok(handle) => handle,
            Err(e) => {
                error!("Bot failed to start: {}", e);
                return;
            }
        };

        bot_handle.await.unwrap();
    });
}

trait MediaPing: Downloadable {
    fn media_type(&self) -> MediaType;

    fn build_pong_reply(&self, upload: UploadResponse) -> wa::Message;
}

impl MediaPing for wa::message::ImageMessage {
    fn media_type(&self) -> MediaType {
        MediaType::Image
    }

    fn build_pong_reply(&self, upload: UploadResponse) -> wa::Message {
        wa::Message {
            image_message: Some(Box::new(wa::message::ImageMessage {
                mimetype: self.mimetype.clone(),
                caption: Some("pong".to_string()),
                url: Some(upload.url),
                direct_path: Some(upload.direct_path),
                media_key: Some(upload.media_key),
                file_enc_sha256: Some(upload.file_enc_sha256),
                file_sha256: Some(upload.file_sha256),
                file_length: Some(upload.file_length),
                ..Default::default()
            })),
            ..Default::default()
        }
    }
}

impl MediaPing for wa::message::VideoMessage {
    fn media_type(&self) -> MediaType {
        MediaType::Video
    }

    fn build_pong_reply(&self, upload: UploadResponse) -> wa::Message {
        wa::Message {
            video_message: Some(Box::new(wa::message::VideoMessage {
                mimetype: self.mimetype.clone(),
                caption: Some("pong".to_string()),
                url: Some(upload.url),
                direct_path: Some(upload.direct_path),
                media_key: Some(upload.media_key),
                file_enc_sha256: Some(upload.file_enc_sha256),
                file_sha256: Some(upload.file_sha256),
                file_length: Some(upload.file_length),
                gif_playback: self.gif_playback,
                height: self.height,
                width: self.width,
                seconds: self.seconds,
                gif_attribution: self.gif_attribution,
                ..Default::default()
            })),
            ..Default::default()
        }
    }
}

fn get_pingable_media<'a>(message: &'a wa::Message) -> Option<&'a (dyn MediaPing + 'a)> {
    let base_message = message.get_base_message();

    if let Some(msg) = &base_message.image_message
        && msg.caption.as_deref() == Some("ping")
    {
        return Some(&**msg);
    }
    if let Some(msg) = &base_message.video_message
        && msg.caption.as_deref() == Some("ping")
    {
        return Some(&**msg);
    }

    None
}

async fn handle_media_ping(ctx: &MessageContext, media: &(dyn MediaPing + '_)) {
    info!(
        "Received {:?} ping from {}",
        media.media_type(),
        ctx.info.source.sender
    );

    let mut data_buffer = Cursor::new(Vec::new());
    if let Err(e) = ctx.client.download_to_file(media, &mut data_buffer).await {
        error!("Failed to download media: {}", e);
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some("Failed to download your media.".to_string()),
                ..Default::default()
            })
            .await;
        return;
    }

    info!(
        "Successfully downloaded media. Size: {} bytes. Now uploading...",
        data_buffer.get_ref().len()
    );
    let plaintext_data = data_buffer.into_inner();
    let upload_response = match ctx.client.upload(plaintext_data, media.media_type()).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to upload media: {}", e);
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some("Failed to re-upload the media.".to_string()),
                    ..Default::default()
                })
                .await;
            return;
        }
    };

    info!("Successfully uploaded media. Constructing reply message...");
    let reply_msg = media.build_pong_reply(upload_response);

    if let Err(e) = ctx.send_message(reply_msg).await {
        error!("Failed to send media pong reply: {}", e);
    } else {
        info!("Media pong reply sent successfully.");
    }
}
