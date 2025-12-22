use chrono::{Local, Utc};
use log::{error, info};
use std::io::Cursor;
use std::sync::Arc;
use wacore::download::{Downloadable, MediaType};
use wacore::proto_helpers::MessageExt;
use wacore::types::events::Event;
use waproto::whatsapp as wa;
use whatsapp_rust::bot::{Bot, MessageContext};
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust::upload::UploadResponse;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

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

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    rt.block_on(async {
        let backend = match SqliteStore::new("whatsapp.db").await {
            Ok(store) => Arc::new(store),
            Err(e) => {
                error!("Failed to create SQLite backend: {}", e);
                return;
            }
        };
        info!("SQLite backend initialized successfully.");

        let transport_factory = TokioWebSocketTransportFactory::new();
        let http_client = UreqHttpClient::new();

        let mut bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport_factory)
            .with_http_client(http_client)
            // Optional: Override the WhatsApp version (normally auto-fetched)
            // .with_version((2, 3000, 1027868167))
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
                                info!("Received text ping, sending pong...");

                                // Send reaction to the ping message
                                let message_key = wa::MessageKey {
                                    remote_jid: Some(ctx.info.source.chat.to_string()),
                                    id: Some(ctx.info.id.clone()),
                                    from_me: Some(ctx.info.source.is_from_me),
                                    participant: if ctx.info.source.is_group {
                                        Some(ctx.info.source.sender.to_string())
                                    } else {
                                        None
                                    },
                                };

                                let reaction_emoji = "🏓".to_string();

                                let reaction_message = wa::message::ReactionMessage {
                                    key: Some(message_key),
                                    text: Some(reaction_emoji),
                                    sender_timestamp_ms: Some(Utc::now().timestamp_millis()),
                                    ..Default::default()
                                };

                                let final_message_to_send = wa::Message {
                                    reaction_message: Some(reaction_message),
                                    ..Default::default()
                                };

                                if let Err(e) = ctx.send_message(final_message_to_send).await {
                                    error!("Failed to send reaction: {}", e);
                                }

                                let start = std::time::Instant::now();

                                // Determine participant JID
                                let participant_jid = if ctx.info.source.is_from_me {
                                    ctx.client.get_pn().await.unwrap_or_default().to_string()
                                } else {
                                    ctx.info.source.sender.to_string()
                                };

                                // Construct ContextInfo for quoting
                                let context_info = wa::ContextInfo {
                                    stanza_id: Some(ctx.info.id.clone()),
                                    participant: Some(participant_jid),
                                    quoted_message: Some(ctx.message.clone()),
                                    ..Default::default()
                                };

                                // Create the initial quoted reply message
                                let reply_message = wa::Message {
                                    extended_text_message: Some(Box::new(
                                        wa::message::ExtendedTextMessage {
                                            text: Some("🏓 Pong!".to_string()),
                                            context_info: Some(Box::new(context_info.clone())),
                                            ..Default::default()
                                        },
                                    )),
                                    ..Default::default()
                                };

                                // 1. Send the initial message and get its ID
                                let sent_msg_id = match ctx.send_message(reply_message).await {
                                    Ok(id) => id,
                                    Err(e) => {
                                        error!("Failed to send initial pong message: {}", e);
                                        return;
                                    }
                                };

                                // 2. Calculate the duration
                                let duration = start.elapsed();
                                let duration_str = format!("{:.2?}", duration);

                                info!(
                                    "Send took {}. Editing message {}...",
                                    duration_str, &sent_msg_id
                                );

                                // 3. Create the new content for the message
                                let updated_content = wa::Message {
                                    extended_text_message: Some(Box::new(
                                        wa::message::ExtendedTextMessage {
                                            text: Some(format!("🏓 Pong!\n`{}`", duration_str)),
                                            context_info: Some(Box::new(context_info)),
                                            ..Default::default()
                                        },
                                    )),
                                    ..Default::default()
                                };

                                // 4. Edit the original message with the new content
                                if let Err(e) =
                                    ctx.edit_message(sent_msg_id.clone(), updated_content).await
                                {
                                    error!("Failed to edit message {}: {}", sent_msg_id, e);
                                } else {
                                    info!("Successfully sent edit for message {}.", sent_msg_id);
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

        bot_handle
            .await
            .expect("Bot task should complete without panicking");
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
