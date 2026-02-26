use chrono::{Local, Utc};
use log::{error, info};
use qrcode::QrCode;
use std::io::Cursor;
use std::sync::Arc;
use wacore::download::{Downloadable, MediaType};
use wacore::proto_helpers::MessageExt;
use wacore::types::events::Event;
use waproto::whatsapp as wa;
use whatsapp_rust::PollOptions;
use whatsapp_rust::bot::{Bot, MessageContext};
use whatsapp_rust::pair_code::PairCodeOptions;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust::upload::UploadResponse;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

const PING_TRIGGER: &str = "🦀ping";
const MEDIA_PING_TRIGGER: &str = "ping";
const PONG_TEXT: &str = "🏓 Pong!";
const MEDIA_PONG_TEXT: &str = "pong";
const REACTION_EMOJI: &str = "🏓";
const POLL_TRIGGER: &str = "!poll";
const QUIZ_TRIGGER: &str = "!quiz";
const HELP_TRIGGER: &str = "!help";

// This is a demo of a simple ping-pong bot with every type of media.
//
// Usage:
//   cargo run                                      # QR code pairing only
//   cargo run -- --phone 15551234567               # Pair code + QR code (concurrent)
//   cargo run -- -p 15551234567                    # Short form
//   cargo run -- -p 15551234567 --code MYCODE12    # Custom 8-char pair code
//   cargo run -- -p 15551234567 -c MYCODE12        # Short form

fn main() {
    // Parse CLI arguments for phone number and optional custom code
    let args: Vec<String> = std::env::args().collect();
    let phone_number = parse_arg(&args, "--phone", "-p");
    let custom_code = parse_arg(&args, "--code", "-c");

    if let Some(ref phone) = phone_number {
        eprintln!("Phone number provided: {}", phone);
        if let Some(ref code) = custom_code {
            eprintln!("Custom pair code: {}", code);
        }
        eprintln!("Will use pair code authentication (concurrent with QR)");
    }
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

        let mut builder = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport_factory)
            .with_http_client(http_client);
        // Optional: Override the WhatsApp version (normally auto-fetched)
        // builder = builder.with_version((2, 3000, 1027868167));

        // Add pair code authentication if phone number provided
        if let Some(phone) = phone_number {
            builder = builder.with_pair_code(PairCodeOptions {
                phone_number: phone,
                custom_code,
                ..Default::default()
            });
        }

        let mut bot = builder
            .on_event(move |event, client| {
                async move {
                    match event {
                        Event::PairingQrCode { code, timeout } => {
                            info!("========================================");
                            info!("QR CODE (valid for {} seconds):", timeout.as_secs());
                            info!("Scan this QR code with WhatsApp on your phone:");
                            info!("WhatsApp > Linked Devices > Link a Device\n");

                            match QrCode::new(&code) {
                                Ok(qr) => {
                                    // Use compact rendering with half-blocks to reduce height
                                    use qrcode::render::unicode;
                                    let string = qr
                                        .render::<unicode::Dense1x2>()
                                        .dark_color(unicode::Dense1x2::Light)
                                        .light_color(unicode::Dense1x2::Dark)
                                        .build();
                                    eprintln!("\n{}\n", string);
                                }
                                Err(e) => {
                                    error!("Failed to generate QR code: {}", e);
                                    info!("QR code string: {}", code);
                                }
                            }

                            info!("========================================");
                        }
                        Event::PairingCode { code, timeout } => {
                            info!("========================================");
                            info!("PAIR CODE (valid for {} seconds):", timeout.as_secs());
                            info!("Enter this code on your phone:");
                            info!("WhatsApp > Linked Devices > Link a Device");
                            info!("> Link with phone number instead");
                            info!("");
                            info!("    >>> {} <<<", code);
                            info!("");
                            info!("========================================");
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

                            // Handle poll creation commands
                            if let Some(text) = ctx.message.text_content() {
                                if text.starts_with(POLL_TRIGGER) {
                                    handle_poll_command(&ctx, text).await;
                                    return;
                                } else if text.starts_with(QUIZ_TRIGGER) {
                                    handle_quiz_command(&ctx, text).await;
                                    return;
                                } else if text == HELP_TRIGGER {
                                    handle_help_command(&ctx).await;
                                    return;
                                }
                            }

                            // Handle poll votes
                            if ctx.message.poll_update_message.is_some() {
                                handle_poll_vote(&ctx).await;
                                return;
                            }

                            if let Some(text) = ctx.message.text_content()
                                && text == PING_TRIGGER
                            {
                                info!("Received text ping, sending pong...");

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

                                let reaction_message = wa::message::ReactionMessage {
                                    key: Some(message_key),
                                    text: Some(REACTION_EMOJI.to_string()),
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

                                let context_info = ctx.build_quote_context();

                                let reply_message = wa::Message {
                                    extended_text_message: Some(Box::new(
                                        wa::message::ExtendedTextMessage {
                                            text: Some(PONG_TEXT.to_string()),
                                            context_info: Some(Box::new(context_info.clone())),
                                            ..Default::default()
                                        },
                                    )),
                                    ..Default::default()
                                };

                                let sent_msg_id = match ctx.send_message(reply_message).await {
                                    Ok(id) => id,
                                    Err(e) => {
                                        error!("Failed to send initial pong message: {}", e);
                                        return;
                                    }
                                };

                                let duration = start.elapsed();
                                let duration_str = format!("{:.2?}", duration);

                                info!(
                                    "Send took {}. Editing message {}...",
                                    duration_str, &sent_msg_id
                                );

                                let updated_content = wa::Message {
                                    extended_text_message: Some(Box::new(
                                        wa::message::ExtendedTextMessage {
                                            text: Some(format!(
                                                "{}\n`{}`",
                                                PONG_TEXT, duration_str
                                            )),
                                            context_info: Some(Box::new(context_info)),
                                            ..Default::default()
                                        },
                                    )),
                                    ..Default::default()
                                };

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
                caption: Some(MEDIA_PONG_TEXT.to_string()),
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
                caption: Some(MEDIA_PONG_TEXT.to_string()),
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
        && msg.caption.as_deref() == Some(MEDIA_PING_TRIGGER)
    {
        return Some(&**msg);
    }
    if let Some(msg) = &base_message.video_message
        && msg.caption.as_deref() == Some(MEDIA_PING_TRIGGER)
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

async fn handle_poll_command(ctx: &MessageContext, text: &str) {
    // Parse: !poll Question? | Option 1 | Option 2 | Option 3
    let parts: Vec<&str> = text
        .strip_prefix(POLL_TRIGGER)
        .unwrap_or("")
        .trim()
        .split('|')
        .map(|s| s.trim())
        .collect();

    if parts.len() < 3 || parts[0].is_empty() {
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some(
                    "❌ Invalid format!\nUsage: !poll Question? | Option 1 | Option 2 | Option 3\n\n\
                    Example: !poll What's your favorite color? | Red | Blue | Green".to_string()
                ),
                ..Default::default()
            })
            .await;
        return;
    }

    let question = parts[0];
    let options: Vec<String> = parts[1..].iter().map(|s| s.to_string()).collect();

    if options.len() > 12 {
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some("❌ Too many options! Maximum is 12.".to_string()),
                ..Default::default()
            })
            .await;
        return;
    }

    match PollOptions::new(question, options) {
        Ok(poll_opts) => {
            info!("Creating poll: {}", question);
            match ctx
                .client
                .polls()
                .create(&ctx.info.source.chat, poll_opts)
                .await
            {
                Ok(result) => {
                    info!("✅ Poll created successfully! ID: {}", result.message_id);
                    info!(
                        "Encryption key (keep for vote decryption): {:?}",
                        hex::encode(result.enc_key)
                    );
                }
                Err(e) => {
                    error!("Failed to create poll: {}", e);
                    let _ = ctx
                        .send_message(wa::Message {
                            conversation: Some(format!("❌ Failed to create poll: {}", e)),
                            ..Default::default()
                        })
                        .await;
                }
            }
        }
        Err(e) => {
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some(format!("❌ Invalid poll: {}", e)),
                    ..Default::default()
                })
                .await;
        }
    }
}

async fn handle_quiz_command(ctx: &MessageContext, text: &str) {
    // Parse: !quiz Question? | Option 1 | Option 2* | Option 3
    // The asterisk (*) marks the correct answer
    let parts: Vec<&str> = text
        .strip_prefix(QUIZ_TRIGGER)
        .unwrap_or("")
        .trim()
        .split('|')
        .map(|s| s.trim())
        .collect();

    if parts.len() < 3 || parts[0].is_empty() {
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some(
                    "❌ Invalid format!\nUsage: !quiz Question? | Option 1 | Option 2* | Option 3\n\
                    Mark the correct answer with *\n\n\
                    Example: !quiz What is 2+2? | 3 | 4* | 5".to_string()
                ),
                ..Default::default()
            })
            .await;
        return;
    }

    let question = parts[0];
    let mut options: Vec<String> = Vec::new();
    let mut correct_index: Option<usize> = None;

    for (i, opt) in parts[1..].iter().enumerate() {
        if opt.ends_with('*') {
            if correct_index.is_some() {
                let _ = ctx
                    .send_message(wa::Message {
                        conversation: Some("❌ Only one correct answer allowed!".to_string()),
                        ..Default::default()
                    })
                    .await;
                return;
            }
            correct_index = Some(i);
            options.push(opt.trim_end_matches('*').trim().to_string());
        } else {
            options.push(opt.to_string());
        }
    }

    if correct_index.is_none() {
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some(
                    "❌ No correct answer marked! Use * to mark the correct option.".to_string(),
                ),
                ..Default::default()
            })
            .await;
        return;
    }

    if options.len() > 12 {
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some("❌ Too many options! Maximum is 12.".to_string()),
                ..Default::default()
            })
            .await;
        return;
    }

    match PollOptions::new_quiz(question, options, correct_index.unwrap()) {
        Ok(quiz_opts) => {
            info!("Creating quiz: {}", question);
            match ctx
                .client
                .polls()
                .create(&ctx.info.source.chat, quiz_opts)
                .await
            {
                Ok(result) => {
                    info!("✅ Quiz created successfully! ID: {}", result.message_id);
                    info!("Encryption key: {:?}", hex::encode(result.enc_key));
                }
                Err(e) => {
                    error!("Failed to create quiz: {}", e);
                    let _ = ctx
                        .send_message(wa::Message {
                            conversation: Some(format!("❌ Failed to create quiz: {}", e)),
                            ..Default::default()
                        })
                        .await;
                }
            }
        }
        Err(e) => {
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some(format!("❌ Invalid quiz: {}", e)),
                    ..Default::default()
                })
                .await;
        }
    }
}

async fn handle_poll_vote(ctx: &MessageContext) {
    if let Some(poll_update) = &ctx.message.poll_update_message {
        info!("📊 Received poll vote from {}", ctx.info.source.sender);

        if let Some(vote_data) = &poll_update.vote {
            info!(
                "Vote encrypted payload size: {} bytes",
                vote_data.enc_payload.as_ref().map(|v| v.len()).unwrap_or(0)
            );
            info!(
                "Vote IV size: {} bytes",
                vote_data.enc_iv.as_ref().map(|v| v.len()).unwrap_or(0)
            );
        }

        if let Some(key) = &poll_update.poll_creation_message_key {
            info!(
                "Vote is for poll: {:?} in chat {:?}",
                key.id, key.remote_jid
            );
        }
    }
}

async fn handle_help_command(ctx: &MessageContext) {
    let help_text = r#"🤖 *WhatsApp Rust Bot - Commands*

*Ping/Pong:*
• 🦀ping - Test bot response time
• Send image/video with caption "ping" to test media

*Polls:*
• !poll Question? | Option 1 | Option 2 | Option 3
  Example: !poll What's for lunch? | Pizza | Pasta | Salad

• !quiz Question? | Wrong | Correct* | Wrong
  Mark correct answer with *
  Example: !quiz What is 2+2? | 3 | 4* | 5

• !help - Show this help message

_Note: You can create polls with 2-12 options_"#;

    let _ = ctx
        .send_message(wa::Message {
            conversation: Some(help_text.to_string()),
            ..Default::default()
        })
        .await;
}

/// Parse a CLI argument by its long and short flags.
/// Supports: --flag VALUE, -f VALUE, --flag=VALUE
fn parse_arg(args: &[String], long: &str, short: &str) -> Option<String> {
    let long_prefix = format!("{}=", long);
    let mut iter = args.iter().skip(1); // Skip program name
    while let Some(arg) = iter.next() {
        if arg == long || arg == short {
            return iter.next().cloned();
        }
        if let Some(value) = arg.strip_prefix(&long_prefix) {
            return Some(value.to_string());
        }
    }
    None
}
