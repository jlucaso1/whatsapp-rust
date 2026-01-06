use chrono::{Local, Utc};
use log::{error, info};
use std::io::Cursor;
use std::sync::Arc;
use std::time::Duration;
use wacore::download::{Downloadable, MediaType};
use wacore::proto_helpers::MessageExt;
use wacore::types::events::Event;
use wacore_binary::jid::Jid;
use waproto::whatsapp as wa;
use whatsapp_rust::bot::{Bot, MessageContext};
use whatsapp_rust::pair_code::PairCodeOptions;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust::sync_actions::{DeleteMessageForMeAction, StarMessageAction};
use whatsapp_rust::upload::UploadResponse;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

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
                            info!("----------------------------------------");
                            info!(
                                "QR code received (valid for {} seconds):",
                                timeout.as_secs()
                            );
                            info!("\n{}\n", code);
                            info!("----------------------------------------");
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

                            if let Some(text) = ctx.message.text_content() {
                                let text_lower = text.to_lowercase();

                                // Handle sync action test commands
                                if handle_sync_action_commands(&ctx, &text_lower).await {
                                    return;
                                }

                                if text == "ping" {
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
                                        info!(
                                            "Successfully sent edit for message {}.",
                                            sent_msg_id
                                        );
                                    }
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

// ============================================================================
// Sync Action Test Commands
// ============================================================================

use wacore_binary::jid::JidExt;

/// Information about a quoted/replied message
struct QuotedMessageInfo {
    message_id: String,
    /// The sender of the quoted message (parsed JID)
    sender: Option<Jid>,
    timestamp: i64,
}

/// Helper to extract context_info from various message types
fn extract_context_info(message: &wa::Message) -> Option<&wa::ContextInfo> {
    // Check extended_text_message first (most common for text replies)
    if let Some(ref etm) = message.extended_text_message
        && let Some(ref ci) = etm.context_info
    {
        return Some(ci);
    }

    // Check image_message
    if let Some(ref img) = message.image_message
        && let Some(ref ci) = img.context_info
    {
        return Some(ci);
    }

    // Check video_message
    if let Some(ref vid) = message.video_message
        && let Some(ref ci) = vid.context_info
    {
        return Some(ci);
    }

    // Check audio_message
    if let Some(ref aud) = message.audio_message
        && let Some(ref ci) = aud.context_info
    {
        return Some(ci);
    }

    // Check document_message
    if let Some(ref doc) = message.document_message
        && let Some(ref ci) = doc.context_info
    {
        return Some(ci);
    }

    // Check sticker_message
    if let Some(ref stk) = message.sticker_message
        && let Some(ref ci) = stk.context_info
    {
        return Some(ci);
    }

    None
}

/// Extract quoted message info from a message's context_info
fn get_quoted_message_info(message: &wa::Message) -> Option<QuotedMessageInfo> {
    // Use get_base_message to unwrap nested message structures (edits, ephemeral, etc.)
    let base_message = message.get_base_message();

    // Try to extract context_info from various message types
    let context_info = extract_context_info(base_message)?;

    let stanza_id = context_info.stanza_id.as_ref()?;

    // Parse the participant (sender of the quoted message) as a proper JID
    let sender = context_info
        .participant
        .as_ref()
        .and_then(|p| p.parse::<Jid>().ok());

    // Use current timestamp - the exact original timestamp isn't critical for sync actions
    let timestamp = Utc::now().timestamp_millis();

    Some(QuotedMessageInfo {
        message_id: stanza_id.clone(),
        sender,
        timestamp,
    })
}

/// Determine if a message sender is "from me" by comparing with own JIDs
async fn is_from_me(sender: Option<&Jid>, ctx: &MessageContext) -> bool {
    let Some(sender) = sender else {
        return false;
    };

    // Get our own JIDs
    let own_pn = ctx.client.get_pn().await;
    let own_lid = ctx.client.get_lid().await;

    // Use the proper JID comparison method
    match (&own_pn, &own_lid) {
        (Some(pn), lid) => sender.matches_user_or_lid(pn, lid.as_ref()),
        (None, Some(lid)) => sender.is_same_user_as(lid),
        (None, None) => false,
    }
}

/// Handle the delete command - separated to reduce Future size
async fn handle_delete_command(ctx: &MessageContext) {
    let Some(quoted) = get_quoted_message_info(&ctx.message) else {
        // Debug: Log what message types are present
        let base = ctx.message.get_base_message();
        log::debug!(
            "No quoted message found. Message has: conversation={}, extended_text={}, image={}, video={}",
            base.conversation.is_some(),
            base.extended_text_message.is_some(),
            base.image_message.is_some(),
            base.video_message.is_some(),
        );
        if let Some(ref etm) = base.extended_text_message {
            log::debug!(
                "extended_text_message has context_info: {}, stanza_id: {:?}",
                etm.context_info.is_some(),
                etm.context_info
                    .as_ref()
                    .and_then(|ci| ci.stanza_id.as_ref())
            );
        }
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some("Reply to a message to delete it".to_string()),
                ..Default::default()
            })
            .await;
        return;
    };

    let from_me = is_from_me(quoted.sender.as_ref(), ctx).await;
    info!(
        "Deleting message {} for me (from_me: {}, sender: {:?})",
        quoted.message_id, from_me, quoted.sender
    );

    let action = if let (true, Some(sender)) = (ctx.info.source.is_group, quoted.sender.clone()) {
        DeleteMessageForMeAction::for_group_message(
            ctx.info.source.chat.clone(),
            quoted.message_id,
            from_me,
            sender,
            quoted.timestamp,
        )
    } else {
        DeleteMessageForMeAction::for_dm_message(
            ctx.info.source.chat.clone(),
            quoted.message_id,
            from_me,
            quoted.timestamp,
        )
    };

    match ctx.client.push_sync_action(action).await {
        Ok(()) => {
            info!("Successfully deleted message for me");
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some("✅ Message deleted for me".to_string()),
                    ..Default::default()
                })
                .await;
        }
        Err(e) => {
            error!("Failed to delete message: {:?}", e);
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some(format!("❌ Failed: {:?}", e)),
                    ..Default::default()
                })
                .await;
        }
    }
}

/// Chat action types for the generic handler
enum ChatAction {
    Pin,
    Unpin,
    Archive,
    Unarchive,
    Mute,
    MuteForever,
    Unmute,
    MarkRead,
    MarkUnread,
}

/// Handle chat actions - separated to reduce Future size
async fn handle_chat_action(ctx: &MessageContext, action: ChatAction) {
    let chat = ctx.info.source.chat.clone();
    let (action_name, success_msg, result) = match action {
        ChatAction::Pin => {
            info!("Pinning chat {}", chat);
            ("pin", "📌 Chat pinned", ctx.client.pin_chat(chat).await)
        }
        ChatAction::Unpin => {
            info!("Unpinning chat {}", chat);
            (
                "unpin",
                "📍 Chat unpinned",
                ctx.client.unpin_chat(chat).await,
            )
        }
        ChatAction::Archive => {
            info!("Archiving chat {}", chat);
            (
                "archive",
                "📦 Chat archived",
                ctx.client.archive_chat(chat).await,
            )
        }
        ChatAction::Unarchive => {
            info!("Unarchiving chat {}", chat);
            (
                "unarchive",
                "📤 Chat unarchived",
                ctx.client.unarchive_chat(chat).await,
            )
        }
        ChatAction::Mute => {
            info!("Muting chat {} for 8 hours", chat);
            (
                "mute",
                "🔇 Chat muted for 8 hours",
                ctx.client
                    .mute_chat(chat, Duration::from_secs(8 * 60 * 60))
                    .await,
            )
        }
        ChatAction::MuteForever => {
            info!("Muting chat {} forever", chat);
            (
                "mute forever",
                "🔇 Chat muted forever",
                ctx.client.mute_chat_forever(chat).await,
            )
        }
        ChatAction::Unmute => {
            info!("Unmuting chat {}", chat);
            (
                "unmute",
                "🔊 Chat unmuted",
                ctx.client.unmute_chat(chat).await,
            )
        }
        ChatAction::MarkRead => {
            info!("Marking chat {} as read", chat);
            (
                "mark as read",
                "✓ Chat marked as read",
                ctx.client.mark_chat_read(chat).await,
            )
        }
        ChatAction::MarkUnread => {
            info!("Marking chat {} as unread", chat);
            (
                "mark as unread",
                "○ Chat marked as unread",
                ctx.client.mark_chat_unread(chat).await,
            )
        }
    };

    match result {
        Ok(()) => {
            info!("Successfully executed {} action", action_name);
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some(success_msg.to_string()),
                    ..Default::default()
                })
                .await;
        }
        Err(e) => {
            error!("Failed to {}: {:?}", action_name, e);
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some(format!("❌ Failed: {:?}", e)),
                    ..Default::default()
                })
                .await;
        }
    }
}

/// Handle star/unstar command - separated to reduce Future size
async fn handle_star_command(ctx: &MessageContext, starred: bool) {
    let Some(quoted) = get_quoted_message_info(&ctx.message) else {
        let msg = if starred {
            "Reply to a message to star it"
        } else {
            "Reply to a message to unstar it"
        };
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some(msg.to_string()),
                ..Default::default()
            })
            .await;
        return;
    };

    let from_me = is_from_me(quoted.sender.as_ref(), ctx).await;
    info!(
        "{} message {} (from_me: {})",
        if starred { "Starring" } else { "Unstarring" },
        quoted.message_id,
        from_me
    );

    let action = if let (true, Some(sender)) = (ctx.info.source.is_group, quoted.sender.clone()) {
        StarMessageAction::for_group(
            ctx.info.source.chat.clone(),
            quoted.message_id,
            from_me,
            sender,
            starred,
        )
    } else {
        StarMessageAction::for_dm(
            ctx.info.source.chat.clone(),
            quoted.message_id,
            from_me,
            starred,
        )
    };

    match ctx.client.push_sync_action(action).await {
        Ok(()) => {
            let msg = if starred {
                "⭐ Message starred"
            } else {
                "💫 Message unstarred"
            };
            info!(
                "Successfully {}starred message",
                if starred { "" } else { "un" }
            );
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some(msg.to_string()),
                    ..Default::default()
                })
                .await;
        }
        Err(e) => {
            error!(
                "Failed to {}star message: {:?}",
                if starred { "" } else { "un" },
                e
            );
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some(format!("❌ Failed: {:?}", e)),
                    ..Default::default()
                })
                .await;
        }
    }
}

/// Handle sync action test commands
/// Returns true if a command was handled
///
/// Note: This function uses Box::pin to move the futures to the heap,
/// preventing stack overflow from large async state machines.
async fn handle_sync_action_commands(ctx: &MessageContext, text: &str) -> bool {
    match text {
        "delete" | "deleteforme" => {
            Box::pin(handle_delete_command(ctx)).await;
            true
        }
        "star" => {
            Box::pin(handle_star_command(ctx, true)).await;
            true
        }
        "unstar" => {
            Box::pin(handle_star_command(ctx, false)).await;
            true
        }

        // Chat actions - use Box::pin to reduce Future size
        "pin" => {
            Box::pin(handle_chat_action(ctx, ChatAction::Pin)).await;
            true
        }
        "unpin" => {
            Box::pin(handle_chat_action(ctx, ChatAction::Unpin)).await;
            true
        }
        "archive" => {
            Box::pin(handle_chat_action(ctx, ChatAction::Archive)).await;
            true
        }
        "unarchive" => {
            Box::pin(handle_chat_action(ctx, ChatAction::Unarchive)).await;
            true
        }
        "mute" => {
            Box::pin(handle_chat_action(ctx, ChatAction::Mute)).await;
            true
        }
        "muteforever" => {
            Box::pin(handle_chat_action(ctx, ChatAction::MuteForever)).await;
            true
        }
        "unmute" => {
            Box::pin(handle_chat_action(ctx, ChatAction::Unmute)).await;
            true
        }
        "markread" => {
            Box::pin(handle_chat_action(ctx, ChatAction::MarkRead)).await;
            true
        }
        "markunread" => {
            Box::pin(handle_chat_action(ctx, ChatAction::MarkUnread)).await;
            true
        }

        // Help command
        "synchelp" => {
            let help_text = r#"*Sync Action Test Commands:*

*Message actions (reply to a message):*
• `delete` / `deleteforme` - Delete replied message for me
• `star` - Star the replied message
• `unstar` - Unstar the replied message

*Chat actions:*
• `pin` - Pin this chat
• `unpin` - Unpin this chat
• `archive` - Archive this chat
• `unarchive` - Unarchive this chat
• `mute` - Mute for 8 hours
• `muteforever` - Mute forever
• `unmute` - Unmute this chat
• `markread` - Mark chat as read
• `markunread` - Mark chat as unread"#;

            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some(help_text.to_string()),
                    ..Default::default()
                })
                .await;
            true
        }

        _ => false,
    }
}
