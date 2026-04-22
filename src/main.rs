use chrono::{Local, Utc};
use log::{error, info, warn};
use std::sync::Arc;
use wacore::proto_helpers::MessageExt;
use wacore::types::call::CallId;
use wacore::types::events::Event;
use waproto::whatsapp as wa;
use whatsapp_rust::TokioRuntime;
use whatsapp_rust::bot::{Bot, MessageContext};
use whatsapp_rust::pair_code::PairCodeOptions;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

const PING_TRIGGER: &str = "🦀ping";
const PONG_TEXT: &str = "🏓 Pong!";
const REACTION_EMOJI: &str = "🏓";

// Usage:
//   cargo run                                      # QR code pairing only
//   cargo run -- --phone 15551234567               # Pair code + QR code (concurrent)
//   cargo run -- -p 15551234567                    # Short form
//   cargo run -- -p 15551234567 --code MYCODE12    # Custom 8-char pair code
//   cargo run -- -p 15551234567 -c MYCODE12        # Short form

fn main() {
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
            .with_http_client(http_client)
            .with_runtime(TokioRuntime);

        if let Some(phone) = phone_number {
            builder = builder.with_pair_code(PairCodeOptions {
                phone_number: phone,
                custom_code,
                ..Default::default()
            });
        }

        let mut bot = builder
            .on_event(move |event, client| async move {
                match &*event {
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
                        let ctx = MessageContext::from_parts(msg, info, client);
                        if let Some(reply) = build_media_pong(msg) {
                            info!("Received media ping from {}", ctx.info.source.sender);
                            if let Err(e) = ctx.send_message(reply).await {
                                error!("Failed to send media pong: {}", e);
                            }
                        } else if msg.text_content() == Some(PING_TRIGGER) {
                            handle_text_ping(&ctx).await;
                        }
                    }
                    Event::Connected(_) => info!("✅ Bot connected successfully!"),
                    Event::LoggedOut(_) => error!("❌ Bot was logged out!"),
                    Event::CallOffer(offer) => {
                        handle_call_offer(offer, client).await;
                    }
                    Event::CallAccepted(accepted) => {
                        info!("📞 Call {} accepted by remote", accepted.meta.call_id);
                    }
                    Event::CallRejected(rejected) => {
                        info!("📞 Call {} rejected by remote", rejected.meta.call_id);
                    }
                    Event::CallEnded(ended) => {
                        info!("📞 Call {} ended", ended.meta.call_id);
                    }
                    _ => {}
                }
            })
            .build()
            .await
            .expect("Failed to build bot");

        let client = bot.client();

        let bot_handle = match bot.run().await {
            Ok(handle) => handle,
            Err(e) => {
                error!("Bot failed to start: {}", e);
                return;
            }
        };

        #[cfg(feature = "signal")]
        {
            tokio::select! {
                _ = bot_handle => {}
                _ = tokio::signal::ctrl_c() => {
                    info!("Received Ctrl+C, shutting down...");
                    client.disconnect().await;
                }
            }
        }

        #[cfg(not(feature = "signal"))]
        {
            bot_handle
                .await
                .expect("Bot task should complete without panicking");
        }
    });
}

async fn handle_text_ping(ctx: &MessageContext) {
    info!("Received text ping, sending pong...");

    let key = wa::MessageKey {
        remote_jid: Some(ctx.info.source.chat.to_string()),
        id: Some(ctx.info.id.clone()),
        from_me: Some(ctx.info.source.is_from_me),
        participant: ctx
            .info
            .source
            .is_group
            .then(|| ctx.info.source.sender.to_string()),
    };
    let reaction = wa::Message {
        reaction_message: Some(wa::message::ReactionMessage {
            key: Some(key),
            text: Some(REACTION_EMOJI.to_string()),
            sender_timestamp_ms: Some(Utc::now().timestamp_millis()),
            ..Default::default()
        }),
        ..Default::default()
    };
    if let Err(e) = ctx.send_message(reaction).await {
        error!("Failed to send reaction: {}", e);
    }

    let start = std::time::Instant::now();
    let context_info = ctx.build_quote_context();
    let reply = wa::Message {
        extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
            text: Some(PONG_TEXT.to_string()),
            context_info: Some(Box::new(context_info)),
            ..Default::default()
        })),
        ..Default::default()
    };

    let sent = match ctx.send_message(reply).await {
        Ok(r) => r,
        Err(e) => {
            error!("Failed to send pong: {}", e);
            return;
        }
    };

    let duration = format!("{:.2?}", start.elapsed());
    info!(
        "Send took {}. Editing message {}...",
        duration, &sent.message_id
    );

    let edit = wa::Message {
        extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
            text: Some(format!("{PONG_TEXT}\n`{duration}`")),
            ..Default::default()
        })),
        ..Default::default()
    };
    if let Err(e) = ctx.edit_message(sent.message_id.clone(), edit).await {
        error!("Failed to edit message {}: {}", sent.message_id, e);
    }
}

/// Reuses the original CDN blob, only swaps the caption. Instant regardless of file size.
fn build_media_pong(message: &wa::Message) -> Option<wa::Message> {
    let base = message.get_base_message();

    if let Some(img) = &base.image_message
        && img.caption.as_deref() == Some(PING_TRIGGER)
    {
        return Some(wa::Message {
            image_message: Some(Box::new(wa::message::ImageMessage {
                caption: Some(PONG_TEXT.to_string()),
                ..*img.clone()
            })),
            ..Default::default()
        });
    }
    if let Some(vid) = &base.video_message
        && vid.caption.as_deref() == Some(PING_TRIGGER)
    {
        return Some(wa::Message {
            video_message: Some(Box::new(wa::message::VideoMessage {
                caption: Some(PONG_TEXT.to_string()),
                ..*vid.clone()
            })),
            ..Default::default()
        });
    }
    None
}

async fn handle_call_offer(
    offer: &wacore::types::events::CallOffer,
    client: std::sync::Arc<whatsapp_rust::Client>,
) {
    info!(
        "📞 Incoming {} call from {} (call_id: {})",
        if offer.media_type == wacore::types::call::CallMediaType::Video {
            "video"
        } else {
            "audio"
        },
        offer.meta.from,
        offer.meta.call_id
    );
    info!(
        "   Remote: {} v{}",
        offer.remote_meta.remote_platform, offer.remote_meta.remote_version
    );

    let call_id = CallId::new(&offer.meta.call_id);
    let call_manager = client.get_call_manager().await;
    if let Some(call_info) = call_manager.get_call(&call_id).await {
        if let Some(ref relay) = call_info.offer_relay_data {
            info!(
                "   Relay: uuid={:?}, self_pid={:?}, peer_pid={:?}",
                relay.uuid, relay.self_pid, relay.peer_pid
            );
            info!(
                "   Relay keys: hbh_key={} bytes, relay_key={} bytes",
                relay.hbh_key.as_ref().map(|k| k.len()).unwrap_or(0),
                relay.relay_key.as_ref().map(|k| k.len()).unwrap_or(0)
            );
            info!(
                "   Relay endpoints: {} endpoints, {} tokens, {} auth_tokens",
                relay.endpoints.len(),
                relay.relay_tokens.len(),
                relay.auth_tokens.len()
            );
            for ep in &relay.endpoints {
                info!(
                    "     - {} (id={}): {} addresses",
                    ep.relay_name,
                    ep.relay_id,
                    ep.addresses.len()
                );
            }
        }
        if let Some(ref media) = call_info.offer_media_params {
            for audio in &media.audio {
                info!("   Audio: {} @ {}Hz", audio.codec, audio.rate);
            }
            if let Some(ref video) = media.video {
                info!("   Video: {:?}", video.codec);
            }
        }
        if let Some(ref enc) = call_info.offer_enc_data {
            info!(
                "   Encrypted key: type={:?}, {} bytes (v{})",
                enc.enc_type,
                enc.ciphertext.len(),
                enc.version
            );
        }
    }

    if offer.is_offline {
        info!("   (Offline call - not accepting)");
        return;
    }

    // Acceptance flow: PREACCEPT → RELAYLATENCY → MUTE_V2 → ACCEPT → connect relay.
    info!("   Caller LID: {}", offer.meta.call_creator);

    info!("   Step 1: Sending PREACCEPT...");
    match call_manager.send_preaccept(&call_id).await {
        Ok(stanza) => {
            if let Err(e) = client.send_node(stanza).await {
                error!("Failed to send PREACCEPT: {}", e);
            } else {
                info!("   ✓ Sent PREACCEPT");
            }
        }
        Err(e) => warn!("Failed to build PREACCEPT: {}", e),
    }

    info!("   Step 2: Sending RELAYLATENCY...");
    if let Some(info_rec) = call_manager.get_call(&call_id).await
        && let Some(ref relay_data) = info_rec.offer_relay_data
    {
        let measurements =
            whatsapp_rust::calls::RelayLatencyMeasurement::from_relay_data(relay_data, 30);
        info!("   Generated {} relay measurements", measurements.len());
        match call_manager
            .send_relay_latency(&call_id, measurements)
            .await
        {
            Ok(stanza) => {
                if let Err(e) = client.send_node(stanza).await {
                    error!("Failed to send RELAYLATENCY: {}", e);
                } else {
                    info!("   ✓ Sent RELAYLATENCY");
                }
            }
            Err(e) => warn!("Failed to build RELAYLATENCY: {}", e),
        }
    }

    info!("   Step 3: Sending MUTE_V2 (unmuted)...");
    match call_manager.send_mute_state(&call_id, false).await {
        Ok(stanza) => {
            if let Err(e) = client.send_node(stanza).await {
                error!("Failed to send MUTE_V2: {}", e);
            } else {
                info!("   ✓ Sent MUTE_V2");
            }
        }
        Err(e) => warn!("Failed to build MUTE_V2: {}", e),
    }

    info!("   Step 4: Sending ACCEPT...");
    match call_manager.accept_call(&call_id).await {
        Ok(stanza) => {
            if let Err(e) = client.send_node(stanza).await {
                error!("Failed to send ACCEPT: {}", e);
            } else {
                info!(
                    "✅ Call accepted! All signaling complete for {}",
                    offer.meta.call_id
                );
            }
        }
        Err(e) => error!("Failed to build ACCEPT stanza: {}", e),
    }

    info!("   Step 5: Connecting to relay via WebRTC...");
    if let Some(relay_data) = call_manager.get_relay_data(&call_id).await {
        let call_manager_clone = call_manager.clone();
        let call_id_clone = call_id.clone();
        tokio::spawn(async move {
            match call_manager_clone
                .connect_relay(&call_id_clone, &relay_data)
                .await
            {
                Ok(relay_name) => info!(
                    "WebRTC connected for call {}: relay={}",
                    call_id_clone, relay_name
                ),
                Err(e) => warn!("WebRTC connection failed for call {}: {}", call_id_clone, e),
            }
        });
    } else {
        warn!(
            "No relay data available for call {} - cannot connect WebRTC",
            call_id
        );
    }
}

fn parse_arg(args: &[String], long: &str, short: &str) -> Option<String> {
    let long_prefix = format!("{}=", long);
    let mut iter = args.iter().skip(1);
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
