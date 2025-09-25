use chrono::Local;
use log::{debug, error, info, warn};
use std::sync::Arc;
use wacore::proto_helpers::MessageExt;
use wacore::types::events::Event;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use whatsapp_rust::store::traits::Backend;

/// A minimal, listen-only bot designed for debugging.
/// It connects, logs in, and prints detailed information for every event.
/// This bot will now act as a receiver to debug messages sent from other clients.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,whatsapp_rust=debug,wacore=debug"),
    )
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

    info!("--- Starting Listen-Only Debugging Bot ---");

    let backend = Arc::new(
        SqliteStore::new("listener.db")
            .await
            .expect("Failed to create listener backend"),
    ) as Arc<dyn Backend>;

    let mut bot = Bot::builder()
        .with_backend(backend)
        .on_event(|event, _client| async move {
            match event {
                Event::PairingQrCode { code, timeout } => {
                    info!("--- Pairing QR Code (valid for {}s) ---", timeout.as_secs());
                    println!("\n{}\n", code); // Use println to make it easy to copy
                    info!("-------------------------------------------------");
                }
                Event::Connected(_) => {
                    info!("[EVENT] ✅ Connected successfully!");
                }
                Event::Message(msg, info) => {
                    let text = msg.text_content().unwrap_or("<media or empty>");
                    info!(
                        "[EVENT] 📩 Message Received from {}: '{}'",
                        info.source.sender, text
                    );
                    debug!("[EVENT] Full Message Info: {:?}", info);
                    debug!("[EVENT] Full Message Content: {:?}", msg);
                }
                Event::Receipt(receipt) => {
                    info!(
                        "[EVENT] 📨 Receipt Received for {:?}, type: {:?}",
                        receipt.message_ids, receipt.r#type
                    );
                }
                Event::LoggedOut(logout_info) => {
                    error!("[EVENT] ❌ Logged out! Reason: {:?}", logout_info.reason);
                }
                Event::UndecryptableMessage(info) => {
                    warn!(
                        "[EVENT] ❗ UNDECRYPTABLE MESSAGE from {}: {:?}",
                        info.info.source.sender, info
                    );
                }
                _ => {
                    debug!("[EVENT] 📢 Other Event: {:?}", event);
                }
            }
        })
        .build()
        .await
        .expect("Failed to build listener bot");

    info!("🤖 Listener bot built. Starting run loop...");
    let bot_handle = bot.run().await.expect("Failed to start listener bot");

    tokio::select! {
        result = bot_handle => {
            if let Err(e) = result {
                error!("Listener bot ended with error: {}", e);
            } else {
                info!("Listener bot ended gracefully");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Received Ctrl+C, shutting down listener...");
        }
    }

    Ok(())
}
