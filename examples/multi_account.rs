use chrono::Local;
use log::{debug, error, info};
use std::sync::Arc;
use wacore::types::events::Event;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use whatsapp_rust::store::traits::Backend;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

/// This example demonstrates the new multi-account capabilities of whatsapp-rust.
/// It shows how to:
/// 1. Create separate backends for each account
/// 2. Create multiple bots using different backends
/// 3. Handle events from multiple accounts
/// 4. Run multiple bots concurrently

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
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

    info!("🚀 Starting Multi-Account WhatsApp Bot Example");

    // Step 1: Create separate backends for each account
    // Each account gets its own database file
    let backend1 = Arc::new(
        SqliteStore::new("account1.db")
            .await
            .expect("Failed to create backend for account 1"),
    ) as Arc<dyn Backend>;

    let backend2 = Arc::new(
        SqliteStore::new("account2.db")
            .await
            .expect("Failed to create backend for account 2"),
    ) as Arc<dyn Backend>;

    info!("📊 Created separate backends for two accounts");

    // Step 2: Create multiple bots using different backends

    // Bot 1: Account 1
    info!("🤖 Creating Bot 1 (Account 1)...");
    let transport1 = TokioWebSocketTransportFactory::new();
    let http_client1 = UreqHttpClient::new();
    let mut bot1 = Bot::builder()
        .with_backend(backend1)
        .with_transport_factory(transport1)
        .with_http_client(http_client1)
        .on_event(|event, _client| async move {
            let account_id = 1;
            match event {
                Event::PairingQrCode { code, timeout } => {
                    info!(
                        "📱 [Account {}] New pairing QR code (valid for {}s):",
                        account_id,
                        timeout.as_secs()
                    );
                    info!("\n{}\n", code);
                }
                Event::Connected(_) => {
                    info!("✅ [Account {}] Connected successfully!", account_id);
                }
                Event::Message(msg, _info) => {
                    if let Some(text) = msg.conversation.as_ref() {
                        info!("💬 [Account {}] Received message: {}", account_id, text);
                    }
                }
                Event::LoggedOut(_) => {
                    error!("❌ [Account {}] Logged out!", account_id);
                }
                _ => {
                    debug!("📨 [Account {}] Received event: {:?}", account_id, event);
                }
            }
        })
        .build()
        .await
        .expect("Failed to create Bot 1");

    info!("🤖 Bot 1 (Account 1) created successfully");

    // Bot 2: Account 2
    info!("🤖 Creating Bot 2 (Account 2)...");
    let transport2 = TokioWebSocketTransportFactory::new();
    let http_client2 = UreqHttpClient::new();
    let mut bot2 = Bot::builder()
        .with_backend(backend2)
        .with_transport_factory(transport2)
        .with_http_client(http_client2)
        .on_event(|event, _client| async move {
            let account_id = 2;
            match event {
                Event::PairingQrCode { code, timeout } => {
                    info!(
                        "📱 [Account {}] New pairing QR code (valid for {}s):",
                        account_id,
                        timeout.as_secs()
                    );
                    info!("\n{}\n", code);
                }
                Event::Connected(_) => {
                    info!("✅ [Account {}] Connected successfully!", account_id);
                }
                Event::Message(msg, _info) => {
                    if let Some(text) = msg.conversation.as_ref() {
                        info!("💬 [Account {}] Received message: {}", account_id, text);
                    }
                }
                Event::LoggedOut(_) => {
                    error!("❌ [Account {}] Logged out!", account_id);
                }
                _ => {
                    debug!("📨 [Account {}] Received event: {:?}", account_id, event);
                }
            }
        })
        .build()
        .await
        .expect("Failed to create Bot 2");

    info!("🤖 Bot 2 (Account 2) created successfully");

    // Step 3: Start the bots
    info!("🚀 Starting all bots...");

    let bot1_handle = bot1.run().await.expect("Failed to start Bot 1");
    info!("✅ Bot 1 started");

    let bot2_handle = bot2.run().await.expect("Failed to start Bot 2");
    info!("✅ Bot 2 started");

    info!("🎯 Both accounts are running. They will display QR codes for pairing.");
    info!("💡 Each account will get its own QR code - scan them with different WhatsApp accounts.");
    info!("🔄 Press Ctrl+C to stop.");

    // Step 7: Wait for the bots to finish (they run indefinitely)
    tokio::select! {
        result1 = bot1_handle => {
            if let Err(e) = result1 {
                error!("Bot 1 ended with error: {}", e);
            } else {
                info!("Bot 1 ended gracefully");
            }
        }
        result2 = bot2_handle => {
            if let Err(e) = result2 {
                error!("Bot 2 ended with error: {}", e);
            } else {
                info!("Bot 2 ended gracefully");
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Received Ctrl+C, shutting down...");
        }
    }

    info!("👋 Multi-account bot example finished");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_multi_account_creation() {
        // This test demonstrates how to programmatically work with multiple accounts
        // In the new architecture, each account uses a separate backend

        // Create separate backends for testing
        let backend1 = Arc::new(
            SqliteStore::new("file:memdb_test1?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend 1"),
        ) as Arc<dyn Backend>;

        let backend2 = Arc::new(
            SqliteStore::new("file:memdb_test2?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend 2"),
        ) as Arc<dyn Backend>;

        // Create bots for each account
        let transport1 = TokioWebSocketTransportFactory::new();
        let http_client1 = UreqHttpClient::new();
        let bot1 = Bot::builder()
            .with_backend(backend1)
            .with_transport_factory(transport1)
            .with_http_client(http_client1)
            .build()
            .await
            .expect("Failed to create bot 1");

        let transport2 = TokioWebSocketTransportFactory::new();
        let http_client2 = UreqHttpClient::new();
        let bot2 = Bot::builder()
            .with_backend(backend2)
            .with_transport_factory(transport2)
            .with_http_client(http_client2)
            .build()
            .await
            .expect("Failed to create bot 2");

        // Verify they work independently
        let device_id1 = bot1.client().persistence_manager().device_id();
        let device_id2 = bot2.client().persistence_manager().device_id();

        // Both should have device ID 1 (single device mode per backend)
        assert_eq!(device_id1, 1);
        assert_eq!(device_id2, 1);
        assert!(!bot1.client().persistence_manager().is_multi_account());
        assert!(!bot2.client().persistence_manager().is_multi_account());
    }

    #[tokio::test]
    async fn test_backward_compatibility() {
        // Test that the old single-account API still works
        // Note: This now requires providing a backend explicitly
        let backend = Arc::new(
            SqliteStore::new("file:memdb_compat?mode=memory&cache=shared")
                .await
                .expect("Failed to create test backend"),
        ) as Arc<dyn Backend>;

        let transport = TokioWebSocketTransportFactory::new();
        let http_client = UreqHttpClient::new();
        let bot = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport)
            .with_http_client(http_client)
            .build()
            .await
            .expect("Failed to create bot with backend");

        // Should work with default device ID
        let device_id = bot.client().persistence_manager().device_id();
        assert_eq!(device_id, 1); // Single device mode
        assert!(!bot.client().persistence_manager().is_multi_account());
    }
}
