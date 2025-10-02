use chrono::Local;
use log::{debug, error, info, warn};
use std::sync::Arc;
use wacore::types::events::Event;
use whatsapp_rust::bot::Bot;
use whatsapp_rust::client::PairClientType;
use whatsapp_rust::store::sqlite_store::SqliteStore;
use whatsapp_rust::store::traits::Backend;

/// This example demonstrates phone-based pairing code authentication.
/// Instead of scanning QR codes, you can pair a device by entering a short
/// code displayed on your primary WhatsApp device.
///
/// This example shows:
/// 1. How to connect to WhatsApp servers
/// 2. How to initiate phone pairing with pair_phone()
/// 3. How to handle the PairingCode event when a code is generated
/// 4. The complete pairing flow from connection to authentication
///
/// Usage: Run this example, then enter your phone number when prompted.
/// A pairing code will be displayed - enter it on your primary device.
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

    info!("🔐 Starting Phone Pairing Code Authentication Example");

    // Create a unique database for this example
    let backend = Arc::new(
        SqliteStore::new("pairing_example.db")
            .await
            .expect("Failed to create pairing backend"),
    ) as Arc<dyn Backend>;

    // Build the bot with event handling
    let mut bot = Bot::builder()
        .with_backend(backend)
        .on_event(|event, _client| async move {
            match event {
                Event::PairingQrCode { code, timeout } => {
                    info!("📱 QR Code available (valid for {}s):", timeout.as_secs());
                    info!("   {}", code);
                    info!("   � You can scan this if you prefer QR pairing");
                }
                Event::PairingCode { code } => {
                    info!("🎯 PAIRING CODE GENERATED!");
                    println!("\n🔥🔥🔥 ENTER THIS CODE ON YOUR PHONE: {} 🔥🔥🔥\n", code);
                    info!("   📱 Go to WhatsApp Settings → Linked Devices → Link a Device");
                    info!("   ⏰ Code is valid for a limited time");
                    info!("   🔄 The code will be automatically invalidated after use");
                }
                Event::Connected(_) => {
                    info!("✅ Successfully connected to WhatsApp servers!");
                    info!("   🔐 Ready for pairing code authentication");
                }
                Event::PairSuccess(success) => {
                    info!("🎉 Pairing successful!");
                    info!("   📱 Device JID: {}", success.id);
                    info!("   🏷️  Business Name: {}", success.business_name);
                    info!("   🖥️  Platform: {}", success.platform);
                    info!("   ✨ Device is now linked and ready to use!");
                }
                Event::PairError(error) => {
                    error!("❌ Pairing failed: {}", error.error);
                    error!("   📱 Device JID: {}", error.id);
                    error!("   💡 Try restarting the example or check your phone number");
                }
                Event::LoggedOut(logout_info) => {
                    error!("❌ Logged out! Reason: {:?}", logout_info.reason);
                }
                Event::Disconnected(_) => {
                    warn!("📡 Disconnected from WhatsApp servers");
                }
                _ => {
                    debug!("📨 Other event: {:?}", event);
                }
            }
        })
        .build()
        .await
        .expect("Failed to build pairing bot");

    info!("🤖 Pairing bot built. Starting connection...");

    // Start the bot in the background
    let bot_handle = bot.run().await.expect("Failed to start pairing bot");

    // Wait a moment for connection to establish
    info!("⏳ Waiting for connection to stabilize...");
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

    // Get phone number from user
    println!("\n📱 Enter your phone number (international format, e.g., +1234567890):");
    let mut phone_input = String::new();
    std::io::stdin().read_line(&mut phone_input)?;
    let phone = phone_input.trim().to_string();

    if phone.is_empty() {
        error!("❌ No phone number provided");
        return Ok(());
    }

    info!("� Initiating phone pairing for: {}", phone);

    // Initiate phone pairing
    match bot
        .client()
        .pair_phone(
            phone.clone(),
            true,                         // Show push notification
            PairClientType::Chrome,       // Browser type
            "Chrome (Linux)".to_string(), // Display name
        )
        .await
    {
        Ok(pairing_code) => {
            info!("✅ Pairing initiated successfully!");
            info!("🎯 PAIRING CODE: {}", pairing_code);
            println!(
                "\n�🔥🔥 ENTER THIS CODE ON YOUR PHONE: {} 🔥🔥🔥\n",
                pairing_code
            );
            info!("   📱 Instructions:");
            info!("      1. Open WhatsApp on your phone");
            info!("      2. Go to Settings → Linked Devices");
            info!("      3. Tap 'Link a Device'");
            info!("      4. Enter the code shown above");
            info!("   ⏰ Code expires in ~3 minutes");
        }
        Err(e) => {
            error!("❌ Failed to initiate phone pairing: {}", e);
            error!("   � Make sure:");
            error!("      - Your phone number is correct and in international format");
            error!("      - WhatsApp is installed and working on your phone");
            error!("      - You're not already logged in with this device");
            return Ok(());
        }
    }

    info!("⏳ Waiting for you to enter the pairing code on your phone...");
    info!("   Press Ctrl+C to exit at any time");

    // Keep running until user interrupts or pairing completes
    tokio::select! {
        result = bot_handle => {
            match result {
                Ok(_) => info!("🤖 Bot ended gracefully"),
                Err(e) => error!("🤖 Bot ended with error: {}", e),
            }
        }
        _ = tokio::signal::ctrl_c() => {
            info!("� Received Ctrl+C, shutting down...");
        }
    }

    info!("� Pairing example completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore::pair::PairUtils;

    #[tokio::test]
    async fn test_pairing_code_crypto_roundtrip() {
        // Test that the pairing code crypto utilities work correctly
        // (These tests remain relevant as they test the underlying crypto that pair_phone() uses)

        // Generate companion ephemeral key and pairing code
        let (companion_ephemeral, wrapped_key, pairing_code) =
            PairUtils::generate_companion_ephemeral_key().unwrap();

        // The wrapped_key contains the encrypted companion ephemeral public key
        // Let's decrypt it back using the pairing code
        let decrypted_companion_pub =
            PairUtils::decrypt_primary_ephemeral_pub(&pairing_code, &wrapped_key).unwrap();

        // Should match the original companion ephemeral public key
        assert_eq!(
            decrypted_companion_pub,
            *companion_ephemeral.public_key.public_key_bytes()
        );

        // Test that we can compute a shared secret (using the same key for both sides as a test)
        // In real usage, this would be with different keys from primary and companion devices
        let shared_secret = PairUtils::compute_pairing_shared_secret(
            &companion_ephemeral.private_key,
            &decrypted_companion_pub,
        )
        .unwrap();

        // Shared secret should be 32 bytes
        assert_eq!(shared_secret.len(), 32);
    }

    #[tokio::test]
    async fn test_pairing_code_uniqueness() {
        // Test that generated pairing codes are unique
        let mut codes = std::collections::HashSet::new();

        for _ in 0..10 {
            let (_, _, code) = PairUtils::generate_companion_ephemeral_key().unwrap();
            assert!(codes.insert(code), "Generated duplicate pairing code");
        }
    }

    #[tokio::test]
    async fn test_invalid_pairing_code() {
        // Test that invalid pairing codes produce different decryption results
        let (_, wrapped_key, _) = PairUtils::generate_companion_ephemeral_key().unwrap();

        // Try to decrypt with wrong pairing code
        let result1 = PairUtils::decrypt_primary_ephemeral_pub("INVALID", &wrapped_key);

        // Try to decrypt with another wrong pairing code
        let result2 = PairUtils::decrypt_primary_ephemeral_pub("ALSOINV", &wrapped_key);

        // Both should succeed (PBKDF2 always produces a key), but produce different results
        assert!(result1.is_ok());
        assert!(result2.is_ok());
        assert_ne!(result1.unwrap(), result2.unwrap());
    }
}
