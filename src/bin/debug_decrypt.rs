use clap::Parser;
use std::path::PathBuf;
use tokio::fs;
use anyhow::{Context, Result};

#[derive(Parser)]
#[command(name = "debug_decrypt")]
#[command(about = "Validate decryption bundles for E2E testing")]
struct Args {
    /// Path to the decryption bundle directory
    bundle_path: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let args = Args::parse();
    
    if !args.bundle_path.exists() {
        anyhow::bail!("Bundle path does not exist: {}", args.bundle_path.display());
    }

    if !args.bundle_path.is_dir() {
        anyhow::bail!("Bundle path is not a directory: {}", args.bundle_path.display());
    }

    // Determine bundle type by checking what files exist
    let message_bin = args.bundle_path.join("message.bin");
    let expected_plaintext = args.bundle_path.join("expected_plaintext.txt");
    
    if !message_bin.exists() {
        anyhow::bail!("Missing message.bin in bundle directory");
    }
    
    if !expected_plaintext.exists() {
        anyhow::bail!("Missing expected_plaintext.txt in bundle directory");
    }

    // Check if it's a group message bundle (has sender key) or direct message bundle
    let sender_key_file = args.bundle_path.join("recipient_sender_key.json");
    let session_file = args.bundle_path.join("recipient_session.json");
    
    if !session_file.exists() {
        anyhow::bail!("Missing recipient_session.json in bundle directory");
    }

    if sender_key_file.exists() {
        validate_group_message_bundle(&args.bundle_path).await
    } else {
        validate_direct_message_bundle(&args.bundle_path).await
    }
}

async fn validate_direct_message_bundle(bundle_path: &PathBuf) -> Result<()> {
    println!("📦 Validating direct message bundle: {}", bundle_path.display());

    // Load all required files
    let message_bin = fs::read(bundle_path.join("message.bin")).await
        .context("Failed to read message.bin")?;
    
    let sender_identity_key_bin = fs::read(bundle_path.join("sender_identity_key.bin")).await
        .context("Failed to read sender_identity_key.bin")?;
    
    let session_json = fs::read_to_string(bundle_path.join("recipient_session.json")).await
        .context("Failed to read recipient_session.json")?;
    
    let identity_keys_json = fs::read_to_string(bundle_path.join("recipient_identity_keys.json")).await
        .context("Failed to read recipient_identity_keys.json")?;
    
    let expected_plaintext = fs::read_to_string(bundle_path.join("expected_plaintext.txt")).await
        .context("Failed to read expected_plaintext.txt")?;

    // Parse the JSON files
    let recipient_session: wacore::signal::state::session_record::SessionRecord = 
        serde_json::from_str(&session_json)
            .context("Failed to parse recipient_session.json")?;
    
    let _recipient_identity_keys: wacore::signal::identity::IdentityKeyPair = 
        serde_json::from_str(&identity_keys_json)
            .context("Failed to parse recipient_identity_keys.json")?;

    // TODO: Implement actual decryption logic using Signal Protocol
    // This would involve:
    // 1. Creating a temporary in-memory store
    // 2. Loading the session and identity keys
    // 3. Creating a SessionCipher
    // 4. Attempting decryption
    // 5. Comparing with expected_plaintext

    println!("✅ Bundle structure validation successful!");
    println!("📋 Bundle contents:");
    println!("  - Message size: {} bytes", message_bin.len());
    println!("  - Sender identity key size: {} bytes", sender_identity_key_bin.len());
    println!("  - Session has {} previous states", recipient_session.previous_states().len());
    println!("  - Expected plaintext: \"{}\"", expected_plaintext.trim());
    
    // For now, just validate that we can load all the components
    // Full decryption implementation would require more Signal Protocol integration
    println!("⚠️  Note: Full decryption validation not yet implemented");
    
    Ok(())
}

async fn validate_group_message_bundle(bundle_path: &PathBuf) -> Result<()> {
    println!("📦 Validating group message bundle: {}", bundle_path.display());

    // Load all required files
    let message_bin = fs::read(bundle_path.join("message.bin")).await
        .context("Failed to read message.bin")?;
    
    let sender_identity_key_bin = fs::read(bundle_path.join("sender_identity_key.bin")).await
        .context("Failed to read sender_identity_key.bin")?;
    
    let session_json = fs::read_to_string(bundle_path.join("recipient_session.json")).await
        .context("Failed to read recipient_session.json")?;
    
    let sender_key_json = fs::read_to_string(bundle_path.join("recipient_sender_key.json")).await
        .context("Failed to read recipient_sender_key.json")?;
    
    let expected_plaintext = fs::read_to_string(bundle_path.join("expected_plaintext.txt")).await
        .context("Failed to read expected_plaintext.txt")?;

    // Parse the JSON files
    let recipient_session: wacore::signal::state::session_record::SessionRecord = 
        serde_json::from_str(&session_json)
            .context("Failed to parse recipient_session.json")?;
    
    let _recipient_sender_key: wacore::signal::state::sender_key_record::SenderKeyRecord = 
        serde_json::from_str(&sender_key_json)
            .context("Failed to parse recipient_sender_key.json")?;

    println!("✅ Bundle structure validation successful!");
    println!("📋 Bundle contents:");
    println!("  - Message size: {} bytes", message_bin.len());
    println!("  - Sender identity key size: {} bytes", sender_identity_key_bin.len());
    println!("  - Session has {} previous states", recipient_session.previous_states().len());
    println!("  - Expected plaintext: \"{}\"", expected_plaintext.trim());
    
    // For now, just validate that we can load all the components
    println!("⚠️  Note: Full decryption validation not yet implemented");
    
    Ok(())
}