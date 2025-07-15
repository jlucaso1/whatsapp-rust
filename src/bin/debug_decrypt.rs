use anyhow::{Context, Result};
use clap::Parser;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use async_trait::async_trait;

// Import Signal Protocol components for decryption
use wacore::signal::{
    SessionCipher,
    address::SignalAddress,
    ecc::keys::DjbEcPublicKey,
    groups::cipher::GroupCipher,
    groups::builder::GroupSessionBuilder,
    groups::message::SenderKeyMessage,
    identity::{IdentityKey, IdentityKeyPair},
    protocol::{Ciphertext, PreKeySignalMessage, SignalMessage},
    sender_key_name::SenderKeyName,
    state::{session_record::SessionRecord, sender_key_record::SenderKeyRecord},
    store::{IdentityKeyStore, PreKeyStore, SessionStore, SignedPreKeyStore, SenderKeyStore},
};
use waproto::whatsapp::{PreKeyRecordStructure, SignedPreKeyRecordStructure};

// Simple in-memory store implementation for debug tool
#[derive(Default, Clone)]
struct DebugMemoryStore {
    identity_key_pair: Option<IdentityKeyPair>,
    registration_id: u32,
    identities: HashMap<String, IdentityKey>,
    sessions: HashMap<String, SessionRecord>,
    prekeys: HashMap<u32, PreKeyRecordStructure>,
    signed_prekeys: HashMap<u32, SignedPreKeyRecordStructure>,
    sender_keys: HashMap<String, SenderKeyRecord>,
}

type StoreError = Box<dyn std::error::Error + Send + Sync>;

#[async_trait]
impl IdentityKeyStore for DebugMemoryStore {
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, StoreError> {
        self.identity_key_pair.clone().ok_or_else(|| "No identity key pair".into())
    }

    async fn get_local_registration_id(&self) -> Result<u32, StoreError> {
        Ok(self.registration_id)
    }

    async fn save_identity(&self, _address: &SignalAddress, _identity_key: &IdentityKey) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to save
    }

    async fn is_trusted_identity(&self, _address: &SignalAddress, _identity_key: &IdentityKey) -> Result<bool, StoreError> {
        Ok(true) // Trust all identities for testing
    }
}

#[async_trait]
impl SessionStore for DebugMemoryStore {
    async fn load_session(&self, address: &SignalAddress) -> Result<SessionRecord, StoreError> {
        let key = format!("{}:{}", address.name(), address.device_id());
        Ok(self.sessions.get(&key).cloned().unwrap_or_default())
    }

    async fn get_sub_device_sessions(&self, _name: &str) -> Result<Vec<u32>, StoreError> {
        Ok(vec![])
    }

    async fn store_session(&self, _address: &SignalAddress, _record: &SessionRecord) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to store
    }

    async fn contains_session(&self, address: &SignalAddress) -> Result<bool, StoreError> {
        let key = format!("{}:{}", address.name(), address.device_id());
        Ok(self.sessions.contains_key(&key))
    }

    async fn delete_session(&self, _address: &SignalAddress) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to delete
    }

    async fn delete_all_sessions(&self, _name: &str) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to delete
    }
}

#[async_trait]
impl PreKeyStore for DebugMemoryStore {
    async fn load_prekey(&self, prekey_id: u32) -> Result<Option<PreKeyRecordStructure>, StoreError> {
        Ok(self.prekeys.get(&prekey_id).cloned())
    }

    async fn store_prekey(&self, _prekey_id: u32, _record: PreKeyRecordStructure) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to store
    }

    async fn contains_prekey(&self, prekey_id: u32) -> Result<bool, StoreError> {
        Ok(self.prekeys.contains_key(&prekey_id))
    }

    async fn remove_prekey(&self, _prekey_id: u32) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to remove
    }
}

#[async_trait]
impl SignedPreKeyStore for DebugMemoryStore {
    async fn load_signed_prekey(&self, signed_prekey_id: u32) -> Result<Option<SignedPreKeyRecordStructure>, StoreError> {
        Ok(self.signed_prekeys.get(&signed_prekey_id).cloned())
    }

    async fn load_signed_prekeys(&self) -> Result<Vec<SignedPreKeyRecordStructure>, StoreError> {
        Ok(self.signed_prekeys.values().cloned().collect())
    }

    async fn store_signed_prekey(&self, _signed_prekey_id: u32, _record: SignedPreKeyRecordStructure) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to store
    }

    async fn contains_signed_prekey(&self, signed_prekey_id: u32) -> Result<bool, StoreError> {
        Ok(self.signed_prekeys.contains_key(&signed_prekey_id))
    }

    async fn remove_signed_prekey(&self, _signed_prekey_id: u32) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to remove
    }
}

#[async_trait]
impl SenderKeyStore for DebugMemoryStore {
    async fn store_sender_key(&self, _sender_key_name: &SenderKeyName, _record: SenderKeyRecord) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to store
    }

    async fn load_sender_key(&self, sender_key_name: &SenderKeyName) -> Result<SenderKeyRecord, StoreError> {
        let key = format!("{}:{}", sender_key_name.group_id(), sender_key_name.sender_id());
        Ok(self.sender_keys.get(&key).cloned().unwrap_or_default())
    }

    async fn delete_sender_key(&self, _sender_key_name: &SenderKeyName) -> Result<(), StoreError> {
        Ok(()) // For testing, we don't need to delete
    }
}

// Don't implement SignalProtocolStore directly - it's already blanket implemented

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
        anyhow::bail!(
            "Bundle path is not a directory: {}",
            args.bundle_path.display()
        );
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

async fn validate_direct_message_bundle(bundle_path: &Path) -> Result<()> {
    println!(
        "📦 Validating direct message bundle: {}",
        bundle_path.display()
    );

    // Load all required files
    let message_bin = fs::read(bundle_path.join("message.bin"))
        .await
        .context("Failed to read message.bin")?;

    let sender_identity_key_bin = fs::read(bundle_path.join("sender_identity_key.bin"))
        .await
        .context("Failed to read sender_identity_key.bin")?;

    let session_json = fs::read_to_string(bundle_path.join("recipient_session.json"))
        .await
        .context("Failed to read recipient_session.json")?;

    let identity_keys_json = fs::read_to_string(bundle_path.join("recipient_identity_keys.json"))
        .await
        .context("Failed to read recipient_identity_keys.json")?;

    let expected_plaintext = fs::read_to_string(bundle_path.join("expected_plaintext.txt"))
        .await
        .context("Failed to read expected_plaintext.txt")?;

    // Parse the JSON files
    let recipient_session: SessionRecord =
        serde_json::from_str(&session_json).context("Failed to parse recipient_session.json")?;

    let recipient_identity_keys: IdentityKeyPair =
        serde_json::from_str(&identity_keys_json)
            .context("Failed to parse recipient_identity_keys.json")?;

    // Parse sender identity key - first convert to array
    let sender_key_len = sender_identity_key_bin.len();
    let sender_identity_key_array: [u8; 32] = sender_identity_key_bin.try_into()
        .map_err(|_| anyhow::anyhow!("Invalid sender identity key length: expected 32 bytes, got {}", sender_key_len))?;
    let sender_identity_key = IdentityKey::new(DjbEcPublicKey::new(sender_identity_key_array));

    println!("✅ Bundle structure validation successful!");
    println!("📋 Bundle contents:");
    println!("  - Message size: {} bytes", message_bin.len());
    println!("  - Sender identity key: {} bytes", sender_identity_key.serialize().len());
    println!(
        "  - Session has {} previous states",
        recipient_session.previous_states().len()
    );
    println!("  - Expected plaintext: \"{}\"", expected_plaintext.trim());

    // Determine message type by checking the first byte
    if message_bin.is_empty() {
        anyhow::bail!("Empty message file");
    }
    
    let version_byte = message_bin[0];
    let msg_type = version_byte & 0x0F;
    
    println!("📝 Message type: {}", if msg_type == 3 { "PreKeySignalMessage" } else { "SignalMessage" });

    // Create store with loaded session and identity
    let mut store = DebugMemoryStore::default();
    store.identity_key_pair = Some(recipient_identity_keys.clone());
    store.registration_id = 1;
    
    // Add the session to the store  
    let sender_address = SignalAddress::new("sender".to_string(), 1);
    store.sessions.insert(
        format!("{}:{}", sender_address.name(), sender_address.device_id()),
        recipient_session
    );

    // Create cipher and attempt decryption
    let cipher = SessionCipher::new(store, sender_address.clone());
    
    let plaintext = if msg_type == 3 {
        // PreKeySignalMessage
        let prekey_msg = PreKeySignalMessage::deserialize(&message_bin)
            .context("Failed to parse PreKeySignalMessage")?;
        cipher.decrypt(Ciphertext::PreKey(prekey_msg)).await
            .context("Failed to decrypt PreKeySignalMessage")?
    } else {
        // SignalMessage
        let signal_msg = SignalMessage::deserialize(&message_bin)
            .context("Failed to parse SignalMessage")?;
        cipher.decrypt(Ciphertext::Whisper(signal_msg)).await
            .context("Failed to decrypt SignalMessage")?
    };

    let plaintext_str = String::from_utf8_lossy(&plaintext);
    println!("🔓 Decrypted plaintext: \"{}\"", plaintext_str);
    
    // Validate against expected plaintext
    let expected_trimmed = expected_plaintext.trim();
    if plaintext_str.trim() == expected_trimmed {
        println!("✅ Decryption validation successful! Plaintext matches expected value.");
    } else {
        anyhow::bail!(
            "❌ Decryption validation failed!\nExpected: \"{}\"\nActual: \"{}\"",
            expected_trimmed,
            plaintext_str.trim()
        );
    }

    Ok(())
}

async fn validate_group_message_bundle(bundle_path: &Path) -> Result<()> {
    println!(
        "📦 Validating group message bundle: {}",
        bundle_path.display()
    );

    // Load all required files
    let message_bin = fs::read(bundle_path.join("message.bin"))
        .await
        .context("Failed to read message.bin")?;

    let sender_identity_key_bin = fs::read(bundle_path.join("sender_identity_key.bin"))
        .await
        .context("Failed to read sender_identity_key.bin")?;

    let session_json = fs::read_to_string(bundle_path.join("recipient_session.json"))
        .await
        .context("Failed to read recipient_session.json")?;

    let sender_key_json = fs::read_to_string(bundle_path.join("recipient_sender_key.json"))
        .await
        .context("Failed to read recipient_sender_key.json")?;

    let expected_plaintext = fs::read_to_string(bundle_path.join("expected_plaintext.txt"))
        .await
        .context("Failed to read expected_plaintext.txt")?;

    // Parse the JSON files
    let recipient_session: SessionRecord =
        serde_json::from_str(&session_json).context("Failed to parse recipient_session.json")?;

    let recipient_sender_key: SenderKeyRecord =
        serde_json::from_str(&sender_key_json)
            .context("Failed to parse recipient_sender_key.json")?;

    println!("✅ Bundle structure validation successful!");
    println!("📋 Bundle contents:");
    println!("  - Message size: {} bytes", message_bin.len());
    println!("  - Sender identity key: {} bytes", sender_identity_key_bin.len());
    println!(
        "  - Session has {} previous states",
        recipient_session.previous_states().len()
    );
    println!("  - Expected plaintext: \"{}\"", expected_plaintext.trim());

    // Parse sender key message
    let (sender_key_message, signed_data) = SenderKeyMessage::deserialize(&message_bin)
        .context("Failed to parse SenderKeyMessage")?;

    println!("📝 Message type: SenderKeyMessage (group message)");

    // Create store with loaded sender key
    let mut store = DebugMemoryStore::default();
    store.registration_id = 1;
    
    // Add the sender key to the store
    let sender_key_name = SenderKeyName::new("group_id".to_string(), "sender_id".to_string());
    store.sender_keys.insert(
        format!("{}:{}", sender_key_name.group_id(), sender_key_name.sender_id()),
        recipient_sender_key
    );

    // Create group cipher and attempt decryption
    let group_session_builder = GroupSessionBuilder::new(store.clone());
    let group_cipher = GroupCipher::new(sender_key_name, store, group_session_builder);
    
    let plaintext = group_cipher.decrypt(&sender_key_message, signed_data).await
        .map_err(|e| anyhow::anyhow!("Failed to decrypt SenderKeyMessage: {}", e))?;

    let plaintext_str = String::from_utf8_lossy(&plaintext);
    println!("🔓 Decrypted plaintext: \"{}\"", plaintext_str);
    
    // Validate against expected plaintext
    let expected_trimmed = expected_plaintext.trim();
    if plaintext_str.trim() == expected_trimmed {
        println!("✅ Decryption validation successful! Plaintext matches expected value.");
    } else {
        anyhow::bail!(
            "❌ Decryption validation failed!\nExpected: \"{}\"\nActual: \"{}\"",
            expected_trimmed,
            plaintext_str.trim()
        );
    }

    Ok(())
}
