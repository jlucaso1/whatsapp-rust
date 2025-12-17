//! Reporting Token Implementation for WhatsApp
//!
//! Reporting tokens are a privacy-preserving mechanism that allows users to report
//! spam/abuse messages to WhatsApp while maintaining end-to-end encryption.
//!
//! ## Protocol Overview
//!
//! 1. **Message Secret**: A 32-byte random value stored in MessageContextInfo
//! 2. **Reporting Token Key**: Derived using HKDF from the message secret
//! 3. **Reporting Token Content**: Hash of the message content (varies by type)
//! 4. **Reporting Token**: HMAC-SHA256 of the content, truncated to 16 bytes

use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

/// Current reporting token version
pub const REPORTING_TOKEN_VERSION: i32 = 2;

/// Size of the message secret in bytes
pub const MESSAGE_SECRET_SIZE: usize = 32;

/// Size of the reporting token key in bytes
pub const REPORTING_TOKEN_KEY_SIZE: usize = 32;

/// Size of the final reporting token in bytes
pub const REPORTING_TOKEN_SIZE: usize = 16;

/// UseCaseSecretModificationType for report token derivation
/// This is the constant used in HKDF info construction
const USE_CASE_REPORT_TOKEN: u8 = 4;

/// Generate a random message secret (32 bytes)
pub fn generate_message_secret() -> [u8; MESSAGE_SECRET_SIZE] {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random()
}

/// Build the HKDF info bytes for reporting token key derivation.
///
/// The info is constructed as: stanza_id || sender_jid || remote_jid || use_case_type
fn build_hkdf_info(stanza_id: &str, sender_jid: &str, remote_jid: &str) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(stanza_id.as_bytes());
    info.extend_from_slice(sender_jid.as_bytes());
    info.extend_from_slice(remote_jid.as_bytes());
    info.push(USE_CASE_REPORT_TOKEN);
    info
}

/// Derive the reporting token key from the message secret using HKDF.
///
/// # Arguments
/// * `message_secret` - The 32-byte message secret
/// * `stanza_id` - The message stanza ID
/// * `sender_jid` - The sender's JID string
/// * `remote_jid` - The recipient's JID string
///
/// # Returns
/// A 32-byte reporting token key
pub fn derive_reporting_token_key(
    message_secret: &[u8],
    stanza_id: &str,
    sender_jid: &str,
    remote_jid: &str,
) -> Result<[u8; REPORTING_TOKEN_KEY_SIZE]> {
    if message_secret.len() != MESSAGE_SECRET_SIZE {
        return Err(anyhow!(
            "Invalid message secret size: expected {}, got {}",
            MESSAGE_SECRET_SIZE,
            message_secret.len()
        ));
    }

    let info = build_hkdf_info(stanza_id, sender_jid, remote_jid);

    let hk = Hkdf::<Sha256>::new(None, message_secret);
    let mut key = [0u8; REPORTING_TOKEN_KEY_SIZE];
    hk.expand(&info, &mut key)
        .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;

    Ok(key)
}

/// Generate reporting token content based on message type.
///
/// For text messages: SHA256 hash of the conversation text
/// For media messages: SHA256 hash of (enc_file_hash || caption)
pub fn generate_reporting_token_content(message: &wa::Message) -> Option<Vec<u8>> {
    use sha2::Digest;

    // Check for conversation (text) message
    if let Some(ref conversation) = message.conversation {
        let mut hasher = Sha256::new();
        hasher.update(conversation.as_bytes());
        return Some(hasher.finalize().to_vec());
    }

    // Check for extended text message
    if let Some(ref ext_text) = message.extended_text_message
        && let Some(ref text) = ext_text.text
    {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        return Some(hasher.finalize().to_vec());
    }

    // Check for image message
    if let Some(ref image) = message.image_message {
        return generate_media_token_content(
            image.file_enc_sha256.as_deref(),
            image.caption.as_deref(),
        );
    }

    // Check for video message
    if let Some(ref video) = message.video_message {
        return generate_media_token_content(
            video.file_enc_sha256.as_deref(),
            video.caption.as_deref(),
        );
    }

    // Check for audio message
    if let Some(ref audio) = message.audio_message {
        return generate_media_token_content(audio.file_enc_sha256.as_deref(), None);
    }

    // Check for document message
    if let Some(ref doc) = message.document_message {
        return generate_media_token_content(
            doc.file_enc_sha256.as_deref(),
            doc.caption.as_deref(),
        );
    }

    // Check for sticker message
    if let Some(ref sticker) = message.sticker_message {
        return generate_media_token_content(sticker.file_enc_sha256.as_deref(), None);
    }

    // For unsupported message types, return None
    None
}

/// Generate token content for media messages.
///
/// Content = SHA256(enc_file_hash || caption)
fn generate_media_token_content(
    enc_file_hash: Option<&[u8]>,
    caption: Option<&str>,
) -> Option<Vec<u8>> {
    use sha2::Digest;

    let enc_hash = enc_file_hash?;

    let mut hasher = Sha256::new();
    hasher.update(enc_hash);
    if let Some(cap) = caption {
        hasher.update(cap.as_bytes());
    }

    Some(hasher.finalize().to_vec())
}

/// Calculate the final reporting token.
///
/// Token = HMAC-SHA256(key, content)[0..16]
pub fn calculate_reporting_token(
    reporting_token_key: &[u8; REPORTING_TOKEN_KEY_SIZE],
    content: &[u8],
) -> Result<[u8; REPORTING_TOKEN_SIZE]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(reporting_token_key)
        .map_err(|_| anyhow!("Failed to create HMAC"))?;
    mac.update(content);

    let result = mac.finalize().into_bytes();
    let mut token = [0u8; REPORTING_TOKEN_SIZE];
    token.copy_from_slice(&result[..REPORTING_TOKEN_SIZE]);

    Ok(token)
}

/// Result of generating a reporting token for a message
#[derive(Debug, Clone)]
pub struct ReportingTokenResult {
    /// The message secret (to be stored in MessageContextInfo)
    pub message_secret: [u8; MESSAGE_SECRET_SIZE],
    /// The reporting token (16 bytes, hex encoded for XML)
    pub reporting_token: [u8; REPORTING_TOKEN_SIZE],
    /// The reporting token version
    pub version: i32,
}

/// Generate a complete reporting token for a message.
///
/// This function:
/// 1. Generates a random message secret (or uses provided one)
/// 2. Derives the reporting token key
/// 3. Generates the content hash based on message type
/// 4. Calculates the final token
///
/// # Arguments
/// * `message` - The WhatsApp message to generate token for
/// * `stanza_id` - The message stanza ID
/// * `sender_jid` - The sender's JID
/// * `remote_jid` - The recipient's JID
/// * `existing_secret` - Optional existing message secret (if already generated)
///
/// # Returns
/// `Some(ReportingTokenResult)` if successful, `None` if the message type doesn't support tokens
pub fn generate_reporting_token(
    message: &wa::Message,
    stanza_id: &str,
    sender_jid: &Jid,
    remote_jid: &Jid,
    existing_secret: Option<&[u8]>,
) -> Option<ReportingTokenResult> {
    // Generate or use existing message secret
    let message_secret: [u8; MESSAGE_SECRET_SIZE] = if let Some(secret) = existing_secret {
        if secret.len() != MESSAGE_SECRET_SIZE {
            log::warn!("Invalid existing secret size, generating new one");
            generate_message_secret()
        } else {
            secret.try_into().ok()?
        }
    } else {
        generate_message_secret()
    };

    // Derive the reporting token key
    let key = derive_reporting_token_key(
        &message_secret,
        stanza_id,
        &sender_jid.to_string(),
        &remote_jid.to_string(),
    )
    .ok()?;

    // Generate content hash based on message type
    let content = generate_reporting_token_content(message)?;

    // Calculate the token
    let token = calculate_reporting_token(&key, &content).ok()?;

    Some(ReportingTokenResult {
        message_secret,
        reporting_token: token,
        version: REPORTING_TOKEN_VERSION,
    })
}

/// Build the `<reporting>` XML node for a message stanza.
///
/// The node structure is:
/// ```xml
/// <reporting>
///     <reporting_token v="2">HEX_ENCODED_TOKEN</reporting_token>
/// </reporting>
/// ```
pub fn build_reporting_node(result: &ReportingTokenResult) -> Node {
    let token_hex = hex::encode_upper(result.reporting_token);

    let token_node = NodeBuilder::new("reporting_token")
        .attrs([("v", result.version.to_string())])
        .string_content(token_hex)
        .build();

    NodeBuilder::new("reporting").children([token_node]).build()
}

/// Prepare a message with MessageContextInfo containing the message secret.
///
/// This function creates a new message with MessageContextInfo populated
/// with the message secret and reporting token version.
pub fn prepare_message_with_context(
    message: &wa::Message,
    message_secret: &[u8; MESSAGE_SECRET_SIZE],
) -> wa::Message {
    let mut new_message = message.clone();

    // Get or create MessageContextInfo
    let mut context_info = new_message.message_context_info.take().unwrap_or_default();

    context_info.message_secret = Some(message_secret.to_vec());
    context_info.reporting_token_version = Some(REPORTING_TOKEN_VERSION);

    new_message.message_context_info = Some(context_info);
    new_message
}

/// Extract message secret from a message's MessageContextInfo
pub fn extract_message_secret(message: &wa::Message) -> Option<&[u8]> {
    message
        .message_context_info
        .as_ref()
        .and_then(|ctx| ctx.message_secret.as_deref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_message_secret() {
        let secret1 = generate_message_secret();
        let secret2 = generate_message_secret();

        assert_eq!(secret1.len(), MESSAGE_SECRET_SIZE);
        assert_eq!(secret2.len(), MESSAGE_SECRET_SIZE);
        // Secrets should be different (extremely unlikely to be the same)
        assert_ne!(secret1, secret2);
    }

    #[test]
    fn test_derive_reporting_token_key() {
        let secret = [0x42u8; MESSAGE_SECRET_SIZE];
        let stanza_id = "3EB0E0E5F2D4F618589C0B";
        let sender_jid = "5511999887766@s.whatsapp.net";
        let remote_jid = "5511888776655@s.whatsapp.net";

        let key = derive_reporting_token_key(&secret, stanza_id, sender_jid, remote_jid).unwrap();

        assert_eq!(key.len(), REPORTING_TOKEN_KEY_SIZE);

        // Verify determinism
        let key2 = derive_reporting_token_key(&secret, stanza_id, sender_jid, remote_jid).unwrap();
        assert_eq!(key, key2);

        // Different inputs should produce different keys
        let key3 =
            derive_reporting_token_key(&secret, "different_id", sender_jid, remote_jid).unwrap();
        assert_ne!(key, key3);
    }

    #[test]
    fn test_generate_reporting_token_content_text() {
        let message = wa::Message {
            conversation: Some("Hello, World!".to_string()),
            ..Default::default()
        };

        let content = generate_reporting_token_content(&message);
        assert!(content.is_some());

        let content = content.unwrap();
        assert_eq!(content.len(), 32); // SHA256 output

        // Verify determinism
        let content2 = generate_reporting_token_content(&message).unwrap();
        assert_eq!(content, content2);
    }

    #[test]
    fn test_generate_reporting_token_content_extended_text() {
        let message = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Extended text message".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let content = generate_reporting_token_content(&message);
        assert!(content.is_some());
        assert_eq!(content.unwrap().len(), 32);
    }

    #[test]
    fn test_calculate_reporting_token() {
        let key = [0x55u8; REPORTING_TOKEN_KEY_SIZE];
        let content = b"test content";

        let token = calculate_reporting_token(&key, content).unwrap();
        assert_eq!(token.len(), REPORTING_TOKEN_SIZE);

        // Verify determinism
        let token2 = calculate_reporting_token(&key, content).unwrap();
        assert_eq!(token, token2);

        // Different content should produce different token
        let token3 = calculate_reporting_token(&key, b"different content").unwrap();
        assert_ne!(token, token3);
    }

    #[test]
    fn test_generate_reporting_token_full() {
        let message = wa::Message {
            conversation: Some("Test message".to_string()),
            ..Default::default()
        };

        let sender = Jid {
            user: "5511999887766".to_string(),
            server: "s.whatsapp.net".to_string(),
            device: 0,
            agent: 0,
            integrator: 0,
        };

        let remote = Jid {
            user: "5511888776655".to_string(),
            server: "s.whatsapp.net".to_string(),
            device: 0,
            agent: 0,
            integrator: 0,
        };

        let result = generate_reporting_token(&message, "test_stanza_id", &sender, &remote, None);
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.message_secret.len(), MESSAGE_SECRET_SIZE);
        assert_eq!(result.reporting_token.len(), REPORTING_TOKEN_SIZE);
        assert_eq!(result.version, REPORTING_TOKEN_VERSION);
    }

    #[test]
    fn test_generate_reporting_token_with_existing_secret() {
        let message = wa::Message {
            conversation: Some("Test message".to_string()),
            ..Default::default()
        };

        let sender = Jid {
            user: "5511999887766".to_string(),
            server: "s.whatsapp.net".to_string(),
            device: 0,
            agent: 0,
            integrator: 0,
        };

        let remote = Jid {
            user: "5511888776655".to_string(),
            server: "s.whatsapp.net".to_string(),
            device: 0,
            agent: 0,
            integrator: 0,
        };

        let existing_secret = [0xAAu8; MESSAGE_SECRET_SIZE];
        let result = generate_reporting_token(
            &message,
            "test_stanza_id",
            &sender,
            &remote,
            Some(&existing_secret),
        );
        assert!(result.is_some());

        let result = result.unwrap();
        assert_eq!(result.message_secret, existing_secret);
    }

    #[test]
    fn test_build_reporting_node() {
        let result = ReportingTokenResult {
            message_secret: [0u8; MESSAGE_SECRET_SIZE],
            reporting_token: [
                0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
                0x77, 0x88,
            ],
            version: 2,
        };

        let node = build_reporting_node(&result);
        assert_eq!(node.tag, "reporting");

        let children: Vec<_> = node.get_children_by_tag("reporting_token");
        assert_eq!(children.len(), 1);

        let token_node = children[0];
        assert_eq!(token_node.attrs().string("v"), "2");
    }

    #[test]
    fn test_prepare_message_with_context() {
        let message = wa::Message {
            conversation: Some("Test".to_string()),
            ..Default::default()
        };

        let secret = [0x42u8; MESSAGE_SECRET_SIZE];
        let prepared = prepare_message_with_context(&message, &secret);

        assert!(prepared.message_context_info.is_some());
        let ctx = prepared.message_context_info.unwrap();
        assert_eq!(ctx.message_secret, Some(secret.to_vec()));
        assert_eq!(ctx.reporting_token_version, Some(REPORTING_TOKEN_VERSION));
    }

    #[test]
    fn test_extract_message_secret() {
        let secret = vec![0x55u8; MESSAGE_SECRET_SIZE];
        let message = wa::Message {
            message_context_info: Some(wa::MessageContextInfo {
                message_secret: Some(secret.clone()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let extracted = extract_message_secret(&message);
        assert!(extracted.is_some());
        assert_eq!(extracted.unwrap(), secret.as_slice());
    }

    #[test]
    fn test_unsupported_message_type_returns_none() {
        // A message with no supported content type
        let message = wa::Message {
            ..Default::default()
        };

        let sender = Jid {
            user: "5511999887766".to_string(),
            server: "s.whatsapp.net".to_string(),
            device: 0,
            agent: 0,
            integrator: 0,
        };

        let remote = Jid {
            user: "5511888776655".to_string(),
            server: "s.whatsapp.net".to_string(),
            device: 0,
            agent: 0,
            integrator: 0,
        };

        let result = generate_reporting_token(&message, "test_id", &sender, &remote, None);
        assert!(result.is_none());
    }
}
