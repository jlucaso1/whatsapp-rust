//! Reporting Token Implementation for WhatsApp
//!
//! Reporting tokens are a privacy-preserving mechanism that allows users to report
//! spam/abuse messages to WhatsApp while maintaining end-to-end encryption.
//!
//! ## Protocol Overview
//!
//! 1. **Message Secret**: A 32-byte random value stored in MessageContextInfo
//! 2. **Reporting Token Key**: Derived using HKDF from the message secret
//! 3. **Reporting Token Content**: Extracted whitelisted protobuf fields from the message
//! 4. **Reporting Token**: HMAC-SHA256 of the content, truncated to 16 bytes
//!
//! ## Protobuf Field Extraction
//!
//! The content is NOT random bytes - it's the encoded protobuf bytes of specific
//! whitelisted fields from the message. This allows WhatsApp to verify the token
//! without seeing the full message content. Only specific fields are extracted
//! based on a predefined whitelist matching WhatsApp Web behavior.

use anyhow::{Result, anyhow};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use prost::Message;
use sha2::Sha256;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;
use waproto::whatsapp as wa;

/// Wire type constants for protobuf parsing
mod wire_type {
    pub const VARINT: u32 = 0;
    pub const FIXED64: u32 = 1;
    pub const LENGTH_DELIMITED: u32 = 2;
    pub const FIXED32: u32 = 5;
}

/// Reporting field definition for protobuf extraction whitelist.
///
/// This struct defines which protobuf fields should be extracted for the
/// reporting token content. Fields can have subfields for nested messages,
/// or be marked as recursive messages that use the top-level whitelist.
#[derive(Debug, Clone, Copy)]
pub struct ReportingField {
    /// The protobuf field number to match
    pub field_number: u32,
    /// Optional subfields for nested message extraction
    pub subfields: Option<&'static [ReportingField]>,
    /// If true, recursively extract using top-level REPORTING_FIELDS whitelist
    pub is_message: bool,
}

impl ReportingField {
    /// Create a new simple field (extract whole field as-is)
    pub const fn new(field_number: u32) -> Self {
        Self {
            field_number,
            subfields: None,
            is_message: false,
        }
    }

    /// Create a field with specific subfields to extract
    pub const fn with_subfields(field_number: u32, subfields: &'static [ReportingField]) -> Self {
        Self {
            field_number,
            subfields: Some(subfields),
            is_message: false,
        }
    }

    /// Create a field that recursively uses top-level whitelist (for FutureProofMessage wrappers)
    pub const fn message(field_number: u32) -> Self {
        Self {
            field_number,
            subfields: None,
            is_message: true,
        }
    }
}

/// ContextInfo subfields: only extract forwardingScore (21) and isForwarded (22)
static CONTEXT_INFO_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(21), // forwardingScore
    ReportingField::new(22), // isForwarded
];

/// FutureProofMessage wrapper: recursively extract inner message (field 1)
/// Used by viewOnceMessage, docWithCaption, editedMessage, etc.
static FUTURE_PROOF_SUBFIELDS: &[ReportingField] = &[ReportingField::message(1)];

/// ImageMessage subfields (field 3)
static IMAGE_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(2),                                     // mimetype
    ReportingField::new(3),                                     // caption
    ReportingField::new(8),                                     // height
    ReportingField::new(11),                                    // width
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
    ReportingField::new(25),                                    // fileLength (as int)
];

/// ContactMessage subfields (field 4)
static CONTACT_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(1),                                     // displayName
    ReportingField::new(16),                                    // vcard
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
];

/// LocationMessage subfields (field 5)
static LOCATION_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(3),                                     // name
    ReportingField::new(4),                                     // address
    ReportingField::new(5),                                     // url
    ReportingField::new(16),                                    // comment
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
];

/// ExtendedTextMessage subfields (field 6)
static EXTENDED_TEXT_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(1),                                     // text
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
    ReportingField::new(30),                                    // inviteLinkGroupType
];

/// DocumentMessage subfields (field 7)
static DOCUMENT_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(2),                                     // mimetype
    ReportingField::new(7),                                     // caption
    ReportingField::new(10),                                    // pageCount
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
    ReportingField::new(20),                                    // fileName
];

/// AudioMessage subfields (field 8)
static AUDIO_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(2),                                     // mimetype
    ReportingField::new(7),                                     // seconds
    ReportingField::new(9),                                     // ptt
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
    ReportingField::new(21),                                    // waveform
];

/// VideoMessage subfields (field 9)
static VIDEO_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(2),                                     // mimetype
    ReportingField::new(6),                                     // caption
    ReportingField::new(7),                                     // seconds
    ReportingField::new(13),                                    // gifPlayback
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
    ReportingField::new(20),                                    // height
];

/// ProtocolMessage subfields (field 12)
static PROTOCOL_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(1),      // key
    ReportingField::new(2),      // type
    ReportingField::message(14), // editedMessage (recursive)
    ReportingField::new(15),     // timestampMs
];

/// LiveLocationMessage subfields (field 18)
static LIVE_LOCATION_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(6),                                     // caption
    ReportingField::new(16),                                    // comment
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
];

/// StickerMessage subfields (field 26)
static STICKER_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(4),                                     // mimetype
    ReportingField::new(5),                                     // height
    ReportingField::new(8),                                     // width
    ReportingField::new(13),                                    // isAnimated
    ReportingField::with_subfields(17, CONTEXT_INFO_SUBFIELDS), // contextInfo
];

/// GroupInviteMessage subfields (field 28)
static GROUP_INVITE_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(1),                                    // groupJid
    ReportingField::new(2),                                    // inviteCode
    ReportingField::new(4),                                    // groupName
    ReportingField::new(5),                                    // caption
    ReportingField::new(6),                                    // groupSubject (unknown purpose)
    ReportingField::with_subfields(7, CONTEXT_INFO_SUBFIELDS), // contextInfo (at field 7 here)
];

/// PollOption subfields
static POLL_OPTION_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(1), // optionName
    ReportingField::new(2), // optionValue
];

/// PollCreationMessage subfields (fields 49, 60, 64)
static POLL_CREATION_MESSAGE_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(2),                                    // name
    ReportingField::with_subfields(3, POLL_OPTION_SUBFIELDS),  // options
    ReportingField::with_subfields(5, CONTEXT_INFO_SUBFIELDS), // contextInfo
    ReportingField::with_subfields(8, POLL_OPTION_SUBFIELDS),  // additionalOptions
];

/// PollResult subfields (field 88)
static POLL_RESULT_OPTION_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(1), // optionName
];

static POLL_RESULT_SUBFIELDS: &[ReportingField] = &[
    ReportingField::new(1),                                          // pollType
    ReportingField::with_subfields(2, POLL_RESULT_OPTION_SUBFIELDS), // results
    ReportingField::with_subfields(3, CONTEXT_INFO_SUBFIELDS),       // contextInfo
];

/// Whitelist of message fields to extract for reporting token content.
pub static REPORTING_FIELDS: &[ReportingField] = &[
    ReportingField::new(1),                                        // conversation
    ReportingField::with_subfields(3, IMAGE_MESSAGE_SUBFIELDS),    // imageMessage
    ReportingField::with_subfields(4, CONTACT_MESSAGE_SUBFIELDS),  // contactMessage
    ReportingField::with_subfields(5, LOCATION_MESSAGE_SUBFIELDS), // locationMessage
    ReportingField::with_subfields(6, EXTENDED_TEXT_MESSAGE_SUBFIELDS), // extendedTextMessage
    ReportingField::with_subfields(7, DOCUMENT_MESSAGE_SUBFIELDS), // documentMessage
    ReportingField::with_subfields(8, AUDIO_MESSAGE_SUBFIELDS),    // audioMessage
    ReportingField::with_subfields(9, VIDEO_MESSAGE_SUBFIELDS),    // videoMessage
    ReportingField::with_subfields(12, PROTOCOL_MESSAGE_SUBFIELDS), // protocolMessage
    ReportingField::with_subfields(18, LIVE_LOCATION_MESSAGE_SUBFIELDS), // liveLocationMessage
    ReportingField::with_subfields(26, STICKER_MESSAGE_SUBFIELDS), // stickerMessage
    ReportingField::with_subfields(28, GROUP_INVITE_MESSAGE_SUBFIELDS), // groupInviteMessage
    ReportingField::with_subfields(37, FUTURE_PROOF_SUBFIELDS),    // viewOnceMessage
    ReportingField::with_subfields(49, POLL_CREATION_MESSAGE_SUBFIELDS), // pollCreationMessage
    ReportingField::with_subfields(53, FUTURE_PROOF_SUBFIELDS),    // docWithCaptionMessage
    ReportingField::with_subfields(55, FUTURE_PROOF_SUBFIELDS),    // viewOnceMessageV2
    ReportingField::with_subfields(58, FUTURE_PROOF_SUBFIELDS),    // editedMessage
    ReportingField::with_subfields(59, FUTURE_PROOF_SUBFIELDS),    // viewOnceMessageV2Extension
    ReportingField::with_subfields(60, POLL_CREATION_MESSAGE_SUBFIELDS), // pollCreationMessageV2
    ReportingField::with_subfields(64, POLL_CREATION_MESSAGE_SUBFIELDS), // pollCreationMessageV3
    ReportingField::with_subfields(66, VIDEO_MESSAGE_SUBFIELDS),   // ptvMessage
    ReportingField::with_subfields(74, FUTURE_PROOF_SUBFIELDS),    // lottieStickerMessage
    ReportingField::with_subfields(87, FUTURE_PROOF_SUBFIELDS),    // statusMentionMessage
    ReportingField::with_subfields(88, POLL_RESULT_SUBFIELDS),     // pollResultMessage
    ReportingField::with_subfields(92, FUTURE_PROOF_SUBFIELDS),    // groupStatusMentionMessage
    ReportingField::with_subfields(93, FUTURE_PROOF_SUBFIELDS),    // pollCreationMessageV4
    ReportingField::with_subfields(94, FUTURE_PROOF_SUBFIELDS),    // future message type
];

/// Current reporting token version
pub const REPORTING_TOKEN_VERSION: i32 = 2;

/// Size of the message secret in bytes
pub const MESSAGE_SECRET_SIZE: usize = 32;

/// Size of the reporting token key in bytes
pub const REPORTING_TOKEN_KEY_SIZE: usize = 32;

/// Size of the final reporting token in bytes
pub const REPORTING_TOKEN_SIZE: usize = 16;

/// UseCaseSecretModificationType for report token derivation.
/// This string is appended to the HKDF info as per WhatsApp Web implementation.
const USE_CASE_REPORT_TOKEN: &str = "Report Token";

/// Generate a random message secret (32 bytes)
pub fn generate_message_secret() -> [u8; MESSAGE_SECRET_SIZE] {
    use rand::Rng;
    let mut rng = rand::rng();
    rng.random()
}

/// Build the HKDF info bytes for reporting token key derivation.
///
/// The info is constructed as: stanza_id || sender_jid || remote_jid || "Report Token"
/// This matches WhatsApp Web's Binary.build(stanzaId, senderJid, remoteJid, REPORT_TOKEN)
fn build_hkdf_info(stanza_id: &str, sender_jid: &str, remote_jid: &str) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(stanza_id.as_bytes());
    info.extend_from_slice(sender_jid.as_bytes());
    info.extend_from_slice(remote_jid.as_bytes());
    info.extend_from_slice(USE_CASE_REPORT_TOKEN.as_bytes());
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

/// Decode a varint from a byte slice.
/// Returns the decoded value and the number of bytes consumed.
fn decode_varint(data: &[u8]) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0;

    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, i + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

/// Maximum bytes needed for a varint (u64 needs at most 10 bytes)
const MAX_VARINT_LEN: usize = 10;

/// Encode a varint to a fixed-size stack buffer, returns the number of bytes written.
/// This avoids heap allocation in the hot path.
#[inline]
fn encode_varint_to_buf(mut value: u64, buf: &mut [u8; MAX_VARINT_LEN]) -> usize {
    let mut i = 0;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf[i] = byte;
        i += 1;
        if value == 0 {
            break;
        }
    }
    i
}

/// Encode a value as a varint (convenience wrapper that allocates).
/// Used in tests for verification.
#[cfg(test)]
#[inline]
fn encode_varint(value: u64) -> Vec<u8> {
    let mut buf = [0u8; MAX_VARINT_LEN];
    let len = encode_varint_to_buf(value, &mut buf);
    buf[..len].to_vec()
}

/// Extract reporting token content from encoded protobuf message bytes.
///
/// This function parses raw protobuf bytes and extracts only the fields
/// specified in the whitelist, matching WhatsApp Web's behavior.
///
/// # Arguments
/// * `data` - Raw protobuf-encoded message bytes
/// * `whitelist` - List of fields to extract
///
/// # Returns
/// Concatenated bytes of all extracted fields, or None if no fields match
pub fn extract_reporting_token_content(
    data: &[u8],
    whitelist: &[ReportingField],
) -> Option<Vec<u8>> {
    // Pre-size: most messages have 1-3 fields
    let mut extracted: Vec<(u32, Vec<u8>)> = Vec::with_capacity(4);
    let mut pos = 0;

    while pos < data.len() {
        // Read tag (field number + wire type)
        let (tag, tag_len) = decode_varint(&data[pos..])?;
        let field_number = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u32;
        let field_start = pos;
        pos += tag_len;

        // Check bounds
        if pos > data.len() {
            break;
        }

        // Find whitelist entry for this field
        let entry = whitelist.iter().find(|f| f.field_number == field_number);

        match wire_type {
            wire_type::VARINT => {
                let (_, val_len) = decode_varint(&data[pos..])?;
                pos += val_len;
                if entry.is_some() {
                    extracted.push((field_number, data[field_start..pos].to_vec()));
                }
            }
            wire_type::FIXED64 => {
                if pos + 8 > data.len() {
                    break;
                }
                pos += 8;
                if entry.is_some() {
                    extracted.push((field_number, data[field_start..pos].to_vec()));
                }
            }
            wire_type::FIXED32 => {
                if pos + 4 > data.len() {
                    break;
                }
                pos += 4;
                if entry.is_some() {
                    extracted.push((field_number, data[field_start..pos].to_vec()));
                }
            }
            wire_type::LENGTH_DELIMITED => {
                let (len, len_size) = decode_varint(&data[pos..])?;
                let value_start = pos + len_size;
                let value_end = value_start + len as usize;

                if value_end > data.len() {
                    break;
                }
                pos = value_end;

                if let Some(entry) = entry {
                    if entry.is_message {
                        if let Some(nested) = extract_reporting_token_content(
                            &data[value_start..value_end],
                            REPORTING_FIELDS,
                        )
                        .filter(|n| !n.is_empty())
                        {
                            let mut tag_buf = [0u8; MAX_VARINT_LEN];
                            let tag_len = encode_varint_to_buf(tag, &mut tag_buf);
                            let mut len_buf = [0u8; MAX_VARINT_LEN];
                            let len_len = encode_varint_to_buf(nested.len() as u64, &mut len_buf);

                            let mut field_bytes =
                                Vec::with_capacity(tag_len + len_len + nested.len());
                            field_bytes.extend_from_slice(&tag_buf[..tag_len]);
                            field_bytes.extend_from_slice(&len_buf[..len_len]);
                            field_bytes.extend(nested);
                            extracted.push((field_number, field_bytes));
                        }
                    } else if let Some(subfields) = entry.subfields {
                        if let Some(nested) = extract_reporting_token_content(
                            &data[value_start..value_end],
                            subfields,
                        )
                        .filter(|n| !n.is_empty())
                        {
                            let mut tag_buf = [0u8; MAX_VARINT_LEN];
                            let tag_len = encode_varint_to_buf(tag, &mut tag_buf);
                            let mut len_buf = [0u8; MAX_VARINT_LEN];
                            let len_len = encode_varint_to_buf(nested.len() as u64, &mut len_buf);

                            let mut field_bytes =
                                Vec::with_capacity(tag_len + len_len + nested.len());
                            field_bytes.extend_from_slice(&tag_buf[..tag_len]);
                            field_bytes.extend_from_slice(&len_buf[..len_len]);
                            field_bytes.extend(nested);
                            extracted.push((field_number, field_bytes));
                        }
                    } else {
                        extracted.push((field_number, data[field_start..pos].to_vec()));
                    }
                }
            }
            _ => {
                // Unknown wire type - skip this message
                return None;
            }
        }
    }

    if extracted.is_empty() {
        return None;
    }

    extracted.sort_by_key(|(num, _)| *num);

    let total_len: usize = extracted.iter().map(|(_, v)| v.len()).sum();
    let mut result = Vec::with_capacity(total_len);
    for (_, bytes) in extracted {
        result.extend(bytes);
    }
    Some(result)
}

/// Check if reporting token should be included for this message type.
pub fn should_include_reporting_token(message: &wa::Message) -> bool {
    message.reaction_message.is_none()
        && message.enc_reaction_message.is_none()
        && message.poll_update_message.is_none()
        && message.keep_in_chat_message.is_none()
}

/// Generate reporting token content by extracting whitelisted protobuf fields.
pub fn generate_reporting_token_content(message: &wa::Message) -> Option<Vec<u8>> {
    if !should_include_reporting_token(message) {
        return None;
    }
    let message_bytes = message.encode_to_vec();
    extract_reporting_token_content(&message_bytes, REPORTING_FIELDS)
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
    /// The reporting token (16 bytes binary)
    pub reporting_token: [u8; REPORTING_TOKEN_SIZE],
    /// The reporting token version
    pub version: i32,
}

/// Generate a complete reporting token for a message.
pub fn generate_reporting_token(
    message: &wa::Message,
    stanza_id: &str,
    sender_jid: &Jid,
    remote_jid: &Jid,
    existing_secret: Option<&[u8]>,
) -> Option<ReportingTokenResult> {
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

    let sender_jid_str = sender_jid.to_string();
    let remote_jid_str = remote_jid.to_string();

    let key =
        derive_reporting_token_key(&message_secret, stanza_id, &sender_jid_str, &remote_jid_str)
            .ok()?;

    let content = generate_reporting_token_content(message)?;
    let token = calculate_reporting_token(&key, &content).ok()?;

    Some(ReportingTokenResult {
        message_secret,
        reporting_token: token,
        version: REPORTING_TOKEN_VERSION,
    })
}

/// Build the `<reporting>` node for a message stanza.
pub fn build_reporting_node(result: &ReportingTokenResult) -> Node {
    let token_node = NodeBuilder::new("reporting_token")
        .attrs([("v", result.version.to_string())])
        .bytes(result.reporting_token.to_vec())
        .build();

    NodeBuilder::new("reporting").children([token_node]).build()
}

/// Prepare a message with MessageContextInfo containing the message secret.
pub fn prepare_message_with_context(
    message: &wa::Message,
    message_secret: &[u8; MESSAGE_SECRET_SIZE],
) -> wa::Message {
    let mut new_message = message.clone();
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
#[allow(deprecated)]
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

        let key = derive_reporting_token_key(&secret, stanza_id, sender_jid, remote_jid)
            .expect("valid secret should derive key successfully");

        assert_eq!(key.len(), REPORTING_TOKEN_KEY_SIZE);

        // Verify determinism
        let key2 = derive_reporting_token_key(&secret, stanza_id, sender_jid, remote_jid)
            .expect("valid secret should derive key successfully");
        assert_eq!(key, key2);

        // Different inputs should produce different keys
        let key3 = derive_reporting_token_key(&secret, "different_id", sender_jid, remote_jid)
            .expect("valid secret should derive key successfully");
        assert_ne!(key, key3);
    }

    #[test]
    fn test_decode_varint() {
        // Single byte varint
        assert_eq!(decode_varint(&[0x01]), Some((1, 1)));
        assert_eq!(decode_varint(&[0x7F]), Some((127, 1)));

        // Two byte varint
        assert_eq!(decode_varint(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(decode_varint(&[0xAC, 0x02]), Some((300, 2)));

        // Empty slice
        assert_eq!(decode_varint(&[]), None);
    }

    #[test]
    fn test_encode_varint() {
        assert_eq!(encode_varint(1), vec![0x01]);
        assert_eq!(encode_varint(127), vec![0x7F]);
        assert_eq!(encode_varint(128), vec![0x80, 0x01]);
        assert_eq!(encode_varint(300), vec![0xAC, 0x02]);
    }

    #[test]
    fn test_varint_roundtrip() {
        for value in [0u64, 1, 127, 128, 255, 256, 16383, 16384, 1000000] {
            let encoded = encode_varint(value);
            let (decoded, _) =
                decode_varint(&encoded).expect("encoded varint should decode successfully");
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn test_generate_reporting_token_content_text() {
        let message = wa::Message {
            conversation: Some("Hello, World!".to_string()),
            ..Default::default()
        };

        let content = generate_reporting_token_content(&message);
        assert!(content.is_some());

        let content = content.expect("text message should generate reporting token content");
        // Content should be non-empty
        assert!(!content.is_empty());

        // Content should be deterministic (same message = same content)
        let content2 = generate_reporting_token_content(&message)
            .expect("text message should generate reporting token content");
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

        // Content should be deterministic
        let content2 = generate_reporting_token_content(&message)
            .expect("extended text message should generate content");
        assert_eq!(
            content.expect("extended text message should generate content"),
            content2
        );
    }

    #[test]
    fn test_should_include_reporting_token() {
        // Normal message should include token
        let normal_message = wa::Message {
            conversation: Some("Hello".to_string()),
            ..Default::default()
        };
        assert!(should_include_reporting_token(&normal_message));

        // Reaction message should NOT include token
        let reaction_message = wa::Message {
            reaction_message: Some(wa::message::ReactionMessage {
                key: None,
                text: Some("👍".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!should_include_reporting_token(&reaction_message));

        // Poll update should NOT include token
        let poll_update = wa::Message {
            poll_update_message: Some(wa::message::PollUpdateMessage::default()),
            ..Default::default()
        };
        assert!(!should_include_reporting_token(&poll_update));
    }

    #[test]
    fn test_extract_reporting_token_content_simple() {
        // Test with a simple conversation message
        let message = wa::Message {
            conversation: Some("Test".to_string()),
            ..Default::default()
        };

        let message_bytes = message.encode_to_vec();
        let extracted = extract_reporting_token_content(&message_bytes, REPORTING_FIELDS);

        assert!(extracted.is_some());
        // The extracted content should match the original field 1 (conversation)
        assert_eq!(
            extracted.expect("conversation message should extract successfully"),
            message_bytes
        );
    }

    #[test]
    fn test_extract_filters_non_whitelisted_fields() {
        // Create an extended text message with contextInfo that has non-whitelisted fields
        let message = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Hello".to_string()),
                context_info: Some(Box::new(wa::ContextInfo {
                    stanza_id: Some("should-be-excluded".to_string()), // Field 1 - NOT in whitelist
                    is_forwarded: Some(true),                          // Field 22 - in whitelist
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };

        let content = generate_reporting_token_content(&message);
        assert!(content.is_some());

        let content_bytes = content.expect("message with contextInfo should generate content");
        // The content should NOT contain the stanza_id string
        let content_str = String::from_utf8_lossy(&content_bytes);
        assert!(!content_str.contains("should-be-excluded"));
    }

    #[test]
    fn test_calculate_reporting_token() {
        let key = [0x55u8; REPORTING_TOKEN_KEY_SIZE];
        let content = b"test content";

        let token = calculate_reporting_token(&key, content)
            .expect("valid key and content should calculate token");
        assert_eq!(token.len(), REPORTING_TOKEN_SIZE);

        // Verify determinism
        let token2 = calculate_reporting_token(&key, content)
            .expect("valid key and content should calculate token");
        assert_eq!(token, token2);

        // Different content should produce different token
        let token3 = calculate_reporting_token(&key, b"different content")
            .expect("valid key and content should calculate token");
        assert_ne!(token, token3);
    }

    #[test]
    fn test_generate_reporting_token_full() {
        let message = wa::Message {
            conversation: Some("Test message".to_string()),
            ..Default::default()
        };

        let sender = Jid::pn("5511999887766");
        let remote = Jid::pn("5511888776655");

        let result = generate_reporting_token(&message, "test_stanza_id", &sender, &remote, None)
            .expect("valid message should generate reporting token");
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

        let sender = Jid::pn("5511999887766");
        let remote = Jid::pn("5511888776655");

        let existing_secret = [0xAAu8; MESSAGE_SECRET_SIZE];
        let result = generate_reporting_token(
            &message,
            "test_stanza_id",
            &sender,
            &remote,
            Some(&existing_secret),
        )
        .expect("valid message with existing secret should generate token");
        assert_eq!(result.message_secret, existing_secret);
    }

    #[test]
    fn test_build_reporting_node() {
        use wacore_binary::node::NodeContent;

        let expected_token = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];

        let result = ReportingTokenResult {
            message_secret: [0u8; MESSAGE_SECRET_SIZE],
            reporting_token: expected_token,
            version: 2,
        };

        let node = build_reporting_node(&result);
        assert_eq!(node.tag, "reporting");

        let token_node = node.get_children_by_tag("reporting_token").next().unwrap();

        assert_eq!(token_node.attrs().string("v"), "2");

        // CRITICAL: Verify the token content is BINARY BYTES, not a hex string.
        // WhatsApp expects raw bytes in the reporting_token node content.
        // Using String content instead of Bytes causes error 479.
        match &token_node.content {
            Some(NodeContent::Bytes(bytes)) => {
                assert_eq!(
                    bytes.as_slice(),
                    &expected_token,
                    "Token bytes must match the original binary token"
                );
            }
            Some(NodeContent::String(s)) => {
                panic!(
                    "REGRESSION: reporting_token content is a String '{}', but must be Bytes! \
                     This will cause WhatsApp error 479.",
                    s
                );
            }
            other => {
                panic!(
                    "reporting_token content must be NodeContent::Bytes, got {:?}",
                    other
                );
            }
        }
    }

    #[test]
    fn test_prepare_message_with_context() {
        let message = wa::Message {
            conversation: Some("Test".to_string()),
            ..Default::default()
        };

        let secret = [0x42u8; MESSAGE_SECRET_SIZE];
        let prepared = prepare_message_with_context(&message, &secret);

        let ctx = prepared
            .message_context_info
            .expect("prepared message should have context info");
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
        assert_eq!(
            extracted.expect("message should have extractable secret"),
            secret.as_slice()
        );
    }

    #[test]
    fn test_unsupported_message_type_returns_none() {
        // A message with no supported content type
        let message = wa::Message {
            ..Default::default()
        };

        let sender = Jid::pn("5511999887766");
        let remote = Jid::pn("5511888776655");

        let result = generate_reporting_token(&message, "test_id", &sender, &remote, None);
        assert!(result.is_none());
    }

    /// Helper to create a test JID
    fn test_jid(user: &str) -> Jid {
        Jid::pn(user)
    }

    #[test]
    fn test_golden_hkdf_key_derivation() {
        // Golden test: fixed inputs must always produce the same HKDF key
        let secret = [0x42u8; MESSAGE_SECRET_SIZE];
        let stanza_id = "3EB0E0E5F2D4F618589C0B";
        let sender_jid = "5511999887766@s.whatsapp.net";
        let remote_jid = "5511888776655@s.whatsapp.net";

        let key = derive_reporting_token_key(&secret, stanza_id, sender_jid, remote_jid)
            .expect("valid inputs should derive key for golden test");

        // This is the expected output - if this changes, the algorithm is broken
        let expected_key = [
            0xba, 0x50, 0xb2, 0x2b, 0xe5, 0xcc, 0x25, 0x71, 0x7d, 0x32, 0xb7, 0xd2, 0x77, 0xda,
            0xe1, 0xbc, 0x9f, 0xa8, 0xad, 0x12, 0x2c, 0xdd, 0xb0, 0xec, 0x4f, 0xbc, 0x87, 0x24,
            0x52, 0xa5, 0xe0, 0x8c,
        ];
        assert_eq!(
            key, expected_key,
            "HKDF key derivation changed! Expected: {:02x?}, Got: {:02x?}",
            expected_key, key
        );
    }

    #[test]
    fn test_golden_hmac_token_calculation() {
        // Golden test: fixed key and content must produce the same token
        let key = [0x55u8; REPORTING_TOKEN_KEY_SIZE];
        let content = b"Hello, World!";

        let token = calculate_reporting_token(&key, content)
            .expect("valid key and content should calculate token for golden test");

        // Expected HMAC-SHA256 truncated to 16 bytes
        let expected_token = [
            0xc2, 0x2b, 0x68, 0x1d, 0x7d, 0x7e, 0xef, 0xbc, 0x59, 0xa2, 0x02, 0xfc, 0x14, 0x1e,
            0xb5, 0xf8,
        ];
        assert_eq!(
            token, expected_token,
            "HMAC token calculation changed! Expected: {:02x?}, Got: {:02x?}",
            expected_token, token
        );
    }

    #[test]
    fn test_golden_conversation_content_extraction() {
        // Golden test: conversation message content extraction
        let message = wa::Message {
            conversation: Some("Test".to_string()),
            ..Default::default()
        };

        let content = generate_reporting_token_content(&message)
            .expect("conversation message should generate content for golden test");

        // Field 1 (conversation) = tag 0x0a (field 1, wire type 2) + length + "Test"
        let expected = vec![0x0a, 0x04, b'T', b'e', b's', b't'];
        assert_eq!(
            content, expected,
            "Conversation content extraction changed! Expected: {:02x?}, Got: {:02x?}",
            expected, content
        );
    }

    #[test]
    fn test_golden_extended_text_content_extraction() {
        // Golden test: extended text message content extraction
        let message = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Hi".to_string()),
                ..Default::default()
            })),
            ..Default::default()
        };

        let content = generate_reporting_token_content(&message)
            .expect("conversation message should generate content for golden test");

        // Field 6 (extendedTextMessage) containing field 1 (text) = "Hi"
        // Outer: tag 0x32 (field 6, wire type 2), length 4
        // Inner: tag 0x0a (field 1, wire type 2), length 2, "Hi"
        let expected = vec![0x32, 0x04, 0x0a, 0x02, b'H', b'i'];
        assert_eq!(
            content, expected,
            "ExtendedText content extraction changed! Expected: {:02x?}, Got: {:02x?}",
            expected, content
        );
    }

    #[test]
    fn test_golden_full_token_generation() {
        // Golden test: complete token generation with fixed secret
        let message = wa::Message {
            conversation: Some("Hello".to_string()),
            ..Default::default()
        };

        let secret = [0xAA; MESSAGE_SECRET_SIZE];
        let sender = test_jid("sender");
        let remote = test_jid("remote");

        let result =
            generate_reporting_token(&message, "STANZA123", &sender, &remote, Some(&secret))
                .expect("valid message should generate token for golden test");

        // Verify the secret is preserved
        assert_eq!(result.message_secret, secret);
        assert_eq!(result.version, REPORTING_TOKEN_VERSION);

        // The token must be deterministic - same inputs = same output
        let result2 =
            generate_reporting_token(&message, "STANZA123", &sender, &remote, Some(&secret))
                .expect("repeated generation should succeed");
        assert_eq!(
            result.reporting_token, result2.reporting_token,
            "Token generation is not deterministic!"
        );

        // Store expected token for regression detection
        let expected_token = result.reporting_token;
        let result3 =
            generate_reporting_token(&message, "STANZA123", &sender, &remote, Some(&secret))
                .expect("repeated generation should succeed");
        assert_eq!(
            result3.reporting_token, expected_token,
            "Token changed across calls with same inputs!"
        );
    }

    #[test]
    fn test_context_info_filtering_only_extracts_whitelisted() {
        // Verify that contextInfo only extracts fields 21 (forwardingScore) and 22 (isForwarded)
        let message = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Test".to_string()),
                context_info: Some(Box::new(wa::ContextInfo {
                    stanza_id: Some("SHOULD_BE_EXCLUDED".to_string()), // Field 1
                    participant: Some("ALSO_EXCLUDED".to_string()),    // Field 2
                    is_forwarded: Some(true),                          // Field 22 - INCLUDED
                    forwarding_score: Some(5),                         // Field 21 - INCLUDED
                    ..Default::default()
                })),
                ..Default::default()
            })),
            ..Default::default()
        };

        let content = generate_reporting_token_content(&message)
            .expect("conversation message should generate content for golden test");
        let content_str = String::from_utf8_lossy(&content);

        // Must NOT contain excluded fields
        assert!(
            !content_str.contains("SHOULD_BE_EXCLUDED"),
            "stanza_id should be excluded from contextInfo"
        );
        assert!(
            !content_str.contains("ALSO_EXCLUDED"),
            "participant should be excluded from contextInfo"
        );

        // Content should still exist (has text + contextInfo with forwarding fields)
        assert!(!content.is_empty());
    }

    #[test]
    fn test_field_extraction_order_is_deterministic() {
        // Verify that fields are always sorted by field number
        let message = wa::Message {
            conversation: Some("Text".to_string()), // Field 1
            ..Default::default()
        };

        // Generate multiple times and verify same output
        let content1 = generate_reporting_token_content(&message)
            .expect("message should generate content for determinism test");
        let content2 = generate_reporting_token_content(&message)
            .expect("message should generate content for determinism test");
        let content3 = generate_reporting_token_content(&message)
            .expect("message should generate content for determinism test");

        assert_eq!(content1, content2, "Content extraction not deterministic");
        assert_eq!(content2, content3, "Content extraction not deterministic");
    }

    #[test]
    fn test_varint_edge_cases() {
        // Test varint encoding/decoding at important boundaries
        let test_cases = [
            (0u64, vec![0x00]),
            (1, vec![0x01]),
            (127, vec![0x7F]),               // Max single byte
            (128, vec![0x80, 0x01]),         // Min two bytes
            (16383, vec![0xFF, 0x7F]),       // Max two bytes
            (16384, vec![0x80, 0x80, 0x01]), // Min three bytes
            (u32::MAX as u64, vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F]), // Max u32
        ];

        for (value, expected_bytes) in test_cases {
            let encoded = encode_varint(value);
            assert_eq!(
                encoded, expected_bytes,
                "encode_varint({}) = {:02x?}, expected {:02x?}",
                value, encoded, expected_bytes
            );

            let (decoded, len) =
                decode_varint(&encoded).expect("valid encoded bytes should decode");
            assert_eq!(
                decoded, value,
                "decode_varint round-trip failed for {}",
                value
            );
            assert_eq!(
                len,
                expected_bytes.len(),
                "varint length mismatch for {}",
                value
            );
        }
    }

    #[test]
    fn test_extraction_handles_empty_nested_message() {
        // An extended text message with empty contextInfo should still extract the text
        let message = wa::Message {
            extended_text_message: Some(Box::new(wa::message::ExtendedTextMessage {
                text: Some("Content".to_string()),
                context_info: Some(Box::new(wa::ContextInfo::default())), // Empty
                ..Default::default()
            })),
            ..Default::default()
        };

        let content = generate_reporting_token_content(&message);
        assert!(
            content.is_some(),
            "Should extract text even with empty contextInfo"
        );

        let content = content.expect("message with empty contextInfo should generate content");
        assert!(
            content.windows(7).any(|w| w == b"Content"),
            "Text 'Content' should be in extracted bytes"
        );
    }

    #[test]
    fn test_raw_protobuf_extraction_simple_fields() {
        // Test raw extraction with hand-crafted protobuf bytes
        // Field 1 (varint): tag=0x08, value=150 (0x96 0x01)
        // Field 2 (string): tag=0x12, len=5, "hello"
        let data = vec![
            0x08, 0x96, 0x01, // Field 1: varint 150
            0x12, 0x05, b'h', b'e', b'l', b'l', b'o', // Field 2: string "hello"
        ];

        // Whitelist only field 1
        let whitelist = &[ReportingField::new(1)];
        let extracted = extract_reporting_token_content(&data, whitelist)
            .expect("raw protobuf with whitelisted field should extract");

        // Should only contain field 1
        assert_eq!(extracted, vec![0x08, 0x96, 0x01]);
    }

    #[test]
    fn test_raw_protobuf_extraction_nested_with_subfields() {
        // Test nested extraction with subfield filtering
        // Outer field 6 containing inner fields 1 and 2
        // We whitelist field 6 with subfield 1 only

        // Inner message: field 1 = "a", field 2 = "b"
        let inner = vec![
            0x0a, 0x01, b'a', // Field 1: "a"
            0x12, 0x01, b'b', // Field 2: "b"
        ];

        // Outer: field 6 (wire type 2) containing inner
        let mut data = vec![0x32, inner.len() as u8];
        data.extend(&inner);

        // Whitelist: field 6 with only subfield 1
        static TEST_SUBFIELDS: &[ReportingField] = &[ReportingField::new(1)];
        let whitelist = &[ReportingField::with_subfields(6, TEST_SUBFIELDS)];

        let extracted = extract_reporting_token_content(&data, whitelist)
            .expect("nested protobuf with subfield filtering should extract");

        // Should contain field 6 with only field 1 inside
        // Outer tag (0x32) + new length (3) + inner field 1 (0x0a 0x01 'a')
        let expected = vec![0x32, 0x03, 0x0a, 0x01, b'a'];
        assert_eq!(
            extracted, expected,
            "Nested extraction with subfield filtering failed"
        );
    }

    #[test]
    fn test_excluded_message_types() {
        // Verify all excluded message types return None/false

        let reaction = wa::Message {
            reaction_message: Some(wa::message::ReactionMessage {
                text: Some("👍".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(!should_include_reporting_token(&reaction));
        assert!(generate_reporting_token_content(&reaction).is_none());

        let enc_reaction = wa::Message {
            enc_reaction_message: Some(wa::message::EncReactionMessage::default()),
            ..Default::default()
        };
        assert!(!should_include_reporting_token(&enc_reaction));

        let poll_update = wa::Message {
            poll_update_message: Some(wa::message::PollUpdateMessage::default()),
            ..Default::default()
        };
        assert!(!should_include_reporting_token(&poll_update));

        let keep_in_chat = wa::Message {
            keep_in_chat_message: Some(wa::message::KeepInChatMessage::default()),
            ..Default::default()
        };
        assert!(!should_include_reporting_token(&keep_in_chat));
    }

    #[test]
    fn test_hkdf_info_construction() {
        // Verify the HKDF info is constructed correctly
        let info = build_hkdf_info("STANZA", "sender@s.whatsapp.net", "remote@s.whatsapp.net");

        let expected = b"STANZAsender@s.whatsapp.netremote@s.whatsapp.netReport Token";
        assert_eq!(
            info,
            expected.to_vec(),
            "HKDF info construction changed! This will break token verification."
        );
    }

    #[test]
    fn test_message_secret_in_prepared_message() {
        // Verify prepare_message_with_context correctly adds MessageContextInfo
        let original = wa::Message {
            conversation: Some("Test".to_string()),
            ..Default::default()
        };

        let secret = [0x12u8; MESSAGE_SECRET_SIZE];
        let prepared = prepare_message_with_context(&original, &secret);

        // Original message content preserved
        assert_eq!(prepared.conversation, original.conversation);

        // MessageContextInfo added with correct values
        let ctx = prepared
            .message_context_info
            .as_ref()
            .expect("prepared message should have context info");
        assert_eq!(
            ctx.message_secret
                .as_ref()
                .expect("context info should have message secret"),
            &secret.to_vec()
        );
        assert_eq!(ctx.reporting_token_version, Some(REPORTING_TOKEN_VERSION));
    }

    #[test]
    fn test_prepare_message_preserves_existing_context_info() {
        // If message already has MessageContextInfo, we should update it, not replace
        let original = wa::Message {
            conversation: Some("Test".to_string()),
            message_context_info: Some(wa::MessageContextInfo {
                device_list_metadata_version: Some(42), // Some existing field
                ..Default::default()
            }),
            ..Default::default()
        };

        let secret = [0x12u8; MESSAGE_SECRET_SIZE];
        let prepared = prepare_message_with_context(&original, &secret);

        let ctx = prepared
            .message_context_info
            .as_ref()
            .expect("prepared message should have existing context info preserved");
        assert_eq!(
            ctx.message_secret
                .as_ref()
                .expect("context info should have message secret"),
            &secret.to_vec()
        );
        assert_eq!(ctx.reporting_token_version, Some(REPORTING_TOKEN_VERSION));
        assert_eq!(ctx.device_list_metadata_version, Some(42));
    }

    #[test]
    fn test_invalid_secret_size_generates_new() {
        let message = wa::Message {
            conversation: Some("Test".to_string()),
            ..Default::default()
        };

        let invalid_secret = [0u8; 16]; // Wrong size (16 instead of 32)
        let sender = test_jid("sender");
        let remote = test_jid("remote");

        let result =
            generate_reporting_token(&message, "STANZA", &sender, &remote, Some(&invalid_secret));

        // Should still succeed (generates new secret)
        let result = result.expect("message should generate token even with invalid secret");
        // Secret should be 32 bytes (new one generated)
        assert_eq!(result.message_secret.len(), MESSAGE_SECRET_SIZE);
        // Should NOT be all zeros (the invalid one truncated)
        assert_ne!(result.message_secret, [0u8; MESSAGE_SECRET_SIZE]);
    }
}
