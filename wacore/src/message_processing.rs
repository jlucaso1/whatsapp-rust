//! Pure functions for message processing logic.
//!
//! These functions extract the classification and categorization logic from
//! the runtime-dependent message handling code, making them usable from any
//! runtime (Tokio, bridge, etc.) without side effects.

use crate::types::events::DecryptFailMode;
use wacore_binary::Node;
use waproto::whatsapp as wa;

// ---------------------------------------------------------------------------
// 2a. Enc-node categorization
// ---------------------------------------------------------------------------

/// Classification of an encryption node's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncType {
    /// Pre-key Signal message (`"pkmsg"`) — initial 1:1 session establishment.
    PreKeyMessage,
    /// Regular Signal message (`"msg"`) — established 1:1 session.
    Message,
    /// Sender-key message (`"skmsg"`) — group encryption.
    SenderKey,
}

impl EncType {
    /// Parse from the wire-format string in the `type` attribute.
    pub fn from_wire(s: &str) -> Option<Self> {
        match s {
            "pkmsg" => Some(Self::PreKeyMessage),
            "msg" => Some(Self::Message),
            "skmsg" => Some(Self::SenderKey),
            _ => None,
        }
    }

    /// Returns the wire-format string.
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            Self::PreKeyMessage => "pkmsg",
            Self::Message => "msg",
            Self::SenderKey => "skmsg",
        }
    }

    /// Whether this is a 1:1 session-based encryption type (pkmsg or msg).
    pub fn is_session(&self) -> bool {
        matches!(self, Self::PreKeyMessage | Self::Message)
    }
}

/// Information extracted from a single `<enc>` node.
#[derive(Debug, Clone)]
pub struct EncNodeInfo<'a> {
    /// Raw ciphertext bytes from the node content.
    pub ciphertext: &'a [u8],
    /// The encryption type (pkmsg, msg, or skmsg).
    pub enc_type: EncType,
    /// Padding version from the `v` attribute (default 2).
    pub padding_version: u8,
    /// Sender retry count from the `count` attribute.
    pub retry_count: u8,
}

/// Result of categorizing all `<enc>` nodes in a message stanza.
#[derive(Debug)]
pub struct CategorizedEncNodes<'a> {
    /// 1:1 session enc nodes (pkmsg/msg) — must be processed before group nodes.
    pub session_enc: Vec<EncNodeInfo<'a>>,
    /// Group enc nodes (skmsg) — require prior SKDM from session nodes.
    pub group_enc: Vec<EncNodeInfo<'a>>,
    /// Maximum sender retry count across all enc nodes.
    pub max_retry_count: u8,
    /// Whether decryption failures should be hidden (edited messages).
    pub decrypt_fail_mode: DecryptFailMode,
    /// Encryption type strings that were not recognized as built-in types.
    /// The caller can use these to dispatch to custom handlers.
    pub unknown_enc_types: Vec<String>,
    /// True if skmsg appeared before pkmsg/msg in a multi-enc message
    /// (protocol violation — SKDM won't have been processed yet).
    pub has_ordering_violation: bool,
}

/// Maximum retry attempts per message (matches WhatsApp Web's MAX_RETRY = 5).
const MAX_DECRYPT_RETRIES: u8 = 5;

/// Categorize the `<enc>` child nodes of a message stanza into session (1:1)
/// and group (sender-key) buckets.
///
/// This is a pure function — no I/O, no state mutation. It only reads node
/// attributes and content bytes.
///
/// Enc nodes that have no byte content or no `type` attribute are silently
/// skipped (with a log warning).
pub fn categorize_enc_nodes<'a>(enc_nodes: &[&'a Node]) -> CategorizedEncNodes<'a> {
    let mut session_enc = Vec::with_capacity(enc_nodes.len());
    let mut group_enc = Vec::with_capacity(enc_nodes.len());
    let mut unknown_enc_types = Vec::new();
    let mut max_retry_count: u8 = 0;
    let mut has_hide_fail = false;

    for &enc_node in enc_nodes {
        // Parse sender retry count (WA Web: e.maybeAttrInt("count") ?? 0)
        // Clamp to MAX_DECRYPT_RETRIES to prevent u64->u8 truncation.
        let retry_count = enc_node
            .attrs()
            .optional_u64("count")
            .map(|c| c.min(MAX_DECRYPT_RETRIES as u64) as u8)
            .unwrap_or(0);
        max_retry_count = max_retry_count.max(retry_count);

        // Parse decrypt-fail attribute (WA Web: e.maybeAttrString("decrypt-fail") === "hide")
        if enc_node
            .attrs
            .get("decrypt-fail")
            .is_some_and(|v| v == "hide")
        {
            has_hide_fail = true;
        }

        let enc_type_str = match enc_node.attrs().optional_string("type") {
            Some(t) => t,
            None => {
                log::warn!("Enc node missing 'type' attribute, skipping");
                continue;
            }
        };

        let ciphertext: &[u8] = match &enc_node.content {
            Some(wacore_binary::NodeContent::Bytes(b)) => b,
            _ => {
                log::warn!("Enc node has no byte content, skipping");
                continue;
            }
        };

        let padding_version = enc_node.attrs().optional_u64("v").unwrap_or(2) as u8;

        match EncType::from_wire(enc_type_str.as_ref()) {
            Some(et @ (EncType::PreKeyMessage | EncType::Message)) => {
                session_enc.push(EncNodeInfo {
                    ciphertext,
                    enc_type: et,
                    padding_version,
                    retry_count,
                });
            }
            Some(EncType::SenderKey) => {
                group_enc.push(EncNodeInfo {
                    ciphertext,
                    enc_type: EncType::SenderKey,
                    padding_version,
                    retry_count,
                });
            }
            None => {
                unknown_enc_types.push(enc_type_str.to_string());
            }
        }
    }

    // WA Web diagnostic: validate skmsg is not first in multi-enc messages.
    // If skmsg comes first, the SKDM (carried in pkmsg/msg) hasn't been processed yet.
    let has_ordering_violation = !session_enc.is_empty()
        && !group_enc.is_empty()
        && enc_nodes
            .first()
            .is_some_and(|n| n.attrs.get("type").is_some_and(|v| v == "skmsg"));

    let decrypt_fail_mode = if has_hide_fail {
        DecryptFailMode::Hide
    } else {
        DecryptFailMode::Show
    };

    CategorizedEncNodes {
        session_enc,
        group_enc,
        max_retry_count,
        decrypt_fail_mode,
        unknown_enc_types,
        has_ordering_violation,
    }
}

// ---------------------------------------------------------------------------
// 2b. Decrypted plaintext classification
// ---------------------------------------------------------------------------

/// Information about protocol-level messages embedded in the decrypted content.
#[derive(Debug, Clone, Default)]
pub struct ProtocolMessageInfo {
    /// History sync notification (triggers download + processing of history blobs).
    pub history_sync_notification: Option<wa::message::HistorySyncNotification>,
    /// App state sync key share (encryption keys for app state patches).
    pub app_state_sync_key_share: Option<wa::message::AppStateSyncKeyShare>,
    /// Peer data operation response (PDO — retry-based message recovery).
    pub peer_data_operation_request_response:
        Option<wa::message::PeerDataOperationRequestResponseMessage>,
}

/// Result of classifying a decrypted plaintext message.
///
/// This separates the *what kind of message is this?* question from the
/// *what should we do about it?* question. The caller decides how to
/// dispatch (emit events, store keys, download history, etc.).
#[derive(Debug, Clone)]
pub struct DecryptedMessageResult {
    /// The user-visible message content (with DeviceSentMessage unwrapped).
    pub message: wa::Message,
    /// The sender key distribution message, if present.
    /// Must be processed to store the sender key for future group decryption.
    pub skdm: Option<wa::message::SenderKeyDistributionMessage>,
    /// Protocol-level messages that require special handling.
    pub protocol_message: Option<ProtocolMessageInfo>,
    /// True if the message contains only SKDM with no user-visible content.
    /// These should not be surfaced as user events.
    pub is_skdm_only: bool,
    /// True if a DeviceSentMessage wrapper was present but the sender was
    /// not "from me" (protocol violation — should be logged as a warning).
    pub has_invalid_dsm: bool,
}

/// Classify a decrypted (and decoded) plaintext message into its component parts.
///
/// This is a pure function that:
/// 1. Validates DeviceSentMessage presence against `is_from_me`
/// 2. Unwraps DeviceSentMessage wrappers (self-sent message sync)
/// 3. Extracts SKDM, protocol messages, and user content
/// 4. Determines whether the message is SKDM-only
///
/// The caller is responsible for:
/// - Actually processing the SKDM (storing sender keys)
/// - Handling protocol messages (history sync, key shares, PDO)
/// - Dispatching user-visible messages to the event bus
pub fn process_decrypted_plaintext(
    padded_plaintext: &[u8],
    padding_version: u8,
    is_from_me: bool,
) -> Result<DecryptedMessageResult, anyhow::Error> {
    let original_msg = crate::messages::decode_plaintext(padded_plaintext, padding_version)?;

    // Validate DSM presence against sender identity
    let has_invalid_dsm = original_msg.device_sent_message.is_set() && !is_from_me;

    // Unwrap DeviceSentMessage wrapper
    let msg = crate::messages::unwrap_device_sent(original_msg);

    // Extract SKDM
    let skdm = msg.sender_key_distribution_message.as_option().cloned();

    // Check if SKDM-only
    let is_skdm_only = crate::messages::is_sender_key_distribution_only(&msg);

    // Extract protocol message info
    let protocol_message = msg
        .protocol_message
        .as_option()
        .map(|pm| ProtocolMessageInfo {
            history_sync_notification: pm.history_sync_notification.as_option().cloned(),
            app_state_sync_key_share: pm.app_state_sync_key_share.as_option().cloned(),
            peer_data_operation_request_response: pm
                .peer_data_operation_request_response_message
                .as_option()
                .cloned(),
        });

    Ok(DecryptedMessageResult {
        message: msg,
        skdm,
        protocol_message,
        is_skdm_only,
        has_invalid_dsm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore_binary::{Attrs, Node, NodeContent, NodeValue};

    fn make_enc_node(enc_type: &str, content: &[u8]) -> Node {
        let mut attrs = Attrs::new();
        attrs.insert("type", NodeValue::from(enc_type));
        Node::new("enc", attrs, Some(NodeContent::Bytes(content.to_vec())))
    }

    fn make_enc_node_with_attrs(
        enc_type: &str,
        content: &[u8],
        count: Option<u64>,
        decrypt_fail: Option<&str>,
        v: Option<u64>,
    ) -> Node {
        let mut attrs = Attrs::new();
        attrs.insert("type", NodeValue::from(enc_type));
        if let Some(c) = count {
            attrs.insert("count", NodeValue::from(c.to_string()));
        }
        if let Some(df) = decrypt_fail {
            attrs.insert("decrypt-fail", NodeValue::from(df));
        }
        if let Some(ver) = v {
            attrs.insert("v", NodeValue::from(ver.to_string()));
        }
        Node::new("enc", attrs, Some(NodeContent::Bytes(content.to_vec())))
    }

    #[test]
    fn test_categorize_empty() {
        let result = categorize_enc_nodes(&[]);
        assert!(result.session_enc.is_empty());
        assert!(result.group_enc.is_empty());
        assert_eq!(result.max_retry_count, 0);
        assert_eq!(result.decrypt_fail_mode, DecryptFailMode::Show);
        assert!(!result.has_ordering_violation);
    }

    #[test]
    fn test_categorize_session_types() {
        let pkmsg = make_enc_node("pkmsg", b"cipher1");
        let msg = make_enc_node("msg", b"cipher2");
        let nodes: Vec<&Node> = vec![&pkmsg, &msg];

        let result = categorize_enc_nodes(&nodes);
        assert_eq!(result.session_enc.len(), 2);
        assert!(result.group_enc.is_empty());
        assert_eq!(result.session_enc[0].enc_type, EncType::PreKeyMessage);
        assert_eq!(result.session_enc[1].enc_type, EncType::Message);
        assert_eq!(result.session_enc[0].ciphertext, b"cipher1");
        assert_eq!(result.session_enc[1].ciphertext, b"cipher2");
    }

    #[test]
    fn test_categorize_group_type() {
        let skmsg = make_enc_node("skmsg", b"group_cipher");
        let nodes: Vec<&Node> = vec![&skmsg];

        let result = categorize_enc_nodes(&nodes);
        assert!(result.session_enc.is_empty());
        assert_eq!(result.group_enc.len(), 1);
        assert_eq!(result.group_enc[0].enc_type, EncType::SenderKey);
    }

    #[test]
    fn test_categorize_mixed_correct_order() {
        let pkmsg = make_enc_node("pkmsg", b"session");
        let skmsg = make_enc_node("skmsg", b"group");
        let nodes: Vec<&Node> = vec![&pkmsg, &skmsg];

        let result = categorize_enc_nodes(&nodes);
        assert_eq!(result.session_enc.len(), 1);
        assert_eq!(result.group_enc.len(), 1);
        assert!(!result.has_ordering_violation);
    }

    #[test]
    fn test_categorize_ordering_violation() {
        let skmsg = make_enc_node("skmsg", b"group");
        let pkmsg = make_enc_node("pkmsg", b"session");
        let nodes: Vec<&Node> = vec![&skmsg, &pkmsg];

        let result = categorize_enc_nodes(&nodes);
        assert!(result.has_ordering_violation);
    }

    #[test]
    fn test_categorize_retry_count() {
        let node1 = make_enc_node_with_attrs("msg", b"c1", Some(2), None, None);
        let node2 = make_enc_node_with_attrs("msg", b"c2", Some(4), None, None);
        let nodes: Vec<&Node> = vec![&node1, &node2];

        let result = categorize_enc_nodes(&nodes);
        assert_eq!(result.max_retry_count, 4);
    }

    #[test]
    fn test_categorize_retry_count_clamped() {
        let node = make_enc_node_with_attrs("msg", b"c", Some(100), None, None);
        let nodes: Vec<&Node> = vec![&node];

        let result = categorize_enc_nodes(&nodes);
        assert_eq!(result.max_retry_count, MAX_DECRYPT_RETRIES);
    }

    #[test]
    fn test_categorize_decrypt_fail_hide() {
        let node = make_enc_node_with_attrs("msg", b"c", None, Some("hide"), None);
        let nodes: Vec<&Node> = vec![&node];

        let result = categorize_enc_nodes(&nodes);
        assert_eq!(result.decrypt_fail_mode, DecryptFailMode::Hide);
    }

    #[test]
    fn test_categorize_decrypt_fail_show_default() {
        let node = make_enc_node_with_attrs("msg", b"c", None, Some("show"), None);
        let nodes: Vec<&Node> = vec![&node];

        let result = categorize_enc_nodes(&nodes);
        assert_eq!(result.decrypt_fail_mode, DecryptFailMode::Show);
    }

    #[test]
    fn test_categorize_padding_version() {
        let node = make_enc_node_with_attrs("msg", b"c", None, None, Some(3));
        let nodes: Vec<&Node> = vec![&node];

        let result = categorize_enc_nodes(&nodes);
        assert_eq!(result.session_enc[0].padding_version, 3);
    }

    #[test]
    fn test_categorize_padding_version_default() {
        let node = make_enc_node("msg", b"c");
        let nodes: Vec<&Node> = vec![&node];

        let result = categorize_enc_nodes(&nodes);
        assert_eq!(result.session_enc[0].padding_version, 2);
    }

    #[test]
    fn test_categorize_unknown_type() {
        let node = make_enc_node("frskmsg", b"custom");
        let nodes: Vec<&Node> = vec![&node];

        let result = categorize_enc_nodes(&nodes);
        assert!(result.session_enc.is_empty());
        assert!(result.group_enc.is_empty());
        assert_eq!(result.unknown_enc_types, vec!["frskmsg"]);
    }

    #[test]
    fn test_categorize_missing_content() {
        let mut attrs = Attrs::new();
        attrs.insert("type", NodeValue::from("msg"));
        let node = Node::new("enc", attrs, None);
        let nodes: Vec<&Node> = vec![&node];

        let result = categorize_enc_nodes(&nodes);
        assert!(result.session_enc.is_empty());
    }

    #[test]
    fn test_enc_type_wire_roundtrip() {
        for wire in &["pkmsg", "msg", "skmsg"] {
            let et = EncType::from_wire(wire).unwrap();
            assert_eq!(et.as_wire_str(), *wire);
        }
        assert!(EncType::from_wire("unknown").is_none());
    }

    #[test]
    fn test_enc_type_is_session() {
        assert!(EncType::PreKeyMessage.is_session());
        assert!(EncType::Message.is_session());
        assert!(!EncType::SenderKey.is_session());
    }

    #[test]
    fn test_process_decrypted_plaintext_simple() {
        use buffa::Message as ProtoMessage;

        // Create a simple text message
        let msg = wa::Message {
            conversation: Some("hello".to_string()),
            ..Default::default()
        };
        let plaintext = msg.encode_to_vec();
        let padded = crate::messages::MessageUtils::pad_message_v2(plaintext);

        let result = process_decrypted_plaintext(&padded, 2, false).unwrap();
        assert_eq!(result.message.conversation.as_deref(), Some("hello"));
        assert!(result.skdm.is_none());
        assert!(result.protocol_message.is_none());
        assert!(!result.is_skdm_only);
        assert!(!result.has_invalid_dsm);
    }

    #[test]
    fn test_process_decrypted_plaintext_with_skdm() {
        use buffa::Message as ProtoMessage;

        let msg = wa::Message {
            conversation: Some("hello".to_string()),
            sender_key_distribution_message: buffa::MessageField::some(
                wa::message::SenderKeyDistributionMessage {
                    group_id: Some("group@g.us".to_string()),
                    axolotl_sender_key_distribution_message: Some(vec![1, 2, 3]),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let plaintext = msg.encode_to_vec();
        let padded = crate::messages::MessageUtils::pad_message_v2(plaintext);

        let result = process_decrypted_plaintext(&padded, 2, false).unwrap();
        assert!(result.skdm.is_some());
        assert!(!result.is_skdm_only); // has conversation content too
    }

    #[test]
    fn test_process_decrypted_plaintext_skdm_only() {
        use buffa::Message as ProtoMessage;

        let msg = wa::Message {
            sender_key_distribution_message: buffa::MessageField::some(
                wa::message::SenderKeyDistributionMessage {
                    group_id: Some("group@g.us".to_string()),
                    axolotl_sender_key_distribution_message: Some(vec![1, 2, 3]),
                    ..Default::default()
                },
            ),
            ..Default::default()
        };
        let plaintext = msg.encode_to_vec();
        let padded = crate::messages::MessageUtils::pad_message_v2(plaintext);

        let result = process_decrypted_plaintext(&padded, 2, false).unwrap();
        assert!(result.skdm.is_some());
        assert!(result.is_skdm_only);
    }

    #[test]
    fn test_process_decrypted_plaintext_invalid_dsm() {
        use buffa::Message as ProtoMessage;

        let msg = wa::Message {
            device_sent_message: buffa::MessageField::some(wa::message::DeviceSentMessage {
                message: buffa::MessageField::some(wa::Message {
                    conversation: Some("inner".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let plaintext = msg.encode_to_vec();
        let padded = crate::messages::MessageUtils::pad_message_v2(plaintext);

        // is_from_me = false but DSM is present => invalid
        let result = process_decrypted_plaintext(&padded, 2, false).unwrap();
        assert!(result.has_invalid_dsm);
        // The inner message should still be unwrapped
        assert_eq!(result.message.conversation.as_deref(), Some("inner"));
    }

    #[test]
    fn test_process_decrypted_plaintext_valid_dsm() {
        use buffa::Message as ProtoMessage;

        let msg = wa::Message {
            device_sent_message: buffa::MessageField::some(wa::message::DeviceSentMessage {
                message: buffa::MessageField::some(wa::Message {
                    conversation: Some("self-sent".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let plaintext = msg.encode_to_vec();
        let padded = crate::messages::MessageUtils::pad_message_v2(plaintext);

        // is_from_me = true and DSM is present => valid
        let result = process_decrypted_plaintext(&padded, 2, true).unwrap();
        assert!(!result.has_invalid_dsm);
        assert_eq!(result.message.conversation.as_deref(), Some("self-sent"));
    }
}
