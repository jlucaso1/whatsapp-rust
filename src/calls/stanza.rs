//! Call stanza parsing and building.
//!
//! Handles `<call>` stanzas according to the WhatsApp binary protocol.

use super::encryption::EncType;
use super::error::CallError;
use super::signaling::SignalingType;
use chrono::{DateTime, TimeZone, Utc};
use std::collections::HashMap;
use wacore::types::call::{BasicCallMeta, CallMediaType, CallPlatform, CallRemoteMeta};
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::{Node, NodeContent};

/// Parsed enc_rekey data from an enc_rekey stanza.
#[derive(Debug, Clone)]
pub struct EncRekeyData {
    pub enc_type: EncType,
    pub ciphertext: Vec<u8>,
    pub count: u32,
}

/// Encrypted call key data from offer/accept stanzas.
#[derive(Debug, Clone)]
pub struct OfferEncData {
    pub enc_type: EncType,
    pub ciphertext: Vec<u8>,
    pub version: u32,
}

/// Relay data from offer stanzas.
#[derive(Debug, Clone)]
pub struct RelayData {
    /// Hop-by-hop SRTP key material (30 bytes: 16-byte key + 14-byte salt)
    pub hbh_key: Option<Vec<u8>>,
    /// Relay session key (16 bytes)
    pub relay_key: Option<Vec<u8>>,
    /// Relay UUID
    pub uuid: Option<String>,
    /// Self participant ID
    pub self_pid: Option<u32>,
    /// Peer participant ID
    pub peer_pid: Option<u32>,
}

/// Parsed call stanza.
#[derive(Debug, Clone)]
pub struct ParsedCallStanza {
    /// Stanza ID for ack/receipt
    pub stanza_id: String,
    /// Call ID
    pub call_id: String,
    /// Call creator JID
    pub call_creator: Jid,
    /// Sender JID
    pub from: Jid,
    /// Signaling type
    pub signaling_type: SignalingType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Whether this is a video call
    pub is_video: bool,
    /// Whether this was delivered offline
    pub is_offline: bool,
    /// Remote peer platform
    pub platform: Option<CallPlatform>,
    /// Remote peer version
    pub version: Option<String>,
    /// Group JID if group call
    pub group_jid: Option<Jid>,
    /// Caller phone number JID
    pub caller_pn: Option<Jid>,
    /// Caller username/push name
    pub caller_username: Option<String>,
    /// Raw payload data (for transport, etc.)
    pub payload: Option<Vec<u8>>,
    /// Parsed enc_rekey data if this is an enc_rekey stanza
    pub enc_rekey_data: Option<EncRekeyData>,
    /// Encrypted call key from offer/accept (Signal-encrypted)
    pub offer_enc_data: Option<OfferEncData>,
    /// Relay information from offer
    pub relay_data: Option<RelayData>,
}

impl ParsedCallStanza {
    /// Parse a call stanza from a Node.
    pub fn parse(node: &Node) -> Result<Self, CallError> {
        if node.tag != "call" {
            return Err(CallError::Parse(format!(
                "expected 'call' tag, got '{}'",
                node.tag
            )));
        }

        let mut attrs = node.attrs();
        let stanza_id = attrs.string("id");
        let from: Jid = attrs.jid("from");
        let timestamp = attrs
            .optional_string("t")
            .and_then(|t| t.parse::<i64>().ok())
            .and_then(|t| Utc.timestamp_opt(t, 0).single())
            .unwrap_or_else(Utc::now);
        let is_offline = attrs
            .optional_string("offline")
            .map(|s| s == "true")
            .unwrap_or(false);
        let platform = attrs.optional_string("platform").map(CallPlatform::from);
        let version = attrs.optional_string("version").map(|s| s.to_string());

        // Find the signaling type child node
        let children = node
            .children()
            .ok_or_else(|| CallError::Parse("call stanza has no children".to_string()))?;

        let (signaling_type, signaling_node) = children
            .iter()
            .find_map(|child| SignalingType::from_tag(&child.tag).map(|st| (st, child)))
            .ok_or_else(|| CallError::Parse("no signaling type child found".to_string()))?;

        let mut sig_attrs = signaling_node.attrs();
        let call_id = sig_attrs.string("call-id");
        let call_creator: Jid = sig_attrs.jid("call-creator");
        let group_jid = sig_attrs.optional_jid("group-jid");
        let caller_pn = sig_attrs.optional_jid("caller_pn");
        let caller_username = sig_attrs.optional_string("username").map(|s| s.to_string());

        // Check for <video/> child
        let is_video = signaling_node
            .children()
            .map(|children| children.iter().any(|c| c.tag == "video"))
            .unwrap_or(false);

        // Get payload if present (bytes content)
        let payload = match &signaling_node.content {
            Some(NodeContent::Bytes(b)) => Some(b.clone()),
            _ => None,
        };

        // Parse enc_rekey data if this is an enc_rekey stanza
        let enc_rekey_data = if signaling_type == SignalingType::EncRekey {
            Self::parse_enc_rekey_data(signaling_node)
        } else {
            None
        };

        // Parse offer enc data (encrypted call key) from offer/accept stanzas
        let offer_enc_data =
            if matches!(signaling_type, SignalingType::Offer | SignalingType::Accept) {
                Self::parse_offer_enc_data(signaling_node)
            } else {
                None
            };

        // Parse relay data from offer stanzas
        let relay_data = if signaling_type == SignalingType::Offer {
            Self::parse_relay_data(signaling_node)
        } else {
            None
        };

        if call_id.is_empty() {
            return Err(CallError::MissingAttribute("call-id"));
        }

        Ok(Self {
            stanza_id,
            call_id,
            call_creator,
            from,
            signaling_type,
            timestamp,
            is_video,
            is_offline,
            platform,
            version,
            group_jid,
            caller_pn,
            caller_username,
            payload,
            enc_rekey_data,
            offer_enc_data,
            relay_data,
        })
    }

    pub fn basic_meta(&self) -> BasicCallMeta {
        BasicCallMeta {
            from: self.from.clone(),
            timestamp: self.timestamp,
            call_creator: self.call_creator.clone(),
            call_id: self.call_id.clone(),
        }
    }

    pub fn remote_meta(&self) -> CallRemoteMeta {
        CallRemoteMeta {
            remote_platform: self
                .platform
                .as_ref()
                .map(|p| format!("{:?}", p))
                .unwrap_or_default(),
            remote_version: self.version.clone().unwrap_or_default(),
        }
    }

    pub fn media_type(&self) -> CallMediaType {
        if self.is_video {
            CallMediaType::Video
        } else {
            CallMediaType::Audio
        }
    }

    fn parse_enc_rekey_data(signaling_node: &Node) -> Option<EncRekeyData> {
        // enc_rekey structure: <enc_rekey><enc type="msg|pkmsg" count="1">ciphertext</enc></enc_rekey>
        let children = signaling_node.children()?;
        let enc_node = children.iter().find(|c| c.tag == "enc")?;

        let mut attrs = enc_node.attrs();
        let enc_type_str = attrs.optional_string("type")?;
        let enc_type: EncType = enc_type_str.parse().ok()?;
        let count = attrs
            .optional_string("count")
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let ciphertext = match &enc_node.content {
            Some(NodeContent::Bytes(b)) => b.clone(),
            _ => return None,
        };

        Some(EncRekeyData {
            enc_type,
            ciphertext,
            count,
        })
    }

    fn parse_offer_enc_data(signaling_node: &Node) -> Option<OfferEncData> {
        // offer/accept structure: <offer><enc type="pkmsg" v="2">ciphertext</enc></offer>
        let children = signaling_node.children()?;
        let enc_node = children.iter().find(|c| c.tag == "enc")?;

        let mut attrs = enc_node.attrs();
        let enc_type_str = attrs.optional_string("type")?;
        let enc_type: EncType = enc_type_str.parse().ok()?;
        let version = attrs
            .optional_string("v")
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);

        let ciphertext = match &enc_node.content {
            Some(NodeContent::Bytes(b)) => b.clone(),
            _ => return None,
        };

        Some(OfferEncData {
            enc_type,
            ciphertext,
            version,
        })
    }

    fn decode_base64_content(content: &Option<NodeContent>) -> Option<Vec<u8>> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        match content {
            Some(NodeContent::String(s)) => STANDARD.decode(s).ok(),
            Some(NodeContent::Bytes(b)) => {
                // Try to decode as base64 string (Android sends base64 as bytes)
                std::str::from_utf8(b)
                    .ok()
                    .and_then(|s| STANDARD.decode(s).ok())
                    // Fallback: use raw bytes if not valid base64
                    .or_else(|| Some(b.clone()))
            }
            _ => None,
        }
    }

    fn parse_relay_data(signaling_node: &Node) -> Option<RelayData> {
        // offer structure: <offer><relay uuid="..." self_pid="3" peer_pid="1">
        //   <key>base64</key>
        //   <hbh_key>base64</hbh_key>
        //   ...
        // </relay></offer>
        let children = signaling_node.children()?;
        let relay_node = children.iter().find(|c| c.tag == "relay")?;

        let mut attrs = relay_node.attrs();
        let uuid = attrs.optional_string("uuid").map(|s| s.to_string());
        let self_pid = attrs
            .optional_string("self_pid")
            .and_then(|s| s.parse().ok());
        let peer_pid = attrs
            .optional_string("peer_pid")
            .and_then(|s| s.parse().ok());

        let relay_children = relay_node.children()?;

        // Parse hbh_key (base64 encoded, 30 bytes when decoded)
        // Handle both String and Bytes content - Android sends as Bytes, iPhone as String
        let hbh_key = relay_children
            .iter()
            .find(|c| c.tag == "hbh_key")
            .and_then(|node| Self::decode_base64_content(&node.content));

        // Parse relay key (base64 encoded, 16 bytes when decoded)
        let relay_key = relay_children
            .iter()
            .find(|c| c.tag == "key")
            .and_then(|node| Self::decode_base64_content(&node.content));

        Some(RelayData {
            hbh_key,
            relay_key,
            uuid,
            self_pid,
            peer_pid,
        })
    }
}

/// Builder for call stanzas.
pub struct CallStanzaBuilder {
    call_id: String,
    call_creator: Jid,
    to: Jid,
    signaling_type: SignalingType,
    is_video: bool,
    group_jid: Option<Jid>,
    payload: Option<Vec<u8>>,
    extra_attrs: HashMap<String, String>,
}

impl CallStanzaBuilder {
    pub fn new(
        call_id: impl Into<String>,
        call_creator: Jid,
        to: Jid,
        signaling_type: SignalingType,
    ) -> Self {
        Self {
            call_id: call_id.into(),
            call_creator,
            to,
            signaling_type,
            is_video: false,
            group_jid: None,
            payload: None,
            extra_attrs: HashMap::new(),
        }
    }

    pub fn video(mut self, is_video: bool) -> Self {
        self.is_video = is_video;
        self
    }

    pub fn group(mut self, group_jid: Jid) -> Self {
        self.group_jid = Some(group_jid);
        self
    }

    pub fn payload(mut self, data: Vec<u8>) -> Self {
        self.payload = Some(data);
        self
    }

    pub fn attr(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_attrs.insert(key.into(), value.into());
        self
    }

    pub fn build(self) -> Node {
        // Build signaling child node
        let mut sig_builder = NodeBuilder::new(self.signaling_type.tag_name())
            .attr("call-id", &self.call_id)
            .attr("call-creator", self.call_creator.to_string());

        if let Some(group_jid) = &self.group_jid {
            sig_builder = sig_builder.attr("group-jid", group_jid.to_string());
        }

        for (k, v) in &self.extra_attrs {
            sig_builder = sig_builder.attr(k.clone(), v.clone());
        }

        // Add <video/> child if video call
        if self.is_video {
            sig_builder = sig_builder.children(std::iter::once(NodeBuilder::new("video").build()));
        }

        // Add payload if present
        if let Some(payload) = self.payload {
            sig_builder = sig_builder.bytes(payload);
        }

        let signaling_node = sig_builder.build();

        // Build outer call stanza
        NodeBuilder::new("call")
            .attr("to", self.to.to_string())
            .children(std::iter::once(signaling_node))
            .build()
    }
}

/// Build a receipt for a call signaling message.
pub fn build_call_receipt(
    stanza_id: &str,
    to: &Jid,
    from: &Jid,
    call_id: &str,
    call_creator: &Jid,
    signaling_type: SignalingType,
) -> Node {
    let inner = NodeBuilder::new(signaling_type.tag_name())
        .attr("call-id", call_id)
        .attr("call-creator", call_creator.to_string())
        .build();

    NodeBuilder::new("receipt")
        .attr("to", to.to_string())
        .attr("id", stanza_id)
        .attr("from", from.to_string())
        .children(std::iter::once(inner))
        .build()
}

/// Build an ack for a call signaling message.
pub fn build_call_ack(stanza_id: &str, to: &Jid, signaling_type: SignalingType) -> Node {
    NodeBuilder::new("ack")
        .attr("to", to.to_string())
        .attr("id", stanza_id)
        .attr("class", "call")
        .attr("type", signaling_type.tag_name())
        .build()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_call_stanza(
        stanza_id: &str,
        from: &str,
        signaling_type: SignalingType,
        call_id: &str,
        call_creator: &str,
        is_video: bool,
    ) -> Node {
        let mut sig_builder = NodeBuilder::new(signaling_type.tag_name())
            .attr("call-id", call_id)
            .attr("call-creator", call_creator);

        if is_video {
            sig_builder = sig_builder.children(std::iter::once(NodeBuilder::new("video").build()));
        }

        NodeBuilder::new("call")
            .attr("id", stanza_id)
            .attr("from", from)
            .attr("t", "1766531871")
            .children(std::iter::once(sig_builder.build()))
            .build()
    }

    /// Test parsing a call offer stanza with real-world-like data.
    /// Based on call flow from WHATSAPP_CALL_LOG_ANALYSIS.md
    #[test]
    fn test_parse_audio_call_offer() {
        let node = make_call_stanza(
            "stanza123",
            "236395184570386@lid",
            SignalingType::Offer,
            "AC90CFD09DF712D981142B172706F9F2",
            "236395184570386@lid",
            false,
        );

        let parsed = ParsedCallStanza::parse(&node).unwrap();

        assert_eq!(parsed.stanza_id, "stanza123");
        assert_eq!(parsed.call_id, "AC90CFD09DF712D981142B172706F9F2");
        assert_eq!(parsed.signaling_type, SignalingType::Offer);
        assert!(!parsed.is_video);
        assert_eq!(parsed.media_type(), CallMediaType::Audio);
    }

    /// Test parsing a video call offer.
    #[test]
    fn test_parse_video_call_offer() {
        let node = make_call_stanza(
            "stanza456",
            "39492358562039@lid",
            SignalingType::Offer,
            "BC5BD1EDE9BBE601F408EF3795479E93",
            "39492358562039@lid",
            true,
        );

        let parsed = ParsedCallStanza::parse(&node).unwrap();

        assert!(parsed.is_video);
        assert_eq!(parsed.media_type(), CallMediaType::Video);
    }

    /// Test parsing different signaling types.
    #[test]
    fn test_parse_various_signaling_types() {
        let types = [
            SignalingType::Offer,
            SignalingType::Accept,
            SignalingType::Reject,
            SignalingType::Terminate,
            SignalingType::PreAccept,
            SignalingType::Transport,
        ];

        for st in types {
            let node = make_call_stanza(
                "test_id",
                "123@lid",
                st,
                "ABCD1234ABCD1234ABCD1234ABCD1234",
                "123@lid",
                false,
            );

            let parsed = ParsedCallStanza::parse(&node).unwrap();
            assert_eq!(parsed.signaling_type, st, "Failed for {:?}", st);
        }
    }

    /// Test building a call stanza matches expected structure.
    #[test]
    fn test_build_call_stanza() {
        let call_id = "AC90CFD09DF712D981142B172706F9F2";
        let creator: Jid = "236395184570386@lid".parse().unwrap();
        let to: Jid = "39492358562039@lid".parse().unwrap();

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Offer)
                .video(true)
                .build();

        assert_eq!(node.tag, "call");

        let children = node.children().unwrap();
        assert_eq!(children.len(), 1);

        let offer_node = &children[0];
        assert_eq!(offer_node.tag, "offer");

        let mut attrs = offer_node.attrs();
        assert_eq!(attrs.string("call-id"), call_id);
        assert_eq!(attrs.string("call-creator"), creator.to_string());

        // Should have video child
        let offer_children = offer_node.children().unwrap();
        assert!(offer_children.iter().any(|c| c.tag == "video"));
    }

    /// Test building a call receipt with correct structure.
    /// Structure: `<receipt><{tag} call-id="..." call-creator="..."/></receipt>`
    #[test]
    fn test_build_call_receipt() {
        let to: Jid = "123@lid".parse().unwrap();
        let from: Jid = "456@lid".parse().unwrap();
        let call_creator: Jid = "123@lid".parse().unwrap();

        let receipt = build_call_receipt(
            "stanza123",
            &to,
            &from,
            "AC90CFD09DF712D981142B172706F9F2",
            &call_creator,
            SignalingType::Offer,
        );

        assert_eq!(receipt.tag, "receipt");

        let mut attrs = receipt.attrs();
        assert_eq!(attrs.string("id"), "stanza123");
        assert_eq!(attrs.string("to"), to.to_string());
        assert_eq!(attrs.string("from"), from.to_string());

        // Should have inner offer node with call-id and call-creator
        let children = receipt.children().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "offer");

        let mut inner_attrs = children[0].attrs();
        assert_eq!(
            inner_attrs.string("call-id"),
            "AC90CFD09DF712D981142B172706F9F2"
        );
    }

    /// Test building a call ack with correct structure.
    /// Structure: `<ack class="call" type="{tag}">`
    #[test]
    fn test_build_call_ack() {
        let to: Jid = "123@lid".parse().unwrap();

        let ack = build_call_ack("stanza456", &to, SignalingType::Transport);

        assert_eq!(ack.tag, "ack");

        let mut attrs = ack.attrs();
        assert_eq!(attrs.string("id"), "stanza456");
        assert_eq!(attrs.string("to"), to.to_string());
        assert_eq!(attrs.string("class"), "call");
        assert_eq!(attrs.string("type"), "transport");
    }

    /// Test LID JID format used in calls.
    /// Calls use LID (Linked ID) format: `{numeric_id}@lid`
    #[test]
    fn test_lid_jid_format() {
        let lid_jid: Jid = "236395184570386@lid".parse().unwrap();
        assert!(lid_jid.is_lid());

        let phone_jid: Jid = "5511999999999@s.whatsapp.net".parse().unwrap();
        assert!(!phone_jid.is_lid());
    }

    /// Test stanza parsing fails gracefully for invalid input.
    #[test]
    fn test_parse_invalid_stanza() {
        // Wrong tag
        let wrong_tag = NodeBuilder::new("message").build();
        assert!(ParsedCallStanza::parse(&wrong_tag).is_err());

        // No children
        let no_children = NodeBuilder::new("call")
            .attr("id", "test")
            .attr("from", "123@lid")
            .build();
        assert!(ParsedCallStanza::parse(&no_children).is_err());

        // Unknown signaling type
        let unknown_type = NodeBuilder::new("call")
            .attr("id", "test")
            .attr("from", "123@lid")
            .children(std::iter::once(
                NodeBuilder::new("unknown_type")
                    .attr("call-id", "test")
                    .attr("call-creator", "123@lid")
                    .build(),
            ))
            .build();
        assert!(ParsedCallStanza::parse(&unknown_type).is_err());
    }

    #[test]
    fn test_parse_enc_rekey_stanza() {
        let ciphertext = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let enc_node = NodeBuilder::new("enc")
            .attr("type", "msg")
            .attr("count", "1")
            .bytes(ciphertext.clone())
            .build();

        let enc_rekey_node = NodeBuilder::new("enc_rekey")
            .attr("call-id", "TEST1234TEST1234TEST1234TEST1234")
            .attr("call-creator", "123@lid")
            .children(std::iter::once(enc_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza789")
            .attr("from", "456@lid")
            .children(std::iter::once(enc_rekey_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        assert_eq!(parsed.signaling_type, SignalingType::EncRekey);
        assert!(parsed.enc_rekey_data.is_some());

        let enc_data = parsed.enc_rekey_data.unwrap();
        assert_eq!(enc_data.enc_type, EncType::Msg);
        assert_eq!(enc_data.ciphertext, ciphertext);
        assert_eq!(enc_data.count, 1);
    }

    #[test]
    fn test_parse_enc_rekey_pkmsg() {
        let ciphertext = vec![0xAA, 0xBB, 0xCC];

        let enc_node = NodeBuilder::new("enc")
            .attr("type", "pkmsg")
            .attr("count", "2")
            .bytes(ciphertext.clone())
            .build();

        let enc_rekey_node = NodeBuilder::new("enc_rekey")
            .attr("call-id", "ABCDABCDABCDABCDABCDABCDABCDABCD")
            .attr("call-creator", "789@lid")
            .children(std::iter::once(enc_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanzaXYZ")
            .attr("from", "789@lid")
            .children(std::iter::once(enc_rekey_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        let enc_data = parsed.enc_rekey_data.unwrap();
        assert_eq!(enc_data.enc_type, EncType::PkMsg);
        assert_eq!(enc_data.count, 2);
    }

    #[test]
    fn test_parse_offer_with_enc_data() {
        let ciphertext = vec![0x01, 0x02, 0x03, 0x04, 0x05];

        let enc_node = NodeBuilder::new("enc")
            .attr("type", "pkmsg")
            .attr("v", "2")
            .bytes(ciphertext.clone())
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "TEST1234TEST1234TEST1234TEST1234")
            .attr("call-creator", "123@lid")
            .children(std::iter::once(enc_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza123")
            .attr("from", "456@lid")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        assert_eq!(parsed.signaling_type, SignalingType::Offer);
        assert!(parsed.offer_enc_data.is_some());

        let enc_data = parsed.offer_enc_data.unwrap();
        assert_eq!(enc_data.enc_type, EncType::PkMsg);
        assert_eq!(enc_data.ciphertext, ciphertext);
        assert_eq!(enc_data.version, 2);
    }

    #[test]
    fn test_parse_offer_with_relay_data() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        // hbh_key is 30 bytes (16-byte key + 14-byte salt)
        let hbh_key_raw = vec![0u8; 30];
        let hbh_key_b64 = STANDARD.encode(&hbh_key_raw);

        // relay key is 16 bytes
        let relay_key_raw = vec![1u8; 16];
        let relay_key_b64 = STANDARD.encode(&relay_key_raw);

        let hbh_key_node = NodeBuilder::new("hbh_key")
            .string_content(&hbh_key_b64)
            .build();

        let key_node = NodeBuilder::new("key")
            .string_content(&relay_key_b64)
            .build();

        let relay_node = NodeBuilder::new("relay")
            .attr("uuid", "test-uuid-1234")
            .attr("self_pid", "3")
            .attr("peer_pid", "1")
            .children([hbh_key_node, key_node].into_iter())
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "ABCDABCDABCDABCDABCDABCDABCDABCD")
            .attr("call-creator", "123@lid")
            .children(std::iter::once(relay_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza456")
            .attr("from", "789@lid")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        assert!(parsed.relay_data.is_some());

        let relay = parsed.relay_data.unwrap();
        assert_eq!(relay.uuid, Some("test-uuid-1234".to_string()));
        assert_eq!(relay.self_pid, Some(3));
        assert_eq!(relay.peer_pid, Some(1));
        assert_eq!(relay.hbh_key, Some(hbh_key_raw));
        assert_eq!(relay.relay_key, Some(relay_key_raw));
    }

    #[test]
    fn test_parse_real_world_offer() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        // Simulate real-world data from captured log
        let hbh_key_b64 = "JbP13zz3zr7KgLkcbpfwnAFbFwM/A8dqhj06EeUD";
        let relay_key_b64 = "mUE7+M4ONPvG8cvyhwYRHQ==";

        let hbh_key_node = NodeBuilder::new("hbh_key")
            .string_content(hbh_key_b64)
            .build();

        let key_node = NodeBuilder::new("key")
            .string_content(relay_key_b64)
            .build();

        let enc_node = NodeBuilder::new("enc")
            .attr("type", "pkmsg")
            .attr("v", "2")
            .bytes(vec![0u8; 230])
            .build();

        let relay_node = NodeBuilder::new("relay")
            .attr("uuid", "imyXpkD6QxOkfQw6")
            .attr("self_pid", "3")
            .attr("peer_pid", "1")
            .children([hbh_key_node, key_node].into_iter())
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "3C28C0EE16982D87B95CF55638E8F3AD")
            .attr("call-creator", "39492358562039@lid")
            .children([enc_node, relay_node].into_iter())
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "1766798782-379")
            .attr("from", "39492358562039@lid")
            .attr("t", "1766838524")
            .attr("platform", "iphone")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        assert_eq!(parsed.call_id, "3C28C0EE16982D87B95CF55638E8F3AD");
        assert_eq!(parsed.signaling_type, SignalingType::Offer);
        assert_eq!(parsed.platform, Some(CallPlatform::IOS));

        // Check enc data
        assert!(parsed.offer_enc_data.is_some());
        let enc_data = parsed.offer_enc_data.unwrap();
        assert_eq!(enc_data.enc_type, EncType::PkMsg);
        assert_eq!(enc_data.version, 2);
        assert_eq!(enc_data.ciphertext.len(), 230);

        // Check relay data
        assert!(parsed.relay_data.is_some());
        let relay = parsed.relay_data.unwrap();
        assert_eq!(relay.uuid, Some("imyXpkD6QxOkfQw6".to_string()));
        assert_eq!(relay.self_pid, Some(3));
        assert_eq!(relay.peer_pid, Some(1));

        // Verify decoded keys
        let hbh_key = relay.hbh_key.unwrap();
        assert_eq!(hbh_key.len(), 30); // 16-byte key + 14-byte salt

        let relay_key = relay.relay_key.unwrap();
        assert_eq!(relay_key.len(), 16);

        // Verify actual decoded values
        assert_eq!(hbh_key, STANDARD.decode(hbh_key_b64).unwrap());
        assert_eq!(relay_key, STANDARD.decode(relay_key_b64).unwrap());
    }

    #[test]
    fn test_parse_android_offer_with_bytes_base64() {
        use base64::{Engine, engine::general_purpose::STANDARD};

        // Android sends base64 as NodeContent::Bytes, not String
        let hbh_key_b64 = "k/RqBHV7RGJatNYU1tV/enPmLxa9DM5G5ksi7mCt";
        let relay_key_b64 = "xTHBglrIlsSV7ewbKun27w==";

        // Create nodes with bytes content (simulating Android behavior)
        let hbh_key_node = NodeBuilder::new("hbh_key")
            .bytes(hbh_key_b64.as_bytes().to_vec())
            .build();

        let key_node = NodeBuilder::new("key")
            .bytes(relay_key_b64.as_bytes().to_vec())
            .build();

        let relay_node = NodeBuilder::new("relay")
            .attr("uuid", "ObFOZDJieY45504Q")
            .attr("self_pid", "3")
            .attr("peer_pid", "1")
            .children([hbh_key_node, key_node].into_iter())
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "ACBCE0CD41E4B7F1513EB665509E8A7E")
            .attr("call-creator", "119009819262985@lid")
            .children(std::iter::once(relay_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "E9457605BF5A89B6A81693B2FE7CE734")
            .attr("from", "119009819262985@lid")
            .attr("platform", "android")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        assert!(parsed.relay_data.is_some());
        let relay = parsed.relay_data.unwrap();

        // Verify keys are decoded correctly even when sent as bytes
        let hbh_key = relay.hbh_key.unwrap();
        assert_eq!(hbh_key.len(), 30); // 16-byte key + 14-byte salt

        let relay_key = relay.relay_key.unwrap();
        assert_eq!(relay_key.len(), 16);

        // Verify actual decoded values match
        assert_eq!(hbh_key, STANDARD.decode(hbh_key_b64).unwrap());
        assert_eq!(relay_key, STANDARD.decode(relay_key_b64).unwrap());
    }
}
