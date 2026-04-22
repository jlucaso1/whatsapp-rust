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

/// Audio codec parameters from offer/accept stanzas.
#[derive(Debug, Clone)]
pub struct AudioParams {
    /// Codec name (e.g., "opus")
    pub codec: String,
    /// Sample rate (e.g., 16000, 8000)
    pub rate: u32,
}

/// Video codec parameters from offer/accept stanzas.
#[derive(Debug, Clone)]
pub struct VideoParams {
    /// Codec name (e.g., "vp8", "h264")
    pub codec: Option<String>,
}

/// Media parameters from offer/accept stanzas.
#[derive(Debug, Clone, Default)]
pub struct MediaParams {
    /// Audio codec options (may have multiple e.g., opus 16kHz and 8kHz)
    pub audio: Vec<AudioParams>,
    /// Video parameters if video call
    pub video: Option<VideoParams>,
}

/// Relay election data from a relay_election stanza.
#[derive(Debug, Clone)]
pub struct RelayElectionData {
    /// Index of the elected relay in the endpoints array.
    pub elected_relay_idx: u32,
}

/// Relay latency measurement from a relaylatency stanza.
#[derive(Debug, Clone)]
pub struct RelayLatencyData {
    /// Relay server name
    pub relay_name: String,
    /// Latency in milliseconds (extracted from raw value)
    pub latency_ms: u32,
    /// Raw latency value as received (contains flags in upper bits)
    pub raw_latency: u32,
    /// IPv4 address if present
    pub ipv4: Option<String>,
    /// IPv6 address if present
    pub ipv6: Option<String>,
    /// Port
    pub port: Option<u16>,
}

/// Relay endpoint address information.
#[derive(Debug, Clone, Default)]
pub struct RelayAddress {
    /// IPv4 address
    pub ipv4: Option<String>,
    /// IPv6 address
    pub ipv6: Option<String>,
    /// Port for IPv4
    pub port: u16,
    /// Port for IPv6 (if different)
    pub port_v6: Option<u16>,
    /// Protocol (0 = default)
    pub protocol: u8,
}

/// Relay endpoint with tokens and addresses.
#[derive(Debug, Clone)]
pub struct RelayEndpoint {
    /// Relay server ID
    pub relay_id: u32,
    /// Relay server name
    pub relay_name: String,
    /// Index into relay_tokens array
    pub token_id: u32,
    /// Index into auth_tokens array
    pub auth_token_id: u32,
    /// Available addresses for this relay
    pub addresses: Vec<RelayAddress>,
    /// Server-estimated client-to-relay RTT in milliseconds (from c2r_rtt attribute)
    pub c2r_rtt_ms: Option<u32>,
}

/// Relay data from offer stanzas.
#[derive(Debug, Clone, Default)]
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
    /// Relay tokens (indexed by token_id)
    pub relay_tokens: Vec<Vec<u8>>,
    /// Auth tokens (indexed by auth_token_id)
    pub auth_tokens: Vec<Vec<u8>>,
    /// Relay endpoints from <te2> elements
    pub endpoints: Vec<RelayEndpoint>,
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
    /// Media parameters from offer/accept (audio/video codec info)
    pub media_params: Option<MediaParams>,
    /// Relay latency measurements from relaylatency stanzas
    pub relay_latency: Vec<RelayLatencyData>,
    /// Relay election data from relay_election stanzas
    pub relay_election: Option<RelayElectionData>,
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
        let stanza_id = attrs.optional_string("id").unwrap_or_default().to_string();
        let from: Jid = attrs.jid("from");
        let timestamp = attrs
            .optional_string("t")
            .and_then(|t| t.parse::<i64>().ok())
            .and_then(|t| Utc.timestamp_opt(t, 0).single())
            .unwrap_or_else(Utc::now);
        // Presence of the `offline` attribute indicates this stanza was delivered
        // during offline sync (i.e., the call happened while we were disconnected).
        // The value can be "0", "true", or other - any presence means offline.
        let is_offline = attrs.optional_string("offline").is_some();
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
        let call_id = sig_attrs
            .optional_string("call-id")
            .unwrap_or_default()
            .to_string();
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

        // Parse media parameters from offer/accept stanzas
        let media_params = if matches!(signaling_type, SignalingType::Offer | SignalingType::Accept)
        {
            Self::parse_media_params(signaling_node)
        } else {
            None
        };

        // Parse relay latency data from relaylatency stanzas
        let relay_latency = if signaling_type == SignalingType::RelayLatency {
            Self::parse_relay_latency(signaling_node)
        } else {
            Vec::new()
        };

        // Parse relay election data from relay_election stanzas
        let relay_election = if signaling_type == SignalingType::RelayElection {
            Self::parse_relay_election(signaling_node)
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
            media_params,
            relay_latency,
            relay_election,
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

    /// Parse indexed tokens from child nodes (e.g., "token" or "auth_token").
    /// Returns a Vec indexed by the "id" attribute value.
    fn parse_indexed_tokens(children: &[Node], tag: &str) -> Vec<Vec<u8>> {
        let mut tokens: Vec<Vec<u8>> = Vec::new();
        for node in children.iter().filter(|c| c.tag == tag) {
            let bytes = match &node.content {
                Some(NodeContent::Bytes(b)) => b.clone(),
                Some(NodeContent::String(s)) => {
                    // Some clients send tokens as string content (e.g., base64 text)
                    log::debug!(
                        "parse_indexed_tokens: <{}> has String content ({} chars)",
                        tag,
                        s.len()
                    );
                    s.as_bytes().to_vec()
                }
                other => {
                    log::debug!(
                        "parse_indexed_tokens: <{}> has unexpected content type: {:?}",
                        tag,
                        other.as_ref().map(|c| match c {
                            NodeContent::Bytes(b) => format!("Bytes({})", b.len()),
                            NodeContent::String(s) => format!("String({})", s.len()),
                            NodeContent::Nodes(n) => format!("Nodes({})", n.len()),
                        })
                    );
                    continue;
                }
            };
            let id = node
                .attrs()
                .optional_string("id")
                .and_then(|s| s.parse::<usize>().ok())
                .unwrap_or(tokens.len());
            if id >= tokens.len() {
                tokens.resize(id + 1, Vec::new());
            }
            tokens[id] = bytes;
        }
        tokens
    }

    fn parse_relay_data(signaling_node: &Node) -> Option<RelayData> {
        // offer structure: <offer><relay uuid="..." self_pid="3" peer_pid="1">
        //   <key>base64</key>
        //   <hbh_key>base64</hbh_key>
        //   <token id="0">binary</token>
        //   <auth_token id="0">binary</auth_token>
        //   <te2 relay_id="0" relay_name="..." token_id="0" auth_token_id="0">binary</te2>
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

        // Parse tokens and auth_tokens (indexed by id attribute)
        let relay_tokens = Self::parse_indexed_tokens(relay_children, "token");
        let auth_tokens = Self::parse_indexed_tokens(relay_children, "auth_token");

        // Parse te2 elements - each contains endpoint address info
        // Binary format: 6 bytes = IPv4 (4 bytes IP + 2 bytes port)
        //               18 bytes = IPv6 (16 bytes IP + 2 bytes port)
        let mut endpoints_map: HashMap<(u32, String), RelayEndpoint> = HashMap::new();
        for node in relay_children.iter().filter(|c| c.tag == "te2") {
            let mut te2_attrs = node.attrs();
            let relay_id = te2_attrs
                .optional_string("relay_id")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let relay_name = te2_attrs
                .optional_string("relay_name")
                .map(|s| s.to_string())
                .unwrap_or_default();
            let token_id = te2_attrs
                .optional_string("token_id")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let auth_token_id = te2_attrs
                .optional_string("auth_token_id")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let protocol = te2_attrs
                .optional_string("protocol")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            // Server-estimated client-to-relay RTT in milliseconds
            let c2r_rtt_ms = te2_attrs
                .optional_string("c2r_rtt")
                .and_then(|s| s.parse().ok());

            // Parse address from binary content
            if let Some(NodeContent::Bytes(bytes)) = &node.content {
                let address = Self::parse_te2_address(bytes, protocol);
                if let Some(addr) = address {
                    let key = (relay_id, relay_name.clone());
                    let endpoint = endpoints_map.entry(key).or_insert_with(|| RelayEndpoint {
                        relay_id,
                        relay_name: relay_name.clone(),
                        token_id,
                        auth_token_id,
                        addresses: Vec::new(),
                        c2r_rtt_ms,
                    });
                    endpoint.addresses.push(addr);
                }
            }
        }

        let endpoints: Vec<RelayEndpoint> = endpoints_map.into_values().collect();

        // Diagnostic logging: token inventory for debugging relay authentication
        log::info!(
            "Relay data parsed: relay_tokens={}, auth_tokens={}, relay_key={} bytes, endpoints={}",
            relay_tokens.len(),
            auth_tokens.len(),
            relay_key.as_ref().map_or(0, |k| k.len()),
            endpoints.len()
        );
        for (i, t) in relay_tokens.iter().enumerate() {
            log::debug!(
                "  relay_token[{}]: {} bytes, first4={:02x?}",
                i,
                t.len(),
                &t[..t.len().min(4)]
            );
        }
        for (i, t) in auth_tokens.iter().enumerate() {
            log::debug!(
                "  auth_token[{}]: {} bytes, first4={:02x?}",
                i,
                t.len(),
                &t[..t.len().min(4)]
            );
        }

        Some(RelayData {
            hbh_key,
            relay_key,
            uuid,
            self_pid,
            peer_pid,
            relay_tokens,
            auth_tokens,
            endpoints,
        })
    }

    fn parse_media_params(signaling_node: &Node) -> Option<MediaParams> {
        // Parse <audio enc="opus" rate="16000"/> and <video enc="vp8"/> from offer/accept
        let children = signaling_node.children()?;

        let mut audio = Vec::new();
        let mut video = None;

        for child in children.iter() {
            if child.tag == "audio" {
                let mut attrs = child.attrs();
                let codec = attrs
                    .optional_string("enc")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "opus".to_string());
                let rate = attrs
                    .optional_string("rate")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(16000);
                audio.push(AudioParams { codec, rate });
            } else if child.tag == "video" {
                let mut attrs = child.attrs();
                let codec = attrs.optional_string("enc").map(|s| s.to_string());
                video = Some(VideoParams { codec });
            }
        }

        if audio.is_empty() && video.is_none() {
            return None;
        }

        Some(MediaParams { audio, video })
    }

    fn parse_relay_latency(signaling_node: &Node) -> Vec<RelayLatencyData> {
        // Parse <te latency="33554444" relay_name="fimp3c01"><!-- 6 bytes --></te>
        // Latency format: upper byte is type/flags, lower 24 bits is latency in ms
        let Some(children) = signaling_node.children() else {
            return Vec::new();
        };

        let mut result = Vec::new();
        for child in children.iter().filter(|c| c.tag == "te") {
            let mut attrs = child.attrs();
            let relay_name = attrs
                .optional_string("relay_name")
                .map(|s| s.to_string())
                .unwrap_or_default();
            let raw_latency = attrs
                .optional_string("latency")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);
            // Extract actual latency (lower 24 bits)
            let latency_ms = raw_latency & 0x00FFFFFF;

            // Parse address from binary content
            let (ipv4, ipv6, port) = match &child.content {
                Some(NodeContent::Bytes(bytes)) if bytes.len() == 6 => {
                    let ip = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
                    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
                    (Some(ip), None, Some(port))
                }
                Some(NodeContent::Bytes(bytes)) if bytes.len() == 18 => {
                    let mut ipv6_bytes = [0u8; 16];
                    ipv6_bytes.copy_from_slice(&bytes[0..16]);
                    let ipv6_addr = std::net::Ipv6Addr::from(ipv6_bytes);
                    let port = u16::from_be_bytes([bytes[16], bytes[17]]);
                    (None, Some(ipv6_addr.to_string()), Some(port))
                }
                _ => (None, None, None),
            };

            result.push(RelayLatencyData {
                relay_name,
                latency_ms,
                raw_latency,
                ipv4,
                ipv6,
                port,
            });
        }

        result
    }

    fn parse_relay_election(signaling_node: &Node) -> Option<RelayElectionData> {
        // Parse relay_election stanza
        // The elected relay index might be in an attribute or binary payload
        let mut attrs = signaling_node.attrs();

        // Try to get from attribute
        if let Some(idx_str) = attrs.optional_string("elected_relay_idx")
            && let Ok(idx) = idx_str.parse::<u32>()
        {
            return Some(RelayElectionData {
                elected_relay_idx: idx,
            });
        }

        // Try to get from relay_id attribute
        if let Some(idx_str) = attrs.optional_string("relay_id")
            && let Ok(idx) = idx_str.parse::<u32>()
        {
            return Some(RelayElectionData {
                elected_relay_idx: idx,
            });
        }

        // Try to parse from binary payload (first 4 bytes as u32)
        if let Some(NodeContent::Bytes(bytes)) = &signaling_node.content {
            if bytes.len() >= 4 {
                let idx = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                return Some(RelayElectionData {
                    elected_relay_idx: idx,
                });
            } else if !bytes.is_empty() {
                // Single byte index
                return Some(RelayElectionData {
                    elected_relay_idx: bytes[0] as u32,
                });
            }
        }

        // Fallback: log for debugging and return None
        log::debug!(
            "Could not parse relay_election: attrs={:?}, content={:?}",
            signaling_node.attrs,
            signaling_node.content
        );
        None
    }

    /// Parse binary address from te2 element content.
    /// 6 bytes = IPv4 address (4 bytes) + port (2 bytes big-endian)
    /// 18 bytes = IPv6 address (16 bytes) + port (2 bytes big-endian)
    fn parse_te2_address(bytes: &[u8], protocol: u8) -> Option<RelayAddress> {
        match bytes.len() {
            6 => {
                // IPv4: 4 bytes IP + 2 bytes port (big-endian)
                let ip = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
                let port = u16::from_be_bytes([bytes[4], bytes[5]]);
                Some(RelayAddress {
                    ipv4: Some(ip),
                    ipv6: None,
                    port,
                    port_v6: None,
                    protocol,
                })
            }
            18 => {
                // IPv6: 16 bytes IP + 2 bytes port (big-endian)
                let mut ipv6_bytes = [0u8; 16];
                ipv6_bytes.copy_from_slice(&bytes[0..16]);
                let ipv6_addr = std::net::Ipv6Addr::from(ipv6_bytes);
                let port = u16::from_be_bytes([bytes[16], bytes[17]]);
                Some(RelayAddress {
                    ipv4: None,
                    ipv6: Some(ipv6_addr.to_string()),
                    port,
                    port_v6: Some(port),
                    protocol,
                })
            }
            _ => None,
        }
    }

    /// Parse relay data from any node that has a `<relay>` child.
    ///
    /// This is a public method that can be used to extract relay data from:
    /// - ACK nodes (server response to offer with relay allocation)
    /// - Call stanza nodes (offer, accept)
    ///
    /// Returns `None` if no relay data is found.
    pub fn parse_relay_data_from_node(node: &Node) -> Option<RelayData> {
        // The relay data could be a direct child or nested in a signaling node
        Self::parse_relay_data(node)
    }
}

use super::encryption::EncryptedCallKey;

/// Parameters for PREACCEPT stanza.
#[derive(Debug, Clone)]
pub struct PreacceptParams {
    /// Audio codec (e.g., "opus")
    pub audio_codec: String,
    /// Audio sample rate (e.g., 16000)
    pub audio_rate: u32,
    /// Key generation version (typically 2)
    pub keygen: u8,
    /// Capability bytes (7 bytes: 0x01, 0x05, 0xF7, 0x09, 0xE4, 0xBB, 0x07)
    pub capability: Vec<u8>,
}

impl Default for PreacceptParams {
    fn default() -> Self {
        Self {
            audio_codec: "opus".to_string(),
            audio_rate: 16000,
            keygen: 2,
            capability: default_voip_capability().to_vec(),
        }
    }
}

/// Default `<capability>` bytes for outgoing call offers / preaccepts.
///
/// Layout (`wa_voip_capabilities.cc::wa_serialize_voip_capabilities`):
/// * byte 0: version (currently 1)
/// * byte 1: bit-mask length in bytes (5)
/// * bytes 2..: bit-mask (each bit = one optional feature)
///
/// Captured from real WA Web traffic. The WASM stack recomputes these
/// bytes at runtime based on which VoIP features are negotiated — if
/// the peer requires a newer bit, it will ignore this offer. Bump here
/// when the server starts rejecting with capability-related nacks.
pub const WHATSAPP_VOIP_CAPABILITY_V1: [u8; 7] = [0x01, 0x05, 0xF7, 0x09, 0xE4, 0xBB, 0x07];

/// Accessor for [`WHATSAPP_VOIP_CAPABILITY_V1`] as a slice, for callers
/// that want to pin a specific snapshot into a log or test assertion.
pub fn default_voip_capability() -> &'static [u8; 7] {
    &WHATSAPP_VOIP_CAPABILITY_V1
}

/// Relay latency measurement for outgoing RELAYLATENCY stanza.
#[derive(Debug, Clone, Default)]
pub struct RelayLatencyMeasurement {
    /// Relay server name (e.g., "for2c02")
    pub relay_name: String,
    /// Measured latency in milliseconds
    pub latency_ms: u32,
    /// Relay token bytes (from offer's relay tokens)
    pub token: Vec<u8>,
    /// IPv4 address (mutually exclusive with `ipv6`).
    pub ipv4: Option<String>,
    /// Port for `ipv4`. Also used as port when this measurement has an IPv6
    /// address but the offer only provided a single port.
    pub port: u16,
    /// IPv6 address (mutually exclusive with `ipv4`).
    /// Matches WA Web `RelayConnectionUtils.js` which emits separate entries
    /// for each IP family.
    pub ipv6: Option<String>,
    /// Port override for `ipv6` (offer's `port_v6`). Falls back to `port`
    /// when the offer didn't provide a separate IPv6 port.
    pub port_v6: Option<u16>,
}

impl RelayLatencyMeasurement {
    /// Encode the latency value for the stanza.
    /// Format: 0x2000000 + latency_ms
    pub fn encode_latency(&self) -> u32 {
        0x2000000 + self.latency_ms
    }

    /// IPv6 address if present. Mirrors the public `ipv4` accessor pattern.
    pub fn ipv6_address(&self) -> Option<&str> {
        self.ipv6.as_deref()
    }

    /// Replace this measurement's address with an IPv6 one (chainable).
    /// `ipv4` is cleared so IPv4 and IPv6 stay mutually exclusive.
    pub fn with_ipv6(mut self, ip: String, port: u16) -> Self {
        self.ipv4 = None;
        self.ipv6 = Some(ip);
        self.port_v6 = Some(port);
        self
    }

    /// Encode the address bytes for the `<te>` element content.
    /// IPv4 → 4 bytes IP + 2 bytes port big-endian (= 6 bytes).
    /// IPv6 → 16 bytes IP + 2 bytes port big-endian (= 18 bytes).
    pub fn encode_address(&self) -> Vec<u8> {
        if let Some(ip6) = self.ipv6.as_deref() {
            // 16 bytes IPv6 + 2 bytes port — allocate exact.
            let mut bytes = Vec::with_capacity(18);
            let parsed: Option<std::net::Ipv6Addr> = ip6.parse().ok();
            match parsed {
                Some(addr) => bytes.extend_from_slice(&addr.octets()),
                None => bytes.extend_from_slice(&[0u8; 16]),
            }
            let port = self.port_v6.unwrap_or(self.port);
            bytes.extend_from_slice(&port.to_be_bytes());
            return bytes;
        }

        // IPv4 path: 4 bytes IP + 2 bytes port — allocate exact.
        let mut bytes = Vec::with_capacity(6);
        let octets: [u8; 4] = self
            .ipv4
            .as_deref()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .map(|a| a.octets())
            .unwrap_or([0, 0, 0, 0]);
        bytes.extend_from_slice(&octets);
        bytes.extend_from_slice(&self.port.to_be_bytes());
        bytes
    }

    /// Create relay latency measurements from offer's relay data.
    ///
    /// Matches WA Web's `RelayConnectionUtils.js`: for every endpoint address,
    /// emit an IPv4 measurement when `ipv4` is set and an IPv6 measurement
    /// when `ipv6`+`port_v6` are set — so a dual-stack endpoint yields two
    /// measurements.
    ///
    /// # Arguments
    /// * `relay_data` - The relay data from the offer stanza
    /// * `base_latency_ms` - Base latency to use (default ~30ms is reasonable for most connections)
    pub fn from_relay_data(relay_data: &RelayData, base_latency_ms: u32) -> Vec<Self> {
        // Pre-size for the common dual-stack case (2 per endpoint).
        let mut measurements = Vec::with_capacity(relay_data.endpoints.len() * 2);

        for endpoint in &relay_data.endpoints {
            let token = relay_data
                .relay_tokens
                .get(endpoint.token_id as usize)
                .cloned()
                .unwrap_or_default();

            for addr in &endpoint.addresses {
                if let Some(v4) = addr.ipv4.as_deref() {
                    let idx = measurements.len() as u32;
                    measurements.push(Self {
                        relay_name: endpoint.relay_name.clone(),
                        latency_ms: base_latency_ms + idx * 5,
                        token: token.clone(),
                        ipv4: Some(v4.to_string()),
                        port: addr.port,
                        ipv6: None,
                        port_v6: None,
                    });
                }
                if let Some(v6) = addr.ipv6.as_deref()
                    && let Some(port_v6) = addr.port_v6
                {
                    let idx = measurements.len() as u32;
                    measurements.push(Self {
                        relay_name: endpoint.relay_name.clone(),
                        latency_ms: base_latency_ms + idx * 5,
                        token: token.clone(),
                        ipv4: None,
                        port: addr.port,
                        ipv6: Some(v6.to_string()),
                        port_v6: Some(port_v6),
                    });
                }
            }
        }

        measurements
    }
}

/// Parameters for TRANSPORT stanza.
#[derive(Debug, Clone, Default)]
pub struct TransportParams {
    /// P2P candidate round number
    pub p2p_cand_round: Option<u32>,
    /// Transport message type
    pub transport_message_type: Option<u32>,
    /// Network protocol (0 = default)
    pub net_protocol: u8,
    /// Network medium (2 = WiFi/LAN)
    pub net_medium: u8,
}

impl TransportParams {
    /// Create default transport params.
    pub fn new() -> Self {
        Self {
            net_protocol: 0,
            net_medium: 2,
            ..Default::default()
        }
    }
}

/// One participant inside a group-call `<destination>` block.
/// Emits `<to jid="...">` with one `<enc>` per fan-out key — typically
/// one key (primary device), optionally two (primary + companion).
#[derive(Debug, Clone)]
pub struct GroupDestinationRecipient {
    /// Participant device JID the inner `<enc>` is encrypted for.
    pub jid: Jid,
    /// Encrypted call key(s) for that participant. Empty vec emits the
    /// `<to>` wrapper with no `<enc>`, matching the WA Web fallback when
    /// Signal encryption fails (all enc nodes stripped).
    pub encrypted_keys: Vec<EncryptedCallKey>,
}

/// Audio codec parameters for building accept stanzas.
#[derive(Debug, Clone)]
pub struct AcceptAudioParams {
    /// Codec name (e.g., "opus")
    pub codec: String,
    /// Sample rate (e.g., 16000)
    pub rate: u32,
}

impl Default for AcceptAudioParams {
    fn default() -> Self {
        Self {
            codec: "opus".to_string(),
            rate: 16000,
        }
    }
}

/// Video codec parameters for building accept stanzas.
#[derive(Debug, Clone)]
pub struct AcceptVideoParams {
    /// Codec name (e.g., "vp8", "h264")
    pub codec: String,
}

impl Default for AcceptVideoParams {
    fn default() -> Self {
        Self {
            codec: "vp8".to_string(),
        }
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
    /// Stanza ID for the outer `<call>` element (for routing and acks).
    stanza_id: Option<String>,
    /// Encrypted call key for offer/accept stanzas.
    encrypted_keys: Vec<EncryptedCallKey>,
    /// Relay endpoints + session keys to embed in the outgoing offer.
    /// Caller obtains this from the server (relay allocate IQ) and passes
    /// it here so the peer can reach the same relay. Without it the peer
    /// has no path for media.
    relay_data: Option<RelayData>,
    /// Per-participant encrypted keys for a group call offer. When set,
    /// the builder emits a `<destination>` child with one `<to jid="...">`
    /// sub-node per participant, each wrapping that participant's
    /// `<enc>`. Matches WA Web's `SendSignalingXmpp.js::E` fan-out.
    destination_recipients: Vec<GroupDestinationRecipient>,
    /// Audio parameters for accept/offer stanzas.
    /// Offers include two entries (8kHz + 16kHz), accepts include one.
    audio_params: Vec<AcceptAudioParams>,
    /// Video parameters for accept stanzas (only if video call).
    video_params: Option<AcceptVideoParams>,
    /// Parameters for PREACCEPT stanza.
    preaccept_params: Option<PreacceptParams>,
    /// Relay latency measurements for RELAYLATENCY stanza.
    relay_latency_measurements: Vec<RelayLatencyMeasurement>,
    /// Transport parameters for TRANSPORT stanza.
    transport_params: Option<TransportParams>,
    /// Mute state for MUTE_V2 stanza (false = unmuted, true = muted).
    mute_state: Option<bool>,
    /// Network medium for ACCEPT stanza (default 2).
    net_medium: Option<u8>,
    /// Encryption key generation version for ACCEPT stanza (default 2).
    encopt_keygen: Option<u8>,
    /// Device identity for pkmsg offers (ADV encoded identity).
    /// Required when sending encrypted key with type "pkmsg" (PreKey message).
    device_identity: Option<Vec<u8>>,
    /// Privacy token bytes for offer stanzas.
    privacy: Option<Vec<u8>>,
    /// Capability bytes for offer stanzas (e.g., [0x01, 0x05, 0xF7, 0x09, 0xE4, 0xBB, 0x07]).
    capability: Option<Vec<u8>>,
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
            stanza_id: None,
            encrypted_keys: Vec::new(),
            relay_data: None,
            destination_recipients: Vec::new(),
            audio_params: Vec::new(),
            video_params: None,
            preaccept_params: None,
            relay_latency_measurements: Vec::new(),
            transport_params: None,
            mute_state: None,
            net_medium: None,
            encopt_keygen: None,
            device_identity: None,
            privacy: None,
            capability: None,
        }
    }

    /// Set the stanza ID for the outer `<call>` element.
    ///
    /// This ID is used for routing and acknowledgment tracking.
    /// If not set, a random ID will be generated.
    pub fn stanza_id(mut self, id: impl Into<String>) -> Self {
        self.stanza_id = Some(id.into());
        self
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

    /// Append an encrypted call key for offer stanzas.
    ///
    /// Emits an `<enc type="msg|pkmsg" v="2">ciphertext</enc>` element.
    /// Call multiple times to fan-out the call key across a peer's
    /// devices — WA Web emits one `<enc>` per device
    /// (`SendSignalingXmpp.js::S` for 1:1 companion + primary, `::E` for
    /// group call `<destination>` sub-nodes).
    pub fn encrypted_key(mut self, key: EncryptedCallKey) -> Self {
        self.encrypted_keys.push(key);
        self
    }

    /// Replace the full encrypted-key list in one call. Useful when the
    /// caller already has the full `Vec` from the fan-out encryption step.
    pub fn encrypted_keys(mut self, keys: Vec<EncryptedCallKey>) -> Self {
        self.encrypted_keys = keys;
        self
    }

    /// Attach a `<relay>` block to the outgoing offer. The peer will
    /// connect to the embedded endpoints / tokens / keys to send media.
    ///
    /// WA Web obtains this from the native VoIP stack after an allocate
    /// request; in Rust the caller is expected to fetch it via the relay
    /// allocate IQ (not yet exposed here as a standalone API) and pass
    /// the parsed [`RelayData`] through.
    pub fn relay_data(mut self, data: RelayData) -> Self {
        self.relay_data = Some(data);
        self
    }

    /// Replace the group `<destination>` recipient list. Each recipient
    /// becomes a `<to jid="...">` child with its own `<enc>` nodes,
    /// matching WA Web's group-call offer shape from
    /// `SendSignalingXmpp.js::E`.
    pub fn destination_recipients(mut self, recipients: Vec<GroupDestinationRecipient>) -> Self {
        self.destination_recipients = recipients;
        self
    }

    /// Append a single participant to the group `<destination>` list.
    /// Chainable to build the full fan-out incrementally.
    pub fn destination_recipient(mut self, recipient: GroupDestinationRecipient) -> Self {
        self.destination_recipients.push(recipient);
        self
    }

    /// Add audio codec parameters.
    ///
    /// This adds an `<audio enc="opus" rate="16000"/>` element.
    /// Can be called multiple times for offers (which include 8kHz + 16kHz).
    pub fn audio(mut self, params: AcceptAudioParams) -> Self {
        self.audio_params.push(params);
        self
    }

    /// Set video codec parameters for accept stanzas.
    ///
    /// This adds an `<video enc="vp8"/>` element with codec info.
    pub fn video_params(mut self, params: AcceptVideoParams) -> Self {
        self.video_params = Some(params);
        self
    }

    /// Set PREACCEPT parameters.
    ///
    /// This adds `<audio>`, `<encopt>`, and `<capability>` elements.
    pub fn preaccept_params(mut self, params: PreacceptParams) -> Self {
        self.preaccept_params = Some(params);
        self
    }

    /// Add relay latency measurements for RELAYLATENCY stanza.
    ///
    /// This adds `<te latency="..." relay_name="...">` elements.
    pub fn relay_latency(mut self, measurements: Vec<RelayLatencyMeasurement>) -> Self {
        self.relay_latency_measurements = measurements;
        self
    }

    /// Set TRANSPORT parameters.
    ///
    /// This adds attributes and `<net>` element.
    pub fn transport_params(mut self, params: TransportParams) -> Self {
        self.transport_params = Some(params);
        self
    }

    /// Set mute state for MUTE_V2 stanza.
    ///
    /// This adds `mute-state="0|1"` attribute.
    pub fn mute_state(mut self, muted: bool) -> Self {
        self.mute_state = Some(muted);
        self
    }

    /// Set network medium for ACCEPT stanza.
    ///
    /// This adds `<net medium="2"/>` element.
    pub fn net_medium(mut self, medium: u8) -> Self {
        self.net_medium = Some(medium);
        self
    }

    /// Set encryption key generation version for ACCEPT stanza.
    ///
    /// This adds `<encopt keygen="2"/>` element.
    pub fn encopt_keygen(mut self, keygen: u8) -> Self {
        self.encopt_keygen = Some(keygen);
        self
    }

    /// Set device identity for pkmsg offers.
    ///
    /// This adds `<device-identity>bytes</device-identity>` element.
    /// Required when sending encrypted key with type "pkmsg" (PreKey message).
    pub fn device_identity(mut self, identity: Vec<u8>) -> Self {
        self.device_identity = Some(identity);
        self
    }

    /// Set privacy token for offer stanzas.
    ///
    /// This adds `<privacy>hex_bytes</privacy>` element.
    pub fn privacy(mut self, privacy_bytes: Vec<u8>) -> Self {
        self.privacy = Some(privacy_bytes);
        self
    }

    /// Set capability bytes for offer stanzas.
    ///
    /// This adds `<capability ver="1">hex_bytes</capability>` element.
    pub fn capability(mut self, capability_bytes: Vec<u8>) -> Self {
        self.capability = Some(capability_bytes);
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

        // Add MUTE_V2 mute-state attribute
        if self.signaling_type == SignalingType::MuteV2
            && let Some(muted) = self.mute_state
        {
            sig_builder = sig_builder.attr("mute-state", if muted { "1" } else { "0" });
        }

        // Add TRANSPORT attributes
        if self.signaling_type == SignalingType::Transport
            && let Some(ref params) = self.transport_params
        {
            if let Some(round) = params.p2p_cand_round {
                sig_builder = sig_builder.attr("p2p-cand-round", round.to_string());
            }
            if let Some(msg_type) = params.transport_message_type {
                sig_builder = sig_builder.attr("transport-message-type", msg_type.to_string());
            }
        }

        for (k, v) in &self.extra_attrs {
            sig_builder = sig_builder.attr_dynamic(k.clone(), v.clone());
        }

        // Collect children to add
        let mut children: Vec<Node> = Vec::new();

        // Handle PREACCEPT stanza elements
        if self.signaling_type == SignalingType::PreAccept
            && let Some(ref params) = self.preaccept_params
        {
            // Add <audio enc="opus" rate="16000" />
            let audio_node = NodeBuilder::new("audio")
                .attr("enc", &params.audio_codec)
                .attr("rate", params.audio_rate.to_string())
                .build();
            children.push(audio_node);

            // Add <encopt keygen="2" />
            let encopt_node = NodeBuilder::new("encopt")
                .attr("keygen", params.keygen.to_string())
                .build();
            children.push(encopt_node);

            // Add <capability ver="1">hex_bytes</capability>
            // Convert capability bytes to hex string
            let hex_capability: String = params
                .capability
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect();
            let capability_node = NodeBuilder::new("capability")
                .attr("ver", "1")
                .string_content(&hex_capability)
                .build();
            children.push(capability_node);
        }

        // Handle RELAYLATENCY stanza elements
        if self.signaling_type == SignalingType::RelayLatency {
            for measurement in &self.relay_latency_measurements {
                // Add <te latency="..." relay_name="...">address_bytes</te>
                let te_node = NodeBuilder::new("te")
                    .attr("latency", measurement.encode_latency().to_string())
                    .attr("relay_name", &measurement.relay_name)
                    .bytes(measurement.encode_address())
                    .build();
                children.push(te_node);
            }
        }

        // Handle TRANSPORT stanza net element
        if self.signaling_type == SignalingType::Transport
            && let Some(ref params) = self.transport_params
        {
            let net_node = NodeBuilder::new("net")
                .attr("protocol", params.net_protocol.to_string())
                .attr("medium", params.net_medium.to_string())
                .build();
            children.push(net_node);
        }

        // Add elements for Offer/Accept stanzas.
        // WhatsApp Web offer order: <privacy>, <audio>x2, <net>, <capability>, <enc>, <encopt>, <device-identity>
        // WhatsApp Web accept order: <audio>, <net>, <encopt>
        if matches!(
            self.signaling_type,
            SignalingType::Offer | SignalingType::Accept
        ) {
            // Add <privacy> for offers
            if self.signaling_type == SignalingType::Offer
                && let Some(ref privacy_bytes) = self.privacy
            {
                let hex: String = privacy_bytes.iter().map(|b| format!("{:02X}", b)).collect();
                let privacy_node = NodeBuilder::new("privacy").string_content(&hex).build();
                children.push(privacy_node);
            }

            // Add <relay> for offers that include relay endpoints. Peer uses
            // this to connect to the same relay the caller's VoIP stack
            // already allocated; without it the peer can't route media.
            if self.signaling_type == SignalingType::Offer
                && let Some(ref data) = self.relay_data
            {
                children.push(build_relay_node(data));
            }

            // Add <audio> elements
            for audio in &self.audio_params {
                let audio_node = NodeBuilder::new("audio")
                    .attr("enc", &audio.codec)
                    .attr("rate", audio.rate.to_string())
                    .build();
                children.push(audio_node);
            }

            // Add <net medium="..."/>
            if let Some(medium) = self.net_medium {
                let net_node = NodeBuilder::new("net")
                    .attr("medium", medium.to_string())
                    .build();
                children.push(net_node);
            }

            // Add <capability> for offers
            if self.signaling_type == SignalingType::Offer
                && let Some(ref cap_bytes) = self.capability
            {
                let hex: String = cap_bytes.iter().map(|b| format!("{:02X}", b)).collect();
                let cap_node = NodeBuilder::new("capability")
                    .attr("ver", "1")
                    .string_content(&hex)
                    .build();
                children.push(cap_node);
            }

            // Group-call fan-out: `<destination><to jid="..."><enc/></to>*</destination>`
            // Per `SendSignalingXmpp.js::E` this is emitted only for group calls
            // (mutually exclusive with the flat `<enc>` list, which is 1:1).
            if self.signaling_type == SignalingType::Offer
                && !self.destination_recipients.is_empty()
            {
                let mut to_nodes: Vec<Node> = Vec::with_capacity(self.destination_recipients.len());
                for recipient in &self.destination_recipients {
                    let mut recipient_children: Vec<Node> =
                        Vec::with_capacity(recipient.encrypted_keys.len());
                    for enc_key in &recipient.encrypted_keys {
                        recipient_children.push(
                            NodeBuilder::new("enc")
                                .attr("type", enc_key.enc_type.to_string())
                                .attr("v", "2")
                                .bytes(enc_key.ciphertext.clone())
                                .build(),
                        );
                    }
                    to_nodes.push(
                        NodeBuilder::new("to")
                            .attr("jid", recipient.jid.to_string())
                            .children(recipient_children)
                            .build(),
                    );
                }
                children.push(NodeBuilder::new("destination").children(to_nodes).build());
            }

            // Add `<enc>` children for offers only. Accept has no enc per
            // protocol (`SendSignalingXmpp.js::C = ["offer", "enc_rekey"]`
            // is the explicit whitelist). One element per fan-out device.
            // Skipped when the group `<destination>` path is active — they
            // carry the per-participant encs instead.
            if self.signaling_type == SignalingType::Offer && self.destination_recipients.is_empty()
            {
                for enc_key in &self.encrypted_keys {
                    let enc_node = NodeBuilder::new("enc")
                        .attr("type", enc_key.enc_type.to_string())
                        .attr("v", "2")
                        .bytes(enc_key.ciphertext.clone())
                        .build();
                    children.push(enc_node);
                }
            }

            // Add <encopt keygen="2"/>
            if let Some(keygen) = self.encopt_keygen {
                let encopt_node = NodeBuilder::new("encopt")
                    .attr("keygen", keygen.to_string())
                    .build();
                children.push(encopt_node);
            }

            // Add <device-identity> for pkmsg offers (required for PreKey messages)
            if let Some(ref identity) = self.device_identity {
                let identity_node = NodeBuilder::new("device-identity")
                    .bytes(identity.clone())
                    .build();
                children.push(identity_node);
            }
        }

        // Add <video> element
        if self.is_video {
            if let Some(ref video) = self.video_params {
                // Video with codec info
                let video_node = NodeBuilder::new("video").attr("enc", &video.codec).build();
                children.push(video_node);
            } else {
                // Plain video indicator
                children.push(NodeBuilder::new("video").build());
            }
        }

        // Add children to signaling node
        if !children.is_empty() {
            sig_builder = sig_builder.children(children);
        }

        // Add payload if present
        if let Some(payload) = self.payload {
            sig_builder = sig_builder.bytes(payload);
        }

        let signaling_node = sig_builder.build();

        // Generate stanza ID if not provided
        let stanza_id = self.stanza_id.unwrap_or_else(|| {
            // Generate a random 32-character hex ID (similar to WhatsApp format)
            use rand::RngExt;
            let mut rng = rand::rng();
            let mut bytes = [0u8; 16];
            rng.fill(&mut bytes);
            bytes.iter().map(|b| format!("{:02X}", b)).collect()
        });

        // Build outer call stanza with id attribute
        NodeBuilder::new("call")
            .attr("to", self.to.to_string())
            .attr("id", stanza_id)
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
///
/// Most ack types are flat: `<ack class="call" type="{tag}"/>`.
/// The relaylatency ack is special and includes a child element:
/// `<ack class="call" type="relaylatency"><relaylatency call-creator="..." call-id="..."/></ack>`
pub fn build_call_ack(
    stanza_id: &str,
    to: &Jid,
    signaling_type: SignalingType,
    call_id: Option<&str>,
    call_creator: Option<&Jid>,
) -> Node {
    let mut builder = NodeBuilder::new("ack")
        .attr("to", to.to_string())
        .attr("id", stanza_id)
        .attr("class", "call")
        .attr("type", signaling_type.tag_name());

    // relaylatency ack requires a child element with call-id and call-creator
    if signaling_type == SignalingType::RelayLatency
        && let (Some(cid), Some(creator)) = (call_id, call_creator)
    {
        let child = NodeBuilder::new("relaylatency")
            .attr("call-creator", creator.to_string())
            .attr("call-id", cid)
            .build();
        builder = builder.children(std::iter::once(child));
    }

    builder.build()
}

/// Parse relay data from an ACK node.
///
/// When we send an offer for an outgoing call, the server responds with an ACK
/// that contains relay allocation data. This function extracts that data from
/// the ACK node.
///
/// # ACK Structure
///
/// ```xml
/// <ack to="..." id="..." class="call" type="offer">
///   <relay uuid="..." self_pid="3" peer_pid="1">
///     <key>base64</key>
///     <hbh_key>base64</hbh_key>
///     <token id="0">binary</token>
///     <auth_token id="0">binary</auth_token>
///     <te2 relay_id="0" relay_name="for2c02" token_id="0" auth_token_id="0">binary</te2>
///   </relay>
/// </ack>
/// ```
pub fn parse_relay_data_from_ack(ack_node: &Node) -> Option<RelayData> {
    // ACK node has relay as a direct child
    ParsedCallStanza::parse_relay_data_from_node(ack_node)
}

/// Inject a `<relay>` block as the first child of the inner `<offer>` node
/// inside a `<call>` stanza. Used by the high-level `Client::place_call`
/// pipeline to splice server-provided relay info into a pre-built offer
/// without reaching into the builder mid-flight.
///
/// No-op (returns the node untouched) if the stanza isn't `<call><offer/>`.
/// The relay block is inserted at position 0 of the offer children so it
/// precedes any `<privacy>` / `<audio>` already emitted by the builder —
/// this is the same ordering WA Web produces.
pub fn inject_relay_block(mut call_stanza: Node, relay: RelayData) -> Node {
    let relay_node = build_relay_node(&relay);

    // Take ownership of `<call>` children so we can splice in place
    // without cloning the whole tree.
    let mut call_children: Vec<Node> = match call_stanza.content.take() {
        Some(NodeContent::Nodes(c)) => c,
        other => {
            // Not a node-container, put it back and bail.
            call_stanza.content = other;
            return call_stanza;
        }
    };

    let Some(offer_idx) = call_children.iter().position(|c| c.tag == "offer") else {
        // No `<offer>` child — put children back and bail.
        call_stanza.content = Some(NodeContent::Nodes(call_children));
        return call_stanza;
    };

    let offer = &mut call_children[offer_idx];
    let mut offer_children: Vec<Node> = match offer.content.take() {
        Some(NodeContent::Nodes(c)) => c,
        _ => Vec::new(),
    };
    offer_children.insert(0, relay_node);
    offer.content = Some(NodeContent::Nodes(offer_children));

    call_stanza.content = Some(NodeContent::Nodes(call_children));
    call_stanza
}

/// Serialize a [`RelayData`] back into a `<relay>` node suitable for embedding
/// into an outgoing `<offer>` stanza. Mirror of [`ParsedCallStanza::parse_relay_data`].
///
/// Wire shape (matches WA Web's `WAVoipNodeToXmlNodeConverter` output):
/// ```xml
/// <relay uuid="..." self_pid="..." peer_pid="...">
///   <key>base64(relay_key)</key>
///   <hbh_key>base64(hbh_key)</hbh_key>
///   <token id="N">raw_bytes</token>*
///   <auth_token id="N">raw_bytes</auth_token>*
///   <te2 relay_id="..." relay_name="..." token_id="..." auth_token_id="..."
///        protocol="..." c2r_rtt="...">addr_bytes</te2>*
/// </relay>
/// ```
pub fn build_relay_node(data: &RelayData) -> Node {
    use base64::Engine;

    let mut children: Vec<Node> = Vec::new();

    // <key> (base64-encoded 16-byte relay key)
    if let Some(ref relay_key) = data.relay_key {
        let b64 = base64::engine::general_purpose::STANDARD.encode(relay_key);
        children.push(NodeBuilder::new("key").string_content(b64).build());
    }

    // <hbh_key> (base64-encoded 30-byte HBH SRTP key+salt)
    if let Some(ref hbh) = data.hbh_key {
        let b64 = base64::engine::general_purpose::STANDARD.encode(hbh);
        children.push(NodeBuilder::new("hbh_key").string_content(b64).build());
    }

    // <token id="N">raw_bytes</token>* — preserves the index assigned by the
    // server so `te2.token_id` indexing stays coherent.
    for (idx, token) in data.relay_tokens.iter().enumerate() {
        children.push(
            NodeBuilder::new("token")
                .attr_dynamic("id".to_string(), idx.to_string())
                .bytes(token.clone())
                .build(),
        );
    }

    // <auth_token id="N">raw_bytes</auth_token>*
    for (idx, token) in data.auth_tokens.iter().enumerate() {
        children.push(
            NodeBuilder::new("auth_token")
                .attr_dynamic("id".to_string(), idx.to_string())
                .bytes(token.clone())
                .build(),
        );
    }

    // <te2 ...>binary_addr</te2>* — one per endpoint address combination.
    for endpoint in &data.endpoints {
        for addr in &endpoint.addresses {
            // Encode the address bytes (IPv4: 6 bytes, IPv6: 18 bytes).
            let addr_bytes = encode_te2_address(addr);
            let mut te2 = NodeBuilder::new("te2")
                .attr_dynamic("relay_id".to_string(), endpoint.relay_id.to_string())
                .attr_dynamic("relay_name".to_string(), endpoint.relay_name.clone())
                .attr_dynamic("token_id".to_string(), endpoint.token_id.to_string())
                .attr_dynamic(
                    "auth_token_id".to_string(),
                    endpoint.auth_token_id.to_string(),
                )
                .attr_dynamic("protocol".to_string(), addr.protocol.to_string());
            if let Some(rtt) = endpoint.c2r_rtt_ms {
                te2 = te2.attr_dynamic("c2r_rtt".to_string(), rtt.to_string());
            }
            te2 = te2.bytes(addr_bytes);
            children.push(te2.build());
        }
    }

    let mut builder = NodeBuilder::new("relay");
    if let Some(ref uuid) = data.uuid {
        builder = builder.attr_dynamic("uuid".to_string(), uuid.clone());
    }
    if let Some(self_pid) = data.self_pid {
        builder = builder.attr_dynamic("self_pid".to_string(), self_pid.to_string());
    }
    if let Some(peer_pid) = data.peer_pid {
        builder = builder.attr_dynamic("peer_pid".to_string(), peer_pid.to_string());
    }
    builder.children(children).build()
}

/// Encode a [`RelayAddress`] back to the `te2` binary payload.
/// IPv6 is preferred when present; IPv4 is the fallback. Unknown /
/// malformed addresses encode as all-zeros so downstream parsers don't
/// misinterpret the length.
fn encode_te2_address(addr: &RelayAddress) -> Vec<u8> {
    if let Some(ref ip6) = addr.ipv6 {
        let mut out = Vec::with_capacity(18);
        let octets: [u8; 16] = ip6
            .parse::<std::net::Ipv6Addr>()
            .map(|a| a.octets())
            .unwrap_or([0u8; 16]);
        out.extend_from_slice(&octets);
        let port = addr.port_v6.unwrap_or(addr.port);
        out.extend_from_slice(&port.to_be_bytes());
        out
    } else {
        let mut out = Vec::with_capacity(6);
        let octets: [u8; 4] = addr
            .ipv4
            .as_deref()
            .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
            .map(|a| a.octets())
            .unwrap_or([0, 0, 0, 0]);
        out.extend_from_slice(&octets);
        out.extend_from_slice(&addr.port.to_be_bytes());
        out
    }
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
        assert_eq!(attrs.required_string("call-id").unwrap(), call_id);
        assert_eq!(
            attrs.required_string("call-creator").unwrap(),
            creator.to_string()
        );

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
        assert_eq!(attrs.required_string("id").unwrap(), "stanza123");
        assert_eq!(attrs.required_string("to").unwrap(), to.to_string());
        assert_eq!(attrs.required_string("from").unwrap(), from.to_string());

        // Should have inner offer node with call-id and call-creator
        let children = receipt.children().unwrap();
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "offer");

        let mut inner_attrs = children[0].attrs();
        assert_eq!(
            inner_attrs.required_string("call-id").unwrap(),
            "AC90CFD09DF712D981142B172706F9F2"
        );
    }

    /// Test building a call ack with correct structure.
    /// Structure: `<ack class="call" type="{tag}">`
    #[test]
    fn test_build_call_ack() {
        let to: Jid = "123@lid".parse().unwrap();

        let ack = build_call_ack("stanza456", &to, SignalingType::Transport, None, None);

        assert_eq!(ack.tag, "ack");

        let mut attrs = ack.attrs();
        assert_eq!(attrs.required_string("id").unwrap(), "stanza456");
        assert_eq!(attrs.required_string("to").unwrap(), to.to_string());
        assert_eq!(attrs.required_string("class").unwrap(), "call");
        assert_eq!(attrs.required_string("type").unwrap(), "transport");

        // Non-relaylatency ack should NOT have children
        assert!(ack.children().is_none());
    }

    /// Test relaylatency ack includes child element with call-id and call-creator.
    /// Structure: `<ack class="call" type="relaylatency"><relaylatency call-creator="..." call-id="..."/></ack>`
    #[test]
    fn test_build_relaylatency_ack() {
        let to: Jid = "123@lid".parse().unwrap();
        let call_creator: Jid = "456@lid".parse().unwrap();
        let call_id = "AC90CFD09DF712D981142B172706F9F2";

        let ack = build_call_ack(
            "stanza789",
            &to,
            SignalingType::RelayLatency,
            Some(call_id),
            Some(&call_creator),
        );

        assert_eq!(ack.tag, "ack");

        let mut attrs = ack.attrs();
        assert_eq!(attrs.required_string("type").unwrap(), "relaylatency");
        assert_eq!(attrs.required_string("class").unwrap(), "call");

        // Should have child <relaylatency> element
        let children = ack
            .children()
            .expect("relaylatency ack should have children");
        assert_eq!(children.len(), 1);
        assert_eq!(children[0].tag, "relaylatency");

        let mut child_attrs = children[0].attrs();
        assert_eq!(child_attrs.required_string("call-id").unwrap(), call_id);
        assert_eq!(
            child_attrs.required_string("call-creator").unwrap(),
            call_creator.to_string()
        );
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
            .children([hbh_key_node, key_node])
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
            .children([hbh_key_node, key_node])
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "3C28C0EE16982D87B95CF55638E8F3AD")
            .attr("call-creator", "39492358562039@lid")
            .children([enc_node, relay_node])
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
            .children([hbh_key_node, key_node])
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

    /// Test parsing te2 IPv4 address (6 bytes: 4 IP + 2 port)
    #[test]
    fn test_parse_te2_ipv4_address() {
        // 192.168.1.100:3480 = [192, 168, 1, 100, 0x0D, 0x98]
        let bytes = [192, 168, 1, 100, 0x0D, 0x98];
        let addr = ParsedCallStanza::parse_te2_address(&bytes, 0).unwrap();

        assert_eq!(addr.ipv4, Some("192.168.1.100".to_string()));
        assert_eq!(addr.ipv6, None);
        assert_eq!(addr.port, 3480);
        assert_eq!(addr.protocol, 0);
    }

    /// Test parsing te2 IPv6 address (18 bytes: 16 IP + 2 port)
    #[test]
    fn test_parse_te2_ipv6_address() {
        // ::1 with port 3480
        let mut bytes = [0u8; 18];
        bytes[15] = 1; // ::1
        bytes[16] = 0x0D;
        bytes[17] = 0x98; // 3480 in big-endian
        let addr = ParsedCallStanza::parse_te2_address(&bytes, 1).unwrap();

        assert_eq!(addr.ipv4, None);
        assert_eq!(addr.ipv6, Some("::1".to_string()));
        assert_eq!(addr.port, 3480);
        assert_eq!(addr.port_v6, Some(3480));
        assert_eq!(addr.protocol, 1);
    }

    /// Test te2 address with invalid length returns None
    #[test]
    fn test_parse_te2_invalid_length() {
        assert!(ParsedCallStanza::parse_te2_address(&[1, 2, 3, 4, 5], 0).is_none()); // 5 bytes
        assert!(ParsedCallStanza::parse_te2_address(&[1, 2, 3, 4, 5, 6, 7], 0).is_none()); // 7 bytes
        assert!(ParsedCallStanza::parse_te2_address(&[], 0).is_none()); // 0 bytes
    }

    /// Test parsing relay latency with bitmask extraction
    #[test]
    fn test_parse_relay_latency_bitmask() {
        // Raw value 33554444 = 0x0200000C, lower 24 bits = 12ms
        let te_node = NodeBuilder::new("te")
            .attr("relay_name", "relay1")
            .attr("latency", "33554444")
            .bytes(vec![192, 168, 1, 1, 0x0D, 0x98]) // 192.168.1.1:3480
            .build();

        let relaylatency_node = NodeBuilder::new("relaylatency")
            .attr("call-id", "TEST1234")
            .attr("call-creator", "123@lid")
            .children(std::iter::once(te_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza123")
            .attr("from", "456@lid")
            .children(std::iter::once(relaylatency_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        assert_eq!(parsed.relay_latency.len(), 1);
        let lat = &parsed.relay_latency[0];
        assert_eq!(lat.relay_name, "relay1");
        assert_eq!(lat.raw_latency, 33554444);
        assert_eq!(lat.latency_ms, 12); // Lower 24 bits
        assert_eq!(lat.ipv4, Some("192.168.1.1".to_string()));
        assert_eq!(lat.port, Some(3480));
    }

    /// Test parsing media params from offer
    #[test]
    fn test_parse_media_params() {
        let audio_node = NodeBuilder::new("audio")
            .attr("enc", "opus")
            .attr("rate", "16000")
            .build();

        let video_node = NodeBuilder::new("video").attr("enc", "vp8").build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "TEST1234TEST1234TEST1234TEST1234")
            .attr("call-creator", "123@lid")
            .children([audio_node, video_node])
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza123")
            .attr("from", "456@lid")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        assert!(parsed.media_params.is_some());
        let params = parsed.media_params.unwrap();

        assert_eq!(params.audio.len(), 1);
        assert_eq!(params.audio[0].codec, "opus");
        assert_eq!(params.audio[0].rate, 16000);

        assert!(params.video.is_some());
        assert_eq!(params.video.unwrap().codec, Some("vp8".to_string()));
    }

    /// Test parsing offer with te2 endpoints
    #[test]
    fn test_parse_offer_with_te2_endpoints() {
        let te2_node = NodeBuilder::new("te2")
            .attr("relay_id", "1")
            .attr("relay_name", "relay.whatsapp.net")
            .attr("token_id", "0")
            .attr("auth_token_id", "0")
            .bytes(vec![10, 0, 0, 1, 0x0D, 0x98]) // 10.0.0.1:3480
            .build();

        let token_node = NodeBuilder::new("token")
            .attr("id", "0")
            .bytes(vec![0xAA, 0xBB, 0xCC])
            .build();

        let auth_token_node = NodeBuilder::new("auth_token")
            .attr("id", "0")
            .bytes(vec![0xDD, 0xEE, 0xFF])
            .build();

        let relay_node = NodeBuilder::new("relay")
            .attr("uuid", "test-uuid")
            .attr("self_pid", "3")
            .attr("peer_pid", "1")
            .children([te2_node, token_node, auth_token_node])
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "TEST1234TEST1234TEST1234TEST1234")
            .attr("call-creator", "123@lid")
            .children(std::iter::once(relay_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza123")
            .attr("from", "456@lid")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();

        assert!(parsed.relay_data.is_some());
        let relay = parsed.relay_data.unwrap();

        // Check tokens
        assert_eq!(relay.relay_tokens.len(), 1);
        assert_eq!(relay.relay_tokens[0], vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(relay.auth_tokens.len(), 1);
        assert_eq!(relay.auth_tokens[0], vec![0xDD, 0xEE, 0xFF]);

        // Check endpoints
        assert_eq!(relay.endpoints.len(), 1);
        let ep = &relay.endpoints[0];
        assert_eq!(ep.relay_id, 1);
        assert_eq!(ep.relay_name, "relay.whatsapp.net");
        assert_eq!(ep.token_id, 0);
        assert_eq!(ep.auth_token_id, 0);
        assert_eq!(ep.addresses.len(), 1);
        assert_eq!(ep.addresses[0].ipv4, Some("10.0.0.1".to_string()));
        assert_eq!(ep.addresses[0].port, 3480);
        // No c2r_rtt was specified in this test
        assert_eq!(ep.c2r_rtt_ms, None);
    }

    /// Test parsing c2r_rtt (server-estimated RTT) from te2 elements
    #[test]
    fn test_parse_te2_c2r_rtt() {
        // Create te2 nodes with c2r_rtt attributes like the real WhatsApp ACK
        let te2_node1 = NodeBuilder::new("te2")
            .attr("relay_id", "0")
            .attr("relay_name", "fbss1c01")
            .attr("token_id", "0")
            .attr("auth_token_id", "0")
            .attr("c2r_rtt", "5")
            .bytes(vec![10, 0, 0, 1, 0x0D, 0x98]) // 10.0.0.1:3480
            .build();

        let te2_node2 = NodeBuilder::new("te2")
            .attr("relay_id", "1")
            .attr("relay_name", "for2c01")
            .attr("token_id", "1")
            .attr("auth_token_id", "1")
            .attr("protocol", "1")
            .attr("c2r_rtt", "27")
            .bytes(vec![10, 0, 0, 2, 0x0D, 0x98]) // 10.0.0.2:3480
            .build();

        let te2_node3 = NodeBuilder::new("te2")
            .attr("relay_id", "2")
            .attr("relay_name", "bsb1c01")
            .attr("token_id", "2")
            .attr("auth_token_id", "1")
            .attr("protocol", "1")
            .attr("c2r_rtt", "21")
            .bytes(vec![10, 0, 0, 3, 0x0D, 0x98]) // 10.0.0.3:3480
            .build();

        let token_node = NodeBuilder::new("token")
            .attr("id", "0")
            .bytes(vec![0xAA, 0xBB, 0xCC])
            .build();

        let relay_node = NodeBuilder::new("relay")
            .attr("uuid", "test-uuid")
            .children([te2_node1, te2_node2, te2_node3, token_node])
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "TEST1234TEST1234TEST1234TEST1234")
            .attr("call-creator", "123@lid")
            .children(std::iter::once(relay_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza123")
            .attr("from", "456@lid")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();
        let relay = parsed.relay_data.unwrap();

        // Find endpoints by name and verify c2r_rtt values
        let fbss = relay
            .endpoints
            .iter()
            .find(|e| e.relay_name == "fbss1c01")
            .unwrap();
        assert_eq!(fbss.c2r_rtt_ms, Some(5));

        let for2 = relay
            .endpoints
            .iter()
            .find(|e| e.relay_name == "for2c01")
            .unwrap();
        assert_eq!(for2.c2r_rtt_ms, Some(27));

        let bsb = relay
            .endpoints
            .iter()
            .find(|e| e.relay_name == "bsb1c01")
            .unwrap();
        assert_eq!(bsb.c2r_rtt_ms, Some(21));
    }

    /// Test handling of sparse token IDs (non-sequential)
    #[test]
    fn test_parse_sparse_token_ids() {
        // Token with id="2" and auth_token with id="0" - should create sparse arrays
        let token_node = NodeBuilder::new("token")
            .attr("id", "2")
            .bytes(vec![0xAA, 0xBB])
            .build();

        let auth_token_node = NodeBuilder::new("auth_token")
            .attr("id", "0")
            .bytes(vec![0xCC, 0xDD])
            .build();

        let relay_node = NodeBuilder::new("relay")
            .attr("uuid", "test-uuid")
            .children([token_node, auth_token_node])
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "TEST1234TEST1234TEST1234TEST1234")
            .attr("call-creator", "123@lid")
            .children(std::iter::once(relay_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza123")
            .attr("from", "456@lid")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();
        let relay = parsed.relay_data.unwrap();

        // relay_tokens should have 3 entries: [empty, empty, actual]
        assert_eq!(relay.relay_tokens.len(), 3);
        assert!(relay.relay_tokens[0].is_empty());
        assert!(relay.relay_tokens[1].is_empty());
        assert_eq!(relay.relay_tokens[2], vec![0xAA, 0xBB]);

        // auth_tokens should have 1 entry
        assert_eq!(relay.auth_tokens.len(), 1);
        assert_eq!(relay.auth_tokens[0], vec![0xCC, 0xDD]);
    }

    /// Test multiple te2 endpoints for same relay are grouped
    #[test]
    fn test_multiple_te2_addresses_grouped() {
        let te2_ipv4 = NodeBuilder::new("te2")
            .attr("relay_id", "1")
            .attr("relay_name", "relay1")
            .attr("token_id", "0")
            .attr("auth_token_id", "0")
            .bytes(vec![10, 0, 0, 1, 0x0D, 0x98]) // IPv4
            .build();

        // Different te2 with IPv6 for same relay
        let mut ipv6_bytes = vec![0u8; 18];
        ipv6_bytes[15] = 1; // ::1
        ipv6_bytes[16] = 0x0D;
        ipv6_bytes[17] = 0x98;
        let te2_ipv6 = NodeBuilder::new("te2")
            .attr("relay_id", "1")
            .attr("relay_name", "relay1")
            .attr("token_id", "0")
            .attr("auth_token_id", "0")
            .bytes(ipv6_bytes)
            .build();

        let relay_node = NodeBuilder::new("relay")
            .attr("uuid", "test-uuid")
            .children([te2_ipv4, te2_ipv6])
            .build();

        let offer_node = NodeBuilder::new("offer")
            .attr("call-id", "TEST1234TEST1234TEST1234TEST1234")
            .attr("call-creator", "123@lid")
            .children(std::iter::once(relay_node))
            .build();

        let call_node = NodeBuilder::new("call")
            .attr("id", "stanza123")
            .attr("from", "456@lid")
            .children(std::iter::once(offer_node))
            .build();

        let parsed = ParsedCallStanza::parse(&call_node).unwrap();
        let relay = parsed.relay_data.unwrap();

        // Should have 1 endpoint with 2 addresses
        assert_eq!(relay.endpoints.len(), 1);
        let ep = &relay.endpoints[0];
        assert_eq!(ep.addresses.len(), 2);

        // Check both addresses are present
        let has_ipv4 = ep.addresses.iter().any(|a| a.ipv4.is_some());
        let has_ipv6 = ep.addresses.iter().any(|a| a.ipv6.is_some());
        assert!(has_ipv4, "Should have IPv4 address");
        assert!(has_ipv6, "Should have IPv6 address");
    }

    /// Test building accept stanza has audio/video but NO enc element.
    /// Per WhatsApp Web protocol, only Offer stanzas include `<enc>`.
    #[test]
    fn test_build_accept_stanza_with_all_params() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Accept)
                .video(true)
                .audio(AcceptAudioParams {
                    codec: "opus".to_string(),
                    rate: 16000,
                })
                .video_params(AcceptVideoParams {
                    codec: "vp8".to_string(),
                })
                .build();

        assert_eq!(node.tag, "call");

        let children = node.children().unwrap();
        assert_eq!(children.len(), 1);

        let accept_node = &children[0];
        assert_eq!(accept_node.tag, "accept");

        let accept_children = accept_node.children().unwrap();

        // Accept should NOT have <enc> - only Offer includes encrypted key
        assert!(
            !accept_children.iter().any(|c| c.tag == "enc"),
            "Accept stanza must NOT have <enc> element"
        );

        let audio_node = accept_children.iter().find(|c| c.tag == "audio");
        assert!(audio_node.is_some(), "Should have <audio> element");
        let audio_node = audio_node.unwrap();
        let mut audio_attrs = audio_node.attrs();
        assert_eq!(audio_attrs.required_string("enc").unwrap(), "opus");
        assert_eq!(audio_attrs.required_string("rate").unwrap(), "16000");

        let video_node = accept_children.iter().find(|c| c.tag == "video");
        assert!(video_node.is_some(), "Should have <video> element");
        let video_node = video_node.unwrap();
        let mut video_attrs = video_node.attrs();
        assert_eq!(video_attrs.required_string("enc").unwrap(), "vp8");
    }

    /// Test building accept stanza without optional params falls back to defaults.
    #[test]
    fn test_build_accept_stanza_minimal() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        // Build with only audio params (no enc key, no video params)
        let node = CallStanzaBuilder::new(call_id, creator, to, SignalingType::Accept)
            .audio(AcceptAudioParams::default())
            .build();

        let children = node.children().unwrap();
        let accept_node = &children[0];
        let accept_children = accept_node.children().unwrap();

        // Should have audio but not enc or video
        assert!(accept_children.iter().any(|c| c.tag == "audio"));
        assert!(!accept_children.iter().any(|c| c.tag == "enc"));
        assert!(!accept_children.iter().any(|c| c.tag == "video"));
    }

    /// Test default audio/video params.
    #[test]
    fn test_default_accept_params() {
        let audio = AcceptAudioParams::default();
        assert_eq!(audio.codec, "opus");
        assert_eq!(audio.rate, 16000);

        let video = AcceptVideoParams::default();
        assert_eq!(video.codec, "vp8");
    }

    /// Test PREACCEPT stanza building.
    #[test]
    fn test_build_preaccept_stanza() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let node = CallStanzaBuilder::new(
            call_id,
            creator.clone(),
            to.clone(),
            SignalingType::PreAccept,
        )
        .preaccept_params(PreacceptParams::default())
        .build();

        assert_eq!(node.tag, "call");
        let children = node.children().unwrap();
        assert_eq!(children.len(), 1);

        let preaccept_node = &children[0];
        assert_eq!(preaccept_node.tag, "preaccept");

        let mut attrs = preaccept_node.attrs();
        assert_eq!(attrs.required_string("call-id").unwrap(), call_id);
        assert_eq!(
            attrs.required_string("call-creator").unwrap(),
            creator.to_string()
        );

        let preaccept_children = preaccept_node.children().unwrap();

        // Should have audio, encopt, capability
        let audio = preaccept_children.iter().find(|c| c.tag == "audio");
        assert!(audio.is_some(), "Should have <audio> element");
        let mut audio_attrs = audio.unwrap().attrs();
        assert_eq!(audio_attrs.required_string("enc").unwrap(), "opus");
        assert_eq!(audio_attrs.required_string("rate").unwrap(), "16000");

        let encopt = preaccept_children.iter().find(|c| c.tag == "encopt");
        assert!(encopt.is_some(), "Should have <encopt> element");
        let mut encopt_attrs = encopt.unwrap().attrs();
        assert_eq!(encopt_attrs.required_string("keygen").unwrap(), "2");

        let capability = preaccept_children.iter().find(|c| c.tag == "capability");
        assert!(capability.is_some(), "Should have <capability> element");
        let mut cap_attrs = capability.unwrap().attrs();
        assert_eq!(cap_attrs.required_string("ver").unwrap(), "1");
    }

    /// Test RELAYLATENCY stanza building.
    #[test]
    fn test_build_relaylatency_stanza() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let measurements = vec![RelayLatencyMeasurement {
            relay_name: "for2c02".to_string(),
            latency_ms: 45,
            token: vec![],
            ipv4: Some("57.144.165.54".to_string()),
            port: 3480,
            ..Default::default()
        }];

        let node = CallStanzaBuilder::new(
            call_id,
            creator.clone(),
            to.clone(),
            SignalingType::RelayLatency,
        )
        .relay_latency(measurements)
        .build();

        assert_eq!(node.tag, "call");
        let children = node.children().unwrap();
        let relaylatency_node = &children[0];
        assert_eq!(relaylatency_node.tag, "relaylatency");

        let te_nodes: Vec<_> = relaylatency_node
            .children()
            .unwrap()
            .iter()
            .filter(|c| c.tag == "te")
            .collect();
        assert_eq!(te_nodes.len(), 1);

        let mut te_attrs = te_nodes[0].attrs();
        assert_eq!(te_attrs.required_string("relay_name").unwrap(), "for2c02");
        // Latency should be 0x2000000 + 45 = 33554477
        assert_eq!(te_attrs.required_string("latency").unwrap(), "33554477");
    }

    /// Test relay latency encoding.
    #[test]
    fn test_relay_latency_encoding() {
        let measurement = RelayLatencyMeasurement {
            relay_name: "test".to_string(),
            latency_ms: 12,
            token: vec![],
            ipv4: Some("192.168.1.1".to_string()),
            port: 3480,
            ..Default::default()
        };

        // Base is 0x2000000 = 33554432
        assert_eq!(measurement.encode_latency(), 33554444);

        // Address should be 6 bytes: IP (4) + port (2 big-endian)
        let addr = measurement.encode_address();
        assert_eq!(addr.len(), 6);
        assert_eq!(addr[0..4], [192, 168, 1, 1]);
        assert_eq!(addr[4..6], [0x0D, 0x98]); // 3480 in big-endian
    }

    /// IPv6 measurements must encode 16 bytes address + 2 bytes port = 18 bytes.
    /// WA Web (`RelayConnectionUtils.js`) treats IPv4 and IPv6 endpoints as
    /// separate entries — we must do the same.
    #[test]
    fn test_relay_latency_encoding_ipv6() {
        let measurement = RelayLatencyMeasurement {
            relay_name: "test".to_string(),
            latency_ms: 12,
            token: vec![],
            ipv4: None,
            port: 3480,
            ..Default::default()
        }
        .with_ipv6("2001:db8::1".to_string(), 3480);

        let addr = measurement.encode_address();
        assert_eq!(addr.len(), 18, "IPv6 + port should encode to 18 bytes");
        // Last 2 bytes: port 3480 big-endian.
        assert_eq!(&addr[16..18], &[0x0D, 0x98]);
    }

    /// `from_relay_data` must emit one measurement per IP family available on
    /// each endpoint (matches `RelayConnectionUtils.js:90-126`).
    #[test]
    fn test_from_relay_data_emits_both_ip_families() {
        let relay_data = RelayData {
            relay_tokens: vec![vec![0xAA; 16]],
            endpoints: vec![RelayEndpoint {
                relay_id: 1,
                relay_name: "for2c02".to_string(),
                token_id: 0,
                auth_token_id: 0,
                addresses: vec![RelayAddress {
                    ipv4: Some("192.168.0.1".to_string()),
                    ipv6: Some("2001:db8::1".to_string()),
                    port: 3480,
                    port_v6: Some(3481),
                    protocol: 0,
                }],
                c2r_rtt_ms: Some(30),
            }],
            ..Default::default()
        };

        let measurements = RelayLatencyMeasurement::from_relay_data(&relay_data, 30);
        assert_eq!(
            measurements.len(),
            2,
            "expected one IPv4 + one IPv6 measurement per endpoint"
        );
        assert!(measurements.iter().any(|m| m.ipv4.is_some()));
        assert!(measurements.iter().any(|m| m.ipv6_address().is_some()));
    }

    /// Test TRANSPORT stanza building.
    #[test]
    fn test_build_transport_stanza() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let params = TransportParams {
            p2p_cand_round: Some(1),
            transport_message_type: Some(0),
            net_protocol: 0,
            net_medium: 2,
        };

        let node = CallStanzaBuilder::new(
            call_id,
            creator.clone(),
            to.clone(),
            SignalingType::Transport,
        )
        .transport_params(params)
        .build();

        assert_eq!(node.tag, "call");
        let children = node.children().unwrap();
        let transport_node = &children[0];
        assert_eq!(transport_node.tag, "transport");

        let mut attrs = transport_node.attrs();
        assert_eq!(
            attrs.optional_string("p2p-cand-round"),
            Some(std::borrow::Cow::Borrowed("1"))
        );
        assert_eq!(
            attrs.optional_string("transport-message-type"),
            Some(std::borrow::Cow::Borrowed("0"))
        );

        // Should have net element
        let transport_children = transport_node.children().unwrap();
        let net_node = transport_children.iter().find(|c| c.tag == "net");
        assert!(net_node.is_some(), "Should have <net> element");
        let mut net_attrs = net_node.unwrap().attrs();
        assert_eq!(net_attrs.required_string("protocol").unwrap(), "0");
        assert_eq!(net_attrs.required_string("medium").unwrap(), "2");
    }

    /// Test MUTE_V2 stanza building.
    #[test]
    fn test_build_mute_v2_stanza() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        // Test unmuted
        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::MuteV2)
                .mute_state(false)
                .build();

        let children = node.children().unwrap();
        let mute_node = &children[0];
        assert_eq!(mute_node.tag, "mute_v2");

        let mut attrs = mute_node.attrs();
        assert_eq!(attrs.required_string("mute-state").unwrap(), "0");

        // Test muted
        let node_muted =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::MuteV2)
                .mute_state(true)
                .build();

        let children_muted = node_muted.children().unwrap();
        let mute_node_muted = &children_muted[0];
        let mut attrs_muted = mute_node_muted.attrs();
        assert_eq!(attrs_muted.required_string("mute-state").unwrap(), "1");
    }

    /// Test ACCEPT stanza with net and encopt elements.
    #[test]
    fn test_build_accept_with_net_encopt() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Accept)
                .audio(AcceptAudioParams::default())
                .net_medium(2)
                .encopt_keygen(2)
                .build();

        let children = node.children().unwrap();
        let accept_node = &children[0];
        assert_eq!(accept_node.tag, "accept");

        let accept_children = accept_node.children().unwrap();

        // Should have audio, net, encopt
        assert!(
            accept_children.iter().any(|c| c.tag == "audio"),
            "Should have <audio>"
        );

        let net = accept_children.iter().find(|c| c.tag == "net");
        assert!(net.is_some(), "Should have <net> element");
        let mut net_attrs = net.unwrap().attrs();
        assert_eq!(net_attrs.required_string("medium").unwrap(), "2");

        let encopt = accept_children.iter().find(|c| c.tag == "encopt");
        assert!(encopt.is_some(), "Should have <encopt> element");
        let mut encopt_attrs = encopt.unwrap().attrs();
        assert_eq!(encopt_attrs.required_string("keygen").unwrap(), "2");
    }

    /// Test default PreacceptParams.
    #[test]
    fn test_default_preaccept_params() {
        let params = PreacceptParams::default();
        assert_eq!(params.audio_codec, "opus");
        assert_eq!(params.audio_rate, 16000);
        assert_eq!(params.keygen, 2);
        assert_eq!(
            params.capability,
            vec![0x01, 0x05, 0xF7, 0x09, 0xE4, 0xBB, 0x07]
        );
    }

    /// Test TransportParams default/new.
    #[test]
    fn test_transport_params() {
        let params = TransportParams::new();
        assert_eq!(params.net_protocol, 0);
        assert_eq!(params.net_medium, 2);
        assert!(params.p2p_cand_round.is_none());
        assert!(params.transport_message_type.is_none());
    }

    /// Test building an offer with dual audio, capability, and privacy elements.
    /// Matches real WhatsApp Web offer structure.
    #[test]
    fn test_build_offer_with_full_elements() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Offer)
                .privacy(vec![0x04, 0x01, 0x1D, 0xB8])
                .audio(AcceptAudioParams {
                    codec: "opus".to_string(),
                    rate: 8000,
                })
                .audio(AcceptAudioParams {
                    codec: "opus".to_string(),
                    rate: 16000,
                })
                .net_medium(3)
                .capability(vec![0x01, 0x05, 0xF7, 0x09, 0xE4, 0xBB, 0x07])
                .encopt_keygen(2)
                .build();

        let children = node.children().unwrap();
        let offer_node = &children[0];
        assert_eq!(offer_node.tag, "offer");

        let offer_children = offer_node.children().unwrap();

        // Check <privacy> element
        let privacy = offer_children.iter().find(|c| c.tag == "privacy");
        assert!(privacy.is_some(), "Should have <privacy> element");

        // Check dual <audio> elements
        let audio_nodes: Vec<_> = offer_children.iter().filter(|c| c.tag == "audio").collect();
        assert_eq!(audio_nodes.len(), 2, "Offer should have 2 audio elements");
        let mut audio0_attrs = audio_nodes[0].attrs();
        assert_eq!(audio0_attrs.required_string("rate").unwrap(), "8000");
        let mut audio1_attrs = audio_nodes[1].attrs();
        assert_eq!(audio1_attrs.required_string("rate").unwrap(), "16000");

        // Check <net medium="3"/>
        let net = offer_children.iter().find(|c| c.tag == "net");
        assert!(net.is_some(), "Should have <net> element");
        let mut net_attrs = net.unwrap().attrs();
        assert_eq!(net_attrs.required_string("medium").unwrap(), "3");

        // Check <capability>
        let capability = offer_children.iter().find(|c| c.tag == "capability");
        assert!(capability.is_some(), "Should have <capability> element");

        // Check <encopt>
        let encopt = offer_children.iter().find(|c| c.tag == "encopt");
        assert!(encopt.is_some(), "Should have <encopt> element");

        // Verify element order: privacy < audio < net < capability < encopt
        let tags: Vec<&str> = offer_children.iter().map(|c| &*c.tag).collect();
        let privacy_idx = tags.iter().position(|&t| t == "privacy").unwrap();
        let first_audio_idx = tags.iter().position(|&t| t == "audio").unwrap();
        let net_idx = tags.iter().position(|&t| t == "net").unwrap();
        let cap_idx = tags.iter().position(|&t| t == "capability").unwrap();
        let encopt_idx = tags.iter().position(|&t| t == "encopt").unwrap();

        assert!(
            privacy_idx < first_audio_idx,
            "privacy should be before audio"
        );
        assert!(first_audio_idx < net_idx, "audio should be before net");
        assert!(net_idx < cap_idx, "net should be before capability");
        assert!(cap_idx < encopt_idx, "capability should be before encopt");
    }

    /// `WHATSAPP_VOIP_CAPABILITY_V1` must (a) decode as version 1 with a
    /// 5-byte bit-mask, and (b) match the default used by `PreacceptParams`.
    /// If WA Web bumps the version, update the constant and this test.
    #[test]
    fn test_voip_capability_v1_layout() {
        let cap = default_voip_capability();
        assert_eq!(cap[0], 0x01, "version byte must be 1");
        assert_eq!(cap[1], 0x05, "bit_mask_length must be 5");
        assert_eq!(cap.len(), 2 + 5, "total length = version + len + mask");
        assert_eq!(
            PreacceptParams::default().capability,
            cap.to_vec(),
            "PreacceptParams default must match the pinned constant"
        );
    }

    /// Group call offer emits `<destination>` with one `<to jid>` per
    /// participant, each wrapping its own `<enc>`. Flat `<enc>` list is
    /// suppressed in this mode (mutually exclusive wire shape).
    #[test]
    fn test_group_offer_emits_destination_with_per_recipient_enc() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "1@lid".parse().unwrap();
        let to: Jid = "group@g.us".parse().unwrap();

        let alice: Jid = "100@lid".parse().unwrap();
        let bob_main: Jid = "200:0@lid".parse().unwrap();
        let bob_companion: Jid = "200:1@lid".parse().unwrap();

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Offer)
                .group(to.clone())
                .destination_recipients(vec![
                    GroupDestinationRecipient {
                        jid: alice.clone(),
                        encrypted_keys: vec![EncryptedCallKey {
                            enc_type: EncType::Msg,
                            ciphertext: vec![0xAA],
                        }],
                    },
                    GroupDestinationRecipient {
                        jid: bob_main.clone(),
                        encrypted_keys: vec![
                            EncryptedCallKey {
                                enc_type: EncType::PkMsg,
                                ciphertext: vec![0xBB],
                            },
                            EncryptedCallKey {
                                enc_type: EncType::Msg,
                                ciphertext: vec![0xCC],
                            },
                        ],
                    },
                    GroupDestinationRecipient {
                        jid: bob_companion.clone(),
                        encrypted_keys: vec![EncryptedCallKey {
                            enc_type: EncType::Msg,
                            ciphertext: vec![0xDD],
                        }],
                    },
                ])
                .build();

        let offer_node = &node.children().unwrap()[0];
        assert_eq!(offer_node.tag, "offer");
        let offer_children = offer_node.children().unwrap();

        // Exactly one <destination> child.
        let destination = offer_children
            .iter()
            .find(|c| c.tag == "destination")
            .expect("group offer must have <destination>");

        let tos: Vec<&Node> = destination
            .children()
            .unwrap()
            .iter()
            .filter(|c| c.tag == "to")
            .collect();
        assert_eq!(tos.len(), 3, "one <to> per participant/device");

        // Per-recipient enc count histogram. Expected: one <to> with 2
        // encs (bob_main primary+companion share same <to> in the test)
        // and two <to>s with 1 enc each.
        let mut enc_counts: Vec<usize> = tos
            .iter()
            .map(|t| {
                t.children()
                    .unwrap()
                    .iter()
                    .filter(|c| c.tag == "enc")
                    .count()
            })
            .collect();
        enc_counts.sort_unstable();
        assert_eq!(
            enc_counts,
            vec![1, 1, 2],
            "expected two 1-enc recipients and one 2-enc recipient"
        );

        // Flat <enc> children must NOT be present when <destination> is.
        let flat_enc_count = offer_children.iter().filter(|c| c.tag == "enc").count();
        assert_eq!(
            flat_enc_count, 0,
            "flat <enc> must be suppressed when <destination> is used"
        );
    }

    /// Outgoing offer must embed the `<relay>` block so the peer can
    /// reach the same relay. Wire round-trip: encode → parse → fields
    /// match the original. Without this block WA Web's parser rejects
    /// the offer ("no relay data"), or the peer falls back to P2P and
    /// fails behind NAT.
    #[test]
    fn test_offer_embeds_and_roundtrips_relay_block() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let relay = RelayData {
            uuid: Some("relay-uuid-42".to_string()),
            self_pid: Some(3),
            peer_pid: Some(1),
            hbh_key: Some(vec![0x11; 30]),
            relay_key: Some(vec![0x22; 16]),
            relay_tokens: vec![vec![0xAA; 8], vec![0xBB; 8]],
            auth_tokens: vec![vec![0xCC; 12]],
            endpoints: vec![RelayEndpoint {
                relay_id: 7,
                relay_name: "fra1-a".to_string(),
                token_id: 0,
                auth_token_id: 0,
                addresses: vec![RelayAddress {
                    ipv4: Some("203.0.113.7".to_string()),
                    ipv6: None,
                    port: 3478,
                    port_v6: None,
                    protocol: 0,
                }],
                c2r_rtt_ms: Some(42),
            }],
        };

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Offer)
                .relay_data(relay.clone())
                .build();

        let parsed = ParsedCallStanza::parse(&node).expect("offer with relay must parse");
        let got = parsed
            .relay_data
            .expect("relay_data must survive the round-trip");

        assert_eq!(got.uuid, relay.uuid);
        assert_eq!(got.self_pid, relay.self_pid);
        assert_eq!(got.peer_pid, relay.peer_pid);
        assert_eq!(got.hbh_key, relay.hbh_key);
        assert_eq!(got.relay_key, relay.relay_key);
        assert_eq!(got.relay_tokens, relay.relay_tokens);
        assert_eq!(got.auth_tokens, relay.auth_tokens);
        assert_eq!(got.endpoints.len(), 1);
        let ep = &got.endpoints[0];
        assert_eq!(ep.relay_id, 7);
        assert_eq!(ep.relay_name, "fra1-a");
        assert_eq!(ep.c2r_rtt_ms, Some(42));
        assert_eq!(ep.addresses.len(), 1);
        assert_eq!(ep.addresses[0].ipv4.as_deref(), Some("203.0.113.7"));
        assert_eq!(ep.addresses[0].port, 3478);
    }

    /// Fan-out: two encrypted keys must emit two `<enc>` children on the
    /// offer. Matches WA Web's `SendSignalingXmpp.js::S` for 1:1 with
    /// companion, and the destination loop for group calls.
    #[test]
    fn test_offer_emits_one_enc_per_fanout_key() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let key_primary = EncryptedCallKey {
            enc_type: EncType::PkMsg,
            ciphertext: vec![0xAA, 0xBB],
        };
        let key_companion = EncryptedCallKey {
            enc_type: EncType::Msg,
            ciphertext: vec![0xCC, 0xDD, 0xEE],
        };

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Offer)
                .encrypted_keys(vec![key_primary.clone(), key_companion.clone()])
                .build();

        let offer_node = &node.children().unwrap()[0];
        let offer_children = offer_node.children().unwrap();
        let encs: Vec<_> = offer_children.iter().filter(|c| c.tag == "enc").collect();
        assert_eq!(encs.len(), 2, "one <enc> per fan-out device expected");

        // First matches primary (pkmsg), second matches companion (msg).
        let mut a0 = encs[0].attrs();
        assert_eq!(a0.required_string("type").unwrap(), "pkmsg");
        assert_eq!(a0.required_string("v").unwrap(), "2");
        let mut a1 = encs[1].attrs();
        assert_eq!(a1.required_string("type").unwrap(), "msg");
    }

    /// `encrypted_key()` must be chainable multiple times — each call
    /// appends a new `<enc>`, matching the fan-out API callers may want
    /// when they don't have the keys in a single `Vec`.
    #[test]
    fn test_encrypted_key_chains_instead_of_replaces() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Offer)
                .encrypted_key(EncryptedCallKey {
                    enc_type: EncType::Msg,
                    ciphertext: vec![0x01],
                })
                .encrypted_key(EncryptedCallKey {
                    enc_type: EncType::Msg,
                    ciphertext: vec![0x02],
                })
                .build();

        let offer_node = &node.children().unwrap()[0];
        let enc_count = offer_node
            .children()
            .unwrap()
            .iter()
            .filter(|c| c.tag == "enc")
            .count();
        assert_eq!(enc_count, 2, "`encrypted_key` must append, not replace");
    }

    /// Test that Accept stanza does NOT include privacy or capability.
    #[test]
    fn test_accept_no_privacy_capability() {
        let call_id = "TEST1234TEST1234TEST1234TEST1234";
        let creator: Jid = "123@lid".parse().unwrap();
        let to: Jid = "456@lid".parse().unwrap();

        let node =
            CallStanzaBuilder::new(call_id, creator.clone(), to.clone(), SignalingType::Accept)
                .audio(AcceptAudioParams::default())
                .net_medium(2)
                .encopt_keygen(2)
                .build();

        let children = node.children().unwrap();
        let accept_node = &children[0];
        let accept_children = accept_node.children().unwrap();

        assert!(
            !accept_children.iter().any(|c| c.tag == "privacy"),
            "Accept should NOT have <privacy>"
        );
        assert!(
            !accept_children.iter().any(|c| c.tag == "capability"),
            "Accept should NOT have <capability>"
        );
        assert!(
            !accept_children.iter().any(|c| c.tag == "enc"),
            "Accept should NOT have <enc>"
        );
    }
}
