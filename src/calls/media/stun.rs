//! STUN binding protocol for WhatsApp relay authentication.
//!
//! Implements RFC 5389 STUN (Session Traversal Utilities for NAT) binding
//! with WhatsApp-specific authentication using relay tokens and MESSAGE-INTEGRITY.
//!
//! # Protocol Flow
//!
//! 1. Client sends STUN Binding Request with:
//!    - USERNAME attribute = auth_token (ice-ufrag, preferred) or relay_token
//!    - MESSAGE-INTEGRITY = HMAC-SHA1 using relay_key (ice-pwd)
//! 2. Server validates MESSAGE-INTEGRITY and responds with Binding Response
//! 3. Connection is authenticated and ready for media transport
//!
//! # WhatsApp Web Compatibility
//!
//! WhatsApp Web uses WebRTC which handles ICE credentials as:
//! - ice-ufrag = authToken ?? token (prefers auth_token)
//! - ice-pwd = relay_key (used for MESSAGE-INTEGRITY)

use crc::{CRC_32_ISO_HDLC, Crc};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::timeout;

/// STUN magic cookie (RFC 5389).
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN FINGERPRINT XOR value (RFC 5389).
/// This is the ASCII representation of "STUN".
const STUN_FINGERPRINT_XOR: u32 = 0x5354554e;

/// CRC-32 calculator for FINGERPRINT (ISO HDLC / CRC-32).
const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// STUN message types (RFC 5389 + RFC 5766 TURN + WhatsApp custom).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StunMessageType {
    /// Binding Request (0x0001) - RFC 5389
    BindingRequest = 0x0001,
    /// Binding Response Success (0x0101)
    BindingResponse = 0x0101,
    /// Binding Error Response (0x0111)
    BindingErrorResponse = 0x0111,
    /// Allocate Request (0x0003) - RFC 5766 TURN
    AllocateRequest = 0x0003,
    /// Allocate Response Success (0x0103)
    AllocateResponse = 0x0103,
    /// Allocate Error Response (0x0113)
    AllocateErrorResponse = 0x0113,
    /// Refresh Request (0x0004) - RFC 5766 TURN
    RefreshRequest = 0x0004,
    /// Refresh Response Success (0x0104)
    RefreshResponse = 0x0104,
    /// WhatsApp Ping/Indication (0x0801) - Custom keepalive
    WhatsAppPing = 0x0801,
    /// WhatsApp Pong/Response (0x0802) - Custom keepalive response
    WhatsAppPong = 0x0802,
}

impl TryFrom<u16> for StunMessageType {
    type Error = StunError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::BindingRequest),
            0x0101 => Ok(Self::BindingResponse),
            0x0111 => Ok(Self::BindingErrorResponse),
            0x0003 => Ok(Self::AllocateRequest),
            0x0103 => Ok(Self::AllocateResponse),
            0x0113 => Ok(Self::AllocateErrorResponse),
            0x0004 => Ok(Self::RefreshRequest),
            0x0104 => Ok(Self::RefreshResponse),
            0x0801 => Ok(Self::WhatsAppPing),
            0x0802 => Ok(Self::WhatsAppPong),
            _ => Err(StunError::InvalidMessageType(value)),
        }
    }
}

/// STUN attribute types (RFC 5389 + RFC 5766 TURN + RFC 8445 ICE + WhatsApp custom).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum StunAttributeType {
    /// MAPPED-ADDRESS (0x0001) - Reflexive transport address
    MappedAddress = 0x0001,
    /// USERNAME (0x0006) - Authentication username (relay token)
    Username = 0x0006,
    /// MESSAGE-INTEGRITY (0x0008) - HMAC-SHA1 authentication
    MessageIntegrity = 0x0008,
    /// ERROR-CODE (0x0009) - Error information
    ErrorCode = 0x0009,
    /// LIFETIME (0x000D) - RFC 5766 TURN allocation lifetime
    Lifetime = 0x000D,
    /// REALM (0x0014) - RFC 5389 long-term credential
    Realm = 0x0014,
    /// NONCE (0x0015) - RFC 5389 long-term credential
    Nonce = 0x0015,
    /// XOR-RELAYED-ADDRESS (0x0016) - RFC 5766 TURN relayed address
    XorRelayedAddress = 0x0016,
    /// REQUESTED-TRANSPORT (0x0019) - RFC 5766 TURN transport protocol
    RequestedTransport = 0x0019,
    /// XOR-MAPPED-ADDRESS (0x0020) - XOR'd reflexive address
    XorMappedAddress = 0x0020,
    /// PRIORITY (0x0024) - RFC 8445 ICE candidate priority
    Priority = 0x0024,
    /// USE-CANDIDATE (0x0025) - RFC 8445 ICE controlling agent nomination
    UseCandidate = 0x0025,
    /// WhatsApp SenderSubscriptions (0x4000) - Custom protobuf-encoded stream subscriptions
    SenderSubscriptions = 0x4000,
    /// WhatsApp ReceiverSubscription (0x4001) - Custom receiver subscription
    ReceiverSubscription = 0x4001,
    /// WhatsApp SubscriptionAck (0x4002) - Custom subscription acknowledgment
    SubscriptionAck = 0x4002,
    /// SOFTWARE (0x8022) - Software description
    Software = 0x8022,
    /// FINGERPRINT (0x8028) - CRC32 checksum
    Fingerprint = 0x8028,
    /// ICE-CONTROLLED (0x8029) - RFC 8445 ICE controlled agent
    IceControlled = 0x8029,
    /// ICE-CONTROLLING (0x802A) - RFC 8445 ICE controlling agent
    IceControlling = 0x802A,
}

impl TryFrom<u16> for StunAttributeType {
    type Error = ();

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(Self::MappedAddress),
            0x0006 => Ok(Self::Username),
            0x0008 => Ok(Self::MessageIntegrity),
            0x0009 => Ok(Self::ErrorCode),
            0x000D => Ok(Self::Lifetime),
            0x0014 => Ok(Self::Realm),
            0x0015 => Ok(Self::Nonce),
            0x0016 => Ok(Self::XorRelayedAddress),
            0x0019 => Ok(Self::RequestedTransport),
            0x0020 => Ok(Self::XorMappedAddress),
            0x0024 => Ok(Self::Priority),
            0x0025 => Ok(Self::UseCandidate),
            0x4000 => Ok(Self::SenderSubscriptions),
            0x4001 => Ok(Self::ReceiverSubscription),
            0x4002 => Ok(Self::SubscriptionAck),
            0x8022 => Ok(Self::Software),
            0x8028 => Ok(Self::Fingerprint),
            0x8029 => Ok(Self::IceControlled),
            0x802A => Ok(Self::IceControlling),
            _ => Err(()),
        }
    }
}

/// Transport protocol for REQUESTED-TRANSPORT attribute (RFC 5766).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TurnTransportProtocol {
    /// UDP (17)
    Udp = 17,
    /// TCP (6) - requires TURN-TCP extension
    Tcp = 6,
}

/// Parsed STUN attribute.
#[derive(Debug, Clone)]
pub enum StunAttribute {
    /// MAPPED-ADDRESS or XOR-MAPPED-ADDRESS
    MappedAddress(SocketAddr),
    /// XOR-RELAYED-ADDRESS (RFC 5766 TURN)
    XorRelayedAddress(SocketAddr),
    /// USERNAME (relay token or auth token)
    Username(Vec<u8>),
    /// MESSAGE-INTEGRITY (20-byte HMAC-SHA1)
    MessageIntegrity([u8; 20]),
    /// ERROR-CODE with code and reason
    ErrorCode { code: u16, reason: String },
    /// REALM (RFC 5389)
    Realm(String),
    /// NONCE (RFC 5389)
    Nonce(Vec<u8>),
    /// REQUESTED-TRANSPORT (RFC 5766 TURN)
    RequestedTransport(TurnTransportProtocol),
    /// LIFETIME in seconds (RFC 5766 TURN)
    Lifetime(u32),
    /// PRIORITY (RFC 8445 ICE) - candidate priority value
    Priority(u32),
    /// USE-CANDIDATE (RFC 8445 ICE) - controlling agent nomination flag
    UseCandidate,
    /// ICE-CONTROLLED with tie-breaker value
    IceControlled(u64),
    /// ICE-CONTROLLING with tie-breaker value
    IceControlling(u64),
    /// SOFTWARE description
    Software(String),
    /// WhatsApp SenderSubscriptions (0x4000) - raw protobuf bytes
    SenderSubscriptions(Vec<u8>),
    /// WhatsApp ReceiverSubscription (0x4001) - raw protobuf bytes
    ReceiverSubscription(Vec<u8>),
    /// WhatsApp SubscriptionAck (0x4002) - raw bytes
    SubscriptionAck(Vec<u8>),
    /// Unknown attribute
    Unknown { attr_type: u16, data: Vec<u8> },
}

/// HMAC-SHA1 type for MESSAGE-INTEGRITY.
type HmacSha1 = Hmac<Sha1>;

/// ICE role for connectivity checks (RFC 8445).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    /// Controlling agent (initiator of the call).
    /// Uses ICE-CONTROLLING attribute with a tie-breaker.
    Controlling(u64),
    /// Controlled agent (answerer of the call).
    /// Uses ICE-CONTROLLED attribute with a tie-breaker.
    Controlled(u64),
}

/// Default ICE priority for relay candidates (RFC 8445).
/// Calculated as: (2^24) * type_pref + (2^8) * local_pref + (256 - component_id)
/// For relay: type_pref=0, local_pref=65535, component_id=1
/// = 0 + 16776960 + 255 = 16777215
const DEFAULT_ICE_PRIORITY: u32 = 16_777_215;

/// STUN message.
#[derive(Debug, Clone)]
pub struct StunMessage {
    /// Message type.
    pub msg_type: StunMessageType,
    /// Transaction ID (12 bytes).
    pub transaction_id: [u8; 12],
    /// Attributes.
    pub attributes: Vec<StunAttribute>,
    /// Password for MESSAGE-INTEGRITY (relay_key / ice-pwd).
    integrity_key: Option<Vec<u8>>,
    /// Whether to include FINGERPRINT attribute (RFC 5389 recommends it).
    include_fingerprint: bool,
    /// ICE priority value (RFC 8445). Set to Some(value) to include PRIORITY attribute.
    ice_priority: Option<u32>,
    /// ICE role with tie-breaker. Set for ICE connectivity checks.
    ice_role: Option<IceRole>,
}

impl StunMessage {
    /// Create a new STUN Binding Request with the given transaction ID.
    ///
    /// By default includes FINGERPRINT (RFC 5389) and PRIORITY (RFC 8445) attributes.
    /// WhatsApp relay servers expect both.
    pub fn binding_request(transaction_id: [u8; 12]) -> Self {
        Self {
            msg_type: StunMessageType::BindingRequest,
            transaction_id,
            attributes: Vec::new(),
            integrity_key: None,
            include_fingerprint: true, // Include FINGERPRINT by default (RFC 5389 recommends it)
            ice_priority: Some(DEFAULT_ICE_PRIORITY), // Include PRIORITY for WhatsApp relay binding
            ice_role: None,
        }
    }

    /// Create a new TURN Allocate Request with the given transaction ID (RFC 5766).
    ///
    /// This creates an Allocate request for UDP relay allocation.
    /// The server will allocate a relay address and return it in XOR-RELAYED-ADDRESS.
    pub fn allocate_request(transaction_id: [u8; 12]) -> Self {
        Self {
            msg_type: StunMessageType::AllocateRequest,
            transaction_id,
            attributes: vec![
                // REQUESTED-TRANSPORT is required for Allocate (RFC 5766 section 6.1)
                StunAttribute::RequestedTransport(TurnTransportProtocol::Udp),
            ],
            integrity_key: None,
            include_fingerprint: true,
            ice_priority: Some(DEFAULT_ICE_PRIORITY),
            ice_role: None,
        }
    }

    /// Create a new TURN Refresh Request with the given transaction ID (RFC 5766).
    ///
    /// This refreshes an existing allocation. If lifetime is 0, the allocation is deleted.
    pub fn refresh_request(transaction_id: [u8; 12], lifetime_secs: u32) -> Self {
        Self {
            msg_type: StunMessageType::RefreshRequest,
            transaction_id,
            attributes: vec![StunAttribute::Lifetime(lifetime_secs)],
            integrity_key: None,
            include_fingerprint: true,
            ice_priority: None, // Refresh doesn't need priority
            ice_role: None,
        }
    }

    /// Create a WhatsApp Ping message (0x0801).
    ///
    /// This is a custom STUN-like keepalive message used by WhatsApp Web.
    /// The relay responds with a Pong (0x0802).
    pub fn whatsapp_ping(transaction_id: [u8; 12]) -> Self {
        Self {
            msg_type: StunMessageType::WhatsAppPing,
            transaction_id,
            attributes: Vec::new(),
            integrity_key: None,
            include_fingerprint: false, // WhatsApp ping has no attributes
            ice_priority: None,
            ice_role: None,
        }
    }

    /// Enable or disable FINGERPRINT attribute.
    pub fn with_fingerprint(mut self, include: bool) -> Self {
        self.include_fingerprint = include;
        self
    }

    /// Add a USERNAME attribute (auth_token or relay_token - ice-ufrag).
    pub fn with_username(mut self, username: &[u8]) -> Self {
        self.attributes
            .push(StunAttribute::Username(username.to_vec()));
        self
    }

    /// Add a LIFETIME attribute (RFC 5766 TURN).
    pub fn with_lifetime(mut self, lifetime_secs: u32) -> Self {
        self.attributes.push(StunAttribute::Lifetime(lifetime_secs));
        self
    }

    /// Set the password for MESSAGE-INTEGRITY (relay_key - ice-pwd).
    ///
    /// When set, the encoded message will include a MESSAGE-INTEGRITY attribute
    /// computed as HMAC-SHA1 over the message using this key.
    pub fn with_integrity_key(mut self, key: &[u8]) -> Self {
        self.integrity_key = Some(key.to_vec());
        self
    }

    /// Add WhatsApp SenderSubscriptions attribute (0x4000).
    ///
    /// This contains protobuf-encoded stream subscription information that tells
    /// the relay what streams we're sending and want to receive.
    pub fn with_sender_subscriptions(mut self, data: Vec<u8>) -> Self {
        self.attributes
            .push(StunAttribute::SenderSubscriptions(data));
        self
    }

    /// Add WhatsApp ReceiverSubscription attribute (0x4001).
    ///
    /// This contains receiver subscription information.
    pub fn with_receiver_subscription(mut self, data: Vec<u8>) -> Self {
        self.attributes
            .push(StunAttribute::ReceiverSubscription(data));
        self
    }

    /// Set the ICE PRIORITY attribute value (RFC 8445).
    ///
    /// The priority is a 32-bit value calculated based on:
    /// - Type preference (host=126, srflx=100, prflx=110, relay=0)
    /// - Local preference (0-65535)
    /// - Component ID (RTP=1, RTCP=2)
    ///
    /// Formula: priority = (2^24) * type_pref + (2^8) * local_pref + (256 - component_id)
    ///
    /// Pass None to disable PRIORITY attribute (not recommended for WhatsApp).
    pub fn with_priority(mut self, priority: Option<u32>) -> Self {
        self.ice_priority = priority;
        self
    }

    /// Set the ICE role for connectivity checks (RFC 8445).
    ///
    /// This adds ICE-CONTROLLING or ICE-CONTROLLED attribute with the tie-breaker.
    /// - Controlling: Call initiator
    /// - Controlled: Call answerer
    pub fn with_ice_role(mut self, role: Option<IceRole>) -> Self {
        self.ice_role = role;
        self
    }

    /// Serialize the STUN message to bytes.
    ///
    /// If an integrity key is set, MESSAGE-INTEGRITY is calculated and appended.
    /// If include_fingerprint is true, FINGERPRINT is added as the last attribute.
    pub fn encode(&self) -> Vec<u8> {
        let mut attrs_buf = Vec::new();

        // Encode attributes (except MESSAGE-INTEGRITY and FINGERPRINT which are calculated last)
        for attr in &self.attributes {
            match attr {
                StunAttribute::Username(data) => {
                    self.encode_attribute(&mut attrs_buf, StunAttributeType::Username as u16, data);
                }
                StunAttribute::RequestedTransport(protocol) => {
                    // REQUESTED-TRANSPORT format: 1 byte protocol + 3 bytes reserved
                    let data = [*protocol as u8, 0, 0, 0];
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::RequestedTransport as u16,
                        &data,
                    );
                }
                StunAttribute::Lifetime(secs) => {
                    // LIFETIME is a 32-bit unsigned integer in seconds
                    let data = secs.to_be_bytes();
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::Lifetime as u16,
                        &data,
                    );
                }
                StunAttribute::Realm(realm) => {
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::Realm as u16,
                        realm.as_bytes(),
                    );
                }
                StunAttribute::Nonce(nonce) => {
                    self.encode_attribute(&mut attrs_buf, StunAttributeType::Nonce as u16, nonce);
                }
                StunAttribute::Priority(priority) => {
                    // PRIORITY is a 32-bit unsigned integer
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::Priority as u16,
                        &priority.to_be_bytes(),
                    );
                }
                StunAttribute::IceControlling(tie_breaker) => {
                    // ICE-CONTROLLING has an 8-byte tie-breaker
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::IceControlling as u16,
                        &tie_breaker.to_be_bytes(),
                    );
                }
                StunAttribute::IceControlled(tie_breaker) => {
                    // ICE-CONTROLLED has an 8-byte tie-breaker
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::IceControlled as u16,
                        &tie_breaker.to_be_bytes(),
                    );
                }
                StunAttribute::UseCandidate => {
                    // USE-CANDIDATE has zero length (flag attribute)
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::UseCandidate as u16,
                        &[],
                    );
                }
                StunAttribute::SenderSubscriptions(data) => {
                    // WhatsApp SenderSubscriptions (0x4000) - raw protobuf bytes
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::SenderSubscriptions as u16,
                        data,
                    );
                }
                StunAttribute::ReceiverSubscription(data) => {
                    // WhatsApp ReceiverSubscription (0x4001) - raw bytes
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::ReceiverSubscription as u16,
                        data,
                    );
                }
                StunAttribute::SubscriptionAck(data) => {
                    // WhatsApp SubscriptionAck (0x4002) - raw bytes
                    self.encode_attribute(
                        &mut attrs_buf,
                        StunAttributeType::SubscriptionAck as u16,
                        data,
                    );
                }
                _ => {
                    // Other attributes not needed for requests
                }
            }
        }

        // Add PRIORITY attribute if set (RFC 8445)
        if let Some(priority) = self.ice_priority {
            self.encode_attribute(
                &mut attrs_buf,
                StunAttributeType::Priority as u16,
                &priority.to_be_bytes(),
            );
        }

        // Add ICE role attribute if set (RFC 8445)
        match self.ice_role {
            Some(IceRole::Controlling(tie_breaker)) => {
                self.encode_attribute(
                    &mut attrs_buf,
                    StunAttributeType::IceControlling as u16,
                    &tie_breaker.to_be_bytes(),
                );
            }
            Some(IceRole::Controlled(tie_breaker)) => {
                self.encode_attribute(
                    &mut attrs_buf,
                    StunAttributeType::IceControlled as u16,
                    &tie_breaker.to_be_bytes(),
                );
            }
            None => {}
        }

        // Calculate final message length including MESSAGE-INTEGRITY and FINGERPRINT
        // MESSAGE-INTEGRITY: 24 bytes (4 byte header + 20 byte HMAC)
        // FINGERPRINT: 8 bytes (4 byte header + 4 byte CRC)
        let has_fingerprint = self.include_fingerprint;

        // If we have an integrity key, we need to add MESSAGE-INTEGRITY
        // Per RFC 5389: The HMAC is computed over the STUN message up to (but excluding)
        // MESSAGE-INTEGRITY itself, with the message length adjusted to point to the end
        // of MESSAGE-INTEGRITY (NOT including FINGERPRINT in the length for HMAC calculation)
        if let Some(ref key) = self.integrity_key {
            // For HMAC: message length = current attrs + MESSAGE-INTEGRITY (24 bytes)
            // FINGERPRINT is NOT included in the length for HMAC calculation
            let msg_len_for_hmac = attrs_buf.len() + 24;

            // Build header for HMAC calculation
            let mut hmac_input = Vec::with_capacity(20 + attrs_buf.len());
            hmac_input.extend_from_slice(&(self.msg_type as u16).to_be_bytes());
            hmac_input.extend_from_slice(&(msg_len_for_hmac as u16).to_be_bytes());
            hmac_input.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            hmac_input.extend_from_slice(&self.transaction_id);
            hmac_input.extend_from_slice(&attrs_buf);

            // Calculate HMAC-SHA1
            let mut mac = HmacSha1::new_from_slice(key).expect("HMAC can take key of any size");
            mac.update(&hmac_input);
            let hmac_result = mac.finalize().into_bytes();

            // Add MESSAGE-INTEGRITY attribute
            self.encode_attribute(
                &mut attrs_buf,
                StunAttributeType::MessageIntegrity as u16,
                &hmac_result,
            );
        }

        // If FINGERPRINT is enabled, add it as the last attribute
        // FINGERPRINT is CRC-32 of the message up to (but excluding) FINGERPRINT itself,
        // XOR'd with 0x5354554e ("STUN")
        if has_fingerprint {
            // Calculate message length including FINGERPRINT
            let msg_len_for_crc = attrs_buf.len() + 8;

            // Build message for CRC calculation (including header with adjusted length)
            let mut crc_input = Vec::with_capacity(20 + attrs_buf.len());
            crc_input.extend_from_slice(&(self.msg_type as u16).to_be_bytes());
            crc_input.extend_from_slice(&(msg_len_for_crc as u16).to_be_bytes());
            crc_input.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            crc_input.extend_from_slice(&self.transaction_id);
            crc_input.extend_from_slice(&attrs_buf);

            // Calculate CRC-32 and XOR with magic value
            let crc = CRC32.checksum(&crc_input) ^ STUN_FINGERPRINT_XOR;

            // Add FINGERPRINT attribute
            self.encode_attribute(
                &mut attrs_buf,
                StunAttributeType::Fingerprint as u16,
                &crc.to_be_bytes(),
            );
        }

        // Build final message
        let mut buf = Vec::with_capacity(20 + attrs_buf.len());

        // Message Type (2 bytes)
        buf.extend_from_slice(&(self.msg_type as u16).to_be_bytes());

        // Message Length (2 bytes) - length of attributes only
        buf.extend_from_slice(&(attrs_buf.len() as u16).to_be_bytes());

        // Magic Cookie (4 bytes)
        buf.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID (12 bytes)
        buf.extend_from_slice(&self.transaction_id);

        // Attributes
        buf.extend_from_slice(&attrs_buf);

        buf
    }

    /// Encode a single attribute.
    fn encode_attribute(&self, buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
        // Attribute Type (2 bytes)
        buf.extend_from_slice(&attr_type.to_be_bytes());

        // Attribute Length (2 bytes) - length of value only
        buf.extend_from_slice(&(data.len() as u16).to_be_bytes());

        // Attribute Value
        buf.extend_from_slice(data);

        // Padding to 4-byte boundary
        let padding = (4 - (data.len() % 4)) % 4;
        buf.extend(std::iter::repeat_n(0u8, padding));
    }

    /// Parse a STUN message from bytes.
    pub fn decode(data: &[u8]) -> Result<Self, StunError> {
        if data.len() < 20 {
            return Err(StunError::TooShort(data.len()));
        }

        // Message Type (2 bytes)
        let msg_type = u16::from_be_bytes([data[0], data[1]]);
        let msg_type = StunMessageType::try_from(msg_type)?;

        // Message Length (2 bytes)
        let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

        // Magic Cookie (4 bytes)
        let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        if cookie != STUN_MAGIC_COOKIE {
            return Err(StunError::InvalidMagicCookie(cookie));
        }

        // Transaction ID (12 bytes)
        let mut transaction_id = [0u8; 12];
        transaction_id.copy_from_slice(&data[8..20]);

        // Verify we have enough data for attributes
        if data.len() < 20 + msg_len {
            return Err(StunError::TooShort(data.len()));
        }

        // Parse attributes
        let mut attributes = Vec::new();
        let mut offset = 20;
        let end = 20 + msg_len;

        while offset + 4 <= end {
            let attr_type = u16::from_be_bytes([data[offset], data[offset + 1]]);
            let attr_len = u16::from_be_bytes([data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;

            if offset + attr_len > end {
                return Err(StunError::InvalidAttribute);
            }

            let attr_data = &data[offset..offset + attr_len];

            let attr = match StunAttributeType::try_from(attr_type) {
                Ok(StunAttributeType::MappedAddress) => {
                    Self::parse_mapped_address(attr_data, false, &transaction_id)?
                }
                Ok(StunAttributeType::XorMappedAddress) => {
                    Self::parse_mapped_address(attr_data, true, &transaction_id)?
                }
                Ok(StunAttributeType::XorRelayedAddress) => {
                    // XOR-RELAYED-ADDRESS uses same encoding as XOR-MAPPED-ADDRESS
                    match Self::parse_mapped_address(attr_data, true, &transaction_id)? {
                        StunAttribute::MappedAddress(addr) => {
                            StunAttribute::XorRelayedAddress(addr)
                        }
                        _ => StunAttribute::Unknown {
                            attr_type,
                            data: attr_data.to_vec(),
                        },
                    }
                }
                Ok(StunAttributeType::MessageIntegrity) => {
                    if attr_data.len() == 20 {
                        let mut hmac = [0u8; 20];
                        hmac.copy_from_slice(attr_data);
                        StunAttribute::MessageIntegrity(hmac)
                    } else {
                        StunAttribute::Unknown {
                            attr_type,
                            data: attr_data.to_vec(),
                        }
                    }
                }
                Ok(StunAttributeType::ErrorCode) => Self::parse_error_code(attr_data)?,
                Ok(StunAttributeType::Software) => {
                    StunAttribute::Software(String::from_utf8_lossy(attr_data).to_string())
                }
                Ok(StunAttributeType::Lifetime) => {
                    if attr_data.len() >= 4 {
                        let secs = u32::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]);
                        StunAttribute::Lifetime(secs)
                    } else {
                        StunAttribute::Unknown {
                            attr_type,
                            data: attr_data.to_vec(),
                        }
                    }
                }
                Ok(StunAttributeType::Realm) => {
                    StunAttribute::Realm(String::from_utf8_lossy(attr_data).to_string())
                }
                Ok(StunAttributeType::Nonce) => StunAttribute::Nonce(attr_data.to_vec()),
                Ok(StunAttributeType::RequestedTransport) => {
                    if !attr_data.is_empty() {
                        let protocol = match attr_data[0] {
                            17 => TurnTransportProtocol::Udp,
                            6 => TurnTransportProtocol::Tcp,
                            _ => TurnTransportProtocol::Udp, // Default to UDP
                        };
                        StunAttribute::RequestedTransport(protocol)
                    } else {
                        StunAttribute::Unknown {
                            attr_type,
                            data: attr_data.to_vec(),
                        }
                    }
                }
                Ok(StunAttributeType::Priority) => {
                    if attr_data.len() >= 4 {
                        let priority = u32::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                        ]);
                        StunAttribute::Priority(priority)
                    } else {
                        StunAttribute::Unknown {
                            attr_type,
                            data: attr_data.to_vec(),
                        }
                    }
                }
                Ok(StunAttributeType::UseCandidate) => StunAttribute::UseCandidate,
                Ok(StunAttributeType::IceControlled) => {
                    if attr_data.len() >= 8 {
                        let tie_breaker = u64::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                            attr_data[4],
                            attr_data[5],
                            attr_data[6],
                            attr_data[7],
                        ]);
                        StunAttribute::IceControlled(tie_breaker)
                    } else {
                        StunAttribute::Unknown {
                            attr_type,
                            data: attr_data.to_vec(),
                        }
                    }
                }
                Ok(StunAttributeType::IceControlling) => {
                    if attr_data.len() >= 8 {
                        let tie_breaker = u64::from_be_bytes([
                            attr_data[0],
                            attr_data[1],
                            attr_data[2],
                            attr_data[3],
                            attr_data[4],
                            attr_data[5],
                            attr_data[6],
                            attr_data[7],
                        ]);
                        StunAttribute::IceControlling(tie_breaker)
                    } else {
                        StunAttribute::Unknown {
                            attr_type,
                            data: attr_data.to_vec(),
                        }
                    }
                }
                _ => StunAttribute::Unknown {
                    attr_type,
                    data: attr_data.to_vec(),
                },
            };

            attributes.push(attr);

            // Move to next attribute (with padding)
            offset += attr_len;
            offset += (4 - (attr_len % 4)) % 4;
        }

        Ok(Self {
            msg_type,
            transaction_id,
            attributes,
            integrity_key: None,        // Not needed for decoded messages
            include_fingerprint: false, // Not needed for decoded messages
            ice_priority: None,         // Not needed for decoded messages
            ice_role: None,             // Not needed for decoded messages
        })
    }

    /// Parse MAPPED-ADDRESS or XOR-MAPPED-ADDRESS attribute.
    fn parse_mapped_address(
        data: &[u8],
        xored: bool,
        transaction_id: &[u8; 12],
    ) -> Result<StunAttribute, StunError> {
        if data.len() < 4 {
            return Err(StunError::InvalidAttribute);
        }

        // First byte is reserved (0x00)
        let family = data[1];
        let port = u16::from_be_bytes([data[2], data[3]]);

        let addr = match family {
            0x01 => {
                // IPv4
                if data.len() < 8 {
                    return Err(StunError::InvalidAttribute);
                }
                let mut ip_bytes = [data[4], data[5], data[6], data[7]];

                if xored {
                    // XOR with magic cookie
                    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                    for i in 0..4 {
                        ip_bytes[i] ^= cookie_bytes[i];
                    }
                }

                IpAddr::V4(Ipv4Addr::from(ip_bytes))
            }
            0x02 => {
                // IPv6
                if data.len() < 20 {
                    return Err(StunError::InvalidAttribute);
                }
                let mut ip_bytes: [u8; 16] = data[4..20].try_into().unwrap();

                if xored {
                    // XOR with magic cookie + transaction ID
                    let cookie_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
                    for i in 0..4 {
                        ip_bytes[i] ^= cookie_bytes[i];
                    }
                    for i in 0..12 {
                        ip_bytes[4 + i] ^= transaction_id[i];
                    }
                }

                IpAddr::V6(Ipv6Addr::from(ip_bytes))
            }
            _ => return Err(StunError::InvalidAttribute),
        };

        let port = if xored {
            port ^ (STUN_MAGIC_COOKIE >> 16) as u16
        } else {
            port
        };

        Ok(StunAttribute::MappedAddress(SocketAddr::new(addr, port)))
    }

    /// Parse ERROR-CODE attribute.
    fn parse_error_code(data: &[u8]) -> Result<StunAttribute, StunError> {
        if data.len() < 4 {
            return Err(StunError::InvalidAttribute);
        }

        let class = data[2] & 0x07;
        let number = data[3];
        let code = (class as u16) * 100 + (number as u16);
        let reason = String::from_utf8_lossy(&data[4..]).to_string();

        Ok(StunAttribute::ErrorCode { code, reason })
    }

    /// Get the mapped address from the response, if present.
    pub fn mapped_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::MappedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Get the relayed address from a TURN Allocate response, if present.
    pub fn relayed_address(&self) -> Option<SocketAddr> {
        for attr in &self.attributes {
            if let StunAttribute::XorRelayedAddress(addr) = attr {
                return Some(*addr);
            }
        }
        None
    }

    /// Get the lifetime from the response, if present.
    pub fn lifetime(&self) -> Option<u32> {
        for attr in &self.attributes {
            if let StunAttribute::Lifetime(secs) = attr {
                return Some(*secs);
            }
        }
        None
    }

    /// Get the realm from the response, if present.
    pub fn realm(&self) -> Option<&str> {
        for attr in &self.attributes {
            if let StunAttribute::Realm(realm) = attr {
                return Some(realm);
            }
        }
        None
    }

    /// Get the nonce from the response, if present.
    pub fn nonce(&self) -> Option<&[u8]> {
        for attr in &self.attributes {
            if let StunAttribute::Nonce(nonce) = attr {
                return Some(nonce);
            }
        }
        None
    }

    /// Get the error code from the response, if present.
    pub fn error_code(&self) -> Option<(u16, &str)> {
        for attr in &self.attributes {
            if let StunAttribute::ErrorCode { code, reason } = attr {
                return Some((*code, reason));
            }
        }
        None
    }

    /// Check if this is an error response.
    pub fn is_error(&self) -> bool {
        matches!(
            self.msg_type,
            StunMessageType::BindingErrorResponse | StunMessageType::AllocateErrorResponse
        )
    }

    /// Check if this is a success response.
    pub fn is_success(&self) -> bool {
        matches!(
            self.msg_type,
            StunMessageType::BindingResponse
                | StunMessageType::AllocateResponse
                | StunMessageType::RefreshResponse
                | StunMessageType::WhatsAppPong
        )
    }

    /// Check if this is a WhatsApp Ping message.
    pub fn is_ping(&self) -> bool {
        self.msg_type == StunMessageType::WhatsAppPing
    }

    /// Check if this is a WhatsApp Pong message.
    pub fn is_pong(&self) -> bool {
        self.msg_type == StunMessageType::WhatsAppPong
    }
}

/// Errors during STUN operations.
#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error("STUN message too short: {0} bytes")]
    TooShort(usize),
    #[error("Invalid STUN message type: 0x{0:04x}")]
    InvalidMessageType(u16),
    #[error("Invalid STUN magic cookie: 0x{0:08x}")]
    InvalidMagicCookie(u32),
    #[error("Invalid STUN attribute")]
    InvalidAttribute,
    #[error("STUN error response: {0} - {1}")]
    ServerError(u16, String),
    #[error("Transaction ID mismatch")]
    TransactionMismatch,
    #[error("Socket error: {0}")]
    Socket(#[from] std::io::Error),
    #[error("Timeout waiting for STUN response")]
    Timeout,
}

/// Result of a successful STUN binding.
#[derive(Debug, Clone)]
pub struct StunBindResult {
    /// Our mapped address as seen by the server.
    pub mapped_address: Option<SocketAddr>,
    /// The full response message.
    pub response: StunMessage,
}

/// Result of a successful TURN Allocate (RFC 5766).
#[derive(Debug, Clone)]
pub struct StunAllocateResult {
    /// Our mapped address as seen by the server (XOR-MAPPED-ADDRESS).
    pub mapped_address: Option<SocketAddr>,
    /// The allocated relay address (XOR-RELAYED-ADDRESS).
    /// This is the address that the peer should send to.
    pub relayed_address: Option<SocketAddr>,
    /// Allocation lifetime in seconds.
    pub lifetime: Option<u32>,
    /// The full response message.
    pub response: StunMessage,
}

/// STUN authentication credentials.
///
/// WhatsApp Web uses:
/// - ice-ufrag = auth_token (preferred) or relay_token
/// - ice-pwd = relay_key (for MESSAGE-INTEGRITY)
#[derive(Debug, Clone)]
pub struct StunCredentials {
    /// USERNAME attribute (ice-ufrag).
    /// Use auth_token if available, otherwise relay_token.
    pub username: Vec<u8>,
    /// MESSAGE-INTEGRITY key (ice-pwd / relay_key).
    /// Optional - if not provided, MESSAGE-INTEGRITY is not included.
    pub integrity_key: Option<Vec<u8>>,
}

impl StunCredentials {
    /// Create credentials with just a username (legacy mode, no MESSAGE-INTEGRITY).
    pub fn username_only(username: &[u8]) -> Self {
        Self {
            username: username.to_vec(),
            integrity_key: None,
        }
    }

    /// Create credentials with username and integrity key (full ICE auth).
    pub fn with_integrity(username: &[u8], integrity_key: &[u8]) -> Self {
        Self {
            username: username.to_vec(),
            integrity_key: Some(integrity_key.to_vec()),
        }
    }
}

/// STUN binding handler.
pub struct StunBinder {
    socket: Arc<UdpSocket>,
}

impl StunBinder {
    /// Create a new STUN binder with the given socket.
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self { socket }
    }

    /// Generate a random transaction ID.
    fn generate_transaction_id() -> [u8; 12] {
        use rand::RngCore;
        let mut id = [0u8; 12];
        rand::rng().fill_bytes(&mut id);
        id
    }

    /// Perform a single STUN binding request (legacy, no MESSAGE-INTEGRITY).
    #[deprecated(note = "Use bind_with_credentials for proper WhatsApp authentication")]
    pub async fn bind(&self, relay_token: &[u8]) -> Result<StunBindResult, StunError> {
        self.bind_with_credentials(&StunCredentials::username_only(relay_token))
            .await
    }

    /// Perform a single STUN binding request with full credentials.
    ///
    /// This follows WhatsApp Web's ICE authentication:
    /// - USERNAME = auth_token (preferred) or relay_token (ice-ufrag)
    /// - MESSAGE-INTEGRITY = HMAC-SHA1 using relay_key (ice-pwd)
    pub async fn bind_with_credentials(
        &self,
        credentials: &StunCredentials,
    ) -> Result<StunBindResult, StunError> {
        let transaction_id = Self::generate_transaction_id();

        // Build binding request with username (auth_token or relay_token)
        let mut request =
            StunMessage::binding_request(transaction_id).with_username(&credentials.username);

        // Add MESSAGE-INTEGRITY if we have an integrity key (relay_key)
        if let Some(ref key) = credentials.integrity_key {
            request = request.with_integrity_key(key);
        }

        let request_bytes = request.encode();

        log::debug!(
            "STUN: Sending binding request ({} bytes, username {} bytes, integrity={}, priority=0x{:x}, tx_id: {:02x}{:02x}{:02x}{:02x}...)",
            request_bytes.len(),
            credentials.username.len(),
            credentials.integrity_key.is_some(),
            DEFAULT_ICE_PRIORITY,
            transaction_id[0],
            transaction_id[1],
            transaction_id[2],
            transaction_id[3]
        );

        // Log first 40 bytes of request for debugging (header + first attr)
        if log::log_enabled!(log::Level::Trace) {
            let preview_len = request_bytes.len().min(40);
            log::trace!("STUN request hex: {:02x?}", &request_bytes[..preview_len]);
        }

        // Send request
        let bytes_sent = self.socket.send(&request_bytes).await?;
        log::debug!(
            "STUN: Sent {} bytes from local {:?}",
            bytes_sent,
            self.socket.local_addr().ok()
        );

        // Receive response with timeout
        let mut buf = [0u8; 1024];
        let recv_future = self.socket.recv(&mut buf);

        // Use shorter timeout (2s) for more responsive retries
        match timeout(Duration::from_millis(2000), recv_future).await {
            Ok(Ok(len)) => {
                log::debug!("STUN: Received {} bytes response", len);
                let response = StunMessage::decode(&buf[..len])?;

                // Verify transaction ID matches
                if response.transaction_id != transaction_id {
                    log::warn!("STUN: Transaction ID mismatch");
                    return Err(StunError::TransactionMismatch);
                }

                // Check for error response
                if response.msg_type == StunMessageType::BindingErrorResponse {
                    if let Some((code, reason)) = response.error_code() {
                        log::warn!("STUN: Server error {}: {}", code, reason);
                        return Err(StunError::ServerError(code, reason.to_string()));
                    }
                    return Err(StunError::ServerError(0, "Unknown error".to_string()));
                }

                let mapped_address = response.mapped_address();
                log::debug!(
                    "STUN: Binding successful, mapped address: {:?}",
                    mapped_address
                );

                Ok(StunBindResult {
                    mapped_address,
                    response,
                })
            }
            Ok(Err(e)) => {
                log::warn!("STUN: Socket error: {}", e);
                Err(StunError::Socket(e))
            }
            Err(_) => {
                log::warn!("STUN: Timeout waiting for response");
                Err(StunError::Timeout)
            }
        }
    }

    /// Perform STUN binding with retries (legacy, no MESSAGE-INTEGRITY).
    #[deprecated(note = "Use bind_with_credentials_retries for proper WhatsApp authentication")]
    pub async fn bind_with_retries(
        &self,
        relay_token: &[u8],
        max_retries: u32,
    ) -> Result<StunBindResult, StunError> {
        self.bind_with_credentials_retries(
            &StunCredentials::username_only(relay_token),
            max_retries,
        )
        .await
    }

    /// Perform STUN binding with retries using full credentials.
    ///
    /// This follows WhatsApp Web's ICE authentication:
    /// - USERNAME = auth_token (preferred) or relay_token (ice-ufrag)
    /// - MESSAGE-INTEGRITY = HMAC-SHA1 using relay_key (ice-pwd)
    pub async fn bind_with_credentials_retries(
        &self,
        credentials: &StunCredentials,
        max_retries: u32,
    ) -> Result<StunBindResult, StunError> {
        let mut last_error = StunError::Timeout;

        for attempt in 0..max_retries {
            log::debug!(
                "STUN: Binding attempt {}/{} with {} byte username",
                attempt + 1,
                max_retries,
                credentials.username.len()
            );
            match self.bind_with_credentials(credentials).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    log::debug!("STUN: Attempt {} failed: {}", attempt + 1, e);
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }

    /// Perform a TURN Allocate request (RFC 5766).
    ///
    /// This allocates a relay address on the TURN server. The server will return:
    /// - XOR-RELAYED-ADDRESS: The relay address that the peer should send to
    /// - XOR-MAPPED-ADDRESS: Our public address as seen by the server
    /// - LIFETIME: How long the allocation is valid (in seconds)
    ///
    /// Uses the same credentials as binding (auth_token + relay_key).
    pub async fn allocate_with_credentials(
        &self,
        credentials: &StunCredentials,
    ) -> Result<StunAllocateResult, StunError> {
        let transaction_id = Self::generate_transaction_id();

        // Build allocate request with REQUESTED-TRANSPORT (UDP)
        let mut request =
            StunMessage::allocate_request(transaction_id).with_username(&credentials.username);

        // Add MESSAGE-INTEGRITY if we have an integrity key (relay_key)
        if let Some(ref key) = credentials.integrity_key {
            request = request.with_integrity_key(key);
        }

        let request_bytes = request.encode();

        log::debug!(
            "STUN: Sending allocate request ({} bytes, username {} bytes, integrity={}, tx_id: {:02x}{:02x}{:02x}{:02x}...)",
            request_bytes.len(),
            credentials.username.len(),
            credentials.integrity_key.is_some(),
            transaction_id[0],
            transaction_id[1],
            transaction_id[2],
            transaction_id[3]
        );

        // Send request
        self.socket.send(&request_bytes).await?;

        // Receive response with timeout
        let mut buf = [0u8; 1024];
        let recv_future = self.socket.recv(&mut buf);

        // Use longer timeout (5s) for allocate since server may need time
        match timeout(Duration::from_millis(5000), recv_future).await {
            Ok(Ok(len)) => {
                log::debug!("STUN: Received {} bytes allocate response", len);
                let response = StunMessage::decode(&buf[..len])?;

                // Verify transaction ID matches
                if response.transaction_id != transaction_id {
                    log::warn!("STUN: Transaction ID mismatch in allocate response");
                    return Err(StunError::TransactionMismatch);
                }

                // Check for error response
                if response.msg_type == StunMessageType::AllocateErrorResponse {
                    if let Some((code, reason)) = response.error_code() {
                        log::warn!("STUN: Allocate error {}: {}", code, reason);
                        return Err(StunError::ServerError(code, reason.to_string()));
                    }
                    return Err(StunError::ServerError(
                        0,
                        "Unknown allocate error".to_string(),
                    ));
                }

                let mapped_address = response.mapped_address();
                let relayed_address = response.relayed_address();
                let lifetime = response.lifetime();

                log::debug!(
                    "STUN: Allocate successful, mapped={:?}, relayed={:?}, lifetime={:?}s",
                    mapped_address,
                    relayed_address,
                    lifetime
                );

                Ok(StunAllocateResult {
                    mapped_address,
                    relayed_address,
                    lifetime,
                    response,
                })
            }
            Ok(Err(e)) => {
                log::warn!("STUN: Socket error during allocate: {}", e);
                Err(StunError::Socket(e))
            }
            Err(_) => {
                log::warn!("STUN: Timeout waiting for allocate response");
                Err(StunError::Timeout)
            }
        }
    }

    /// Perform TURN Allocate with retries.
    pub async fn allocate_with_credentials_retries(
        &self,
        credentials: &StunCredentials,
        max_retries: u32,
    ) -> Result<StunAllocateResult, StunError> {
        let mut last_error = StunError::Timeout;

        for attempt in 0..max_retries {
            log::debug!(
                "STUN: Allocate attempt {}/{} with {} byte username",
                attempt + 1,
                max_retries,
                credentials.username.len()
            );
            match self.allocate_with_credentials(credentials).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    log::debug!("STUN: Allocate attempt {} failed: {}", attempt + 1, e);
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }

    /// Classify an incoming packet as STUN Binding, STUN Allocate, or non-STUN.
    ///
    /// This is useful for detecting packet types like WhatsApp Web does for ICE restart logic.
    /// Returns the STUN message type if it's a valid STUN message, None otherwise.
    pub fn classify_packet(data: &[u8]) -> Option<StunMessageType> {
        if data.len() < 2 {
            return None;
        }

        // STUN messages have first 2 bits as 00
        if (data[0] & 0xC0) != 0 {
            return None; // Not a STUN message
        }

        // Extract message type from first 14 bits
        let msg_type = ((data[0] as u16 & 0x3F) << 8) | (data[1] as u16);
        StunMessageType::try_from(msg_type).ok()
    }

    /// Check if a packet is a STUN Allocate message (for ICE restart detection).
    ///
    /// WhatsApp Web uses this to detect when to restart ICE if no RX packets for 10+ seconds.
    pub fn is_allocate_packet(data: &[u8]) -> bool {
        matches!(
            Self::classify_packet(data),
            Some(StunMessageType::AllocateRequest) | Some(StunMessageType::AllocateResponse)
        )
    }

    /// Check if a packet is a STUN Binding message.
    pub fn is_binding_packet(data: &[u8]) -> bool {
        matches!(
            Self::classify_packet(data),
            Some(StunMessageType::BindingRequest) | Some(StunMessageType::BindingResponse)
        )
    }

    /// Check if a packet is any kind of STUN message.
    pub fn is_stun_packet(data: &[u8]) -> bool {
        Self::classify_packet(data).is_some()
    }

    /// Check if a packet is a WhatsApp Ping message (0x0801).
    pub fn is_ping_packet(data: &[u8]) -> bool {
        matches!(
            Self::classify_packet(data),
            Some(StunMessageType::WhatsAppPing)
        )
    }

    /// Check if a packet is a WhatsApp Pong message (0x0802).
    pub fn is_pong_packet(data: &[u8]) -> bool {
        matches!(
            Self::classify_packet(data),
            Some(StunMessageType::WhatsAppPong)
        )
    }

    /// Check if a packet is a WhatsApp Ping or Pong message.
    pub fn is_ping_pong_packet(data: &[u8]) -> bool {
        matches!(
            Self::classify_packet(data),
            Some(StunMessageType::WhatsAppPing) | Some(StunMessageType::WhatsAppPong)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stun_message_encode() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMessage::binding_request(tx_id)
            .with_fingerprint(false)
            .with_priority(None); // Disable PRIORITY for this test
        let encoded = msg.encode();

        // Header: 20 bytes (no FINGERPRINT, no PRIORITY)
        assert_eq!(encoded.len(), 20);

        // Message type: 0x0001
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x01);

        // Message length: 0 (no attributes)
        assert_eq!(encoded[2], 0x00);
        assert_eq!(encoded[3], 0x00);

        // Magic cookie: 0x2112A442
        assert_eq!(encoded[4], 0x21);
        assert_eq!(encoded[5], 0x12);
        assert_eq!(encoded[6], 0xA4);
        assert_eq!(encoded[7], 0x42);

        // Transaction ID
        assert_eq!(&encoded[8..20], &tx_id);
    }

    #[test]
    fn test_stun_message_with_username() {
        let tx_id = [0u8; 12];
        let msg = StunMessage::binding_request(tx_id)
            .with_username(b"test")
            .with_fingerprint(false)
            .with_priority(None); // Disable PRIORITY for this test
        let encoded = msg.encode();

        // Header (20) + Username attr (4 header + 4 data) = 28 bytes (no FINGERPRINT, no PRIORITY)
        assert_eq!(encoded.len(), 28);

        // Message length: 8 (4 byte header + 4 byte data)
        assert_eq!(encoded[2], 0x00);
        assert_eq!(encoded[3], 0x08);
    }

    #[test]
    fn test_stun_message_decode_binding_response() {
        // Construct a minimal binding response
        let mut data = Vec::new();

        // Message type: Binding Response (0x0101)
        data.extend_from_slice(&[0x01, 0x01]);

        // Message length: 12 (XOR-MAPPED-ADDRESS)
        data.extend_from_slice(&[0x00, 0x0c]);

        // Magic cookie
        data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        data.extend_from_slice(&tx_id);

        // XOR-MAPPED-ADDRESS attribute
        // Type: 0x0020
        data.extend_from_slice(&[0x00, 0x20]);
        // Length: 8
        data.extend_from_slice(&[0x00, 0x08]);
        // Reserved + Family (IPv4)
        data.extend_from_slice(&[0x00, 0x01]);
        // Port XOR'd with magic cookie upper bits: 12345 (0x3039) ^ 0x2112 = 0x112B
        data.extend_from_slice(&[0x11, 0x2b]);
        // IPv4 XOR'd: 192.168.1.1 ^ 0x2112A442
        // 192.168.1.1 = 0xC0A80101
        // 0xC0A80101 ^ 0x2112A442 = 0xE1BAA543
        data.extend_from_slice(&[0xe1, 0xba, 0xa5, 0x43]);

        let msg = StunMessage::decode(&data).unwrap();
        assert_eq!(msg.msg_type, StunMessageType::BindingResponse);
        assert_eq!(msg.transaction_id, tx_id);

        let mapped = msg.mapped_address().unwrap();
        assert_eq!(mapped.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(mapped.port(), 12345);
    }

    #[test]
    fn test_transaction_id_generation() {
        let id1 = StunBinder::generate_transaction_id();
        let id2 = StunBinder::generate_transaction_id();

        // IDs should be different (with overwhelming probability)
        assert_ne!(id1, id2);

        // IDs should be 12 bytes
        assert_eq!(id1.len(), 12);
        assert_eq!(id2.len(), 12);
    }

    #[test]
    fn test_stun_message_with_integrity() {
        let tx_id = [0u8; 12];
        let username = b"test-username";
        let integrity_key = b"test-password-key";

        let msg = StunMessage::binding_request(tx_id)
            .with_username(username)
            .with_integrity_key(integrity_key)
            .with_fingerprint(false)
            .with_priority(None); // Disable PRIORITY for this test
        let encoded = msg.encode();

        // Header (20) + Username attr (4 + 13 + 3 padding = 20) + MESSAGE-INTEGRITY (4 + 20 = 24) = 64 bytes
        assert_eq!(encoded.len(), 64);

        // Message length should be 44 (20 + 24)
        let msg_len = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(msg_len, 44);

        // Check MESSAGE-INTEGRITY attribute is present at offset 40 (20 header + 20 username attr)
        let mi_type = u16::from_be_bytes([encoded[40], encoded[41]]);
        assert_eq!(mi_type, StunAttributeType::MessageIntegrity as u16);

        // MESSAGE-INTEGRITY length should be 20
        let mi_len = u16::from_be_bytes([encoded[42], encoded[43]]);
        assert_eq!(mi_len, 20);
    }

    #[test]
    fn test_stun_credentials() {
        let creds1 = StunCredentials::username_only(b"token");
        assert_eq!(creds1.username, b"token");
        assert!(creds1.integrity_key.is_none());

        let creds2 = StunCredentials::with_integrity(b"auth", b"key");
        assert_eq!(creds2.username, b"auth");
        assert_eq!(creds2.integrity_key.as_ref().unwrap(), b"key");
    }

    #[test]
    fn test_allocate_request_encode() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMessage::allocate_request(tx_id)
            .with_fingerprint(false)
            .with_priority(None); // Disable PRIORITY for this test
        let encoded = msg.encode();

        // Message type: 0x0003 (AllocateRequest)
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x03);

        // Magic cookie
        assert_eq!(encoded[4], 0x21);
        assert_eq!(encoded[5], 0x12);
        assert_eq!(encoded[6], 0xA4);
        assert_eq!(encoded[7], 0x42);

        // Should contain REQUESTED-TRANSPORT attribute
        // Header (20) + REQUESTED-TRANSPORT (4 header + 4 data) = 28 bytes (no FINGERPRINT, no PRIORITY)
        assert_eq!(encoded.len(), 28);

        // Check REQUESTED-TRANSPORT attribute at offset 20
        let attr_type = u16::from_be_bytes([encoded[20], encoded[21]]);
        assert_eq!(attr_type, StunAttributeType::RequestedTransport as u16);

        // First byte of data should be UDP (17)
        assert_eq!(encoded[24], 17); // UDP protocol number
    }

    #[test]
    fn test_allocate_response_decode() {
        // Construct an allocate response with XOR-RELAYED-ADDRESS and LIFETIME
        let mut data = Vec::new();

        // Message type: Allocate Response (0x0103)
        data.extend_from_slice(&[0x01, 0x03]);

        // Message length: 24 (XOR-RELAYED-ADDRESS 12 + XOR-MAPPED-ADDRESS 12)
        // But let's just do XOR-RELAYED-ADDRESS (12) + LIFETIME (8)
        data.extend_from_slice(&[0x00, 0x14]); // 20 bytes

        // Magic cookie
        data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        data.extend_from_slice(&tx_id);

        // XOR-RELAYED-ADDRESS attribute (type 0x0016)
        data.extend_from_slice(&[0x00, 0x16]); // Type
        data.extend_from_slice(&[0x00, 0x08]); // Length: 8 bytes (IPv4)
        data.extend_from_slice(&[0x00, 0x01]); // Reserved + Family (IPv4)
        // Port XOR'd: 54321 (0xD431) ^ 0x2112 = 0xF523
        data.extend_from_slice(&[0xF5, 0x23]);
        // IPv4 XOR'd: 10.0.0.1 ^ 0x2112A442
        // 10.0.0.1 = 0x0A000001
        // 0x0A000001 ^ 0x2112A442 = 0x2B12A443
        data.extend_from_slice(&[0x2B, 0x12, 0xA4, 0x43]);

        // LIFETIME attribute (type 0x000D)
        data.extend_from_slice(&[0x00, 0x0D]); // Type
        data.extend_from_slice(&[0x00, 0x04]); // Length: 4 bytes
        data.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]); // 3600 seconds

        let msg = StunMessage::decode(&data).unwrap();
        assert_eq!(msg.msg_type, StunMessageType::AllocateResponse);
        assert_eq!(msg.transaction_id, tx_id);

        // Check relayed address
        let relayed = msg.relayed_address().unwrap();
        assert_eq!(relayed.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(relayed.port(), 54321);

        // Check lifetime
        let lifetime = msg.lifetime().unwrap();
        assert_eq!(lifetime, 3600);
    }

    #[test]
    fn test_classify_packet() {
        // Binding request (0x0001)
        let binding_req = [0x00, 0x01, 0x00, 0x00];
        assert_eq!(
            StunBinder::classify_packet(&binding_req),
            Some(StunMessageType::BindingRequest)
        );

        // Allocate request (0x0003)
        let alloc_req = [0x00, 0x03, 0x00, 0x00];
        assert_eq!(
            StunBinder::classify_packet(&alloc_req),
            Some(StunMessageType::AllocateRequest)
        );

        // Allocate response (0x0103)
        let alloc_resp = [0x01, 0x03, 0x00, 0x00];
        assert_eq!(
            StunBinder::classify_packet(&alloc_resp),
            Some(StunMessageType::AllocateResponse)
        );

        // Non-STUN packet (first 2 bits not 00)
        let rtp_packet = [0x80, 0x60, 0x00, 0x00]; // RTP packet (version 2)
        assert_eq!(StunBinder::classify_packet(&rtp_packet), None);

        // Empty packet
        assert_eq!(StunBinder::classify_packet(&[]), None);
    }

    #[test]
    fn test_is_stun_packet_helpers() {
        // Binding request
        let binding_req = [0x00, 0x01, 0x00, 0x00];
        assert!(StunBinder::is_binding_packet(&binding_req));
        assert!(!StunBinder::is_allocate_packet(&binding_req));
        assert!(StunBinder::is_stun_packet(&binding_req));

        // Allocate request
        let alloc_req = [0x00, 0x03, 0x00, 0x00];
        assert!(!StunBinder::is_binding_packet(&alloc_req));
        assert!(StunBinder::is_allocate_packet(&alloc_req));
        assert!(StunBinder::is_stun_packet(&alloc_req));

        // RTP packet
        let rtp = [0x80, 0x60, 0x00, 0x00];
        assert!(!StunBinder::is_binding_packet(&rtp));
        assert!(!StunBinder::is_allocate_packet(&rtp));
        assert!(!StunBinder::is_stun_packet(&rtp));
    }

    #[test]
    fn test_stun_message_helpers() {
        // Create an error response
        let mut data = Vec::new();
        data.extend_from_slice(&[0x01, 0x13]); // AllocateErrorResponse (0x0113)
        data.extend_from_slice(&[0x00, 0x08]); // Message length: 8
        data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        data.extend_from_slice(&[0; 12]); // Transaction ID
        // ERROR-CODE attribute
        data.extend_from_slice(&[0x00, 0x09]); // Type
        data.extend_from_slice(&[0x00, 0x04]); // Length
        data.extend_from_slice(&[0x00, 0x00, 0x04, 0x01]); // Error 401

        let msg = StunMessage::decode(&data).unwrap();
        assert!(msg.is_error());
        assert!(!msg.is_success());

        // Success response
        let mut data = Vec::new();
        data.extend_from_slice(&[0x01, 0x03]); // AllocateResponse (0x0103)
        data.extend_from_slice(&[0x00, 0x00]); // No attributes
        data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        data.extend_from_slice(&[0; 12]); // Transaction ID

        let msg = StunMessage::decode(&data).unwrap();
        assert!(!msg.is_error());
        assert!(msg.is_success());
    }

    #[test]
    fn test_refresh_request_encode() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMessage::refresh_request(tx_id, 600).with_fingerprint(false);
        let encoded = msg.encode();

        // Message type: 0x0004 (RefreshRequest)
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x04);

        // Should contain LIFETIME attribute
        // Header (20) + LIFETIME (4 header + 4 data) = 28 bytes (no FINGERPRINT)
        assert_eq!(encoded.len(), 28);

        // Check LIFETIME attribute at offset 20
        let attr_type = u16::from_be_bytes([encoded[20], encoded[21]]);
        assert_eq!(attr_type, StunAttributeType::Lifetime as u16);

        // Lifetime value should be 600
        let lifetime = u32::from_be_bytes([encoded[24], encoded[25], encoded[26], encoded[27]]);
        assert_eq!(lifetime, 600);
    }

    #[test]
    fn test_allocate_request_with_credentials() {
        let tx_id = [0u8; 12];
        let msg = StunMessage::allocate_request(tx_id)
            .with_username(b"test-user")
            .with_integrity_key(b"test-key")
            .with_fingerprint(false)
            .with_priority(None); // Disable PRIORITY for this test
        let encoded = msg.encode();

        // Should contain:
        // - Header (20)
        // - REQUESTED-TRANSPORT (4 + 4 = 8)
        // - USERNAME (4 + 9 + 3 padding = 16)
        // - MESSAGE-INTEGRITY (4 + 20 = 24)
        // Total: 68 bytes (no FINGERPRINT, no PRIORITY)
        assert_eq!(encoded.len(), 68);

        // Message type should be AllocateRequest
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x03);
    }

    #[test]
    fn test_stun_message_with_fingerprint() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMessage::binding_request(tx_id).with_priority(None); // Disable PRIORITY for this test, FINGERPRINT enabled by default
        let encoded = msg.encode();

        // Header (20) + FINGERPRINT (8) = 28 bytes (no PRIORITY)
        assert_eq!(encoded.len(), 28);

        // Message length should be 8 (FINGERPRINT only)
        let msg_len = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(msg_len, 8);

        // Check FINGERPRINT attribute at offset 20
        let attr_type = u16::from_be_bytes([encoded[20], encoded[21]]);
        assert_eq!(attr_type, StunAttributeType::Fingerprint as u16);

        // FINGERPRINT length should be 4
        let fp_len = u16::from_be_bytes([encoded[22], encoded[23]]);
        assert_eq!(fp_len, 4);
    }

    #[test]
    fn test_stun_message_with_integrity_and_fingerprint() {
        let tx_id = [0u8; 12];
        let username = b"test";
        let integrity_key = b"key";

        let msg = StunMessage::binding_request(tx_id)
            .with_username(username)
            .with_integrity_key(integrity_key)
            .with_priority(None); // Disable PRIORITY, FINGERPRINT enabled by default
        let encoded = msg.encode();

        // Header (20) + USERNAME (4+4=8) + MESSAGE-INTEGRITY (4+20=24) + FINGERPRINT (8) = 60 bytes (no PRIORITY)
        assert_eq!(encoded.len(), 60);

        // Message length should be 40 (8 + 24 + 8)
        let msg_len = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(msg_len, 40);

        // Check FINGERPRINT is the last attribute
        let fp_type = u16::from_be_bytes([encoded[52], encoded[53]]);
        assert_eq!(fp_type, StunAttributeType::Fingerprint as u16);
    }

    #[test]
    fn test_stun_message_with_priority() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMessage::binding_request(tx_id).with_fingerprint(false); // Keep PRIORITY enabled by default
        let encoded = msg.encode();

        // Header (20) + PRIORITY (4 header + 4 data = 8) = 28 bytes
        assert_eq!(encoded.len(), 28);

        // Message length should be 8 (PRIORITY only)
        let msg_len = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(msg_len, 8);

        // Check PRIORITY attribute at offset 20
        let attr_type = u16::from_be_bytes([encoded[20], encoded[21]]);
        assert_eq!(attr_type, StunAttributeType::Priority as u16);

        // PRIORITY length should be 4
        let pri_len = u16::from_be_bytes([encoded[22], encoded[23]]);
        assert_eq!(pri_len, 4);

        // Check PRIORITY value is the default (16777215 = 0x00FFFFFF)
        let priority = u32::from_be_bytes([encoded[24], encoded[25], encoded[26], encoded[27]]);
        assert_eq!(priority, DEFAULT_ICE_PRIORITY);
    }

    #[test]
    fn test_stun_message_with_priority_and_fingerprint() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMessage::binding_request(tx_id); // Both PRIORITY and FINGERPRINT enabled by default
        let encoded = msg.encode();

        // Header (20) + PRIORITY (8) + FINGERPRINT (8) = 36 bytes
        assert_eq!(encoded.len(), 36);

        // Message length should be 16 (PRIORITY + FINGERPRINT)
        let msg_len = u16::from_be_bytes([encoded[2], encoded[3]]);
        assert_eq!(msg_len, 16);

        // Check PRIORITY attribute at offset 20
        let attr_type = u16::from_be_bytes([encoded[20], encoded[21]]);
        assert_eq!(attr_type, StunAttributeType::Priority as u16);

        // Check FINGERPRINT is the last attribute at offset 28
        let fp_type = u16::from_be_bytes([encoded[28], encoded[29]]);
        assert_eq!(fp_type, StunAttributeType::Fingerprint as u16);
    }
}
