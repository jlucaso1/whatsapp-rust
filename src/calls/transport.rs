//! Transport payload parsing for ICE candidates.
//!
//! This module handles parsing and building transport stanzas used for
//! ICE (Interactive Connectivity Establishment) candidate exchange.
//!
//! # Protocol
//!
//! Transport stanzas are exchanged between call participants to share
//! ICE candidates for establishing peer-to-peer connectivity.
//!
//! ```xml
//! <call to="peer@lid">
//!   <transport call-id="..." call-creator="...">
//!     <!-- Binary payload containing ICE candidates -->
//!   </transport>
//! </call>
//! ```
//!
//! # Architecture
//!
//! The transport payload is typically binary data passed to the WASM module.
//! This module provides:
//! - Raw byte storage for passthrough to external media handlers
//! - Port constants for WhatsApp relay servers
//! - ICE candidate types for future WebRTC integration

use super::error::CallError;
use serde::{Deserialize, Serialize};

/// WhatsApp relay server port (SCTP over DTLS)
pub const WHATSAPP_RELAY_PORT: u16 = 3480;

/// Standard TURN server port
pub const TURN_RELAY_PORT: u16 = 3478;

/// An ICE candidate received from or to be sent to a peer.
///
/// This represents a single ICE candidate as used in WebRTC.
/// The format follows RFC 5245.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidate {
    /// The candidate string (e.g., "candidate:1 1 UDP 2130706431 192.168.1.1 8888 typ host")
    pub candidate: String,
    /// SDP media stream identification (e.g., "0" for audio)
    pub sdp_mid: Option<String>,
    /// SDP media line index
    pub sdp_m_line_index: Option<u16>,
    /// Username fragment for ICE
    pub username_fragment: Option<String>,
}

impl IceCandidate {
    /// Create a new ICE candidate.
    pub fn new(candidate: impl Into<String>) -> Self {
        Self {
            candidate: candidate.into(),
            sdp_mid: None,
            sdp_m_line_index: None,
            username_fragment: None,
        }
    }

    /// Set the SDP media ID.
    pub fn with_sdp_mid(mut self, sdp_mid: impl Into<String>) -> Self {
        self.sdp_mid = Some(sdp_mid.into());
        self
    }

    /// Set the SDP media line index.
    pub fn with_sdp_m_line_index(mut self, index: u16) -> Self {
        self.sdp_m_line_index = Some(index);
        self
    }

    /// Set the username fragment.
    pub fn with_username_fragment(mut self, ufrag: impl Into<String>) -> Self {
        self.username_fragment = Some(ufrag.into());
        self
    }
}

/// JSON representation of transport data (for potential JSON payloads).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ufrag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pwd: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<TransportCandidateJson>,
}

/// JSON representation of an ICE candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportCandidateJson {
    pub candidate: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_mid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sdp_m_line_index: Option<u16>,
}

/// Parsed transport payload containing ICE candidates.
#[derive(Debug, Clone, Default)]
pub struct TransportPayload {
    /// Raw binary payload (for passthrough to external media handler)
    pub raw_data: Vec<u8>,
    /// ICE candidates from the transport stanza
    pub candidates: Vec<IceCandidate>,
    /// ICE username fragment (local ufrag)
    pub ufrag: Option<String>,
    /// ICE password
    pub pwd: Option<String>,
}

impl TransportPayload {
    /// Create an empty transport payload.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a transport payload from raw bytes.
    pub fn from_raw(data: Vec<u8>) -> Self {
        // Try to parse as JSON if it looks like JSON
        let (ufrag, pwd, candidates) = if data.first() == Some(&b'{')
            && let Ok(json) = serde_json::from_slice::<TransportJson>(&data)
        {
            let candidates = json
                .candidates
                .into_iter()
                .map(|c| {
                    let mut candidate = IceCandidate::new(c.candidate);
                    if let Some(mid) = c.sdp_mid {
                        candidate = candidate.with_sdp_mid(mid);
                    }
                    if let Some(idx) = c.sdp_m_line_index {
                        candidate = candidate.with_sdp_m_line_index(idx);
                    }
                    candidate
                })
                .collect();
            (json.ufrag, json.pwd, candidates)
        } else {
            (None, None, Vec::new())
        };

        Self {
            raw_data: data,
            candidates,
            ufrag,
            pwd,
        }
    }

    /// Add an ICE candidate.
    pub fn add_candidate(&mut self, candidate: IceCandidate) {
        self.candidates.push(candidate);
    }

    /// Set ICE credentials.
    pub fn set_credentials(&mut self, ufrag: String, pwd: String) {
        self.ufrag = Some(ufrag);
        self.pwd = Some(pwd);
    }

    /// Parse transport payload from binary data.
    ///
    /// The transport payload is stored as raw bytes for passthrough to external
    /// media handlers (WASM/WebRTC). If the data appears to be JSON, it will
    /// also attempt to parse ICE candidates.
    ///
    /// # Arguments
    /// * `data` - The binary payload from the transport stanza
    ///
    /// # Returns
    /// The parsed transport payload with raw_data preserved
    pub fn parse(data: &[u8]) -> Result<Self, CallError> {
        Ok(Self::from_raw(data.to_vec()))
    }

    /// Serialize transport payload to binary data.
    ///
    /// If raw_data is present, returns it directly. Otherwise serializes
    /// ICE candidates as JSON.
    ///
    /// # Returns
    /// The serialized binary payload
    pub fn serialize(&self) -> Vec<u8> {
        // If we have raw data, return it
        if !self.raw_data.is_empty() {
            return self.raw_data.clone();
        }

        // Otherwise serialize as JSON
        let json = TransportJson {
            ufrag: self.ufrag.clone(),
            pwd: self.pwd.clone(),
            candidates: self
                .candidates
                .iter()
                .map(|c| TransportCandidateJson {
                    candidate: c.candidate.clone(),
                    sdp_mid: c.sdp_mid.clone(),
                    sdp_m_line_index: c.sdp_m_line_index,
                })
                .collect(),
        };
        serde_json::to_vec(&json).unwrap_or_default()
    }

    /// Get the raw data for passthrough to external media handler.
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw_data
    }

    /// Check if payload has raw data.
    pub fn has_raw_data(&self) -> bool {
        !self.raw_data.is_empty()
    }
}

/// ICE candidate type (RFC 5245).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    /// Direct host candidate
    Host,
    /// Server reflexive (STUN) candidate
    ServerReflexive,
    /// Peer reflexive candidate
    PeerReflexive,
    /// Relay (TURN) candidate
    Relay,
}

impl CandidateType {
    /// Convert to string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::ServerReflexive => "srflx",
            Self::PeerReflexive => "prflx",
            Self::Relay => "relay",
        }
    }
}

impl std::str::FromStr for CandidateType {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "host" => Ok(Self::Host),
            "srflx" => Ok(Self::ServerReflexive),
            "prflx" => Ok(Self::PeerReflexive),
            "relay" => Ok(Self::Relay),
            _ => Err(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ice_candidate_builder() {
        let candidate = IceCandidate::new("candidate:1 1 UDP 2130706431 192.168.1.1 8888 typ host")
            .with_sdp_mid("0")
            .with_sdp_m_line_index(0)
            .with_username_fragment("abc123");

        assert!(candidate.candidate.starts_with("candidate:"));
        assert_eq!(candidate.sdp_mid, Some("0".to_string()));
        assert_eq!(candidate.sdp_m_line_index, Some(0));
        assert_eq!(candidate.username_fragment, Some("abc123".to_string()));
    }

    #[test]
    fn test_transport_payload() {
        let mut payload = TransportPayload::new();
        payload.set_credentials("ufrag123".to_string(), "pwd456".to_string());
        payload.add_candidate(IceCandidate::new(
            "candidate:1 1 UDP 2130706431 192.168.1.1 8888 typ host",
        ));

        assert_eq!(payload.candidates.len(), 1);
        assert_eq!(payload.ufrag, Some("ufrag123".to_string()));
        assert_eq!(payload.pwd, Some("pwd456".to_string()));
    }

    #[test]
    fn test_candidate_type_parsing() {
        assert_eq!("host".parse(), Ok(CandidateType::Host));
        assert_eq!("srflx".parse(), Ok(CandidateType::ServerReflexive));
        assert_eq!("prflx".parse(), Ok(CandidateType::PeerReflexive));
        assert_eq!("relay".parse(), Ok(CandidateType::Relay));
        assert!("unknown".parse::<CandidateType>().is_err());
    }

    #[test]
    fn test_candidate_type_as_str() {
        assert_eq!(CandidateType::Host.as_str(), "host");
        assert_eq!(CandidateType::ServerReflexive.as_str(), "srflx");
        assert_eq!(CandidateType::PeerReflexive.as_str(), "prflx");
        assert_eq!(CandidateType::Relay.as_str(), "relay");
    }

    #[test]
    fn test_transport_json_parsing() {
        let json = r#"{"ufrag":"abc123","pwd":"secret456","candidates":[{"candidate":"candidate:1 1 UDP 2130706431 192.168.1.1 8888 typ host","sdp_mid":"0","sdp_m_line_index":0}]}"#;
        let payload = TransportPayload::from_raw(json.as_bytes().to_vec());

        assert_eq!(payload.ufrag, Some("abc123".to_string()));
        assert_eq!(payload.pwd, Some("secret456".to_string()));
        assert_eq!(payload.candidates.len(), 1);
        assert!(payload.candidates[0].candidate.contains("192.168.1.1"));
        assert_eq!(payload.candidates[0].sdp_mid, Some("0".to_string()));
        assert_eq!(payload.candidates[0].sdp_m_line_index, Some(0));
    }

    #[test]
    fn test_transport_json_roundtrip() {
        let mut payload = TransportPayload::new();
        payload.set_credentials("ufrag_test".to_string(), "pwd_test".to_string());
        payload.add_candidate(
            IceCandidate::new("candidate:1 1 UDP 2130706431 10.0.0.1 3480 typ host")
                .with_sdp_mid("audio")
                .with_sdp_m_line_index(0),
        );

        let serialized = payload.serialize();
        let reparsed = TransportPayload::from_raw(serialized);

        assert_eq!(reparsed.ufrag, Some("ufrag_test".to_string()));
        assert_eq!(reparsed.pwd, Some("pwd_test".to_string()));
        assert_eq!(reparsed.candidates.len(), 1);
        assert!(reparsed.candidates[0].candidate.contains("10.0.0.1"));
    }

    #[test]
    fn test_transport_non_json_passthrough() {
        // Non-JSON binary data should be stored as raw_data
        let binary = vec![0x00, 0x01, 0x02, 0x03, 0xFF];
        let payload = TransportPayload::from_raw(binary.clone());

        assert!(payload.candidates.is_empty());
        assert_eq!(payload.raw_data, binary);
        assert!(payload.has_raw_data());
    }

    #[test]
    fn test_port_constants() {
        assert_eq!(WHATSAPP_RELAY_PORT, 3480);
        assert_eq!(TURN_RELAY_PORT, 3478);
    }
}
