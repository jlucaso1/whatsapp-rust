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
//! # Phase 2 Integration
//!
//! This module provides foundational types for Phase 2 WebRTC/ICE integration.
//! The actual ICE candidate handling will be implemented using the `webrtc` crate.

use super::error::CallError;

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

/// Parsed transport payload containing ICE candidates.
#[derive(Debug, Clone, Default)]
pub struct TransportPayload {
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
    /// The actual binary format will be determined through reverse engineering.
    /// This is a placeholder that returns an empty payload.
    ///
    /// # Arguments
    /// * `_data` - The binary payload from the transport stanza
    ///
    /// # Returns
    /// The parsed transport payload (currently empty - Phase 2 implementation)
    pub fn parse(_data: &[u8]) -> Result<Self, CallError> {
        // TODO: Implement actual parsing when binary format is understood
        // The transport payload format needs to be reverse engineered from
        // WhatsApp Web's VoIP implementation
        Ok(Self::new())
    }

    /// Serialize transport payload to binary data.
    ///
    /// The actual binary format will be determined through reverse engineering.
    /// This is a placeholder that returns an empty vector.
    ///
    /// # Returns
    /// The serialized binary payload (currently empty - Phase 2 implementation)
    pub fn serialize(&self) -> Vec<u8> {
        // TODO: Implement actual serialization when binary format is understood
        Vec::new()
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
}
