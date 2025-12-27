//! Call signaling type definitions.
//!
//! These match the `WAWebVoipSignalingEnums` from the WhatsApp Web client.
//! There are 26 signaling types used for call control.

use std::fmt;

/// Signaling message types for call control.
///
/// These are sent as child tags of the `<call>` stanza.
/// Each type serves a specific purpose in the call lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(u8)]
pub enum SignalingType {
    /// No type / invalid (internal use).
    #[default]
    None = 0,

    /// Initial call offer sent to recipient.
    /// Contains call metadata and optional `<video/>` child for video calls.
    Offer = 1,

    /// Acknowledgment that offer was received by recipient.
    OfferReceipt = 2,

    /// Call accepted by recipient.
    /// Triggers media connection establishment.
    Accept = 3,

    /// Call rejected by recipient.
    /// Includes rejection reason in attributes.
    Reject = 4,

    /// Call ended / terminated.
    /// Can be sent by either party at any time.
    Terminate = 5,

    /// ICE candidates / transport information.
    /// Contains serialized ICE candidates for connectivity.
    Transport = 6,

    /// Acknowledgment of offer processing.
    OfferAck = 7,

    /// Negative acknowledgment of offer (error case).
    OfferNack = 8,

    /// Relay server latency measurement.
    /// Used for TURN server selection.
    RelayLatency = 9,

    /// Relay server selection result.
    RelayElection = 10,

    /// Call interruption event (e.g., incoming GSM call).
    Interruption = 11,

    /// Audio/video mute state change.
    /// Contains `audio` and/or `video` attributes.
    Mute = 12,

    /// Pre-acceptance signaling (preparing to accept).
    PreAccept = 13,

    /// Acknowledgment of accept message.
    AcceptReceipt = 14,

    /// Video on/off state change.
    /// Separate from mute for granular control.
    VideoState = 15,

    /// General notification.
    Notify = 16,

    /// Group call participant information.
    /// Contains list of participants and their states.
    GroupInfo = 17,

    /// E2EE key renegotiation for call encryption.
    /// Contains Signal-encrypted call encryption key.
    EncRekey = 18,

    /// Peer connection state update.
    PeerState = 19,

    /// Acknowledgment of video state change.
    VideoStateAck = 20,

    /// Media flow control (e.g., congestion).
    FlowControl = 21,

    /// Web client specific signaling.
    WebClient = 22,

    /// Acknowledgment of accept message.
    AcceptAck = 23,

    /// Group call membership update.
    GroupUpdate = 24,

    /// Incoming call notification (push notification trigger).
    /// Special notification for waking up receiving client.
    OfferNotice = 25,
}

impl SignalingType {
    /// All signaling types in order.
    pub const ALL: [SignalingType; 26] = [
        Self::None,
        Self::Offer,
        Self::OfferReceipt,
        Self::Accept,
        Self::Reject,
        Self::Terminate,
        Self::Transport,
        Self::OfferAck,
        Self::OfferNack,
        Self::RelayLatency,
        Self::RelayElection,
        Self::Interruption,
        Self::Mute,
        Self::PreAccept,
        Self::AcceptReceipt,
        Self::VideoState,
        Self::Notify,
        Self::GroupInfo,
        Self::EncRekey,
        Self::PeerState,
        Self::VideoStateAck,
        Self::FlowControl,
        Self::WebClient,
        Self::AcceptAck,
        Self::GroupUpdate,
        Self::OfferNotice,
    ];

    /// Get the tag name used in binary protocol stanzas.
    pub const fn tag_name(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Offer => "offer",
            Self::OfferReceipt => "offer_receipt",
            Self::Accept => "accept",
            Self::Reject => "reject",
            Self::Terminate => "terminate",
            Self::Transport => "transport",
            Self::OfferAck => "offer_ack",
            Self::OfferNack => "offer_nack",
            Self::RelayLatency => "relaylatency",
            Self::RelayElection => "relay_election",
            Self::Interruption => "interruption",
            Self::Mute => "mute",
            Self::PreAccept => "preaccept",
            Self::AcceptReceipt => "accept_receipt",
            Self::VideoState => "video_state",
            Self::Notify => "notify",
            Self::GroupInfo => "group_info",
            Self::EncRekey => "enc_rekey",
            Self::PeerState => "peer_state",
            Self::VideoStateAck => "video_state_ack",
            Self::FlowControl => "flow_control",
            Self::WebClient => "web_client",
            Self::AcceptAck => "accept_ack",
            Self::GroupUpdate => "group_update",
            Self::OfferNotice => "offer_notice",
        }
    }

    /// Parse from tag name (case-insensitive).
    pub fn from_tag(tag: &str) -> Option<Self> {
        match tag.to_lowercase().as_str() {
            "none" => Some(Self::None),
            "offer" => Some(Self::Offer),
            "offer_receipt" => Some(Self::OfferReceipt),
            "accept" => Some(Self::Accept),
            "reject" => Some(Self::Reject),
            "terminate" => Some(Self::Terminate),
            "transport" => Some(Self::Transport),
            "offer_ack" => Some(Self::OfferAck),
            "offer_nack" => Some(Self::OfferNack),
            "relaylatency" => Some(Self::RelayLatency),
            "relay_election" => Some(Self::RelayElection),
            "interruption" => Some(Self::Interruption),
            "mute" => Some(Self::Mute),
            "preaccept" => Some(Self::PreAccept),
            "accept_receipt" => Some(Self::AcceptReceipt),
            "video_state" => Some(Self::VideoState),
            "notify" => Some(Self::Notify),
            "group_info" => Some(Self::GroupInfo),
            "enc_rekey" => Some(Self::EncRekey),
            "peer_state" => Some(Self::PeerState),
            "video_state_ack" => Some(Self::VideoStateAck),
            "flow_control" => Some(Self::FlowControl),
            "web_client" => Some(Self::WebClient),
            "accept_ack" => Some(Self::AcceptAck),
            "group_update" => Some(Self::GroupUpdate),
            "offer_notice" => Some(Self::OfferNotice),
            _ => None,
        }
    }

    /// Parse from numeric value.
    pub fn from_u8(value: u8) -> Option<Self> {
        Self::ALL.get(value as usize).copied()
    }

    /// Whether this signaling type requires a `<receipt>` response.
    ///
    /// Receipt responses include a nested child with call-id and call-creator.
    /// Based on WhatsApp Web JS: OFFER, ACCEPT, REJECT, ENC_REKEY send receipts.
    pub const fn requires_receipt(&self) -> bool {
        matches!(
            self,
            Self::Offer | Self::Accept | Self::Reject | Self::EncRekey
        )
    }

    /// Whether this signaling type requires a simple `<ack>` response.
    ///
    /// Based on WhatsApp Web JS: ALL types except receipt types get an ack.
    /// The JS code uses a default case that sends ack for any non-receipt type.
    pub const fn requires_ack(&self) -> bool {
        // All types except None and receipt types get an ack
        !matches!(
            self,
            Self::None | Self::Offer | Self::Accept | Self::Reject | Self::EncRekey
        )
    }

    /// Whether this is a critical signaling type that affects call state.
    pub const fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::Offer | Self::Accept | Self::Reject | Self::Terminate | Self::EncRekey
        )
    }

    /// Get the response type for this signaling type.
    pub const fn response_type(&self) -> Option<ResponseType> {
        if self.requires_receipt() {
            Some(ResponseType::Receipt)
        } else if self.requires_ack() {
            Some(ResponseType::Ack)
        } else {
            None
        }
    }
}

impl fmt::Display for SignalingType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.tag_name().to_uppercase())
    }
}

/// Type of response required for a signaling message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseType {
    /// Simple acknowledgment: `<ack class="call" type="{tag}">`.
    Ack,
    /// Full receipt: `<receipt><{tag} call-id="..." call-creator="..."/></receipt>`.
    Receipt,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signaling_type_roundtrip() {
        for st in SignalingType::ALL {
            let tag = st.tag_name();
            let parsed = SignalingType::from_tag(tag).unwrap();
            assert_eq!(st, parsed, "Failed roundtrip for {:?}", st);
        }
    }

    #[test]
    fn test_signaling_type_from_u8() {
        for (i, st) in SignalingType::ALL.iter().enumerate() {
            let parsed = SignalingType::from_u8(i as u8).unwrap();
            assert_eq!(*st, parsed);
        }
        assert!(SignalingType::from_u8(26).is_none());
    }

    #[test]
    fn test_critical_types() {
        assert!(SignalingType::Offer.is_critical());
        assert!(SignalingType::Accept.is_critical());
        assert!(SignalingType::Terminate.is_critical());
        assert!(!SignalingType::Transport.is_critical());
        assert!(!SignalingType::Mute.is_critical());
    }

    #[test]
    fn test_response_types() {
        // Receipt types (as per WhatsApp Web JS)
        assert_eq!(
            SignalingType::Offer.response_type(),
            Some(ResponseType::Receipt)
        );
        assert_eq!(
            SignalingType::Accept.response_type(),
            Some(ResponseType::Receipt)
        );
        assert_eq!(
            SignalingType::Reject.response_type(),
            Some(ResponseType::Receipt)
        );
        assert_eq!(
            SignalingType::EncRekey.response_type(),
            Some(ResponseType::Receipt)
        );

        // Ack types (all others except None)
        assert_eq!(
            SignalingType::Transport.response_type(),
            Some(ResponseType::Ack)
        );
        assert_eq!(SignalingType::Mute.response_type(), Some(ResponseType::Ack));
        assert_eq!(
            SignalingType::Terminate.response_type(),
            Some(ResponseType::Ack)
        );
        assert_eq!(
            SignalingType::GroupInfo.response_type(),
            Some(ResponseType::Ack)
        );

        // None type returns None
        assert_eq!(SignalingType::None.response_type(), None);
    }

    #[test]
    fn test_display() {
        assert_eq!(SignalingType::Offer.to_string(), "OFFER");
        assert_eq!(SignalingType::EncRekey.to_string(), "ENC_REKEY");
    }

    /// Test signaling type values match WAWebVoipSignalingEnums exactly.
    /// From captured WhatsApp Web JS:
    /// ```javascript
    /// TYPE = {
    ///   NONE: 0, OFFER: 1, OFFER_RECEIPT: 2, ACCEPT: 3, REJECT: 4,
    ///   TERMINATE: 5, TRANSPORT: 6, OFFER_ACK: 7, OFFER_NACK: 8,
    ///   RELAY_LATENCY: 9, RELAY_ELECTION: 10, INTERRUPTION: 11, MUTE: 12,
    ///   PREACCEPT: 13, ACCEPT_RECEIPT: 14, VIDEO_STATE: 15, NOTIFY: 16,
    ///   GROUP_INFO: 17, ENC_REKEY: 18, PEER_STATE: 19, VIDEO_STATE_ACK: 20,
    ///   FLOW_CONTROL: 21, WEB_CLIENT: 22, ACCEPT_ACK: 23, GROUP_UPDATE: 24,
    ///   OFFER_NOTICE: 25, MAX: 26
    /// }
    /// ```
    #[test]
    fn test_signaling_type_values_match_js_enum() {
        assert_eq!(SignalingType::None as u8, 0);
        assert_eq!(SignalingType::Offer as u8, 1);
        assert_eq!(SignalingType::OfferReceipt as u8, 2);
        assert_eq!(SignalingType::Accept as u8, 3);
        assert_eq!(SignalingType::Reject as u8, 4);
        assert_eq!(SignalingType::Terminate as u8, 5);
        assert_eq!(SignalingType::Transport as u8, 6);
        assert_eq!(SignalingType::OfferAck as u8, 7);
        assert_eq!(SignalingType::OfferNack as u8, 8);
        assert_eq!(SignalingType::RelayLatency as u8, 9);
        assert_eq!(SignalingType::RelayElection as u8, 10);
        assert_eq!(SignalingType::Interruption as u8, 11);
        assert_eq!(SignalingType::Mute as u8, 12);
        assert_eq!(SignalingType::PreAccept as u8, 13);
        assert_eq!(SignalingType::AcceptReceipt as u8, 14);
        assert_eq!(SignalingType::VideoState as u8, 15);
        assert_eq!(SignalingType::Notify as u8, 16);
        assert_eq!(SignalingType::GroupInfo as u8, 17);
        assert_eq!(SignalingType::EncRekey as u8, 18);
        assert_eq!(SignalingType::PeerState as u8, 19);
        assert_eq!(SignalingType::VideoStateAck as u8, 20);
        assert_eq!(SignalingType::FlowControl as u8, 21);
        assert_eq!(SignalingType::WebClient as u8, 22);
        assert_eq!(SignalingType::AcceptAck as u8, 23);
        assert_eq!(SignalingType::GroupUpdate as u8, 24);
        assert_eq!(SignalingType::OfferNotice as u8, 25);

        // Verify we have exactly 26 types (MAX in JS)
        assert_eq!(SignalingType::ALL.len(), 26);
    }

    /// Test tag names match binary protocol dictionary tokens.
    /// Some tokens are in the dictionary, others are sent as literal strings.
    #[test]
    fn test_tag_names_match_protocol() {
        // These must match the binary protocol dictionary exactly
        assert_eq!(SignalingType::Offer.tag_name(), "offer");
        assert_eq!(SignalingType::Accept.tag_name(), "accept");
        assert_eq!(SignalingType::Reject.tag_name(), "reject");
        assert_eq!(SignalingType::Terminate.tag_name(), "terminate");
        assert_eq!(SignalingType::Transport.tag_name(), "transport");
        assert_eq!(SignalingType::PreAccept.tag_name(), "preaccept");
        assert_eq!(SignalingType::Mute.tag_name(), "mute");
        assert_eq!(SignalingType::Notify.tag_name(), "notify");
        assert_eq!(SignalingType::GroupInfo.tag_name(), "group_info");
        assert_eq!(SignalingType::EncRekey.tag_name(), "enc_rekey");
        assert_eq!(SignalingType::GroupUpdate.tag_name(), "group_update");

        // relaylatency has no underscore (matches binary dictionary)
        assert_eq!(SignalingType::RelayLatency.tag_name(), "relaylatency");
    }

    /// Test call flow signaling types for outgoing call.
    /// Expected flow: OFFER → PREACCEPT → TRANSPORT → ACCEPT → ACCEPT_ACK → (media) → TERMINATE
    #[test]
    fn test_outgoing_call_flow_types() {
        let flow = [
            SignalingType::Offer,     // 1. Caller sends offer
            SignalingType::PreAccept, // 2. Callee acknowledges ringing
            SignalingType::Transport, // 3. ICE candidates exchange
            SignalingType::Accept,    // 4. Callee accepts
            SignalingType::AcceptAck, // 5. Caller acknowledges accept
            SignalingType::Terminate, // 6. Either party ends call
        ];

        // All flow types should be parseable
        for st in flow {
            let tag = st.tag_name();
            let parsed = SignalingType::from_tag(tag).unwrap();
            assert_eq!(st, parsed);
        }

        // Critical types in flow
        assert!(SignalingType::Offer.is_critical());
        assert!(SignalingType::Accept.is_critical());
        assert!(SignalingType::Terminate.is_critical());
    }

    /// Test rejection flow signaling types.
    /// Expected flow: OFFER → REJECT
    #[test]
    fn test_rejection_flow_types() {
        assert!(SignalingType::Offer.is_critical());
        assert!(SignalingType::Reject.is_critical());

        // Both require receipt response
        assert_eq!(
            SignalingType::Offer.response_type(),
            Some(ResponseType::Receipt)
        );
        assert_eq!(
            SignalingType::Reject.response_type(),
            Some(ResponseType::Receipt)
        );
    }

    /// Test all ack types get ack response (matches JS default case).
    #[test]
    fn test_all_non_receipt_types_get_ack() {
        let receipt_types = [
            SignalingType::Offer,
            SignalingType::Accept,
            SignalingType::Reject,
            SignalingType::EncRekey,
        ];

        for st in SignalingType::ALL {
            if st == SignalingType::None {
                assert_eq!(st.response_type(), None);
            } else if receipt_types.contains(&st) {
                assert_eq!(st.response_type(), Some(ResponseType::Receipt));
            } else {
                assert_eq!(
                    st.response_type(),
                    Some(ResponseType::Ack),
                    "{:?} should require ACK",
                    st
                );
            }
        }
    }
}
