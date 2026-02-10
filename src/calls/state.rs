//! Call state machine implementation.

use chrono::{DateTime, Utc};
use serde::Serialize;
use wacore::types::call::{CallDirection, CallId, CallMediaType, CallType, EndCallReason};
use wacore_binary::jid::Jid;

use super::encryption::{CallEncryptionKey, DerivedCallKeys, derive_call_keys};
use super::stanza::{MediaParams, OfferEncData, RelayData, TransportParams};

/// Current state of a call.
#[derive(Debug, Clone, Serialize, Default)]
pub enum CallState {
    /// Outgoing call: initializing before offer sent.
    #[default]
    Initiating,
    /// Outgoing call: offer sent, waiting for response.
    Ringing { offer_sent_at: DateTime<Utc> },
    /// Incoming call: ringing locally.
    IncomingRinging {
        received_at: DateTime<Utc>,
        silenced: bool,
    },
    /// Call accepted, establishing media connection.
    Connecting { accepted_at: DateTime<Utc> },
    /// Call active with media flowing.
    Active {
        connected_at: DateTime<Utc>,
        audio_muted: bool,
        video_off: bool,
    },
    /// Call on hold.
    OnHold {
        held_at: DateTime<Utc>,
        connected_at: DateTime<Utc>,
        audio_muted: bool,
        video_off: bool,
    },
    /// Call ended.
    Ended {
        reason: EndCallReason,
        ended_at: DateTime<Utc>,
        duration_secs: Option<i64>,
    },
}

impl CallState {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }

    pub fn is_ringing(&self) -> bool {
        matches!(self, Self::Ringing { .. } | Self::IncomingRinging { .. })
    }

    pub fn is_ended(&self) -> bool {
        matches!(self, Self::Ended { .. })
    }

    pub fn can_accept(&self) -> bool {
        matches!(self, Self::IncomingRinging { .. })
    }

    pub fn can_reject(&self) -> bool {
        matches!(self, Self::IncomingRinging { .. } | Self::Ringing { .. })
    }
}

/// State transitions for calls.
#[derive(Debug, Clone)]
pub enum CallTransition {
    OfferSent,
    OfferReceived { silenced: bool },
    LocalAccepted,
    RemoteAccepted,
    LocalRejected { reason: EndCallReason },
    RemoteRejected { reason: EndCallReason },
    MediaConnected,
    Terminated { reason: EndCallReason },
    Hold,
    Resume,
    AudioMuteChanged { muted: bool },
    VideoStateChanged { off: bool },
}

/// Encryption state for a call.
#[derive(Clone)]
pub struct CallEncryption {
    pub master_key: CallEncryptionKey,
    pub derived_keys: DerivedCallKeys,
}

impl std::fmt::Debug for CallEncryption {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallEncryption")
            .field("master_key", &self.master_key)
            .field("derived_keys", &self.derived_keys)
            .finish()
    }
}

/// Full call session information.
#[derive(Debug, Clone, Serialize)]
pub struct CallInfo {
    pub call_id: CallId,
    pub peer_jid: Jid,
    pub call_creator: Jid,
    pub direction: CallDirection,
    pub media_type: CallMediaType,
    pub call_type: CallType,
    pub state: CallState,
    pub created_at: DateTime<Utc>,
    pub group_jid: Option<Jid>,
    pub is_offline: bool,
    /// Caller phone number JID (for Signal encryption).
    /// Signal sessions are tied to phone numbers, not LIDs.
    pub caller_pn: Option<Jid>,
    #[serde(skip)]
    pub encryption: Option<CallEncryption>,
    /// Relay data from the offer (for incoming calls).
    #[serde(skip)]
    pub offer_relay_data: Option<RelayData>,
    /// Media parameters from the offer (for incoming calls).
    #[serde(skip)]
    pub offer_media_params: Option<MediaParams>,
    /// Encrypted call key from the offer (for incoming calls).
    #[serde(skip)]
    pub offer_enc_data: Option<OfferEncData>,
    /// Transport parameters received from peer (for echo response).
    #[serde(skip)]
    pub received_transport: Option<TransportParams>,
}

impl CallInfo {
    pub fn new_outgoing(
        call_id: CallId,
        peer_jid: Jid,
        our_jid: Jid,
        media_type: CallMediaType,
    ) -> Self {
        Self {
            call_id,
            peer_jid,
            call_creator: our_jid,
            direction: CallDirection::Outgoing,
            media_type,
            call_type: CallType::Regular,
            state: CallState::Initiating,
            created_at: Utc::now(),
            group_jid: None,
            is_offline: false,
            caller_pn: None,
            encryption: None,
            offer_relay_data: None,
            offer_media_params: None,
            offer_enc_data: None,
            received_transport: None,
        }
    }

    pub fn new_incoming(
        call_id: CallId,
        peer_jid: Jid,
        call_creator: Jid,
        caller_pn: Option<Jid>,
        media_type: CallMediaType,
    ) -> Self {
        Self {
            call_id,
            peer_jid,
            call_creator,
            direction: CallDirection::Incoming,
            media_type,
            call_type: CallType::Regular,
            state: CallState::IncomingRinging {
                received_at: Utc::now(),
                silenced: false,
            },
            created_at: Utc::now(),
            group_jid: None,
            is_offline: false,
            caller_pn,
            encryption: None,
            offer_relay_data: None,
            offer_media_params: None,
            offer_enc_data: None,
            received_transport: None,
        }
    }

    pub fn set_encryption_key(&mut self, key: CallEncryptionKey) {
        let derived_keys = derive_call_keys(&key);
        self.encryption = Some(CallEncryption {
            master_key: key,
            derived_keys,
        });
    }

    pub fn is_initiator(&self) -> bool {
        self.direction == CallDirection::Outgoing
    }

    /// Apply a state transition. Returns error if transition is invalid.
    pub fn apply_transition(
        &mut self,
        transition: CallTransition,
    ) -> Result<(), InvalidTransition> {
        let new_state = match (&self.state, transition) {
            (CallState::Initiating, CallTransition::OfferSent) => CallState::Ringing {
                offer_sent_at: Utc::now(),
            },
            (CallState::Initiating, CallTransition::OfferReceived { silenced }) => {
                CallState::IncomingRinging {
                    received_at: Utc::now(),
                    silenced,
                }
            }
            (CallState::Ringing { .. }, CallTransition::RemoteAccepted) => CallState::Connecting {
                accepted_at: Utc::now(),
            },
            (
                CallState::Ringing { .. },
                CallTransition::RemoteRejected { reason } | CallTransition::Terminated { reason },
            ) => CallState::Ended {
                reason,
                ended_at: Utc::now(),
                duration_secs: None,
            },
            (CallState::IncomingRinging { .. }, CallTransition::LocalAccepted) => {
                CallState::Connecting {
                    accepted_at: Utc::now(),
                }
            }
            (
                CallState::IncomingRinging { .. },
                CallTransition::LocalRejected { reason } | CallTransition::Terminated { reason },
            ) => CallState::Ended {
                reason,
                ended_at: Utc::now(),
                duration_secs: None,
            },
            (CallState::Connecting { .. }, CallTransition::MediaConnected) => CallState::Active {
                connected_at: Utc::now(),
                audio_muted: false,
                video_off: self.media_type != CallMediaType::Video,
            },
            (CallState::Connecting { .. }, CallTransition::Terminated { reason }) => {
                CallState::Ended {
                    reason,
                    ended_at: Utc::now(),
                    duration_secs: None,
                }
            }
            (CallState::Active { connected_at, .. }, CallTransition::Terminated { reason }) => {
                let duration = Utc::now()
                    .signed_duration_since(*connected_at)
                    .num_seconds();
                CallState::Ended {
                    reason,
                    ended_at: Utc::now(),
                    duration_secs: Some(duration),
                }
            }
            (
                CallState::Active {
                    connected_at,
                    audio_muted,
                    video_off,
                },
                CallTransition::Hold,
            ) => CallState::OnHold {
                held_at: Utc::now(),
                connected_at: *connected_at,
                audio_muted: *audio_muted,
                video_off: *video_off,
            },
            (
                CallState::Active {
                    connected_at,
                    video_off,
                    ..
                },
                CallTransition::AudioMuteChanged { muted },
            ) => CallState::Active {
                connected_at: *connected_at,
                audio_muted: muted,
                video_off: *video_off,
            },
            (
                CallState::Active {
                    connected_at,
                    audio_muted,
                    ..
                },
                CallTransition::VideoStateChanged { off },
            ) => CallState::Active {
                connected_at: *connected_at,
                audio_muted: *audio_muted,
                video_off: off,
            },
            (
                CallState::OnHold {
                    connected_at,
                    audio_muted,
                    video_off,
                    ..
                },
                CallTransition::Resume,
            ) => CallState::Active {
                connected_at: *connected_at,
                audio_muted: *audio_muted,
                video_off: *video_off,
            },
            (CallState::OnHold { connected_at, .. }, CallTransition::Terminated { reason }) => {
                let duration = Utc::now()
                    .signed_duration_since(*connected_at)
                    .num_seconds();
                CallState::Ended {
                    reason,
                    ended_at: Utc::now(),
                    duration_secs: Some(duration),
                }
            }
            (current, transition) => {
                return Err(InvalidTransition {
                    current_state: format!("{:?}", current),
                    attempted: format!("{:?}", transition),
                });
            }
        };
        self.state = new_state;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct InvalidTransition {
    pub current_state: String,
    pub attempted: String,
}

impl std::fmt::Display for InvalidTransition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid transition {} in state {}",
            self.attempted, self.current_state
        )
    }
}

impl std::error::Error for InvalidTransition {}

#[cfg(test)]
mod tests {
    use super::*;
    use wacore::types::call::CallId;

    fn make_outgoing_call() -> CallInfo {
        CallInfo::new_outgoing(
            CallId::new("AC90CFD09DF712D981142B172706F9F2"),
            "39492358562039@lid".parse().unwrap(),
            "236395184570386@lid".parse().unwrap(),
            CallMediaType::Audio,
        )
    }

    fn make_incoming_call() -> CallInfo {
        CallInfo::new_incoming(
            CallId::new("BC5BD1EDE9BBE601F408EF3795479E93"),
            "236395184570386@lid".parse().unwrap(),
            "236395184570386@lid".parse().unwrap(),
            None, // caller_pn
            CallMediaType::Video,
        )
    }

    /// Test complete outgoing call flow.
    /// Flow: Initiating → Ringing → Connecting → Active → Ended
    #[test]
    fn test_outgoing_call_flow() {
        let mut call = make_outgoing_call();

        // Initial state
        assert!(matches!(call.state, CallState::Initiating));

        // Offer sent → Ringing
        call.apply_transition(CallTransition::OfferSent).unwrap();
        assert!(call.state.is_ringing());

        // Remote accepts → Connecting
        call.apply_transition(CallTransition::RemoteAccepted)
            .unwrap();
        assert!(matches!(call.state, CallState::Connecting { .. }));

        // Media connected → Active
        call.apply_transition(CallTransition::MediaConnected)
            .unwrap();
        assert!(call.state.is_active());

        // Terminate → Ended
        call.apply_transition(CallTransition::Terminated {
            reason: EndCallReason::UserEnded,
        })
        .unwrap();
        assert!(call.state.is_ended());

        // Verify duration was recorded
        if let CallState::Ended { duration_secs, .. } = call.state {
            assert!(duration_secs.is_some());
        }
    }

    /// Test complete incoming call flow.
    /// Flow: IncomingRinging → Connecting → Active → Ended
    #[test]
    fn test_incoming_call_flow() {
        let mut call = make_incoming_call();

        // Initial state is IncomingRinging
        assert!(call.state.is_ringing());
        assert!(call.state.can_accept());

        // Local accepts → Connecting
        call.apply_transition(CallTransition::LocalAccepted)
            .unwrap();
        assert!(matches!(call.state, CallState::Connecting { .. }));

        // Media connected → Active
        call.apply_transition(CallTransition::MediaConnected)
            .unwrap();
        assert!(call.state.is_active());

        // Terminate
        call.apply_transition(CallTransition::Terminated {
            reason: EndCallReason::UserEnded,
        })
        .unwrap();
        assert!(call.state.is_ended());
    }

    /// Test outgoing call rejection flow.
    /// Flow: Initiating → Ringing → Ended (rejected)
    #[test]
    fn test_outgoing_call_rejected() {
        let mut call = make_outgoing_call();

        call.apply_transition(CallTransition::OfferSent).unwrap();

        // Remote rejects
        call.apply_transition(CallTransition::RemoteRejected {
            reason: EndCallReason::Declined,
        })
        .unwrap();

        assert!(call.state.is_ended());
        if let CallState::Ended { reason, .. } = call.state {
            assert_eq!(reason, EndCallReason::Declined);
        }
    }

    /// Test incoming call rejection flow.
    /// Flow: IncomingRinging → Ended (rejected)
    #[test]
    fn test_incoming_call_rejected() {
        let mut call = make_incoming_call();

        assert!(call.state.can_reject());

        call.apply_transition(CallTransition::LocalRejected {
            reason: EndCallReason::RejectDoNotDisturb,
        })
        .unwrap();

        assert!(call.state.is_ended());
        if let CallState::Ended { reason, .. } = call.state {
            assert_eq!(reason, EndCallReason::RejectDoNotDisturb);
        }
    }

    /// Test hold and resume flow preserves mute state.
    #[test]
    fn test_hold_resume_preserves_mute_state() {
        let mut call = make_outgoing_call();

        // Get to active state
        call.apply_transition(CallTransition::OfferSent).unwrap();
        call.apply_transition(CallTransition::RemoteAccepted)
            .unwrap();
        call.apply_transition(CallTransition::MediaConnected)
            .unwrap();

        // Mute audio
        call.apply_transition(CallTransition::AudioMuteChanged { muted: true })
            .unwrap();

        if let CallState::Active { audio_muted, .. } = call.state {
            assert!(audio_muted);
        }

        // Hold
        call.apply_transition(CallTransition::Hold).unwrap();
        assert!(matches!(call.state, CallState::OnHold { .. }));

        // Resume - mute state should be preserved
        call.apply_transition(CallTransition::Resume).unwrap();

        if let CallState::Active { audio_muted, .. } = call.state {
            assert!(audio_muted, "Mute state should be preserved after resume");
        }
    }

    /// Test video state changes.
    #[test]
    fn test_video_state_changes() {
        let mut call = CallInfo::new_outgoing(
            CallId::new("TEST1234TEST1234TEST1234TEST1234"),
            "123@lid".parse().unwrap(),
            "456@lid".parse().unwrap(),
            CallMediaType::Video,
        );

        // Get to active state
        call.apply_transition(CallTransition::OfferSent).unwrap();
        call.apply_transition(CallTransition::RemoteAccepted)
            .unwrap();
        call.apply_transition(CallTransition::MediaConnected)
            .unwrap();

        // Video should be on for video calls
        if let CallState::Active { video_off, .. } = call.state {
            assert!(!video_off, "Video should be on for video calls");
        }

        // Turn video off
        call.apply_transition(CallTransition::VideoStateChanged { off: true })
            .unwrap();

        if let CallState::Active { video_off, .. } = call.state {
            assert!(video_off);
        }
    }

    /// Test invalid state transitions are rejected.
    #[test]
    fn test_invalid_transitions() {
        let mut call = make_outgoing_call();

        // Can't accept from Initiating
        assert!(
            call.apply_transition(CallTransition::RemoteAccepted)
                .is_err()
        );

        // Can't media connect from Initiating
        assert!(
            call.apply_transition(CallTransition::MediaConnected)
                .is_err()
        );

        // Can't hold from Initiating
        assert!(call.apply_transition(CallTransition::Hold).is_err());
    }

    /// Test that ended calls reject further transitions.
    #[test]
    fn test_ended_call_rejects_transitions() {
        let mut call = make_incoming_call();

        call.apply_transition(CallTransition::LocalRejected {
            reason: EndCallReason::Declined,
        })
        .unwrap();

        assert!(call.state.is_ended());

        // All transitions should fail
        assert!(
            call.apply_transition(CallTransition::LocalAccepted)
                .is_err()
        );
        assert!(
            call.apply_transition(CallTransition::MediaConnected)
                .is_err()
        );
        assert!(
            call.apply_transition(CallTransition::Terminated {
                reason: EndCallReason::UserEnded,
            })
            .is_err()
        );
    }

    /// Test call direction is set correctly.
    #[test]
    fn test_call_direction() {
        let outgoing = make_outgoing_call();
        assert_eq!(outgoing.direction, CallDirection::Outgoing);

        let incoming = make_incoming_call();
        assert_eq!(incoming.direction, CallDirection::Incoming);
    }

    /// Test call media type is set correctly.
    #[test]
    fn test_call_media_type() {
        let audio = make_outgoing_call();
        assert_eq!(audio.media_type, CallMediaType::Audio);

        let video = make_incoming_call();
        assert_eq!(video.media_type, CallMediaType::Video);
    }
}
