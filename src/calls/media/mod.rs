//! Media transport for WhatsApp VoIP calls.
//!
//! This module handles UDP relay connections, STUN binding, RTP media transport,
//! SRTP encryption, RTCP feedback, and jitter buffering for complete VoIP media handling.
//!
//! # Architecture
//!
//! - [`MediaSession`]: Complete media session combining all components
//! - [`CallMediaTransport`]: High-level media transport orchestration
//! - [`WebRtcTransport`]: WebRTC-based transport (WhatsApp Web approach)
//! - [`RelayConnection`]: UDP connection to WhatsApp relay servers
//! - [`StunBinder`]: STUN binding protocol for relay authentication
//! - [`RtpPacket`], [`RtpSession`]: RTP packet handling
//! - [`SrtpSession`]: SRTP encryption/decryption
//! - [`RtcpNack`], [`NackTracker`]: RTCP feedback for packet loss recovery
//! - [`JitterBuffer`]: Packet reordering and timing
//!
//! # Protocol Overview
//!
//! ## WebRTC Transport (Recommended - WhatsApp Web Approach)
//!
//! 1. Create RTCPeerConnection with DataChannel
//! 2. Generate offer SDP and manipulate it:
//!    - Replace ice-ufrag with auth_token
//!    - Replace ice-pwd with relay_key
//!    - Set hardcoded DTLS fingerprint
//!    - Inject relay server as ICE candidate
//! 3. Set manipulated SDP as remote answer
//! 4. WebRTC handles ICE/DTLS/SCTP automatically
//! 5. DataChannel opens - ready for media
//!
//! ## Raw UDP Transport (Legacy)
//!
//! 1. Connect to relay servers via UDP (port 3480)
//! 2. Send STUN Binding Request with relay token authentication
//! 3. Receive STUN Binding Response with allocated address
//! 4. Select best relay based on latency
//! 5. Send/receive RTP packets encrypted with SRTP
//! 6. Buffer incoming packets in jitter buffer for smooth playout
//! 7. Send RTCP NACK for lost packets, handle retransmission requests

mod jitter;
mod relay;
mod rtcp;
mod rtp;
mod sender_subscriptions;
mod session;
mod srtp;
mod stun;
mod transport;
mod webrtc;

pub use jitter::{JitterBuffer, JitterBufferConfig, JitterStats};
pub use relay::{ConnectedRelay, RelayConnection, RelayConnectionConfig, RelayError, RelayState};
pub use rtcp::{
    NackEntry, NackStats, NackTracker, PsfbFmt, RTCP_VERSION, RetransmitBuffer, RtcpHeader,
    RtcpNack, RtcpPayloadType, RtpfbFmt,
};
pub use rtp::{PayloadType, RTP_VERSION, RtpHeader, RtpPacket, RtpSession};
pub use sender_subscriptions::{
    create_audio_sender_subscriptions, create_audio_sender_subscriptions_with_jid,
};
pub use session::{
    MediaSession, MediaSessionBuilder, MediaSessionConfig, MediaSessionError, MediaSessionState,
    MediaSessionStats,
};
pub use srtp::{SRTP_AUTH_TAG_LEN, SrtpContext, SrtpError, SrtpSession};
pub use stun::{
    StunAllocateResult, StunAttribute, StunBindResult, StunBinder, StunCredentials, StunError,
    StunMessage, StunMessageType, TurnTransportProtocol,
};
pub use transport::{
    ActiveRelay, CallMediaTransport, MediaTransportConfig, RelayLatency, TransportError,
    TransportState,
};
pub use webrtc::{
    RelayConnectionInfo, WHATSAPP_DTLS_FINGERPRINT, WebRtcConnectionResult, WebRtcError,
    WebRtcState, WebRtcTransport, WebRtcTransportConfig, manipulate_sdp,
};
