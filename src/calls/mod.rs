//! Call signaling module for WhatsApp VoIP.
//!
//! This module implements VoIP support: call signaling over WebSocket and
//! protocol-level data parsing for external media handlers.
//!
//! # Architecture
//!
//! - [`SignalingType`]: The 26 signaling types used in WhatsApp call protocol
//! - [`CallState`] & [`CallInfo`]: Call state machine for tracking call lifecycle
//! - [`ParsedCallStanza`]: Parser for incoming `<call>` stanzas
//! - [`CallStanzaBuilder`]: Builder for outgoing call stanzas
//! - [`CallHandler`]: StanzaHandler implementation for processing call stanzas
//! - [`CallManager`]: Orchestrates call lifecycle and state
//! - [`CallMediaCallback`]: Trait for external media handlers to receive parsed data
//!
//! # Protocol Overview
//!
//! Call signaling uses `<call>` stanzas with child elements indicating the
//! signaling type (offer, accept, reject, terminate, transport, etc.).
//! Each signaling type may require either an ACK or Receipt response.
//!
//! # Media Integration
//!
//! This library handles protocol parsing only. External packages implement
//! [`CallMediaCallback`] to receive:
//! - Relay endpoints with tokens and addresses
//! - Audio/video codec parameters
//! - Transport payloads (ICE candidates)
//! - SRTP key material

mod encryption;
mod error;
mod handler;
mod manager;
mod signaling;
mod stanza;
mod state;
mod transport;

pub use encryption::{
    CallEncryptionKey, DerivedCallKeys, EncType, EncryptedCallKey, SrtpKeyingMaterial,
    decrypt_call_key, derive_call_keys, derive_srtp_keys, encrypt_call_key,
};
pub use error::CallError;
pub use handler::CallHandler;
pub use manager::{CallManager, CallManagerConfig, CallMediaCallback, CallOptions};
pub use signaling::{ResponseType, SignalingType};
pub use stanza::{
    AcceptAudioParams, AcceptVideoParams, AudioParams, CallStanzaBuilder, EncRekeyData,
    MediaParams, OfferEncData, ParsedCallStanza, PreacceptParams, RelayAddress, RelayData,
    RelayEndpoint, RelayLatencyData, RelayLatencyMeasurement, TransportParams, VideoParams,
    build_call_ack, build_call_receipt,
};
pub use state::{CallEncryption, CallInfo, CallState, CallTransition, InvalidTransition};
pub use transport::{
    CandidateType, IceCandidate, TURN_RELAY_PORT, TransportPayload, WHATSAPP_RELAY_PORT,
};
