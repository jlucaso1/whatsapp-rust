//! Call signaling module for WhatsApp VoIP.
//!
//! This module implements Phase 1 of VoIP support: call signaling over WebSocket.
//! It handles incoming/outgoing call stanzas, state machine transitions, and
//! proper acknowledgment responses.
//!
//! # Architecture
//!
//! - [`SignalingType`]: The 26 signaling types used in WhatsApp call protocol
//! - [`CallState`] & [`CallInfo`]: Call state machine for tracking call lifecycle
//! - [`ParsedCallStanza`]: Parser for incoming `<call>` stanzas
//! - [`CallStanzaBuilder`]: Builder for outgoing call stanzas
//! - [`CallHandler`]: StanzaHandler implementation for processing call stanzas
//! - [`CallManager`]: Orchestrates call lifecycle and state
//!
//! # Protocol Overview
//!
//! Call signaling uses `<call>` stanzas with child elements indicating the
//! signaling type (offer, accept, reject, terminate, transport, etc.).
//! Each signaling type may require either an ACK or Receipt response.

mod encryption;
mod error;
mod handler;
mod manager;
mod signaling;
mod stanza;
mod state;

pub use encryption::{CallEncryption, CallEncryptionKey};
pub use error::CallError;
pub use handler::CallHandler;
pub use manager::{CallManager, CallManagerConfig, CallOptions};
pub use signaling::{ResponseType, SignalingType};
pub use stanza::{CallStanzaBuilder, ParsedCallStanza, build_call_ack, build_call_receipt};
pub use state::{CallInfo, CallState, CallTransition, InvalidTransition};
