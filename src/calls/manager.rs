//! Call manager for orchestrating call lifecycle.

use super::encryption::DerivedCallKeys;
use super::error::CallError;
use super::signaling::SignalingType;
use super::stanza::{
    CallStanzaBuilder, MediaParams, OfferEncData, ParsedCallStanza, RelayData, RelayLatencyData,
};
use super::state::{CallInfo, CallTransition};
use super::transport::TransportPayload;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use wacore::types::call::{CallId, CallMediaType, EndCallReason};
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

/// Callback trait for media protocol events.
///
/// External media handlers (e.g., UI packages, WebRTC implementations) implement
/// this trait to receive parsed protocol data from call signaling.
///
/// This is the primary integration point between whatsapp-rust protocol layer
/// and external media handling code.
#[async_trait]
pub trait CallMediaCallback: Send + Sync {
    /// Called when an offer is received with full relay/media data.
    ///
    /// This provides all the data needed to set up a media connection:
    /// - Relay endpoints with tokens and addresses
    /// - Audio/video codec parameters
    /// - Encrypted call key for SRTP
    async fn on_offer_received(
        &self,
        call_id: &str,
        relay_data: &RelayData,
        media_params: &MediaParams,
        enc_data: &OfferEncData,
    );

    /// Called when transport candidates are received.
    ///
    /// The raw_data can be passed directly to WASM/WebRTC for processing.
    async fn on_transport_received(&self, call_id: &str, transport: &TransportPayload);

    /// Called when relay latency measurement is received.
    ///
    /// Used for relay selection - choose the relay with lowest latency.
    async fn on_relay_latency(&self, call_id: &str, latency: &[RelayLatencyData]);

    /// Called when enc_rekey is received (new SRTP keys).
    ///
    /// The derived keys should be used to update SRTP encryption.
    async fn on_enc_rekey(&self, call_id: &str, keys: &DerivedCallKeys);
}

/// Configuration for the call manager.
#[derive(Clone)]
pub struct CallManagerConfig {
    /// Maximum concurrent calls allowed.
    pub max_concurrent_calls: usize,
    /// Ring timeout in seconds before auto-rejecting.
    pub ring_timeout_secs: u64,
    /// Optional media callback for external handlers.
    pub media_callback: Option<Arc<dyn CallMediaCallback>>,
}

impl std::fmt::Debug for CallManagerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallManagerConfig")
            .field("max_concurrent_calls", &self.max_concurrent_calls)
            .field("ring_timeout_secs", &self.ring_timeout_secs)
            .field("media_callback", &self.media_callback.is_some())
            .finish()
    }
}

impl Default for CallManagerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_calls: 1,
            ring_timeout_secs: 45,
            media_callback: None,
        }
    }
}

/// Options for starting a call.
#[derive(Debug, Clone, Default)]
pub struct CallOptions {
    /// Whether this is a video call.
    pub video: bool,
    /// Group JID if this is a group call.
    pub group_jid: Option<Jid>,
}

impl CallOptions {
    pub fn audio() -> Self {
        Self::default()
    }

    pub fn video() -> Self {
        Self {
            video: true,
            ..Default::default()
        }
    }
}

/// Manages active calls and their state transitions.
pub struct CallManager {
    /// Our JID.
    our_jid: Jid,
    /// Configuration.
    #[allow(dead_code)]
    config: CallManagerConfig,
    /// Active calls indexed by call ID.
    calls: RwLock<HashMap<String, CallInfo>>,
}

impl CallManager {
    /// Create a new call manager.
    pub fn new(our_jid: Jid, config: CallManagerConfig) -> Arc<Self> {
        Arc::new(Self {
            our_jid,
            config,
            calls: RwLock::new(HashMap::new()),
        })
    }

    /// Start an outgoing call.
    pub async fn start_call(
        &self,
        peer_jid: Jid,
        options: CallOptions,
    ) -> Result<CallId, CallError> {
        let call_id = CallId::generate();
        let media_type = if options.video {
            CallMediaType::Video
        } else {
            CallMediaType::Audio
        };

        let mut info =
            CallInfo::new_outgoing(call_id.clone(), peer_jid, self.our_jid.clone(), media_type);

        if let Some(group_jid) = options.group_jid {
            info.group_jid = Some(group_jid);
        }

        let mut calls = self.calls.write().await;
        // Count only active (non-ended) calls against the limit
        let active_count = calls.values().filter(|c| !c.state.is_ended()).count();
        if active_count >= self.config.max_concurrent_calls {
            return Err(CallError::AlreadyExists(
                "max concurrent calls reached".into(),
            ));
        }

        calls.insert(call_id.as_str().to_string(), info);
        Ok(call_id)
    }

    /// Build an offer stanza for an outgoing call.
    pub async fn build_offer_stanza(&self, call_id: &CallId) -> Result<Node, CallError> {
        let calls = self.calls.read().await;
        let info = calls
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        let mut builder = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::Offer,
        )
        .video(info.media_type == CallMediaType::Video);

        if let Some(ref group_jid) = info.group_jid {
            builder = builder.group(group_jid.clone());
        }

        Ok(builder.build())
    }

    /// Mark offer as sent and transition to Ringing state.
    pub async fn mark_offer_sent(&self, call_id: &CallId) -> Result<(), CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        info.apply_transition(CallTransition::OfferSent)?;
        Ok(())
    }

    /// Handle an incoming call offer (register the call).
    pub async fn register_incoming_call(&self, parsed: &ParsedCallStanza) -> Result<(), CallError> {
        let call_id = CallId::new(&parsed.call_id);
        let media_type = parsed.media_type();

        let mut info = CallInfo::new_incoming(
            call_id.clone(),
            parsed.from.clone(),
            parsed.call_creator.clone(),
            media_type,
        );
        info.is_offline = parsed.is_offline;
        info.group_jid.clone_from(&parsed.group_jid);

        let mut calls = self.calls.write().await;
        calls.insert(call_id.as_str().to_string(), info);

        Ok(())
    }

    /// Accept an incoming call.
    pub async fn accept_call(&self, call_id: &CallId) -> Result<Node, CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        if !info.state.can_accept() {
            return Err(CallError::InvalidTransition(
                super::state::InvalidTransition {
                    current_state: format!("{:?}", info.state),
                    attempted: "LocalAccepted".to_string(),
                },
            ));
        }

        info.apply_transition(CallTransition::LocalAccepted)?;

        let stanza = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::Accept,
        )
        .video(info.media_type == CallMediaType::Video)
        .build();

        Ok(stanza)
    }

    /// Reject an incoming call.
    pub async fn reject_call(
        &self,
        call_id: &CallId,
        reason: EndCallReason,
    ) -> Result<Node, CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        if !info.state.can_reject() {
            return Err(CallError::InvalidTransition(
                super::state::InvalidTransition {
                    current_state: format!("{:?}", info.state),
                    attempted: "LocalRejected".to_string(),
                },
            ));
        }

        info.apply_transition(CallTransition::LocalRejected { reason })?;

        let stanza = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::Reject,
        )
        .build();

        Ok(stanza)
    }

    /// End an active or ringing call.
    pub async fn end_call(&self, call_id: &CallId) -> Result<Node, CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        info.apply_transition(CallTransition::Terminated {
            reason: EndCallReason::UserEnded,
        })?;

        let stanza = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::Terminate,
        )
        .build();

        Ok(stanza)
    }

    /// Handle remote accept.
    pub async fn handle_remote_accept(&self, parsed: &ParsedCallStanza) -> Result<(), CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(&parsed.call_id)
            .ok_or_else(|| CallError::NotFound(parsed.call_id.clone()))?;

        info.apply_transition(CallTransition::RemoteAccepted)?;
        Ok(())
    }

    /// Handle remote reject.
    pub async fn handle_remote_reject(&self, parsed: &ParsedCallStanza) -> Result<(), CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(&parsed.call_id)
            .ok_or_else(|| CallError::NotFound(parsed.call_id.clone()))?;

        info.apply_transition(CallTransition::RemoteRejected {
            reason: EndCallReason::Declined,
        })?;
        Ok(())
    }

    /// Handle terminate from remote.
    pub async fn handle_terminate(&self, parsed: &ParsedCallStanza) -> Result<(), CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(&parsed.call_id)
            .ok_or_else(|| CallError::NotFound(parsed.call_id.clone()))?;

        info.apply_transition(CallTransition::Terminated {
            reason: EndCallReason::UserEnded,
        })?;
        Ok(())
    }

    /// Get call info by ID.
    pub async fn get_call(&self, call_id: &CallId) -> Option<CallInfo> {
        self.calls.read().await.get(call_id.as_str()).cloned()
    }

    /// Get all active calls.
    pub async fn get_active_calls(&self) -> Vec<CallInfo> {
        self.calls
            .read()
            .await
            .values()
            .filter(|c| !c.state.is_ended())
            .cloned()
            .collect()
    }

    /// Remove ended calls from memory.
    pub async fn cleanup_ended_calls(&self) {
        let mut calls = self.calls.write().await;
        calls.retain(|_, info| !info.state.is_ended());
    }

    /// Check if we have an active call.
    pub async fn has_active_call(&self) -> bool {
        self.calls
            .read()
            .await
            .values()
            .any(|c| c.state.is_active())
    }

    /// Check if we're currently ringing.
    pub async fn is_ringing(&self) -> bool {
        self.calls
            .read()
            .await
            .values()
            .any(|c| c.state.is_ringing())
    }
}
