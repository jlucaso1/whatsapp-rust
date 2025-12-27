//! Call manager for orchestrating call lifecycle.

use super::error::CallError;
use super::signaling::SignalingType;
use super::stanza::{CallStanzaBuilder, ParsedCallStanza};
use super::state::{CallInfo, CallTransition};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use wacore::types::call::{CallId, CallMediaType, EndCallReason};
use wacore_binary::jid::Jid;
use wacore_binary::node::Node;

/// Configuration for the call manager.
#[derive(Debug, Clone)]
pub struct CallManagerConfig {
    /// Maximum concurrent calls allowed.
    pub max_concurrent_calls: usize,
    /// Ring timeout in seconds before auto-rejecting.
    pub ring_timeout_secs: u64,
}

impl Default for CallManagerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_calls: 1,
            ring_timeout_secs: 45,
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
        if calls.len() >= self.config.max_concurrent_calls {
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
