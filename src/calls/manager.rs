//! Call manager for orchestrating call lifecycle.

use super::encryption::{CallEncryptionKey, DerivedCallKeys, EncryptedCallKey};
use super::error::CallError;
use super::media::{
    CallMediaTransport, MediaTransportConfig, RelayLatency, WebRtcConnectionResult, WebRtcState,
    WebRtcTransport, WebRtcTransportConfig,
};
use super::signaling::SignalingType;
use super::stanza::{
    AcceptAudioParams, AcceptVideoParams, CallStanzaBuilder, MediaParams, OfferEncData,
    ParsedCallStanza, PreacceptParams, RelayData, RelayLatencyData, RelayLatencyMeasurement,
    TransportParams,
};
use super::state::{CallInfo, CallTransition};
use super::transport::TransportPayload;
use async_trait::async_trait;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
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

    /// Called when the call is accepted by the remote peer.
    ///
    /// For outgoing calls, this is when the callee accepts.
    /// This is the signal to start connecting to the relay for media.
    async fn on_call_accepted(&self, call_id: &str);
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
    /// Transport type for media connections (default: WebRTC).
    pub transport_type: TransportType,
    /// WebRTC connection timeout in seconds.
    pub webrtc_timeout_secs: u64,
}

impl std::fmt::Debug for CallManagerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CallManagerConfig")
            .field("max_concurrent_calls", &self.max_concurrent_calls)
            .field("ring_timeout_secs", &self.ring_timeout_secs)
            .field("media_callback", &self.media_callback.is_some())
            .field("transport_type", &self.transport_type)
            .field("webrtc_timeout_secs", &self.webrtc_timeout_secs)
            .finish()
    }
}

impl Default for CallManagerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_calls: 1,
            ring_timeout_secs: 45,
            media_callback: None,
            // WebRTC is the recommended transport - it's what WhatsApp Web uses
            transport_type: TransportType::WebRtc,
            webrtc_timeout_secs: 30,
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

/// Transport type for call media.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportType {
    /// Legacy raw UDP STUN transport (may not work with modern relays).
    #[default]
    Legacy,
    /// WebRTC DataChannel transport (WhatsApp Web approach - recommended).
    WebRtc,
}

/// Manages active calls and their state transitions.
pub struct CallManager {
    /// Our JID.
    our_jid: Jid,
    /// Configuration.
    config: CallManagerConfig,
    /// Active calls indexed by call ID.
    calls: RwLock<HashMap<String, CallInfo>>,
    /// Pre-bound legacy transports for calls (bound early after ACK, before peer accepts).
    /// Indexed by call ID.
    bound_transports: RwLock<HashMap<String, Arc<CallMediaTransport>>>,
    /// WebRTC transports for calls (WhatsApp Web approach).
    /// Indexed by call ID.
    webrtc_transports: RwLock<HashMap<String, Arc<WebRtcTransport>>>,
    /// Elected relay indices from RELAY_ELECTION stanzas.
    /// Indexed by call ID.
    elected_relays: RwLock<HashMap<String, u32>>,
}

impl CallManager {
    /// Create a new call manager.
    pub fn new(our_jid: Jid, config: CallManagerConfig) -> Arc<Self> {
        Arc::new(Self {
            our_jid,
            config,
            calls: RwLock::new(HashMap::new()),
            bound_transports: RwLock::new(HashMap::new()),
            webrtc_transports: RwLock::new(HashMap::new()),
            elected_relays: RwLock::new(HashMap::new()),
        })
    }

    /// Start an outgoing call.
    pub async fn start_call(
        &self,
        peer_jid: Jid,
        options: CallOptions,
    ) -> Result<CallId, CallError> {
        // Clean up ended calls before checking limits
        self.cleanup_ended_calls().await;

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

    /// Build an offer stanza for an outgoing call (basic, without encrypted key).
    ///
    /// For a fully functional offer, use `build_offer_stanza_with_key` instead which
    /// includes the encrypted call key required for media connection.
    pub async fn build_offer_stanza(&self, call_id: &CallId) -> Result<Node, CallError> {
        self.build_offer_stanza_with_key(call_id, None).await
    }

    /// Build an offer stanza for an outgoing call with an encrypted call key.
    ///
    /// This builds a complete offer stanza with:
    /// - Encrypted call key (`<enc type="msg|pkmsg" v="2">...`)
    /// - Audio codec parameters (`<audio enc="opus" rate="16000">`)
    /// - Video codec parameters if video call (`<video enc="vp8">`)
    /// - Network medium (`<net medium="2"/>`)
    /// - Encryption key generation (`<encopt keygen="2"/>`)
    ///
    /// # Arguments
    /// * `call_id` - The call to build the offer for
    /// * `encrypted_key` - The encrypted call key (encrypted using Signal protocol
    ///   for the recipient). If None, builds a basic offer stanza.
    ///
    /// # Example
    /// ```ignore
    /// // Generate and encrypt call key for the recipient
    /// let (call_key, encrypted) = client.encrypt_call_key_for(&peer_jid).await?;
    ///
    /// // Build offer stanza with encrypted key
    /// let stanza = call_manager.build_offer_stanza_with_key(&call_id, Some(encrypted)).await?;
    /// client.send_node(stanza).await?;
    /// ```
    pub async fn build_offer_stanza_with_key(
        &self,
        call_id: &CallId,
        encrypted_key: Option<EncryptedCallKey>,
    ) -> Result<Node, CallError> {
        let calls = self.calls.read().await;
        let info = calls
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        let is_video = info.media_type == CallMediaType::Video;

        let mut builder = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::Offer,
        )
        .video(is_video);

        if let Some(ref group_jid) = info.group_jid {
            builder = builder.group(group_jid.clone());
        }

        // Add encrypted key if provided
        if let Some(key) = encrypted_key {
            builder = builder.encrypted_key(key);
        }

        // Add audio params (default codec settings)
        builder = builder.audio(AcceptAudioParams::default());

        // Add video params if video call
        if is_video {
            builder = builder.video_params(AcceptVideoParams::default());
        }

        // Add net and encopt elements (required for proper call initiation)
        builder = builder.net_medium(2).encopt_keygen(2);

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
            parsed.caller_pn.clone(),
            media_type,
        );
        info.is_offline = parsed.is_offline;
        info.group_jid.clone_from(&parsed.group_jid);

        // Store offer data for later use when accepting the call
        info.offer_relay_data.clone_from(&parsed.relay_data);
        info.offer_media_params.clone_from(&parsed.media_params);
        info.offer_enc_data.clone_from(&parsed.offer_enc_data);

        let mut calls = self.calls.write().await;
        calls.insert(call_id.as_str().to_string(), info);

        Ok(())
    }

    /// Accept an incoming call (basic stanza without encrypted key).
    ///
    /// For a fully functional accept, use `accept_call_with_key` instead which
    /// includes the encrypted call key required for media connection.
    pub async fn accept_call(&self, call_id: &CallId) -> Result<Node, CallError> {
        self.accept_call_with_key(call_id, None).await
    }

    /// Accept an incoming call with an encrypted call key.
    ///
    /// This builds a complete accept stanza with:
    /// - Encrypted call key (`<enc type="msg" v="2">...`)
    /// - Audio codec parameters (`<audio enc="opus" rate="16000">`)
    /// - Video codec parameters if video call (`<video enc="vp8">`)
    ///
    /// # Arguments
    /// * `call_id` - The call to accept
    /// * `encrypted_key` - The encrypted call key (encrypted using Signal protocol
    ///   for the call creator). If None, builds a basic accept stanza.
    ///
    /// # Example
    /// ```ignore
    /// // Generate and encrypt call key
    /// let call_key = CallEncryptionKey::generate();
    /// let encrypted = encrypt_call_key(&mut session_store, &mut identity_store,
    ///                                   &peer_jid, &call_key).await?;
    ///
    /// // Build accept stanza with encrypted key
    /// let stanza = call_manager.accept_call_with_key(&call_id, Some(encrypted)).await?;
    /// client.send_node(stanza).await?;
    /// ```
    pub async fn accept_call_with_key(
        &self,
        call_id: &CallId,
        encrypted_key: Option<EncryptedCallKey>,
    ) -> Result<Node, CallError> {
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

        let is_video = info.media_type == CallMediaType::Video;

        let mut builder = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::Accept,
        )
        .video(is_video);

        // Add encrypted key if provided
        if let Some(key) = encrypted_key {
            builder = builder.encrypted_key(key);
        }

        // Add audio params (use offer params or default)
        let audio = if let Some(ref mp) = info.offer_media_params
            && let Some(first_audio) = mp.audio.first()
        {
            AcceptAudioParams {
                codec: first_audio.codec.clone(),
                rate: first_audio.rate,
            }
        } else {
            AcceptAudioParams::default()
        };
        builder = builder.audio(audio);

        // Add video params if video call
        if is_video {
            let video = if let Some(ref mp) = info.offer_media_params
                && let Some(ref vp) = mp.video
                && let Some(ref codec) = vp.codec
            {
                AcceptVideoParams {
                    codec: codec.clone(),
                }
            } else {
                AcceptVideoParams::default()
            };
            builder = builder.video_params(video);
        }

        // Add net and encopt elements (required for proper call acceptance)
        builder = builder.net_medium(2).encopt_keygen(2);

        Ok(builder.build())
    }

    /// Send PREACCEPT to acknowledge incoming call (shows "ringing" to caller).
    ///
    /// Should be called immediately after receiving OFFER.
    /// This tells the caller that we're ringing and processing their call.
    pub async fn send_preaccept(&self, call_id: &CallId) -> Result<Node, CallError> {
        let calls = self.calls.read().await;
        let info = calls
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        let builder = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::PreAccept,
        )
        .preaccept_params(PreacceptParams::default());

        Ok(builder.build())
    }

    /// Send relay latency measurements to the caller.
    ///
    /// Should be called after measuring latency to relay servers from the offer.
    /// The caller uses these measurements for relay selection.
    pub async fn send_relay_latency(
        &self,
        call_id: &CallId,
        measurements: Vec<RelayLatencyMeasurement>,
    ) -> Result<Node, CallError> {
        let calls = self.calls.read().await;
        let info = calls
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        let builder = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::RelayLatency,
        )
        .relay_latency(measurements);

        Ok(builder.build())
    }

    /// Send TRANSPORT stanza in response to received transport.
    ///
    /// This "echoes" the transport message back to the caller for P2P negotiation.
    pub async fn send_transport(
        &self,
        call_id: &CallId,
        params: TransportParams,
    ) -> Result<Node, CallError> {
        let calls = self.calls.read().await;
        let info = calls
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        let builder = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::Transport,
        )
        .transport_params(params);

        Ok(builder.build())
    }

    /// Send mute state to peer (should be sent before ACCEPT).
    ///
    /// # Arguments
    /// * `call_id` - The call ID
    /// * `muted` - true if audio is muted, false otherwise
    pub async fn send_mute_state(&self, call_id: &CallId, muted: bool) -> Result<Node, CallError> {
        let calls = self.calls.read().await;
        let info = calls
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        let builder = CallStanzaBuilder::new(
            call_id.as_str(),
            info.call_creator.clone(),
            info.peer_jid.clone(),
            SignalingType::MuteV2,
        )
        .mute_state(muted);

        Ok(builder.build())
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

    /// Get the media callback if configured.
    pub fn media_callback(&self) -> Option<&Arc<dyn CallMediaCallback>> {
        self.config.media_callback.as_ref()
    }

    /// Notify callback about an incoming offer.
    pub async fn notify_offer_received(
        &self,
        call_id: &str,
        relay_data: &RelayData,
        media_params: &MediaParams,
        enc_data: &OfferEncData,
    ) {
        if let Some(cb) = &self.config.media_callback {
            cb.on_offer_received(call_id, relay_data, media_params, enc_data)
                .await;
        }
    }

    /// Notify callback about transport data.
    pub async fn notify_transport_received(&self, call_id: &str, transport: &TransportPayload) {
        if let Some(cb) = &self.config.media_callback {
            cb.on_transport_received(call_id, transport).await;
        }
    }

    /// Notify callback about relay latency measurements.
    pub async fn notify_relay_latency(&self, call_id: &str, latency: &[RelayLatencyData]) {
        if let Some(cb) = &self.config.media_callback {
            cb.on_relay_latency(call_id, latency).await;
        }
    }

    /// Notify callback about enc_rekey (new SRTP keys).
    pub async fn notify_enc_rekey(&self, call_id: &str, keys: &DerivedCallKeys) {
        if let Some(cb) = &self.config.media_callback {
            cb.on_enc_rekey(call_id, keys).await;
        }
    }

    /// Notify callback that the call was accepted.
    ///
    /// For outgoing calls, this indicates the callee has accepted and
    /// media connection should be established.
    pub async fn notify_call_accepted(&self, call_id: &str) {
        if let Some(cb) = &self.config.media_callback {
            cb.on_call_accepted(call_id).await;
        }
    }

    /// Get relay data for a call.
    ///
    /// Returns the relay data from the offer (for incoming calls) or from
    /// the offer ACK (for outgoing calls, must be stored after receiving ACK).
    pub async fn get_relay_data(&self, call_id: &CallId) -> Option<RelayData> {
        self.calls
            .read()
            .await
            .get(call_id.as_str())
            .and_then(|info| info.offer_relay_data.clone())
    }

    /// Store relay data from an offer ACK (for outgoing calls).
    ///
    /// When we send an offer, the server allocates relays and returns them
    /// in the ACK response. This method stores that data in the call info.
    pub async fn store_relay_data(
        &self,
        call_id: &CallId,
        relay_data: RelayData,
    ) -> Result<(), CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        info.offer_relay_data = Some(relay_data);
        Ok(())
    }

    /// Connect to relay using the configured transport type.
    ///
    /// This is the **primary method** for establishing relay connections.
    /// It automatically uses the transport type configured in `CallManagerConfig`:
    /// - `TransportType::WebRtc` (default): Uses WebRTC DataChannel (WhatsApp Web approach)
    /// - `TransportType::Legacy`: Uses raw UDP STUN (may not work with modern relays)
    ///
    /// For WebRTC transport, this method:
    /// 1. Creates RTCPeerConnection with unordered DataChannel
    /// 2. Manipulates SDP to inject relay credentials
    /// 3. Establishes ICE/DTLS/SCTP connection automatically
    ///
    /// # Arguments
    /// * `call_id` - The call to connect
    /// * `relay_data` - Relay data from offer ACK
    ///
    /// # Returns
    /// * `Ok(relay_name)` - Name of the connected relay
    /// * `Err(CallError)` - If connection fails
    ///
    /// # Example
    /// ```ignore
    /// // After receiving offer ACK
    /// let relay_data = parse_relay_data_from_ack(&ack_node)?;
    /// call_manager.store_relay_data(&call_id, relay_data.clone()).await?;
    ///
    /// // Connect using configured transport (WebRTC by default)
    /// let relay_name = call_manager.connect_relay(&call_id, &relay_data).await?;
    /// println!("Connected to relay: {}", relay_name);
    /// ```
    pub async fn connect_relay(
        &self,
        call_id: &CallId,
        relay_data: &RelayData,
    ) -> Result<String, CallError> {
        match self.config.transport_type {
            TransportType::WebRtc => {
                info!(
                    "Connecting to relay via WebRTC for call {} ({} endpoints)",
                    call_id,
                    relay_data.endpoints.len()
                );

                let config = WebRtcTransportConfig {
                    timeout: Duration::from_secs(self.config.webrtc_timeout_secs),
                    ice_debug: false,
                };

                let result = self
                    .connect_webrtc_with_config(call_id, relay_data, config)
                    .await?;

                Ok(result.relay_info.relay_name)
            }
            TransportType::Legacy => {
                info!(
                    "Connecting to relay via legacy STUN for call {} ({} endpoints)",
                    call_id,
                    relay_data.endpoints.len()
                );

                let latencies = self.bind_relays_early_legacy(call_id, relay_data).await?;
                let relay_name = latencies
                    .first()
                    .map(|l| l.relay_name.clone())
                    .unwrap_or_else(|| "unknown".to_string());

                Ok(relay_name)
            }
        }
    }

    /// Bind to relays immediately after receiving ACK (legacy STUN approach).
    ///
    /// **Note**: This uses the legacy raw UDP STUN approach which may not work
    /// with modern WhatsApp relays. Consider using `connect_relay()` instead,
    /// which uses WebRTC by default.
    ///
    /// This performs STUN binding to measure actual latency and keeps the
    /// connections alive for when the peer accepts. This prevents token
    /// expiration issues that occur when binding is delayed.
    ///
    /// Returns the measured latencies for each relay, which should be sent
    /// in RELAYLATENCY stanzas.
    ///
    /// The bound transport is stored internally and can be retrieved later
    /// with `get_bound_transport()`.
    pub async fn bind_relays_early_legacy(
        &self,
        call_id: &CallId,
        relay_data: &RelayData,
    ) -> Result<Vec<RelayLatency>, CallError> {
        info!(
            "Early binding (legacy STUN) to {} relay endpoints for call {}",
            relay_data.endpoints.len(),
            call_id
        );

        // Create transport and connect (performs STUN binding)
        let transport = Arc::new(CallMediaTransport::new(MediaTransportConfig::default()));

        match transport.connect(relay_data).await {
            Ok(active_relay) => {
                info!(
                    "Early binding successful for call {}: connected to {} (RTT: {:?})",
                    call_id, active_relay.relay.relay_name, active_relay.latency
                );

                // Get all relay latencies
                let latencies = transport.relay_latencies().await;
                debug!(
                    "Call {}: measured {} relay latencies",
                    call_id,
                    latencies.len()
                );

                // Store the bound transport
                self.bound_transports
                    .write()
                    .await
                    .insert(call_id.to_string(), transport);

                Ok(latencies)
            }
            Err(e) => {
                warn!("Early binding failed for call {}: {}", call_id, e);
                // Return the actual error - don't hide binding failures
                Err(CallError::Transport(format!("Relay binding failed: {}", e)))
            }
        }
    }

    /// Bind to relays immediately after receiving ACK.
    ///
    /// **Deprecated**: Use `connect_relay()` instead which uses WebRTC by default.
    #[deprecated(since = "0.2.0", note = "Use connect_relay() instead")]
    pub async fn bind_relays_early(
        &self,
        call_id: &CallId,
        relay_data: &RelayData,
    ) -> Result<Vec<RelayLatency>, CallError> {
        self.bind_relays_early_legacy(call_id, relay_data).await
    }

    /// Get a pre-bound transport for a call.
    ///
    /// Returns the transport that was bound during early binding (after ACK).
    /// This should be used when the peer accepts to avoid re-binding.
    pub async fn get_bound_transport(&self, call_id: &CallId) -> Option<Arc<CallMediaTransport>> {
        self.bound_transports
            .read()
            .await
            .get(call_id.as_str())
            .cloned()
    }

    /// Remove and return a pre-bound transport for a call.
    ///
    /// This takes ownership of the transport, removing it from storage.
    pub async fn take_bound_transport(&self, call_id: &CallId) -> Option<Arc<CallMediaTransport>> {
        self.bound_transports.write().await.remove(call_id.as_str())
    }

    /// Create relay latency measurements from offer relay data.
    ///
    /// This creates measurements for each relay endpoint. For actual latency
    /// measurement, use `bind_relays_early()` which performs STUN
    /// binding and returns real RTT values.
    ///
    /// This is a convenience method that creates placeholder measurements
    /// for cases where actual measurement is not needed.
    pub async fn create_relay_latency_measurements(
        &self,
        call_id: &CallId,
    ) -> Result<Vec<RelayLatencyMeasurement>, CallError> {
        let calls = self.calls.read().await;
        let info = calls
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        let relay_data = info
            .offer_relay_data
            .as_ref()
            .ok_or_else(|| CallError::Parse("no relay data available".into()))?;

        // Use 30ms as base latency (reasonable for most connections)
        Ok(RelayLatencyMeasurement::from_relay_data(relay_data, 30))
    }

    /// Get the derived call encryption keys for a call.
    ///
    /// Returns None if no encryption key has been set for this call.
    pub async fn get_derived_keys(&self, call_id: &CallId) -> Option<DerivedCallKeys> {
        self.calls
            .read()
            .await
            .get(call_id.as_str())
            .and_then(|info| info.encryption.as_ref())
            .map(|enc| enc.derived_keys.clone())
    }

    /// Get the master encryption key for a call.
    ///
    /// Returns None if no encryption key has been set for this call.
    pub async fn get_encryption_key(&self, call_id: &CallId) -> Option<CallEncryptionKey> {
        self.calls
            .read()
            .await
            .get(call_id.as_str())
            .and_then(|info| info.encryption.as_ref())
            .map(|enc| enc.master_key.clone())
    }

    /// Check if this call was initiated by us (outgoing call).
    pub async fn is_initiator(&self, call_id: &CallId) -> Option<bool> {
        self.calls
            .read()
            .await
            .get(call_id.as_str())
            .map(|info| info.is_initiator())
    }

    /// Get the full call info for a call.
    pub async fn get_call_info(&self, call_id: &CallId) -> Option<CallInfo> {
        self.calls.read().await.get(call_id.as_str()).cloned()
    }

    /// Store the encryption key for an outgoing call.
    ///
    /// This should be called after generating and encrypting the call key,
    /// before sending the offer stanza. The key will be used to derive SRTP
    /// keys when the call is accepted.
    ///
    /// # Returns
    /// `Ok(())` if the key was stored successfully.
    /// `Err(CallError::NotFound)` if the call doesn't exist.
    pub async fn store_encryption_key(
        &self,
        call_id: &CallId,
        key: CallEncryptionKey,
    ) -> Result<(), CallError> {
        let mut calls = self.calls.write().await;
        let info = calls
            .get_mut(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(call_id.to_string()))?;

        info.set_encryption_key(key);
        log::debug!("Stored encryption key for call {}", call_id);
        Ok(())
    }

    /// Store the elected relay index from a RELAY_ELECTION stanza.
    ///
    /// The server sends this to tell both peers which relay to use.
    pub async fn store_elected_relay(
        &self,
        call_id: &CallId,
        elected_relay_idx: u32,
    ) -> Result<(), CallError> {
        // Verify the call exists
        if !self.calls.read().await.contains_key(call_id.as_str()) {
            return Err(CallError::NotFound(call_id.to_string()));
        }

        self.elected_relays
            .write()
            .await
            .insert(call_id.to_string(), elected_relay_idx);

        info!(
            "Stored elected relay index {} for call {}",
            elected_relay_idx, call_id
        );
        Ok(())
    }

    /// Get the elected relay index for a call.
    ///
    /// Returns None if no RELAY_ELECTION has been received yet.
    pub async fn get_elected_relay(&self, call_id: &CallId) -> Option<u32> {
        self.elected_relays
            .read()
            .await
            .get(call_id.as_str())
            .copied()
    }

    // ==================== WebRTC Transport Methods ====================

    /// Connect to relay using WebRTC DataChannel (WhatsApp Web approach).
    ///
    /// This is the **recommended** method for connecting to WhatsApp relays.
    /// It replicates what WhatsApp Web does:
    /// 1. Creates RTCPeerConnection with unordered DataChannel
    /// 2. Generates offer SDP
    /// 3. Manipulates SDP to inject relay credentials and address
    /// 4. Sets modified SDP as remote answer
    /// 5. WebRTC handles ICE/DTLS/SCTP automatically
    ///
    /// # Arguments
    /// * `call_id` - The call to connect
    /// * `relay_data` - Relay data from offer ACK (contains auth_tokens, relay_key, endpoints)
    ///
    /// # Returns
    /// * `Ok(WebRtcConnectionResult)` - Connection info including relay name and ID
    /// * `Err(CallError)` - If connection fails
    ///
    /// # Example
    /// ```ignore
    /// // After receiving offer ACK with relay data
    /// let relay_data = parse_relay_data_from_ack(&ack_node)?;
    /// call_manager.store_relay_data(&call_id, relay_data.clone()).await?;
    ///
    /// // Connect using WebRTC (recommended)
    /// let result = call_manager.connect_webrtc(&call_id, &relay_data).await?;
    /// println!("Connected to relay: {}", result.relay_info.relay_name);
    /// ```
    pub async fn connect_webrtc(
        &self,
        call_id: &CallId,
        relay_data: &RelayData,
    ) -> Result<WebRtcConnectionResult, CallError> {
        info!(
            "Connecting to relay via WebRTC for call {} ({} endpoints)",
            call_id,
            relay_data.endpoints.len()
        );

        // Create WebRTC transport with default config
        let config = WebRtcTransportConfig {
            timeout: Duration::from_secs(30),
            ice_debug: false,
        };
        let transport = Arc::new(WebRtcTransport::new(config));

        // Connect to relay
        let result = transport.connect(relay_data).await.map_err(|e| {
            warn!("WebRTC connection failed for call {}: {}", call_id, e);
            CallError::Transport(format!("WebRTC connection failed: {}", e))
        })?;

        info!(
            "WebRTC connection established for call {}: relay={} (id={})",
            call_id, result.relay_info.relay_name, result.relay_info.relay_id
        );

        // Store the transport
        self.webrtc_transports
            .write()
            .await
            .insert(call_id.to_string(), transport);

        Ok(result)
    }

    /// Connect to relay using WebRTC with custom configuration.
    ///
    /// This will reuse an existing connected transport if available,
    /// avoiding unnecessary reconnection overhead.
    pub async fn connect_webrtc_with_config(
        &self,
        call_id: &CallId,
        relay_data: &RelayData,
        config: WebRtcTransportConfig,
    ) -> Result<WebRtcConnectionResult, CallError> {
        // Check if we already have a connected transport for this call
        if let Some(existing_transport) = self.webrtc_transports.read().await.get(call_id.as_str())
            && existing_transport.state().await == WebRtcState::Connected
            && let Some(relay_info) = existing_transport.connected_relay().await
        {
            info!(
                "Reusing existing WebRTC connection for call {}: relay={} (c2r_rtt={}ms)",
                call_id,
                relay_info.relay_name,
                relay_info
                    .c2r_rtt_ms
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "?".to_string())
            );
            return Ok(WebRtcConnectionResult {
                relay_info,
                local_addr: None,
            });
        }

        info!(
            "Connecting to relay via WebRTC for call {} (timeout: {:?})",
            call_id, config.timeout
        );

        let transport = Arc::new(WebRtcTransport::new(config));

        let result = transport.connect(relay_data).await.map_err(|e| {
            warn!("WebRTC connection failed for call {}: {}", call_id, e);
            CallError::Transport(format!("WebRTC connection failed: {}", e))
        })?;

        info!(
            "WebRTC connection established for call {}: relay={} (c2r_rtt={}ms)",
            call_id,
            result.relay_info.relay_name,
            result
                .relay_info
                .c2r_rtt_ms
                .map(|r| r.to_string())
                .unwrap_or_else(|| "?".to_string())
        );

        self.webrtc_transports
            .write()
            .await
            .insert(call_id.to_string(), transport);

        Ok(result)
    }

    /// Get the WebRTC transport for a call.
    ///
    /// Returns None if no WebRTC transport has been created for this call.
    pub async fn get_webrtc_transport(&self, call_id: &CallId) -> Option<Arc<WebRtcTransport>> {
        self.webrtc_transports
            .read()
            .await
            .get(call_id.as_str())
            .cloned()
    }

    /// Remove and return the WebRTC transport for a call.
    ///
    /// This takes ownership of the transport, removing it from storage.
    pub async fn take_webrtc_transport(&self, call_id: &CallId) -> Option<Arc<WebRtcTransport>> {
        self.webrtc_transports
            .write()
            .await
            .remove(call_id.as_str())
    }

    /// Send data through the WebRTC DataChannel.
    ///
    /// # Arguments
    /// * `call_id` - The call to send data for
    /// * `data` - Binary data to send (typically RTP/SRTP packets)
    ///
    /// # Returns
    /// * `Ok(())` - If data was sent successfully
    /// * `Err(CallError)` - If transport not found or send failed
    pub async fn send_via_webrtc(&self, call_id: &CallId, data: &[u8]) -> Result<(), CallError> {
        let transports = self.webrtc_transports.read().await;
        let transport = transports
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(format!("No WebRTC transport for {}", call_id)))?;

        transport
            .send(data)
            .await
            .map_err(|e| CallError::Transport(format!("WebRTC send failed: {}", e)))
    }

    /// Receive data from the WebRTC DataChannel.
    ///
    /// This is a non-blocking call that returns immediately if no data is available.
    ///
    /// # Arguments
    /// * `call_id` - The call to receive data for
    ///
    /// # Returns
    /// * `Ok(Some(data))` - If data was received
    /// * `Ok(None)` - If no data available or channel closed
    /// * `Err(CallError)` - If transport not found
    pub async fn recv_from_webrtc(&self, call_id: &CallId) -> Result<Option<Vec<u8>>, CallError> {
        let transports = self.webrtc_transports.read().await;
        let transport = transports
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(format!("No WebRTC transport for {}", call_id)))?;

        Ok(transport.recv().await)
    }

    /// Receive data from the WebRTC DataChannel with timeout.
    ///
    /// # Arguments
    /// * `call_id` - The call to receive data for
    /// * `timeout` - Maximum time to wait for data
    ///
    /// # Returns
    /// * `Ok(data)` - If data was received
    /// * `Err(CallError)` - If timeout, transport not found, or channel closed
    pub async fn recv_from_webrtc_timeout(
        &self,
        call_id: &CallId,
        timeout: Duration,
    ) -> Result<Vec<u8>, CallError> {
        let transports = self.webrtc_transports.read().await;
        let transport = transports
            .get(call_id.as_str())
            .ok_or_else(|| CallError::NotFound(format!("No WebRTC transport for {}", call_id)))?;

        transport
            .recv_timeout(timeout)
            .await
            .map_err(|e| CallError::Transport(format!("WebRTC recv failed: {}", e)))
    }

    /// Close the WebRTC transport for a call.
    ///
    /// This closes the DataChannel and PeerConnection, releasing all resources.
    pub async fn close_webrtc_transport(&self, call_id: &CallId) -> Result<(), CallError> {
        if let Some(transport) = self
            .webrtc_transports
            .write()
            .await
            .remove(call_id.as_str())
        {
            transport
                .close()
                .await
                .map_err(|e| CallError::Transport(format!("WebRTC close failed: {}", e)))?;
            info!("Closed WebRTC transport for call {}", call_id);
        }
        Ok(())
    }

    /// Check if a call has an active WebRTC transport.
    pub async fn has_webrtc_transport(&self, call_id: &CallId) -> bool {
        self.webrtc_transports
            .read()
            .await
            .contains_key(call_id.as_str())
    }

    /// Cleanup all transports for a call (both legacy and WebRTC).
    ///
    /// Should be called when a call ends to release all resources.
    pub async fn cleanup_call_transports(&self, call_id: &CallId) {
        // Remove legacy transport
        self.bound_transports.write().await.remove(call_id.as_str());

        // Close and remove WebRTC transport
        if let Some(transport) = self
            .webrtc_transports
            .write()
            .await
            .remove(call_id.as_str())
        {
            let _ = transport.close().await;
        }

        // Remove elected relay
        self.elected_relays.write().await.remove(call_id.as_str());

        debug!("Cleaned up transports for call {}", call_id);
    }
}
