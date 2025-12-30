//! Call media callback implementation for the UI.
//!
//! This module implements the `CallMediaCallback` trait to handle
//! call media events and manage the media transport connection.

use log::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use whatsapp_rust::calls::{
    CallMediaCallback, DerivedCallKeys, MediaParams, OfferEncData, RelayData, RelayLatencyData,
    TransportPayload,
    media::{
        CallMediaTransport, MediaSession, MediaSessionBuilder, MediaSessionState, MediaSessionStats,
    },
};

use crate::audio::{
    AudioCaptureHandle, AudioPlaybackHandle, start_audio_capture, start_audio_playback,
};

/// Active call media session with audio streams.
pub struct ActiveMediaSession {
    /// The call ID.
    pub call_id: String,
    /// The media session.
    pub session: Arc<MediaSession>,
    /// Whether we're the initiator.
    pub is_initiator: bool,
    /// Audio capture handle (owns the capture thread).
    capture_handle: Mutex<Option<AudioCaptureHandle>>,
    /// Audio playback handle (owns the playback thread).
    playback_handle: Mutex<Option<AudioPlaybackHandle>>,
}

impl ActiveMediaSession {
    /// Check if the session is connected.
    pub async fn is_connected(&self) -> bool {
        self.session.state().await == MediaSessionState::Active
    }

    /// Get session statistics.
    pub async fn stats(&self) -> MediaSessionStats {
        self.session.stats().await
    }
}

/// Media manager for handling call media sessions.
pub struct CallMediaManager {
    /// Active media sessions by call ID.
    sessions: Mutex<std::collections::HashMap<String, Arc<ActiveMediaSession>>>,
}

impl CallMediaManager {
    /// Create a new media manager.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Start a media session for a call.
    ///
    /// Creates the session, connects to the relay, and starts audio.
    pub async fn start_session(
        &self,
        call_id: &str,
        relay_data: RelayData,
        keys: DerivedCallKeys,
        is_initiator: bool,
    ) -> Result<Arc<ActiveMediaSession>, String> {
        info!(
            "Starting media session for call {} (initiator: {})",
            call_id, is_initiator
        );

        // Create the media session
        let session = MediaSessionBuilder::new()
            .initiator(is_initiator)
            .sample_rate(16000)
            .samples_per_packet(320) // 20ms at 16kHz
            .build();

        let session = Arc::new(session);

        // Connect to the relay
        match session.connect(&relay_data, &keys).await {
            Ok(active_relay) => {
                info!(
                    "Call {} connected to relay {} (RTT: {}ms)",
                    call_id,
                    active_relay.relay.remote_addr,
                    active_relay.latency.as_millis()
                );

                let active_session = Arc::new(ActiveMediaSession {
                    call_id: call_id.to_string(),
                    session: session.clone(),
                    is_initiator,
                    capture_handle: Mutex::new(None),
                    playback_handle: Mutex::new(None),
                });

                // Store the session first
                self.sessions
                    .lock()
                    .await
                    .insert(call_id.to_string(), active_session.clone());

                // Start audio capture
                match start_audio_capture() {
                    Ok(capture_result) => {
                        info!("Audio capture started for call {}", call_id);

                        // Spawn send loop with the receiver
                        let session_clone = session.clone();
                        let call_id_clone = call_id.to_string();
                        let mut rx = capture_result.rx;
                        tokio::spawn(async move {
                            Self::audio_send_loop(&call_id_clone, session_clone, &mut rx).await;
                        });

                        // Store capture handle (thread will be stopped on drop)
                        *active_session.capture_handle.lock().await = Some(capture_result.handle);
                    }
                    Err(e) => {
                        warn!("Failed to start audio capture for call {}: {}", call_id, e);
                        // Continue without capture
                    }
                }

                // Start audio playback
                match start_audio_playback() {
                    Ok(playback_result) => {
                        info!("Audio playback started for call {}", call_id);

                        // Spawn receive loop with the sender
                        let session_clone = session.clone();
                        let call_id_clone = call_id.to_string();
                        let playback_tx = playback_result.tx;
                        tokio::spawn(async move {
                            Self::receive_loop(&call_id_clone, session_clone, playback_tx).await;
                        });

                        // Store playback handle
                        *active_session.playback_handle.lock().await = Some(playback_result.handle);
                    }
                    Err(e) => {
                        warn!("Failed to start audio playback for call {}: {}", call_id, e);
                        // Continue without playback
                    }
                }

                Ok(active_session)
            }
            Err(e) => {
                error!("Failed to connect call {} to relay: {}", call_id, e);
                Err(format!("Relay connection failed: {}", e))
            }
        }
    }

    /// Start a media session using a pre-bound transport.
    ///
    /// This is used when early binding was performed (after ACK, before peer accept).
    /// The transport is already connected to relays, so we just set up SRTP.
    pub async fn start_session_with_transport(
        &self,
        call_id: &str,
        relay_data: RelayData,
        transport: Arc<CallMediaTransport>,
        is_initiator: bool,
    ) -> Result<Arc<ActiveMediaSession>, String> {
        info!(
            "Starting media session for call {} using pre-bound transport (initiator: {})",
            call_id, is_initiator
        );

        // Create the media session
        let session = MediaSessionBuilder::new()
            .initiator(is_initiator)
            .sample_rate(16000)
            .samples_per_packet(320) // 20ms at 16kHz
            .build();

        let session = Arc::new(session);

        // Use the pre-connected transport
        match session
            .use_preconnected_transport(transport, &relay_data)
            .await
        {
            Ok(active_relay) => {
                info!(
                    "Call {} using pre-bound relay {} (RTT: {}ms)",
                    call_id,
                    active_relay.relay.remote_addr,
                    active_relay.latency.as_millis()
                );

                let active_session = Arc::new(ActiveMediaSession {
                    call_id: call_id.to_string(),
                    session: session.clone(),
                    is_initiator,
                    capture_handle: Mutex::new(None),
                    playback_handle: Mutex::new(None),
                });

                // Store the session first
                self.sessions
                    .lock()
                    .await
                    .insert(call_id.to_string(), active_session.clone());

                // Start audio capture
                match start_audio_capture() {
                    Ok(capture_result) => {
                        info!("Audio capture started for call {}", call_id);

                        // Spawn send loop with the receiver
                        let session_clone = session.clone();
                        let call_id_clone = call_id.to_string();
                        let mut rx = capture_result.rx;
                        tokio::spawn(async move {
                            Self::audio_send_loop(&call_id_clone, session_clone, &mut rx).await;
                        });

                        // Store capture handle (thread will be stopped on drop)
                        *active_session.capture_handle.lock().await = Some(capture_result.handle);
                    }
                    Err(e) => {
                        warn!("Failed to start audio capture for call {}: {}", call_id, e);
                        // Continue without capture
                    }
                }

                // Start audio playback
                match start_audio_playback() {
                    Ok(playback_result) => {
                        info!("Audio playback started for call {}", call_id);

                        // Spawn receive loop with the sender
                        let session_clone = session.clone();
                        let call_id_clone = call_id.to_string();
                        let playback_tx = playback_result.tx;
                        tokio::spawn(async move {
                            Self::receive_loop(&call_id_clone, session_clone, playback_tx).await;
                        });

                        // Store playback handle
                        *active_session.playback_handle.lock().await = Some(playback_result.handle);
                    }
                    Err(e) => {
                        warn!("Failed to start audio playback for call {}: {}", call_id, e);
                        // Continue without playback
                    }
                }

                Ok(active_session)
            }
            Err(e) => {
                error!(
                    "Failed to use pre-bound transport for call {}: {}",
                    call_id, e
                );
                Err(format!("Pre-bound transport failed: {}", e))
            }
        }
    }

    /// Audio send loop - reads from capture and sends via RTP.
    async fn audio_send_loop(
        call_id: &str,
        session: Arc<MediaSession>,
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) {
        info!("Audio send loop started for call {}", call_id);
        let mut packets_sent = 0u64;
        let mut bytes_sent = 0usize;
        let mut errors = 0u64;

        while let Some(opus_frame) = rx.recv().await {
            if session.state().await != MediaSessionState::Active {
                info!(
                    "Call {} session no longer active, stopping send loop (sent {} packets, {} errors)",
                    call_id, packets_sent, errors
                );
                break;
            }

            match session.send_audio(&opus_frame).await {
                Ok(sent) => {
                    packets_sent += 1;
                    bytes_sent += sent;
                    if packets_sent == 1 {
                        info!(
                            "Call {} sent first audio packet ({} bytes Opus -> {} bytes SRTP)",
                            call_id,
                            opus_frame.len(),
                            sent
                        );
                    }
                    if packets_sent.is_multiple_of(100) {
                        info!(
                            "Call {} sent {} audio packets ({} KB total, {} errors)",
                            call_id,
                            packets_sent,
                            bytes_sent / 1024,
                            errors
                        );
                    }
                }
                Err(e) => {
                    errors += 1;
                    if errors <= 5 {
                        warn!("Call {} send error #{}: {}", call_id, errors, e);
                    }
                }
            }
        }

        info!(
            "Audio send loop ended for call {} ({} packets sent)",
            call_id, packets_sent
        );
    }

    /// Receive loop for processing incoming packets and forwarding to playback.
    async fn receive_loop(
        call_id: &str,
        session: Arc<MediaSession>,
        playback_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) {
        info!("Starting receive loop for call {}", call_id);
        let mut packets_received = 0u64;

        loop {
            if session.state().await != MediaSessionState::Active {
                info!(
                    "Session {} no longer active, stopping receive loop",
                    call_id
                );
                break;
            }

            match session.recv_packet(Duration::from_millis(100)).await {
                Ok(Some(packet)) => {
                    packets_received += 1;
                    if packets_received.is_multiple_of(50) {
                        debug!(
                            "Call {} received {} packets (seq={})",
                            call_id, packets_received, packet.header.sequence_number
                        );
                    }

                    // Forward Opus payload to playback
                    if playback_tx.send(packet.payload.clone()).is_err() {
                        warn!("Call {} playback channel closed", call_id);
                        break;
                    }
                }
                Ok(None) => {
                    // Timeout, continue loop
                }
                Err(e) => {
                    warn!("Call {} receive error: {}", call_id, e);
                }
            }
        }

        info!(
            "Receive loop ended for call {} ({} packets received)",
            call_id, packets_received
        );
    }

    /// Get an active media session.
    pub async fn get_session(&self, call_id: &str) -> Option<Arc<ActiveMediaSession>> {
        self.sessions.lock().await.get(call_id).cloned()
    }

    /// Stop and remove a media session.
    pub async fn stop_session(&self, call_id: &str) {
        if let Some(session) = self.sessions.lock().await.remove(call_id) {
            info!("Stopping media session for call {}", call_id);

            // Stop audio (handles are dropped, which stops the threads)
            {
                let mut capture = session.capture_handle.lock().await;
                if let Some(ref handle) = *capture {
                    handle.stop();
                }
                *capture = None;
            }
            {
                let mut playback = session.playback_handle.lock().await;
                if let Some(ref handle) = *playback {
                    handle.stop();
                }
                *playback = None;
            }

            // Close the media session
            session.session.close().await;
            info!("Media session stopped for call {}", call_id);
        }
    }

    /// Get statistics for a session.
    pub async fn get_stats(&self, call_id: &str) -> Option<MediaSessionStats> {
        if let Some(session) = self.get_session(call_id).await {
            Some(session.session.stats().await)
        } else {
            None
        }
    }
}

impl Default for CallMediaManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Media callback that forwards events to the media manager.
pub struct UiCallMediaCallback {
    _marker: std::marker::PhantomData<()>,
}

impl UiCallMediaCallback {
    pub fn new() -> Self {
        Self {
            _marker: std::marker::PhantomData,
        }
    }
}

impl Default for UiCallMediaCallback {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl CallMediaCallback for UiCallMediaCallback {
    async fn on_offer_received(
        &self,
        call_id: &str,
        relay_data: &RelayData,
        _media_params: &MediaParams,
        _enc_data: &OfferEncData,
    ) {
        debug!(
            "Call {} offer received with {} relay endpoints",
            call_id,
            relay_data.endpoints.len()
        );
    }

    async fn on_transport_received(&self, call_id: &str, _transport: &TransportPayload) {
        debug!("Call {} transport received", call_id);
    }

    async fn on_relay_latency(&self, call_id: &str, latency: &[RelayLatencyData]) {
        debug!(
            "Call {} relay latency received: {} measurements",
            call_id,
            latency.len()
        );
    }

    async fn on_enc_rekey(&self, call_id: &str, _keys: &DerivedCallKeys) {
        debug!("Call {} enc_rekey received", call_id);
    }

    async fn on_call_accepted(&self, call_id: &str) {
        info!(
            "Call {} accepted - media connection will be started",
            call_id
        );
    }
}
