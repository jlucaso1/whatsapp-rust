//! Call media pipeline for VoIP audio.
//!
//! This module orchestrates the full audio pipeline:
//! - Capture audio → Opus encode → RTP packetize → SRTP encrypt → send via DataChannel
//! - Receive from DataChannel → SRTP decrypt → RTP depacketize → Opus decode → playback

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use log::{debug, info, warn};
use tokio::sync::mpsc;
use whatsapp_rust::calls::media::{
    RtpSession, SrtpSession, StunMessage, create_audio_sender_subscriptions,
};
use whatsapp_rust::calls::{CallManager, SrtpKeyingMaterial};
use whatsapp_rust::types::call::CallId;

use super::call_audio::{
    AudioCaptureHandle, AudioPlaybackHandle, CallAudioError, start_audio_capture,
    start_audio_playback,
};

/// Handle to a running call media session.
pub struct CallMediaPipelineHandle {
    stop_signal: Arc<AtomicBool>,
    _capture_task: tokio::task::JoinHandle<()>,
    _playback_task: tokio::task::JoinHandle<()>,
    _receive_task: tokio::task::JoinHandle<()>,
    _ping_task: tokio::task::JoinHandle<()>,
    /// Audio capture handle - MUST be kept alive for the duration of the call!
    _audio_capture_handle: AudioCaptureHandle,
    /// Audio playback handle - MUST be kept alive for the duration of the call!
    _audio_playback_handle: AudioPlaybackHandle,
}

impl CallMediaPipelineHandle {
    /// Stop the media pipeline.
    pub fn stop(&self) {
        info!("Stopping call media pipeline");
        self.stop_signal.store(true, Ordering::Relaxed);
        // Also stop the audio threads
        self._audio_capture_handle.stop();
        self._audio_playback_handle.stop();
    }
}

impl Drop for CallMediaPipelineHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Configuration for the call media pipeline.
#[derive(Default)]
pub struct CallMediaPipelineConfig {
    /// SSRC for our RTP stream (random if not specified).
    pub ssrc: Option<u32>,
}

/// Errors from the call media pipeline.
#[derive(Debug)]
pub enum CallMediaPipelineError {
    AudioCapture(CallAudioError),
    AudioPlayback(CallAudioError),
    Srtp(String),
    Send(String),
    Receive(String),
    StunAllocate(String),
}

impl std::fmt::Display for CallMediaPipelineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AudioCapture(e) => write!(f, "Audio capture error: {}", e),
            Self::AudioPlayback(e) => write!(f, "Audio playback error: {}", e),
            Self::Srtp(e) => write!(f, "SRTP error: {}", e),
            Self::Send(e) => write!(f, "Send error: {}", e),
            Self::Receive(e) => write!(f, "Receive error: {}", e),
            Self::StunAllocate(e) => write!(f, "STUN Allocate error: {}", e),
        }
    }
}

impl std::error::Error for CallMediaPipelineError {}

fn generate_transaction_id() -> [u8; 12] {
    use rand::RngCore;
    let mut id = [0u8; 12];
    rand::rng().fill_bytes(&mut id);
    id
}

/// Perform STUN Allocate to bind with the relay.
///
/// This must be called BEFORE sending media packets. The relay needs this
/// allocation request to know where to forward packets.
///
/// # Arguments
/// * `ssrc` - Our RTP SSRC for SenderSubscriptions (tells relay what streams we're sending)
async fn perform_stun_allocate(
    call_manager: &Arc<CallManager>,
    call_id: &str,
    auth_token: &[u8],
    relay_key: &[u8],
    ssrc: u32,
) -> Result<(), CallMediaPipelineError> {
    info!(
        "Sending STUN Allocate for call {} with SSRC 0x{:08x}",
        call_id, ssrc
    );

    let transaction_id = generate_transaction_id();

    // Create SenderSubscriptions with our SSRC (tells relay what streams we're sending)
    // This is the WhatsApp 0x4000 attribute - protobuf-encoded stream subscription
    let sender_subscriptions = create_audio_sender_subscriptions(ssrc);
    info!(
        "SenderSubscriptions: {} bytes for SSRC 0x{:08x}",
        sender_subscriptions.len(),
        ssrc
    );

    // Create STUN Allocate request with credentials and SenderSubscriptions
    // USERNAME = auth_token (the base64-decoded token)
    // MESSAGE-INTEGRITY = HMAC-SHA1 using relay_key
    // 0x4000 = SenderSubscriptions (tells relay what streams we're sending)
    let msg = StunMessage::allocate_request(transaction_id)
        .with_username(auth_token)
        .with_integrity_key(relay_key)
        .with_sender_subscriptions(sender_subscriptions);

    let data = msg.encode();
    info!(
        "STUN Allocate request: {} bytes, tx_id={:02x}{:02x}{:02x}{:02x}...",
        data.len(),
        transaction_id[0],
        transaction_id[1],
        transaction_id[2],
        transaction_id[3]
    );

    // Send via DataChannel
    call_manager
        .send_via_webrtc(&CallId::from(call_id.to_string()), &data)
        .await
        .map_err(|e| CallMediaPipelineError::StunAllocate(format!("Send failed: {}", e)))?;

    // Wait for Allocate Response (timeout 5s)
    let timeout = std::time::Duration::from_secs(5);
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        match call_manager
            .recv_from_webrtc_timeout(
                &CallId::from(call_id.to_string()),
                std::time::Duration::from_millis(200),
            )
            .await
        {
            Ok(response) => {
                // Check if it's a STUN response (first 2 bits = 00, type >= 0x0100)
                if response.len() >= 20 {
                    let msg_type = ((response[0] as u16 & 0x3F) << 8) | (response[1] as u16);
                    debug!(
                        "Received potential STUN response: {} bytes, type=0x{:04x}",
                        response.len(),
                        msg_type
                    );

                    // Check for Allocate Success Response (0x0103) or Binding Response (0x0101)
                    if msg_type == 0x0103 {
                        info!(
                            "STUN Allocate successful for call {} (type=0x{:04x})",
                            call_id, msg_type
                        );
                        return Ok(());
                    } else if msg_type == 0x0113 {
                        // Allocate Error Response
                        warn!("STUN Allocate error response for call {}", call_id);
                        // Continue waiting - maybe we need to retry
                    } else if msg_type == 0x0101 {
                        // Binding Response - also acceptable
                        info!(
                            "STUN Binding response for call {} (type=0x{:04x})",
                            call_id, msg_type
                        );
                        return Ok(());
                    }
                    // Else continue waiting for the right response
                }
            }
            Err(e) => {
                // Timeout is normal - just continue waiting
                if !e.to_string().contains("imeout") {
                    debug!("STUN Allocate recv error: {}", e);
                }
            }
        }
    }

    // If we get here, we timed out waiting for a response
    // Log a warning but continue anyway - maybe the relay doesn't require explicit allocation
    warn!(
        "STUN Allocate timeout for call {} - continuing anyway (relay may not require explicit allocation)",
        call_id
    );
    Ok(())
}

/// Start the call media pipeline.
///
/// This starts:
/// 1. STUN Allocate to bind with the relay (CRITICAL: must happen first!)
/// 2. Audio capture thread (microphone → Opus frames)
/// 3. Send task (Opus frames → RTP → SRTP → DataChannel)
/// 4. Receive task (DataChannel → SRTP → RTP → Opus frames)
/// 5. Audio playback thread (Opus frames → speaker)
///
/// # Arguments
/// * `call_manager` - The call manager for sending/receiving via WebRTC
/// * `call_id` - The call identifier
/// * `hbh_key` - Hop-by-hop SRTP key (30 bytes: 16-byte key + 14-byte salt)
/// * `auth_token` - Authentication token for STUN USERNAME attribute (raw bytes from relay data)
/// * `relay_key` - Relay key for STUN MESSAGE-INTEGRITY (raw bytes from relay data)
/// * `config` - Pipeline configuration
pub async fn start_call_media_pipeline(
    call_manager: Arc<CallManager>,
    call_id: String,
    hbh_key: &[u8],
    auth_token: &[u8],
    relay_key: &[u8],
    config: CallMediaPipelineConfig,
) -> Result<CallMediaPipelineHandle, CallMediaPipelineError> {
    info!("Starting call media pipeline for {}", call_id);

    // Generate SSRC early - we need it for both STUN Allocate (SenderSubscriptions) and RTP
    // The SSRC MUST be consistent: SenderSubscriptions tells relay what SSRC to expect,
    // and RTP packets must use that same SSRC.
    let ssrc = config.ssrc.unwrap_or_else(rand::random);
    info!("Using SSRC 0x{:08x} for call {}", ssrc, call_id);

    // STEP 1: Perform STUN Allocate to bind with the relay
    // This MUST happen before sending any media packets!
    // The SenderSubscriptions (0x4000 attribute) tells the relay what streams we're sending.
    // See docs/wasm-reverse-engineering.md for details.
    perform_stun_allocate(&call_manager, &call_id, auth_token, relay_key, ssrc).await?;

    // Validate and parse hbh_key (30 bytes: 16-byte key + 14-byte salt)
    if hbh_key.len() != 30 {
        return Err(CallMediaPipelineError::Srtp(format!(
            "hbh_key must be 30 bytes, got {}",
            hbh_key.len()
        )));
    }
    let mut master_key = [0u8; 16];
    let mut master_salt = [0u8; 14];
    master_key.copy_from_slice(&hbh_key[..16]);
    master_salt.copy_from_slice(&hbh_key[16..30]);
    let keying = SrtpKeyingMaterial {
        master_key,
        master_salt,
    };
    // Symmetric key - same for send and receive (client <-> relay)
    let srtp_session = Arc::new(tokio::sync::Mutex::new(SrtpSession::new(&keying, &keying)));

    // Create RTP session for sending (WhatsApp uses PT=120)
    // Uses the same SSRC we sent in SenderSubscriptions
    let rtp_session = Arc::new(tokio::sync::Mutex::new(RtpSession::whatsapp_opus(ssrc)));
    info!(
        "Using WhatsApp RTP session with SSRC=0x{:08x}, PT=120",
        ssrc
    );

    // Stop signal
    let stop_signal = Arc::new(AtomicBool::new(false));

    // Start audio capture (microphone → Opus frames)
    let capture_result = start_audio_capture().map_err(CallMediaPipelineError::AudioCapture)?;
    let mut opus_rx = capture_result.rx;
    let audio_capture_handle = capture_result.handle;

    // Start audio playback (Opus frames → speaker)
    let playback_result = start_audio_playback().map_err(CallMediaPipelineError::AudioPlayback)?;
    let playback_tx = playback_result.tx;
    let audio_playback_handle = playback_result.handle;

    // Channel for received Opus frames to playback
    let (decoded_tx, mut decoded_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Capture task: Opus frames → RTP → SRTP → DataChannel
    let capture_stop = stop_signal.clone();
    let capture_call_id = call_id.clone();
    let capture_call_manager = call_manager.clone();
    let capture_srtp = srtp_session.clone();
    let capture_rtp = rtp_session.clone();

    let capture_task = tokio::spawn(async move {
        info!("Capture pipeline started for call {}", capture_call_id);
        let mut packet_count = 0u64;

        while !capture_stop.load(Ordering::Relaxed) {
            // Get Opus frame from capture
            match opus_rx.recv().await {
                Some(opus_frame) => {
                    // Create RTP packet
                    let rtp_packet = {
                        let mut rtp = capture_rtp.lock().await;
                        // Set marker bit on first packet
                        let marker = packet_count == 0;
                        rtp.create_packet(opus_frame, marker)
                    };

                    // SRTP encrypt
                    let srtp_data = {
                        let mut srtp = capture_srtp.lock().await;
                        match srtp.protect(&rtp_packet) {
                            Ok(data) => data,
                            Err(e) => {
                                warn!("SRTP encrypt failed: {}", e);
                                continue;
                            }
                        }
                    };

                    // Send via WebRTC DataChannel
                    if let Err(e) = capture_call_manager
                        .send_via_webrtc(&CallId::from(capture_call_id.clone()), &srtp_data)
                        .await
                    {
                        warn!("Failed to send audio packet: {}", e);
                    } else {
                        packet_count += 1;
                        if packet_count.is_multiple_of(500) {
                            debug!(
                                "Sent {} audio packets for call {}",
                                packet_count, capture_call_id
                            );
                        }
                    }
                }
                None => {
                    info!("Audio capture channel closed");
                    break;
                }
            }
        }

        info!(
            "Capture pipeline stopped for call {} ({} packets sent)",
            capture_call_id, packet_count
        );
    });

    // Receive task: DataChannel → SRTP → RTP → Opus frames
    let receive_stop = stop_signal.clone();
    let receive_call_id = call_id.clone();
    let receive_call_manager = call_manager.clone();
    let receive_srtp = srtp_session.clone();

    let receive_task = tokio::spawn(async move {
        info!("Receive pipeline started for call {}", receive_call_id);
        let mut packet_count = 0u64;

        while !receive_stop.load(Ordering::Relaxed) {
            // Receive from WebRTC DataChannel
            let data = match receive_call_manager
                .recv_from_webrtc_timeout(
                    &CallId::from(receive_call_id.clone()),
                    std::time::Duration::from_millis(100),
                )
                .await
            {
                Ok(data) => data,
                Err(e) => {
                    // Timeout is normal - just continue
                    if !e.to_string().contains("timeout") && !e.to_string().contains("Timeout") {
                        debug!("Receive error: {}", e);
                    }
                    continue;
                }
            };

            // Skip STUN messages (first 2 bytes determine type)
            if data.len() >= 2 {
                let first_two = ((data[0] as u16) << 8) | (data[1] as u16);
                // STUN messages have first 2 bits = 00 (type < 0x4000)
                if (data[0] & 0xC0) == 0x00 && first_two < 0x4000 {
                    debug!("Received STUN message, skipping");
                    continue;
                }
            }

            // SRTP decrypt
            let rtp_packet = {
                let mut srtp = receive_srtp.lock().await;
                match srtp.unprotect(&data) {
                    Ok(packet) => packet,
                    Err(e) => {
                        debug!("SRTP decrypt failed (may be STUN): {}", e);
                        continue;
                    }
                }
            };

            // Extract Opus payload and send to playback
            if !rtp_packet.payload.is_empty() {
                if decoded_tx.send(rtp_packet.payload).is_err() {
                    warn!("Playback channel closed");
                    break;
                }
                packet_count += 1;
                if packet_count.is_multiple_of(500) {
                    debug!(
                        "Received {} audio packets for call {}",
                        packet_count, receive_call_id
                    );
                }
            }
        }

        info!(
            "Receive pipeline stopped for call {} ({} packets received)",
            receive_call_id, packet_count
        );
    });

    // Playback task: Forward decoded Opus frames to playback thread
    let playback_stop = stop_signal.clone();
    let playback_call_id = call_id.clone();

    let playback_task = tokio::spawn(async move {
        info!("Playback pipeline started for call {}", playback_call_id);

        while !playback_stop.load(Ordering::Relaxed) {
            match decoded_rx.recv().await {
                Some(opus_frame) => {
                    if playback_tx.send(opus_frame).is_err() {
                        warn!("Audio playback channel closed");
                        break;
                    }
                }
                None => {
                    info!("Decoded audio channel closed");
                    break;
                }
            }
        }

        info!("Playback pipeline stopped for call {}", playback_call_id);
    });

    // Ping task: Send periodic pings to keep the connection alive
    let ping_stop = stop_signal.clone();
    let ping_call_id = call_id.clone();
    let ping_call_manager = call_manager.clone();

    let ping_task = tokio::spawn(async move {
        info!("Ping task started for call {}", ping_call_id);
        let mut ping_count = 0u64;

        // WhatsApp sends pings approximately every 5 seconds
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));

        while !ping_stop.load(Ordering::Relaxed) {
            interval.tick().await;

            if ping_stop.load(Ordering::Relaxed) {
                break;
            }

            let transaction_id = generate_transaction_id();

            // Create WhatsApp ping message (0x0801)
            let ping_msg = StunMessage::whatsapp_ping(transaction_id);
            let ping_data = ping_msg.encode();

            // Send via DataChannel
            if let Err(e) = ping_call_manager
                .send_via_webrtc(&CallId::from(ping_call_id.clone()), &ping_data)
                .await
            {
                debug!("Failed to send ping for call {}: {}", ping_call_id, e);
            } else {
                ping_count += 1;
                if ping_count.is_multiple_of(10) {
                    debug!("Sent {} pings for call {}", ping_count, ping_call_id);
                }
            }
        }

        info!(
            "Ping task stopped for call {} ({} pings sent)",
            ping_call_id, ping_count
        );
    });

    info!("Call media pipeline started successfully for {}", call_id);

    Ok(CallMediaPipelineHandle {
        stop_signal,
        _capture_task: capture_task,
        _playback_task: playback_task,
        _receive_task: receive_task,
        _ping_task: ping_task,
        _audio_capture_handle: audio_capture_handle,
        _audio_playback_handle: audio_playback_handle,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = CallMediaPipelineConfig::default();
        assert!(config.ssrc.is_none());
    }
}
