//! Complete media session for VoIP calls.

use log::{debug, info};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, RwLock};

use super::jitter::{JitterBuffer, JitterBufferConfig, JitterStats};
use super::relay::RelayError;
use super::rtp::{RtpPacket, RtpSession};
use super::srtp::{SrtpError, SrtpSession};
use super::transport::{ActiveRelay, CallMediaTransport, MediaTransportConfig, TransportError};
use crate::calls::{DerivedCallKeys, RelayData};

/// Media session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaSessionState {
    /// Not started.
    Idle,
    /// Connecting to relay.
    Connecting,
    /// Connected and active.
    Active,
    /// Session ended.
    Ended,
    /// Error state.
    Error,
}

/// Configuration for media session.
#[derive(Debug, Clone)]
pub struct MediaSessionConfig {
    pub transport: MediaTransportConfig,
    pub jitter: JitterBufferConfig,
    pub sample_rate: u32,
    pub samples_per_packet: u32,
    pub recv_buffer_size: usize,
}

impl Default for MediaSessionConfig {
    fn default() -> Self {
        Self {
            transport: MediaTransportConfig::default(),
            jitter: JitterBufferConfig::default(),
            sample_rate: 16000,      // 16kHz for WhatsApp voice
            samples_per_packet: 320, // 20ms at 16kHz
            recv_buffer_size: 2048,  // Max RTP packet size
        }
    }
}

/// Statistics for the media session.
#[derive(Debug, Clone, Default)]
pub struct MediaSessionStats {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub encrypt_errors: u64,
    pub decrypt_errors: u64,
    pub jitter: JitterStats,
}

/// Complete media session for a VoIP call.
pub struct MediaSession {
    state: RwLock<MediaSessionState>,
    config: MediaSessionConfig,
    transport: RwLock<Arc<CallMediaTransport>>,
    srtp: Mutex<Option<SrtpSession>>,
    rtp: Mutex<RtpSession>,
    jitter: Mutex<JitterBuffer>,
    stats: RwLock<MediaSessionStats>,
    ssrc: u32,
    is_initiator: bool,
}

impl MediaSession {
    pub fn new(config: MediaSessionConfig, is_initiator: bool) -> Self {
        let ssrc: u32 = rand::random();

        Self {
            state: RwLock::new(MediaSessionState::Idle),
            config: config.clone(),
            transport: RwLock::new(Arc::new(CallMediaTransport::new(config.transport))),
            srtp: Mutex::new(None),
            rtp: Mutex::new(RtpSession::new(
                ssrc,
                111, // Opus payload type
                config.sample_rate,
                config.samples_per_packet,
            )),
            jitter: Mutex::new(JitterBuffer::new(config.jitter, config.sample_rate)),
            stats: RwLock::new(MediaSessionStats::default()),
            ssrc,
            is_initiator,
        }
    }

    pub async fn state(&self) -> MediaSessionState {
        *self.state.read().await
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub async fn connect(
        &self,
        relay_data: &RelayData,
        _keys: &DerivedCallKeys,
    ) -> Result<ActiveRelay, MediaSessionError> {
        *self.state.write().await = MediaSessionState::Connecting;

        debug!(
            "MediaSession connect: hbh_key={:?}, relay_key={:?}, {} endpoints",
            relay_data.hbh_key.as_ref().map(|k| k.len()),
            relay_data.relay_key.as_ref().map(|k| k.len()),
            relay_data.endpoints.len()
        );

        // Connect to relay
        let transport = self.transport.read().await.clone();
        let active_relay = transport.connect(relay_data).await?;

        // Set up SRTP using hbh_key
        self.setup_srtp(relay_data).await?;

        *self.state.write().await = MediaSessionState::Active;

        Ok(active_relay)
    }

    pub async fn use_preconnected_transport(
        &self,
        transport: Arc<CallMediaTransport>,
        relay_data: &RelayData,
    ) -> Result<ActiveRelay, MediaSessionError> {
        *self.state.write().await = MediaSessionState::Connecting;

        let active_relay = transport
            .active_relay()
            .await
            .ok_or(MediaSessionError::NotActive)?;

        info!(
            "Using pre-connected transport: {} (RTT: {:?})",
            active_relay.relay.relay_name, active_relay.latency
        );

        *self.transport.write().await = transport;
        self.setup_srtp(relay_data).await?;
        *self.state.write().await = MediaSessionState::Active;

        Ok(active_relay)
    }

    pub async fn transport(&self) -> Arc<CallMediaTransport> {
        self.transport.read().await.clone()
    }

    async fn setup_srtp(&self, relay_data: &RelayData) -> Result<(), MediaSessionError> {
        let hbh_key = relay_data
            .hbh_key
            .as_ref()
            .ok_or(MediaSessionError::MissingHbhKey)?;

        if hbh_key.len() != 30 {
            return Err(MediaSessionError::InvalidHbhKey(hbh_key.len()));
        }

        debug!(
            "MediaSession: Setting up SRTP with hbh_key ({} bytes)",
            hbh_key.len()
        );

        let mut master_key = [0u8; 16];
        let mut master_salt = [0u8; 14];
        master_key.copy_from_slice(&hbh_key[..16]);
        master_salt.copy_from_slice(&hbh_key[16..30]);

        let srtp_keying = crate::calls::SrtpKeyingMaterial {
            master_key,
            master_salt,
        };

        let srtp = SrtpSession::new(&srtp_keying, &srtp_keying);
        *self.srtp.lock().await = Some(srtp);

        Ok(())
    }

    pub async fn send_audio(&self, opus_data: &[u8]) -> Result<usize, MediaSessionError> {
        if *self.state.read().await != MediaSessionState::Active {
            return Err(MediaSessionError::NotActive);
        }

        let packet = {
            let mut rtp = self.rtp.lock().await;
            rtp.create_packet(opus_data.to_vec(), false)
        };

        let encrypted = {
            let mut srtp_guard = self.srtp.lock().await;
            let srtp = srtp_guard.as_mut().ok_or(MediaSessionError::NotActive)?;
            srtp.protect(&packet)?
        };

        let transport = self.transport.read().await.clone();
        let bytes_sent = transport.send(&encrypted).await?;

        {
            let mut stats = self.stats.write().await;
            stats.packets_sent += 1;
            stats.bytes_sent += bytes_sent as u64;
        }

        Ok(bytes_sent)
    }

    pub async fn recv_packet(
        &self,
        timeout: Duration,
    ) -> Result<Option<RtpPacket>, MediaSessionError> {
        if *self.state.read().await != MediaSessionState::Active {
            return Err(MediaSessionError::NotActive);
        }

        let mut buf = vec![0u8; self.config.recv_buffer_size];
        let transport = self.transport.read().await.clone();
        let recv_result = tokio::time::timeout(timeout, transport.recv(&mut buf)).await;

        let len = match recv_result {
            Ok(Ok(len)) => len,
            Ok(Err(e)) => return Err(MediaSessionError::Transport(e)),
            Err(_) => return Ok(None), // Timeout
        };

        let packet = {
            let mut srtp_guard = self.srtp.lock().await;
            let srtp = srtp_guard.as_mut().ok_or(MediaSessionError::NotActive)?;
            match srtp.unprotect(&buf[..len]) {
                Ok(p) => p,
                Err(e) => {
                    self.stats.write().await.decrypt_errors += 1;
                    return Err(MediaSessionError::Srtp(e));
                }
            }
        };

        {
            let mut stats = self.stats.write().await;
            stats.packets_received += 1;
            stats.bytes_received += len as u64;
        }

        self.jitter.lock().await.push(packet.clone());
        Ok(Some(packet))
    }

    pub async fn pop_audio(&self) -> Option<RtpPacket> {
        let mut jitter = self.jitter.lock().await;
        let result = jitter.pop();
        if result.is_some() {
            self.stats.write().await.jitter = jitter.stats();
        }
        result
    }

    pub async fn stats(&self) -> MediaSessionStats {
        let mut stats = self.stats.read().await.clone();
        stats.jitter = self.jitter.lock().await.stats();
        stats
    }

    pub async fn active_relay(&self) -> Option<ActiveRelay> {
        self.transport.read().await.active_relay().await
    }

    pub async fn close(&self) {
        *self.state.write().await = MediaSessionState::Ended;
        self.transport.read().await.close().await;
        *self.srtp.lock().await = None;
        self.jitter.lock().await.reset();
    }
}

impl std::fmt::Debug for MediaSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MediaSession")
            .field("ssrc", &self.ssrc)
            .field("is_initiator", &self.is_initiator)
            .field("config", &self.config)
            .finish()
    }
}

/// Errors from media session operations.
#[derive(Debug, thiserror::Error)]
pub enum MediaSessionError {
    #[error("Session not active")]
    NotActive,
    #[error("Missing hbh_key in relay data")]
    MissingHbhKey,
    #[error("Invalid hbh_key length: expected 30, got {0}")]
    InvalidHbhKey(usize),
    #[error("Transport error: {0}")]
    Transport(#[from] TransportError),
    #[error("SRTP error: {0}")]
    Srtp(#[from] SrtpError),
    #[error("Relay error: {0}")]
    Relay(#[from] RelayError),
}

/// Builder for creating media sessions.
pub struct MediaSessionBuilder {
    config: MediaSessionConfig,
    is_initiator: bool,
}

impl MediaSessionBuilder {
    pub fn new() -> Self {
        Self {
            config: MediaSessionConfig::default(),
            is_initiator: false,
        }
    }

    pub fn initiator(mut self, is_initiator: bool) -> Self {
        self.is_initiator = is_initiator;
        self
    }

    pub fn sample_rate(mut self, rate: u32) -> Self {
        self.config.sample_rate = rate;
        self
    }

    pub fn samples_per_packet(mut self, samples: u32) -> Self {
        self.config.samples_per_packet = samples;
        self
    }

    pub fn jitter_delay(mut self, delay: Duration) -> Self {
        self.config.jitter.target_delay = delay;
        self
    }

    pub fn build(self) -> MediaSession {
        MediaSession::new(self.config, self.is_initiator)
    }
}

impl Default for MediaSessionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_media_session_creation() {
        let session = MediaSessionBuilder::new()
            .initiator(true)
            .sample_rate(16000)
            .build();

        assert_eq!(session.state().await, MediaSessionState::Idle);
        assert!(session.ssrc() != 0);
    }

    #[tokio::test]
    async fn test_media_session_not_active_error() {
        let session = MediaSessionBuilder::new().build();

        // Should fail since not connected
        let result = session.send_audio(&[0u8; 100]).await;
        assert!(matches!(result, Err(MediaSessionError::NotActive)));
    }

    #[tokio::test]
    async fn test_media_session_close() {
        let session = MediaSessionBuilder::new().build();
        session.close().await;

        assert_eq!(session.state().await, MediaSessionState::Ended);
    }

    #[tokio::test]
    async fn test_media_session_stats() {
        let session = MediaSessionBuilder::new().build();
        let stats = session.stats().await;

        assert_eq!(stats.packets_sent, 0);
        assert_eq!(stats.packets_received, 0);
    }
}
