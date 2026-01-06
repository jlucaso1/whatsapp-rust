//! WebRTC-based media transport for WhatsApp calls.
//!
//! This module implements WhatsApp Web's approach to relay connections:
//! using WebRTC DataChannels with SDP manipulation to connect directly
//! to WhatsApp relay servers.
//!
//! # The SDP Trick
//!
//! WhatsApp Web doesn't use standard WebRTC signaling. Instead, it:
//! 1. Creates a local RTCPeerConnection and DataChannel
//! 2. Generates an offer SDP
//! 3. Manipulates the SDP to:
//!    - Replace `ice-ufrag` with the auth_token from the server
//!    - Replace `ice-pwd` with the relay_key from the server
//!    - Set a hardcoded DTLS fingerprint
//!    - Replace ICE candidates with the relay server address
//! 4. Sets this modified SDP as the remote "answer"
//!
//! This tricks WebRTC into connecting directly to the relay server,
//! performing STUN binding, DTLS handshake, and SCTP negotiation automatically.
//!
//! # Reference
//!
//! See `docs/captured-js/sTyteLh02ST.js` for the original JavaScript implementation.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use log::{debug, info, warn};
use regex::Regex;
use tokio::sync::{Mutex, RwLock, mpsc};
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

use crate::calls::{RelayData, WHATSAPP_RELAY_PORT};

/// Hardcoded DTLS fingerprint used by WhatsApp Web.
/// This is validated via HMAC by the relay server.
pub const WHATSAPP_DTLS_FINGERPRINT: &str = "sha-256 F9:CA:0C:98:A3:CC:71:D6:42:CE:5A:E2:53:D2:15:20:D3:1B:BA:D8:57:A4:F0:AF:BE:0B:FB:F3:6B:0C:A0:68";

/// DataChannel name used by WhatsApp Web.
pub const DATA_CHANNEL_NAME: &str = "wa-web-call";

/// Connection state for WebRTC transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WebRtcState {
    /// Not started.
    Idle,
    /// Creating offer.
    CreatingOffer,
    /// Connecting (ICE/DTLS/SCTP in progress).
    Connecting,
    /// DataChannel is open and ready.
    Connected,
    /// Connection failed.
    Failed,
    /// Connection closed.
    Closed,
}

/// Information about a relay we're connecting to.
#[derive(Debug, Clone)]
pub struct RelayConnectionInfo {
    /// Relay server IP address.
    pub ip: String,
    /// Relay server port (typically 3480).
    pub port: u16,
    /// Authentication token (base64 encoded, used as ice-ufrag).
    pub auth_token: String,
    /// Relay key (base64 encoded, used as ice-pwd for MESSAGE-INTEGRITY).
    pub relay_key: String,
    /// Relay name for logging.
    pub relay_name: String,
    /// Relay ID.
    pub relay_id: u32,
    /// Server-estimated client-to-relay RTT in milliseconds.
    /// Used for relay selection - lower is better.
    pub c2r_rtt_ms: Option<u32>,
}

/// Configuration for WebRTC transport.
#[derive(Debug, Clone)]
pub struct WebRtcTransportConfig {
    /// Connection timeout.
    pub timeout: Duration,
    /// Enable verbose ICE logging.
    pub ice_debug: bool,
}

impl Default for WebRtcTransportConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(30),
            ice_debug: false,
        }
    }
}

/// Result of a successful WebRTC connection.
#[derive(Debug, Clone)]
pub struct WebRtcConnectionResult {
    /// Relay we're connected to.
    pub relay_info: RelayConnectionInfo,
    /// Local address (if available).
    pub local_addr: Option<SocketAddr>,
}

/// WebRTC-based transport for WhatsApp calls.
///
/// This implements WhatsApp Web's approach: using WebRTC DataChannels
/// with SDP manipulation to connect to relay servers.
pub struct WebRtcTransport {
    /// Current connection state.
    state: Arc<RwLock<WebRtcState>>,
    /// Configuration.
    config: WebRtcTransportConfig,
    /// RTCPeerConnection (if created).
    peer_connection: Mutex<Option<Arc<RTCPeerConnection>>>,
    /// DataChannel (if created).
    data_channel: Mutex<Option<Arc<RTCDataChannel>>>,
    /// Channel for receiving data from the DataChannel.
    rx: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// Channel for sending data (held by the DataChannel callback).
    tx: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// Connected relay info.
    connected_relay: Mutex<Option<RelayConnectionInfo>>,
}

impl WebRtcTransport {
    /// Create a new WebRTC transport.
    pub fn new(config: WebRtcTransportConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(WebRtcState::Idle)),
            config,
            peer_connection: Mutex::new(None),
            data_channel: Mutex::new(None),
            rx: Mutex::new(None),
            tx: Mutex::new(None),
            connected_relay: Mutex::new(None),
        }
    }

    /// Get the current connection state.
    pub async fn state(&self) -> WebRtcState {
        *self.state.read().await
    }

    /// Connect to a relay using the relay data from the server.
    ///
    /// This will:
    /// 1. Extract ALL available relay endpoints with protocol=0 (UDP)
    /// 2. Sort relays by c2r_rtt (server-estimated RTT) - lowest first
    /// 3. Try to connect to the best relay first, then fallback to others
    ///
    /// IMPORTANT: Both peers should connect to the same relay (the one with lowest c2r_rtt)
    /// for media to be forwarded correctly. Connecting to different relays results in
    /// packets not being forwarded between peers.
    pub async fn connect(
        &self,
        relay_data: &RelayData,
    ) -> Result<WebRtcConnectionResult, WebRtcError> {
        // Extract ALL relay endpoints
        let mut all_relays = self.extract_all_relay_info(relay_data)?;

        // Sort relays by c2r_rtt (lowest first) to prioritize the best relay
        // This ensures both peers connect to the same relay (the one with lowest latency)
        all_relays.sort_by(|a, b| {
            let a_rtt = a.c2r_rtt_ms.unwrap_or(u32::MAX);
            let b_rtt = b.c2r_rtt_ms.unwrap_or(u32::MAX);
            a_rtt.cmp(&b_rtt)
        });

        info!(
            "Connecting to {} relay endpoints (sorted by c2r_rtt)",
            all_relays.len()
        );
        for relay_info in &all_relays {
            info!(
                "  - {} at {}:{} (relay_id={}, c2r_rtt={}ms)",
                relay_info.relay_name,
                relay_info.ip,
                relay_info.port,
                relay_info.relay_id,
                relay_info
                    .c2r_rtt_ms
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "?".to_string())
            );
        }

        *self.state.write().await = WebRtcState::CreatingOffer;

        // Connect by priority: try best relay (lowest c2r_rtt) first with all its addresses,
        // only fallback to next relay if the best one completely fails.
        // This ensures we connect to the SAME relay as the peer (both use same c2r_rtt priority).
        let result = self.connect_by_priority(&all_relays).await;

        match &result {
            Ok(r) => {
                info!(
                    "Successfully connected to relay {} at {}:{} (c2r_rtt={}ms)",
                    r.relay_info.relay_name,
                    r.relay_info.ip,
                    r.relay_info.port,
                    r.relay_info
                        .c2r_rtt_ms
                        .map(|r| r.to_string())
                        .unwrap_or_else(|| "?".to_string())
                );
            }
            Err(e) => {
                warn!("Failed to connect to any relay: {}", e);
            }
        }

        result
    }

    /// Connect to relays in priority order (lowest c2r_rtt first).
    /// For each relay, try ALL its addresses (IPv4 + IPv6) in parallel.
    /// Only fallback to the next relay if the current one completely fails.
    /// This ensures both peers connect to the same relay since they use the same priority.
    async fn connect_by_priority(
        &self,
        relays: &[RelayConnectionInfo],
    ) -> Result<WebRtcConnectionResult, WebRtcError> {
        use std::collections::HashMap;

        if relays.is_empty() {
            return Err(WebRtcError::NoValidRelay);
        }

        // Group relays by relay_id, preserving c2r_rtt order (already sorted)
        let mut relay_groups: HashMap<u32, Vec<&RelayConnectionInfo>> = HashMap::new();
        let mut relay_order: Vec<u32> = Vec::new();

        for relay in relays {
            if !relay_groups.contains_key(&relay.relay_id) {
                relay_order.push(relay.relay_id);
            }
            relay_groups.entry(relay.relay_id).or_default().push(relay);
        }

        info!(
            "Connecting by priority: {} relay groups (best first)",
            relay_groups.len()
        );

        // Try each relay in priority order (c2r_rtt order)
        for relay_id in relay_order {
            let addresses = relay_groups.get(&relay_id).unwrap();
            let relay_name = &addresses[0].relay_name;

            info!(
                "Trying relay {} ({} addresses, c2r_rtt={}ms)...",
                relay_name,
                addresses.len(),
                addresses[0]
                    .c2r_rtt_ms
                    .map(|r| r.to_string())
                    .unwrap_or_else(|| "?".to_string())
            );

            // Try all addresses for this relay in parallel
            match self.try_relay_addresses(addresses).await {
                Ok(result) => {
                    info!(
                        "Connected to relay {} at {}:{}",
                        result.relay_info.relay_name, result.relay_info.ip, result.relay_info.port
                    );
                    return Ok(result);
                }
                Err(e) => {
                    warn!("Relay {} failed: {}", relay_name, e);
                    // Continue to next relay
                }
            }
        }

        *self.state.write().await = WebRtcState::Failed;
        Err(WebRtcError::ConnectionFailed)
    }

    /// Try to connect to any of the given addresses for a single relay.
    /// Tries all addresses in parallel and returns the first success.
    async fn try_relay_addresses(
        &self,
        addresses: &[&RelayConnectionInfo],
    ) -> Result<WebRtcConnectionResult, WebRtcError> {
        use futures::future::select_all;

        let timeout = self.config.timeout;
        let mut handles = Vec::new();

        for &relay_info in addresses {
            let relay_info = relay_info.clone();
            let handle =
                tokio::spawn(async move { Self::try_connect_to_relay(relay_info, timeout).await });
            handles.push(handle);
        }

        let mut remaining = handles;

        while !remaining.is_empty() {
            let (result, _index, rest) = select_all(remaining).await;

            match result {
                Ok(Ok((relay_info, peer_connection, data_channel, tx, rx))) => {
                    // Store the successful connection
                    *self.peer_connection.lock().await = Some(peer_connection.clone());
                    *self.data_channel.lock().await = Some(data_channel);
                    *self.tx.lock().await = Some(tx);
                    *self.rx.lock().await = Some(rx);
                    *self.connected_relay.lock().await = Some(relay_info.clone());
                    *self.state.write().await = WebRtcState::Connected;

                    // Abort remaining connection attempts
                    for handle in rest {
                        handle.abort();
                    }

                    return Ok(WebRtcConnectionResult {
                        relay_info,
                        local_addr: None,
                    });
                }
                Ok(Err(e)) => {
                    debug!("Address connection failed: {}", e);
                    remaining = rest;
                }
                Err(e) => {
                    warn!("Connection task panicked: {}", e);
                    remaining = rest;
                }
            }
        }

        Err(WebRtcError::ConnectionFailed)
    }

    /// Try to connect to the first available relay from the list.
    /// Attempts connections in parallel and returns the first successful one.
    #[allow(dead_code)]
    async fn connect_to_first_available(
        &self,
        relays: &[RelayConnectionInfo],
    ) -> Result<WebRtcConnectionResult, WebRtcError> {
        use futures::future::select_all;

        if relays.is_empty() {
            return Err(WebRtcError::NoValidRelay);
        }

        // Spawn connection attempts to all relays using tokio::spawn for true parallelism
        let mut handles = Vec::new();

        for relay_info in relays {
            let relay_info = relay_info.clone();
            let config_timeout = self.config.timeout;
            let handle = tokio::spawn(async move {
                Self::try_connect_to_relay(relay_info, config_timeout).await
            });
            handles.push(handle);
        }

        // Wait for the first successful connection
        let mut remaining = handles;

        while !remaining.is_empty() {
            let (result, _index, rest) = select_all(remaining).await;

            match result {
                Ok(Ok((relay_info, peer_connection, data_channel, tx, rx))) => {
                    // Store the successful connection
                    *self.peer_connection.lock().await = Some(peer_connection.clone());
                    *self.data_channel.lock().await = Some(data_channel);
                    *self.tx.lock().await = Some(tx);
                    *self.rx.lock().await = Some(rx);
                    *self.connected_relay.lock().await = Some(relay_info.clone());
                    *self.state.write().await = WebRtcState::Connected;

                    // Abort remaining connection attempts
                    for handle in rest {
                        handle.abort();
                    }

                    return Ok(WebRtcConnectionResult {
                        relay_info,
                        local_addr: None,
                    });
                }
                Ok(Err(e)) => {
                    debug!("Connection attempt failed: {}", e);
                    remaining = rest;
                }
                Err(e) => {
                    warn!("Connection task panicked: {}", e);
                    remaining = rest;
                }
            }
        }

        *self.state.write().await = WebRtcState::Failed;
        Err(WebRtcError::ConnectionFailed)
    }

    /// Try to connect to a single relay.
    /// This is the core connection logic extracted for parallel execution.
    async fn try_connect_to_relay(
        relay_info: RelayConnectionInfo,
        timeout: Duration,
    ) -> Result<
        (
            RelayConnectionInfo,
            Arc<RTCPeerConnection>,
            Arc<RTCDataChannel>,
            mpsc::Sender<Vec<u8>>,
            mpsc::Receiver<Vec<u8>>,
        ),
        WebRtcError,
    > {
        info!(
            "Trying to connect to relay {} at {}:{}",
            relay_info.relay_name, relay_info.ip, relay_info.port
        );

        // Create the WebRTC API
        let api = Self::create_api_static().await?;

        // Create peer connection with empty config (no ICE servers - we inject the relay)
        let config = RTCConfiguration::default();
        let peer_connection = Arc::new(api.new_peer_connection(config).await?);

        // Create the data channel (unordered for low latency, like WhatsApp Web)
        let data_channel = peer_connection
            .create_data_channel(
                DATA_CHANNEL_NAME,
                Some(
                    webrtc::data_channel::data_channel_init::RTCDataChannelInit {
                        ordered: Some(false),
                        ..Default::default()
                    },
                ),
            )
            .await?;

        // Set up the receive channel
        let (tx, rx) = mpsc::channel::<Vec<u8>>(1024);

        // Set up data channel message handler
        let tx_clone = tx.clone();
        data_channel.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = tx_clone.clone();
            Box::pin(async move {
                if let Err(e) = tx.send(msg.data.to_vec()).await {
                    warn!("Failed to forward DataChannel message: {}", e);
                }
            })
        }));

        // Use a oneshot channel to signal when the DataChannel opens
        let (open_tx, open_rx) = tokio::sync::oneshot::channel::<()>();
        let open_tx = Arc::new(std::sync::Mutex::new(Some(open_tx)));
        let relay_name_for_log = relay_info.relay_name.clone();
        data_channel.on_open(Box::new(move || {
            let open_tx = open_tx.clone();
            let relay_name = relay_name_for_log.clone();
            Box::pin(async move {
                info!(
                    "DataChannel '{}' opened for relay {}!",
                    DATA_CHANNEL_NAME, relay_name
                );
                if let Some(tx) = open_tx.lock().unwrap().take() {
                    let _ = tx.send(());
                }
            })
        }));

        // Set up ICE connection state handler for logging and failure detection
        let (ice_failed_tx, ice_failed_rx) = tokio::sync::oneshot::channel::<()>();
        let ice_failed_tx = Arc::new(std::sync::Mutex::new(Some(ice_failed_tx)));
        let relay_name_for_ice = relay_info.relay_name.clone();
        peer_connection.on_ice_connection_state_change(Box::new(
            move |state: RTCIceConnectionState| {
                let ice_failed_tx = ice_failed_tx.clone();
                let relay_name = relay_name_for_ice.clone();
                Box::pin(async move {
                    info!("ICE connection state for {}: {:?}", relay_name, state);
                    if state == RTCIceConnectionState::Failed
                        && let Some(tx) = ice_failed_tx.lock().unwrap().take()
                    {
                        let _ = tx.send(());
                    }
                })
            },
        ));

        // Set up ICE candidate handler for logging
        let relay_name_for_cand = relay_info.relay_name.clone();
        peer_connection.on_ice_candidate(Box::new(move |candidate| {
            let relay_name = relay_name_for_cand.clone();
            Box::pin(async move {
                if let Some(c) = candidate {
                    debug!(
                        "ICE candidate gathered for {}: {:?}",
                        relay_name,
                        c.to_json().map(|j| j.candidate)
                    );
                }
            })
        }));

        // Create offer
        let offer = peer_connection.create_offer(None).await?;

        // Set local description - this triggers ICE candidate gathering
        peer_connection.set_local_description(offer.clone()).await?;

        // Wait a short time for ICE candidate gathering (we don't need our local candidates
        // since we're replacing them with the relay anyway)
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Get the SDP (with or without gathered candidates - doesn't matter)
        let local_desc = peer_connection.local_description().await;
        let original_sdp = local_desc
            .map(|d| d.sdp)
            .unwrap_or_else(|| offer.sdp.clone());
        debug!(
            "Original SDP for {}:\n{}",
            relay_info.relay_name, original_sdp
        );

        let modified_sdp = manipulate_sdp(&original_sdp, &relay_info);
        debug!(
            "Modified SDP for {}:\n{}",
            relay_info.relay_name, modified_sdp
        );

        // Set the modified SDP as remote answer
        let answer = RTCSessionDescription::answer(modified_sdp)?;
        peer_connection.set_remote_description(answer).await?;

        // IMPORTANT: Add a small delay to allow the async candidate addition task to complete.
        // webrtc-rs spawns a tokio task to add remote candidates, and connectivity checks
        // might start before the task completes, resulting in "no candidate pairs".
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Wait for DataChannel to open OR timeout OR ICE failure
        let deadline = tokio::time::Instant::now() + timeout;

        tokio::select! {
            _ = open_rx => {
                info!("DataChannel opened successfully for relay {}", relay_info.relay_name);
                Ok((relay_info, peer_connection, data_channel, tx, rx))
            }
            _ = ice_failed_rx => {
                warn!("ICE connection failed for relay {}", relay_info.relay_name);
                let _ = peer_connection.close().await;
                Err(WebRtcError::ConnectionFailed)
            }
            _ = tokio::time::sleep_until(deadline) => {
                warn!("Connection timeout for relay {}", relay_info.relay_name);
                let _ = peer_connection.close().await;
                Err(WebRtcError::Timeout)
            }
        }
    }

    /// Create the WebRTC API with appropriate settings (static version for parallel connections).
    async fn create_api_static() -> Result<webrtc::api::API, WebRtcError> {
        let mut media_engine = MediaEngine::default();
        media_engine.register_default_codecs()?;

        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)?;

        let mut setting_engine = SettingEngine::default();

        // Disable mDNS candidates (we're injecting relay directly)
        setting_engine.set_ice_multicast_dns_mode(webrtc::ice::mdns::MulticastDnsMode::Disabled);

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(setting_engine)
            .build();

        Ok(api)
    }

    /// Extract ALL relay connection info from relay data.
    ///
    /// Converts the binary tokens to base64 strings as used by WhatsApp Web's SDP manipulation.
    /// Returns all valid relay endpoints (both IPv4 and IPv6) so we can try them in parallel.
    /// This matches WhatsApp Web's SctpConnectionManager behavior - they create connections
    /// to ALL relays simultaneously and use whichever responds first.
    fn extract_all_relay_info(
        &self,
        relay_data: &RelayData,
    ) -> Result<Vec<RelayConnectionInfo>, WebRtcError> {
        // Get relay key (required for MESSAGE-INTEGRITY)
        let relay_key_bytes = relay_data
            .relay_key
            .as_ref()
            .ok_or(WebRtcError::MissingRelayKey)?;

        // Convert relay_key to base64 (like WhatsApp Web's ice-pwd)
        let relay_key = base64::engine::general_purpose::STANDARD.encode(relay_key_bytes);

        let mut all_relays = Vec::new();

        // Extract ALL endpoints with protocol=0 (UDP) addresses
        for endpoint in &relay_data.endpoints {
            // Get auth token (preferred) or relay token
            let auth_token_bytes = match relay_data
                .auth_tokens
                .get(endpoint.auth_token_id as usize)
                .or_else(|| relay_data.relay_tokens.get(endpoint.token_id as usize))
            {
                Some(token) => token,
                None => {
                    warn!(
                        "Skipping relay {} - no valid auth token (auth_token_id={}, token_id={})",
                        endpoint.relay_name, endpoint.auth_token_id, endpoint.token_id
                    );
                    continue;
                }
            };

            // Convert auth_token to base64 (like WhatsApp Web's ice-ufrag)
            let auth_token = base64::engine::general_purpose::STANDARD.encode(auth_token_bytes);

            // Find ALL protocol=0 (UDP) addresses for this endpoint
            for addr in &endpoint.addresses {
                if addr.protocol != 0 {
                    continue;
                }

                // Add IPv4 address if available
                if let Some(ipv4) = &addr.ipv4 {
                    all_relays.push(RelayConnectionInfo {
                        ip: ipv4.clone(),
                        port: WHATSAPP_RELAY_PORT, // Always use 3480
                        auth_token: auth_token.clone(),
                        relay_key: relay_key.clone(),
                        relay_name: endpoint.relay_name.clone(),
                        relay_id: endpoint.relay_id,
                        c2r_rtt_ms: endpoint.c2r_rtt_ms,
                    });
                }

                // Add IPv6 address if available
                if let Some(ipv6) = &addr.ipv6 {
                    all_relays.push(RelayConnectionInfo {
                        ip: ipv6.clone(),
                        port: addr.port_v6.unwrap_or(WHATSAPP_RELAY_PORT),
                        auth_token: auth_token.clone(),
                        relay_key: relay_key.clone(),
                        relay_name: endpoint.relay_name.clone(),
                        relay_id: endpoint.relay_id,
                        c2r_rtt_ms: endpoint.c2r_rtt_ms,
                    });
                }
            }
        }

        if all_relays.is_empty() {
            return Err(WebRtcError::NoValidRelay);
        }

        info!(
            "Extracted {} relay endpoints from {} relays",
            all_relays.len(),
            relay_data.endpoints.len()
        );

        Ok(all_relays)
    }

    /// Send data through the DataChannel.
    pub async fn send(&self, data: &[u8]) -> Result<(), WebRtcError> {
        let dc = self.data_channel.lock().await;
        let dc = dc.as_ref().ok_or(WebRtcError::NotConnected)?;

        if dc.ready_state() != webrtc::data_channel::data_channel_state::RTCDataChannelState::Open {
            return Err(WebRtcError::NotConnected);
        }

        dc.send(&bytes::Bytes::copy_from_slice(data)).await?;
        Ok(())
    }

    /// Receive data from the DataChannel.
    ///
    /// Returns `None` if the channel is closed.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        let mut rx = self.rx.lock().await;
        let rx = rx.as_mut()?;
        rx.recv().await
    }

    /// Try to receive data with a timeout.
    pub async fn recv_timeout(&self, timeout: Duration) -> Result<Vec<u8>, WebRtcError> {
        let mut rx = self.rx.lock().await;
        let rx = rx.as_mut().ok_or(WebRtcError::NotConnected)?;

        match tokio::time::timeout(timeout, rx.recv()).await {
            Ok(Some(data)) => Ok(data),
            Ok(None) => Err(WebRtcError::ConnectionClosed),
            Err(_) => Err(WebRtcError::Timeout),
        }
    }

    /// Close the WebRTC connection.
    pub async fn close(&self) -> Result<(), WebRtcError> {
        *self.state.write().await = WebRtcState::Closed;

        // Close data channel
        if let Some(dc) = self.data_channel.lock().await.take() {
            let _ = dc.close().await;
        }

        // Close peer connection
        if let Some(pc) = self.peer_connection.lock().await.take() {
            let _ = pc.close().await;
        }

        // Drop channels
        *self.tx.lock().await = None;
        *self.rx.lock().await = None;

        info!("WebRTC transport closed");
        Ok(())
    }

    /// Get the connected relay info.
    pub async fn connected_relay(&self) -> Option<RelayConnectionInfo> {
        self.connected_relay.lock().await.clone()
    }
}

/// Manipulate SDP to connect to WhatsApp relay.
///
/// This replicates the `xe()` function from sTyteLh02ST.js.
pub fn manipulate_sdp(sdp: &str, relay_info: &RelayConnectionInfo) -> String {
    let mut modified = sdp.to_string();

    // 1. Change setup direction from actpass to passive
    modified = modified.replace("a=setup:actpass", "a=setup:passive");

    // 2. Replace ice-ufrag with auth_token
    let ice_ufrag_re = Regex::new(r"a=ice-ufrag:[^\r\n]+").unwrap();
    modified = ice_ufrag_re
        .replace_all(&modified, format!("a=ice-ufrag:{}", relay_info.auth_token))
        .to_string();

    // 3. Replace ice-pwd with relay_key
    let ice_pwd_re = Regex::new(r"a=ice-pwd:[^\r\n]+").unwrap();
    modified = ice_pwd_re
        .replace_all(&modified, format!("a=ice-pwd:{}", relay_info.relay_key))
        .to_string();

    // 4. Replace fingerprint with WhatsApp's hardcoded fingerprint
    let fingerprint_re = Regex::new(r"a=fingerprint:[^\r\n]+").unwrap();
    modified = fingerprint_re
        .replace_all(
            &modified,
            format!("a=fingerprint:{}", WHATSAPP_DTLS_FINGERPRINT),
        )
        .to_string();

    // 5. Remove ice-options
    let ice_options_re = Regex::new(r"a=ice-options:[^\r\n]+\r?\n").unwrap();
    modified = ice_options_re.replace_all(&modified, "").to_string();

    // 6. Replace ICE candidates with relay server
    modified = add_relay_candidate(&modified, &relay_info.ip, relay_info.port);

    modified
}

/// Add relay server as the only ICE candidate.
///
/// This replicates the `De()` function from sTyteLh02ST.js.
fn add_relay_candidate(sdp: &str, ip: &str, port: u16) -> String {
    // Remove existing candidates
    let candidate_re = Regex::new(r"a=candidate:[^\r\n]+\r?\n").unwrap();
    let mut modified = candidate_re.replace_all(sdp, "").to_string();

    // Remove end-of-candidates
    let eoc_re = Regex::new(r"a=end-of-candidates\r?\n?").unwrap();
    modified = eoc_re.replace_all(&modified, "").to_string();

    // Add relay as host candidate (exactly like WhatsApp Web)
    // Format: a=candidate:2 1 udp 2122262783 <ip> <port> typ host generation 0 network-cost 5
    let candidate = format!(
        "a=candidate:2 1 udp 2122262783 {} {} typ host generation 0 network-cost 5",
        ip, port
    );

    // Append candidate and end-of-candidates
    modified.push_str(&candidate);
    modified.push_str("\r\n");
    modified.push_str("a=end-of-candidates\r\n");

    modified
}

/// Errors from WebRTC transport.
#[derive(Debug, thiserror::Error)]
pub enum WebRtcError {
    #[error("WebRTC error: {0}")]
    WebRtc(#[from] webrtc::Error),

    #[error("No valid relay endpoint found (need protocol=0 UDP address)")]
    NoValidRelay,

    #[error("Missing relay key (required for MESSAGE-INTEGRITY)")]
    MissingRelayKey,

    #[error("Missing auth token for relay")]
    MissingAuthToken,

    #[error("Connection timeout")]
    Timeout,

    #[error("Connection failed")]
    ConnectionFailed,

    #[error("Connection closed")]
    ConnectionClosed,

    #[error("Not connected")]
    NotConnected,

    #[error("Send error: {0}")]
    Send(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_manipulate_sdp_ice_ufrag() {
        let sdp = "v=0\r\na=ice-ufrag:original\r\na=ice-pwd:password\r\n";
        let relay_info = RelayConnectionInfo {
            ip: "1.2.3.4".to_string(),
            port: 3480,
            auth_token: "new_auth_token_70_bytes_looooooooooooooooooooooooooooooooooong"
                .to_string(),
            relay_key: "relay_key_16b!".to_string(),
            relay_name: "test-relay".to_string(),
            relay_id: 1,
            c2r_rtt_ms: None,
        };

        let modified = manipulate_sdp(sdp, &relay_info);
        assert!(modified.contains("a=ice-ufrag:new_auth_token_70_bytes"));
        assert!(!modified.contains("a=ice-ufrag:original"));
    }

    #[test]
    fn test_manipulate_sdp_ice_pwd() {
        let sdp = "v=0\r\na=ice-ufrag:ufrag\r\na=ice-pwd:original_password\r\n";
        let relay_info = RelayConnectionInfo {
            ip: "1.2.3.4".to_string(),
            port: 3480,
            auth_token: "auth".to_string(),
            relay_key: "new_relay_key!".to_string(),
            relay_name: "test-relay".to_string(),
            relay_id: 1,
            c2r_rtt_ms: None,
        };

        let modified = manipulate_sdp(sdp, &relay_info);
        assert!(modified.contains("a=ice-pwd:new_relay_key!"));
        assert!(!modified.contains("a=ice-pwd:original_password"));
    }

    #[test]
    fn test_manipulate_sdp_fingerprint() {
        let sdp = "v=0\r\na=fingerprint:sha-256 AA:BB:CC:DD\r\n";
        let relay_info = RelayConnectionInfo {
            ip: "1.2.3.4".to_string(),
            port: 3480,
            auth_token: "auth".to_string(),
            relay_key: "key".to_string(),
            relay_name: "test-relay".to_string(),
            relay_id: 1,
            c2r_rtt_ms: None,
        };

        let modified = manipulate_sdp(sdp, &relay_info);
        assert!(modified.contains(WHATSAPP_DTLS_FINGERPRINT));
        assert!(!modified.contains("AA:BB:CC:DD"));
    }

    #[test]
    fn test_manipulate_sdp_setup_passive() {
        let sdp = "v=0\r\na=setup:actpass\r\n";
        let relay_info = RelayConnectionInfo {
            ip: "1.2.3.4".to_string(),
            port: 3480,
            auth_token: "auth".to_string(),
            relay_key: "key".to_string(),
            relay_name: "test-relay".to_string(),
            relay_id: 1,
            c2r_rtt_ms: None,
        };

        let modified = manipulate_sdp(sdp, &relay_info);
        assert!(modified.contains("a=setup:passive"));
        assert!(!modified.contains("a=setup:actpass"));
    }

    #[test]
    fn test_add_relay_candidate() {
        let sdp =
            "v=0\r\na=candidate:1 1 udp 123 192.168.1.1 8080 typ host\r\na=end-of-candidates\r\n";
        let modified = add_relay_candidate(sdp, "10.0.0.1", 3480);

        // Should have removed old candidate
        assert!(!modified.contains("192.168.1.1"));

        // Should have added relay as candidate
        assert!(modified.contains("a=candidate:2 1 udp 2122262783 10.0.0.1 3480 typ host"));
        assert!(modified.contains("a=end-of-candidates"));
    }

    #[test]
    fn test_full_sdp_manipulation() {
        let sdp = r#"v=0
o=- 123456 2 IN IP4 127.0.0.1
s=-
t=0 0
a=group:BUNDLE 0
a=msid-semantic: WMS
m=application 9 UDP/DTLS/SCTP webrtc-datachannel
c=IN IP4 0.0.0.0
a=ice-ufrag:ABCD
a=ice-pwd:EFGHIJKLMNOP
a=ice-options:trickle
a=fingerprint:sha-256 12:34:56:78:90:AB:CD:EF
a=setup:actpass
a=mid:0
a=sctp-port:5000
a=candidate:1 1 udp 2130706431 192.168.1.100 54321 typ host
a=end-of-candidates
"#;

        let relay_info = RelayConnectionInfo {
            ip: "177.86.249.163".to_string(),
            port: 3480,
            auth_token: "AUTH_TOKEN_FROM_SERVER_70_BYTES_EXACTLY_FOR_ICE_UFRAG_VALUE".to_string(),
            relay_key: "RELAY_KEY_16B!".to_string(),
            relay_name: "ssb3".to_string(),
            relay_id: 0,
            c2r_rtt_ms: Some(5),
        };

        let modified = manipulate_sdp(sdp, &relay_info);

        // Verify all manipulations
        assert!(modified.contains("a=ice-ufrag:AUTH_TOKEN_FROM_SERVER"));
        assert!(modified.contains("a=ice-pwd:RELAY_KEY_16B!"));
        assert!(modified.contains(WHATSAPP_DTLS_FINGERPRINT));
        assert!(modified.contains("a=setup:passive"));
        assert!(modified.contains("177.86.249.163"));
        assert!(modified.contains("3480"));
        assert!(!modified.contains("192.168.1.100")); // Old candidate removed
        assert!(!modified.contains("a=ice-options:trickle")); // Ice options removed
    }
}
