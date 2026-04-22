//! UDP relay connection for WhatsApp VoIP.
//!
//! Handles establishing and maintaining UDP connections to WhatsApp relay servers.

use log::{debug, info, warn};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::stun::{StunBinder, StunCredentials, StunError};
use crate::calls::{RelayData, RelayEndpoint, WHATSAPP_RELAY_PORT};

/// Default WhatsApp relay port for Web clients.
/// Note: WhatsApp Web uses port 3480, not standard STUN port 3478.
#[allow(dead_code)]
pub const RELAY_PORT: u16 = WHATSAPP_RELAY_PORT; // 3480

/// Configuration for relay connection.
#[derive(Debug, Clone)]
pub struct RelayConnectionConfig {
    /// Connection timeout in milliseconds.
    pub timeout_ms: u64,
    /// Number of STUN binding retries.
    pub stun_retries: u32,
    /// Whether to prefer IPv6 addresses.
    pub prefer_ipv6: bool,
}

impl Default for RelayConnectionConfig {
    fn default() -> Self {
        Self {
            timeout_ms: 5000,
            stun_retries: 3,
            prefer_ipv6: false,
        }
    }
}

/// Errors that can occur during relay connection.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    #[error("No relay endpoints available")]
    NoEndpoints,
    #[error("No valid address for relay: {0}")]
    NoValidAddress(String),
    #[error("Socket error: {0}")]
    Socket(#[from] std::io::Error),
    #[error("STUN binding failed: {0}")]
    StunBinding(#[from] StunError),
    #[error("Missing relay token for endpoint")]
    MissingToken,
    #[error("Missing auth token for endpoint")]
    MissingAuthToken,
    #[error("Connection timeout")]
    Timeout,
}

/// Connection state for a relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayState {
    /// Not connected.
    Disconnected,
    /// STUN binding in progress.
    Binding,
    /// Successfully bound and ready for media.
    Bound,
    /// Connection failed.
    Failed,
}

/// Information about a connected relay.
#[derive(Debug, Clone)]
pub struct ConnectedRelay {
    /// Relay server name.
    pub relay_name: String,
    /// Relay server ID.
    pub relay_id: u32,
    /// Remote address we're connected to.
    pub remote_addr: SocketAddr,
    /// Local address (our bound address).
    pub local_addr: SocketAddr,
    /// Server-reflexive address from STUN response (our public address as seen by relay).
    pub mapped_addr: Option<SocketAddr>,
}

/// UDP connection to a WhatsApp relay server.
pub struct RelayConnection {
    /// UDP socket for communication.
    socket: Arc<UdpSocket>,
    /// Current connection state.
    state: Mutex<RelayState>,
    /// Connected relay info.
    connected: Mutex<Option<ConnectedRelay>>,
    /// Configuration.
    config: RelayConnectionConfig,
    /// Stored credentials for keepalives (auth_token + relay_key).
    credentials: Mutex<Option<StunCredentials>>,
    /// Stable-routing 64-bit connection id. When populated, every outgoing
    /// packet on this relay is prefixed with `conn_id.to_be_bytes()` so the
    /// relay can fast-route to the correct session.
    ///
    /// WA Web: `wa_tp_connection.cc::wa_transport_maybe_prepend_relay_conn_id`.
    /// Server signals per-relay conn_id in the allocate response (exact attr
    /// code pending reverse engineering); until we parse it, callers can set
    /// this directly via `set_conn_id`.
    conn_id: Mutex<Option<u64>>,
    /// WARP MI (hop-by-hop MAC) configuration. When set, `send_with_warp_mi`
    /// appends a truncated HMAC-SHA256 over the packet (conn_id prefix
    /// included). WA Web enables this per packet type via
    /// `tp->enable_hbh_warp_mi_req_bitmap`; here we expose it as an
    /// opt-in per send until we reverse the bitmap wire format.
    warp_mi: Mutex<Option<WarpMiState>>,
}

/// Installed WARP MI configuration for a [`RelayConnection`].
#[derive(Debug, Clone, Copy)]
struct WarpMiState {
    key: [u8; 32],
    tagger: super::warp_mi::WarpMi,
}

impl RelayConnection {
    /// Create a new relay connection (not yet connected).
    pub async fn new(config: RelayConnectionConfig) -> Result<Self, RelayError> {
        // Bind to any available port
        let socket = UdpSocket::bind("0.0.0.0:0").await?;

        Ok(Self {
            socket: Arc::new(socket),
            state: Mutex::new(RelayState::Disconnected),
            connected: Mutex::new(None),
            config,
            credentials: Mutex::new(None),
            conn_id: Mutex::new(None),
            warp_mi: Mutex::new(None),
        })
    }

    /// Install the stable-routing connection id. Once set, [`send`] prefixes
    /// every packet with the 8-byte big-endian encoded id.
    ///
    /// [`send`]: Self::send
    pub async fn set_conn_id(&self, conn_id: u64) {
        *self.conn_id.lock().await = Some(conn_id);
    }

    /// Clear the stable-routing connection id (revert to raw-packet mode).
    pub async fn clear_conn_id(&self) {
        *self.conn_id.lock().await = None;
    }

    /// Currently-installed stable-routing connection id, if any.
    pub async fn conn_id(&self) -> Option<u64> {
        *self.conn_id.lock().await
    }

    /// Install a WARP MI key + tag length. Until [`clear_warp_mi`] is
    /// called, [`send_with_warp_mi`] appends the truncated HMAC-SHA256 tag
    /// to every packet it frames.
    ///
    /// [`clear_warp_mi`]: Self::clear_warp_mi
    /// [`send_with_warp_mi`]: Self::send_with_warp_mi
    pub async fn set_warp_mi(&self, key: [u8; 32], tag_len: usize) {
        *self.warp_mi.lock().await = Some(WarpMiState {
            key,
            tagger: super::warp_mi::WarpMi::new().with_tag_len(tag_len),
        });
    }

    /// Remove the WARP MI configuration; subsequent `send_with_warp_mi`
    /// calls behave like plain `send`.
    pub async fn clear_warp_mi(&self) {
        *self.warp_mi.lock().await = None;
    }

    /// True iff WARP MI is currently armed.
    pub async fn has_warp_mi(&self) -> bool {
        self.warp_mi.lock().await.is_some()
    }

    /// Get the local address.
    pub fn local_addr(&self) -> Result<SocketAddr, RelayError> {
        Ok(self.socket.local_addr()?)
    }

    /// Get the current connection state.
    pub async fn state(&self) -> RelayState {
        *self.state.lock().await
    }

    /// Get connected relay info if available.
    pub async fn connected_relay(&self) -> Option<ConnectedRelay> {
        self.connected.lock().await.clone()
    }

    /// Connect to a relay from the relay data.
    ///
    /// This will:
    /// 1. Select the best relay endpoint
    /// 2. Resolve the relay address
    /// 3. Perform STUN binding with the relay token
    pub async fn connect(&self, relay_data: &RelayData) -> Result<ConnectedRelay, RelayError> {
        if relay_data.endpoints.is_empty() {
            return Err(RelayError::NoEndpoints);
        }

        // Try each endpoint in order
        for endpoint in &relay_data.endpoints {
            match self.try_connect_endpoint(endpoint, relay_data).await {
                Ok(info) => {
                    *self.state.lock().await = RelayState::Bound;
                    *self.connected.lock().await = Some(info.clone());
                    return Ok(info);
                }
                Err(_e) => {
                    // Failed to connect, try next endpoint
                }
            }
        }

        *self.state.lock().await = RelayState::Failed;
        Err(RelayError::NoEndpoints)
    }

    /// Try to connect to a specific relay endpoint.
    ///
    /// Uses WhatsApp Web's ICE authentication:
    /// - USERNAME = auth_token (preferred) or relay_token (ice-ufrag)
    /// - MESSAGE-INTEGRITY = HMAC-SHA1 using relay_key (ice-pwd)
    async fn try_connect_endpoint(
        &self,
        endpoint: &RelayEndpoint,
        relay_data: &RelayData,
    ) -> Result<ConnectedRelay, RelayError> {
        debug!(
            "Trying to connect to relay endpoint: {} (id={}, token_id={}, auth_token_id={})",
            endpoint.relay_name, endpoint.relay_id, endpoint.token_id, endpoint.auth_token_id
        );

        // Get the relay token (fallback for USERNAME if no auth_token)
        let relay_token = relay_data
            .relay_tokens
            .get(endpoint.token_id as usize)
            .ok_or_else(|| {
                warn!(
                    "Missing relay token {} for endpoint {} (available: {})",
                    endpoint.token_id,
                    endpoint.relay_name,
                    relay_data.relay_tokens.len()
                );
                RelayError::MissingToken
            })?;

        debug!(
            "Relay token for {}: {} bytes",
            endpoint.relay_name,
            relay_token.len()
        );

        // Get the auth token (preferred for USERNAME / ice-ufrag)
        let auth_token = relay_data.auth_tokens.get(endpoint.auth_token_id as usize);

        if let Some(at) = auth_token {
            debug!(
                "Auth token for {}: {} bytes (using as USERNAME)",
                endpoint.relay_name,
                at.len()
            );
        } else {
            debug!(
                "No auth token for {} (using relay_token as USERNAME fallback)",
                endpoint.relay_name
            );
        }

        // WhatsApp Web: ice-ufrag = authToken ?? token (prefer auth_token)
        let username = auth_token.unwrap_or(relay_token);

        // Get relay_key for MESSAGE-INTEGRITY (ice-pwd)
        let relay_key = relay_data.relay_key.as_ref();

        if let Some(key) = relay_key {
            debug!(
                "Relay key for {}: {} bytes (using for MESSAGE-INTEGRITY)",
                endpoint.relay_name,
                key.len()
            );
        } else {
            debug!(
                "No relay_key for {} (MESSAGE-INTEGRITY disabled)",
                endpoint.relay_name
            );
        }

        // Build STUN credentials like WhatsApp Web
        let credentials = if let Some(key) = relay_key {
            StunCredentials::with_integrity(username, key)
        } else {
            StunCredentials::username_only(username)
        };

        // Find the best address for this endpoint
        let remote_addr = self.select_address(endpoint)?;
        info!(
            "Selected address for relay {}: {}",
            endpoint.relay_name, remote_addr
        );

        // Update state
        *self.state.lock().await = RelayState::Binding;

        // Connect the UDP socket to this remote address
        debug!("Connecting UDP socket to {}", remote_addr);
        self.socket.connect(remote_addr).await?;

        // Perform STUN binding with proper credentials
        info!(
            "Performing STUN binding to {} with {} byte username, integrity={}",
            remote_addr,
            credentials.username.len(),
            credentials.integrity_key.is_some()
        );
        let binder = StunBinder::new(self.socket.clone());
        let stun_result = binder
            .bind_with_credentials_retries(&credentials, self.config.stun_retries)
            .await
            .map_err(|e| {
                warn!("STUN binding failed for {}: {}", endpoint.relay_name, e);
                e
            })?;

        let local_addr = self.socket.local_addr()?;

        info!(
            "STUN binding successful for {}: local={}, mapped={:?}",
            endpoint.relay_name, local_addr, stun_result.mapped_address
        );

        // If the bind response carried a stable-routing connection id, latch
        // it immediately so all subsequent `send` calls prefix the 8 bytes.
        if let Some(conn_id) = stun_result.response.stable_routing_conn_id() {
            debug!(
                "stable routing: latched conn_id 0x{:016x} for relay {}",
                conn_id, endpoint.relay_name
            );
            *self.conn_id.lock().await = Some(conn_id);
        }

        // Store credentials for keepalives
        *self.credentials.lock().await = Some(credentials);

        Ok(ConnectedRelay {
            relay_name: endpoint.relay_name.clone(),
            relay_id: endpoint.relay_id,
            remote_addr,
            local_addr,
            mapped_addr: stun_result.mapped_address,
        })
    }

    /// Select the best address from a relay endpoint.
    ///
    /// WhatsApp Web only uses protocol=0 (UDP) addresses. Protocol=1 (TCP) is a fallback.
    fn select_address(&self, endpoint: &RelayEndpoint) -> Result<SocketAddr, RelayError> {
        debug!(
            "Selecting address for {} from {} addresses",
            endpoint.relay_name,
            endpoint.addresses.len()
        );

        // Helper to try parsing an address with the given protocol
        let try_address = |addr: &crate::calls::RelayAddress| -> Option<SocketAddr> {
            if self.config.prefer_ipv6
                && let Some(ipv6) = &addr.ipv6
                && let Ok(ip) = ipv6.parse::<IpAddr>()
            {
                return Some(SocketAddr::new(ip, addr.port_v6.unwrap_or(addr.port)));
            }
            if let Some(ipv4) = &addr.ipv4
                && let Ok(ip) = ipv4.parse::<Ipv4Addr>()
            {
                return Some(SocketAddr::new(IpAddr::V4(ip), addr.port));
            }
            if let Some(ipv6) = &addr.ipv6
                && let Ok(ip) = ipv6.parse::<IpAddr>()
            {
                return Some(SocketAddr::new(ip, addr.port_v6.unwrap_or(addr.port)));
            }
            None
        };

        // First pass: protocol=0 (UDP), second pass: protocol=1 (TCP) fallback
        for protocol in [0, 1] {
            for addr in endpoint.addresses.iter().filter(|a| a.protocol == protocol) {
                if let Some(socket_addr) = try_address(addr) {
                    debug!(
                        "Selected protocol={} address for {}: {}",
                        protocol, endpoint.relay_name, socket_addr
                    );
                    return Ok(socket_addr);
                }
            }
        }

        warn!("No valid address found for relay {}", endpoint.relay_name);
        Err(RelayError::NoValidAddress(endpoint.relay_name.clone()))
    }

    /// Frame an outbound packet for stable routing. When `conn_id` is `None`
    /// the packet is returned borrowed untouched; when `Some`, the 8-byte BE
    /// encoded id is prepended. Pure: zero I/O, zero global state. Unit test
    /// entry point for the wire layout.
    pub fn frame_packet(conn_id: Option<u64>, data: &[u8]) -> std::borrow::Cow<'_, [u8]> {
        match conn_id {
            Some(id) => {
                let mut buf = Vec::with_capacity(8 + data.len());
                buf.extend_from_slice(&id.to_be_bytes());
                buf.extend_from_slice(data);
                std::borrow::Cow::Owned(buf)
            }
            None => std::borrow::Cow::Borrowed(data),
        }
    }

    /// Frame an outbound packet with both stable-routing prefix and WARP MI
    /// tag in a single owned buffer. Wire layout (when both are enabled):
    ///
    /// `[ conn_id (8 BE) | payload | HMAC-SHA256(key, conn_id||payload) tag ]`
    ///
    /// The MAC covers the conn_id prefix so it cannot be swapped relay-side
    /// without failing verification — same contract as `add_hbh_warp_mi_tag`.
    /// When both are `None` / disabled, returns the original slice borrowed.
    pub fn frame_packet_with_warp(
        conn_id: Option<u64>,
        warp_key_tag: Option<(&[u8; 32], &super::warp_mi::WarpMi)>,
        data: &[u8],
    ) -> Vec<u8> {
        let tag_len = warp_key_tag.map(|(_, t)| t.tag_len()).unwrap_or(0);
        let prefix_len = if conn_id.is_some() { 8 } else { 0 };
        let mut buf = Vec::with_capacity(prefix_len + data.len() + tag_len);
        if let Some(id) = conn_id {
            buf.extend_from_slice(&id.to_be_bytes());
        }
        buf.extend_from_slice(data);
        if let Some((key, tagger)) = warp_key_tag {
            tagger.append_tag(key, &mut buf);
        }
        buf
    }

    /// Send data to the connected relay. When a stable-routing connection
    /// id is installed (see [`set_conn_id`]) the 8-byte BE encoding is
    /// prepended to the packet before it hits the wire, matching WA Web's
    /// `wa_transport_maybe_prepend_relay_conn_id`.
    ///
    /// [`set_conn_id`]: Self::set_conn_id
    pub async fn send(&self, data: &[u8]) -> Result<usize, RelayError> {
        let state = *self.state.lock().await;
        if state != RelayState::Bound {
            return Err(RelayError::Socket(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "Relay not connected",
            )));
        }

        let conn_id = *self.conn_id.lock().await;
        let framed = Self::frame_packet(conn_id, data);
        Ok(self.socket.send(framed.as_ref()).await?)
    }

    /// Same as [`send`] but also appends the WARP MI tag if one is armed
    /// via [`set_warp_mi`]. Use this for packet types that the relay
    /// requires to be authenticated (audio RTP, FEC, etc.); `send` stays
    /// the cheap path for types that don't require a tag.
    ///
    /// [`send`]: Self::send
    /// [`set_warp_mi`]: Self::set_warp_mi
    pub async fn send_with_warp_mi(&self, data: &[u8]) -> Result<usize, RelayError> {
        let state = *self.state.lock().await;
        if state != RelayState::Bound {
            return Err(RelayError::Socket(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "Relay not connected",
            )));
        }

        let conn_id = *self.conn_id.lock().await;
        let warp_state = *self.warp_mi.lock().await;
        let warp_ref = warp_state.as_ref().map(|w| (&w.key, &w.tagger));
        let framed = Self::frame_packet_with_warp(conn_id, warp_ref, data);
        Ok(self.socket.send(&framed).await?)
    }

    /// Receive data from the relay.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, RelayError> {
        Ok(self.socket.recv(buf).await?)
    }

    /// Send a keepalive STUN binding request to maintain the relay connection.
    ///
    /// The WhatsApp relay has a short timeout (~4 seconds), so we need to send
    /// periodic STUN binding requests to keep the connection alive.
    /// Uses the same credentials (auth_token + relay_key) as the initial binding.
    pub async fn send_keepalive(&self) -> Result<(), RelayError> {
        let state = *self.state.lock().await;
        if state != RelayState::Bound {
            return Err(RelayError::Socket(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "Relay not connected",
            )));
        }

        let credentials = self.credentials.lock().await;
        let credentials = credentials.as_ref().ok_or_else(|| {
            RelayError::Socket(std::io::Error::other(
                "No credentials available for keepalive",
            ))
        })?;

        debug!(
            "Sending STUN keepalive with {} byte username, integrity={}",
            credentials.username.len(),
            credentials.integrity_key.is_some()
        );

        let binder = StunBinder::new(self.socket.clone());
        match binder.bind_with_credentials(credentials).await {
            Ok(result) => {
                debug!(
                    "STUN keepalive successful, mapped={:?}",
                    result.mapped_address
                );
                Ok(())
            }
            Err(e) => {
                warn!("STUN keepalive failed: {}", e);
                Err(RelayError::StunBinding(e))
            }
        }
    }

    /// Get the underlying socket for advanced operations.
    pub fn socket(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_relay_connection_creation() {
        let config = RelayConnectionConfig::default();
        let conn = RelayConnection::new(config).await.unwrap();
        assert_eq!(conn.state().await, RelayState::Disconnected);
    }

    #[tokio::test]
    async fn test_local_addr() {
        let config = RelayConnectionConfig::default();
        let conn = RelayConnection::new(config).await.unwrap();
        let local = conn.local_addr().unwrap();
        // Should be bound to 0.0.0.0 with some port
        assert!(local.port() > 0);
    }

    /// `frame_packet(None, payload)` must pass-through (borrow) without
    /// allocating a new buffer.
    #[test]
    fn test_frame_packet_noop_when_conn_id_missing() {
        let payload = [0xABu8; 32];
        let framed = RelayConnection::frame_packet(None, &payload);
        assert!(
            matches!(framed, std::borrow::Cow::Borrowed(_)),
            "frame_packet with None must borrow, not allocate"
        );
        assert_eq!(framed.as_ref(), &payload);
    }

    /// `frame_packet(Some(id), payload)` prepends exactly 8 bytes BE-encoded
    /// `id`, preserving the payload verbatim.
    #[test]
    fn test_frame_packet_prepends_be_id() {
        let id: u64 = 0x0102030405060708;
        let payload = [0xDEu8, 0xAD, 0xBE, 0xEF];
        let framed = RelayConnection::frame_packet(Some(id), &payload);
        assert_eq!(framed.len(), 12);
        assert_eq!(&framed[..8], &id.to_be_bytes());
        assert_eq!(&framed[8..], &payload);
    }

    /// Setter/getter round-trip for the stable-routing connection id.
    #[tokio::test]
    async fn test_set_conn_id_roundtrip() {
        let config = RelayConnectionConfig::default();
        let conn = RelayConnection::new(config).await.unwrap();
        assert_eq!(conn.conn_id().await, None);
        conn.set_conn_id(0xCAFEBABEDEADBEEF).await;
        assert_eq!(conn.conn_id().await, Some(0xCAFEBABEDEADBEEF));
        conn.clear_conn_id().await;
        assert_eq!(conn.conn_id().await, None);
    }

    /// `frame_packet_with_warp` with both conn_id and WARP MI armed emits
    /// the full wire layout: `[conn_id BE | payload | tag]`.
    #[test]
    fn test_frame_packet_with_warp_layout() {
        use super::super::warp_mi::WarpMi;
        let key = [0xAAu8; 32];
        let tagger = WarpMi::new();
        let payload = b"rtp-like-payload".to_vec();
        let conn_id: u64 = 0x0102030405060708;

        let framed =
            RelayConnection::frame_packet_with_warp(Some(conn_id), Some((&key, &tagger)), &payload);
        assert_eq!(framed.len(), 8 + payload.len() + tagger.tag_len());
        assert_eq!(&framed[..8], &conn_id.to_be_bytes());
        assert_eq!(&framed[8..8 + payload.len()], &payload[..]);

        // Verify the tag is computed over conn_id || payload, not payload alone.
        let expected_payload_view = &framed[..8 + payload.len()];
        let tag_slice = &framed[8 + payload.len()..];
        let mut recomputed = [0u8; 32];
        let wrote = tagger.compute_into(&key, expected_payload_view, &mut recomputed);
        assert_eq!(tag_slice, &recomputed[..wrote]);
    }

    /// WARP MI disabled → same bytes as `frame_packet`.
    #[test]
    fn test_frame_packet_with_warp_disabled_matches_plain() {
        let payload = [0u8, 1, 2, 3];
        let plain = RelayConnection::frame_packet(None, &payload);
        let with_warp = RelayConnection::frame_packet_with_warp(None, None, &payload);
        assert_eq!(plain.as_ref(), with_warp.as_slice());
    }

    /// Set/clear WARP MI state.
    #[tokio::test]
    async fn test_set_warp_mi_roundtrip() {
        let config = RelayConnectionConfig::default();
        let conn = RelayConnection::new(config).await.unwrap();
        assert!(!conn.has_warp_mi().await);
        conn.set_warp_mi([0x42u8; 32], 16).await;
        assert!(conn.has_warp_mi().await);
        conn.clear_warp_mi().await;
        assert!(!conn.has_warp_mi().await);
    }
}
