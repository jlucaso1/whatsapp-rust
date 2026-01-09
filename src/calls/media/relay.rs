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
        })
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

    /// Send data to the connected relay.
    pub async fn send(&self, data: &[u8]) -> Result<usize, RelayError> {
        let state = *self.state.lock().await;
        if state != RelayState::Bound {
            return Err(RelayError::Socket(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "Relay not connected",
            )));
        }

        Ok(self.socket.send(data).await?)
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
}
