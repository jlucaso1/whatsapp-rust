//! Call media transport orchestration.
//!
//! Manages relay connections and media flow for a call.

use log::{debug, info, warn};
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};

use super::relay::{ConnectedRelay, RelayConnection, RelayConnectionConfig, RelayError};
use crate::calls::RelayData;

/// Media transport state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    /// Not started.
    Idle,
    /// Connecting to relays.
    Connecting,
    /// Connected and ready for media.
    Connected,
    /// Connection failed.
    Failed,
    /// Closed.
    Closed,
}

/// Relay latency measurement result.
#[derive(Debug, Clone)]
pub struct RelayLatency {
    /// Relay name.
    pub relay_name: String,
    /// Relay ID.
    pub relay_id: u32,
    /// Measured round-trip time.
    pub rtt: Duration,
    /// Remote address.
    pub remote_addr: SocketAddr,
}

/// Information about the active relay.
#[derive(Debug, Clone)]
pub struct ActiveRelay {
    /// Connected relay info.
    pub relay: ConnectedRelay,
    /// Measured latency.
    pub latency: Duration,
}

/// Configuration for media transport.
#[derive(Debug, Clone)]
pub struct MediaTransportConfig {
    /// Relay connection config.
    pub relay_config: RelayConnectionConfig,
    /// Number of relays to connect to in parallel.
    pub parallel_connections: usize,
    /// Timeout for relay selection.
    pub selection_timeout: Duration,
}

impl Default for MediaTransportConfig {
    fn default() -> Self {
        Self {
            relay_config: RelayConnectionConfig::default(),
            parallel_connections: 3,
            // 20 seconds to allow for STUN retries (3 retries * 5s each + margin)
            selection_timeout: Duration::from_secs(20),
        }
    }
}

/// Call media transport - manages relay connections for a call.
pub struct CallMediaTransport {
    /// Transport state.
    state: RwLock<TransportState>,
    /// Configuration.
    config: MediaTransportConfig,
    /// All connected relays with their latencies.
    connected_relays: Mutex<Vec<(RelayConnection, ConnectedRelay, Duration)>>,
    /// Currently active (best) relay index.
    active_relay_idx: Mutex<Option<usize>>,
}

impl CallMediaTransport {
    /// Create a new media transport.
    pub fn new(config: MediaTransportConfig) -> Self {
        Self {
            state: RwLock::new(TransportState::Idle),
            config,
            connected_relays: Mutex::new(Vec::new()),
            active_relay_idx: Mutex::new(None),
        }
    }

    /// Get current transport state.
    pub async fn state(&self) -> TransportState {
        *self.state.read().await
    }

    /// Connect to relays from relay data.
    ///
    /// This will:
    /// 1. Connect to multiple relays in parallel
    /// 2. Measure latency to each
    /// 3. Select the best (lowest latency) relay
    pub async fn connect(&self, relay_data: &RelayData) -> Result<ActiveRelay, TransportError> {
        *self.state.write().await = TransportState::Connecting;

        info!(
            "Connecting to {} relay endpoints (max parallel: {})",
            relay_data.endpoints.len(),
            self.config.parallel_connections
        );

        // Log relay endpoint details
        for (i, endpoint) in relay_data.endpoints.iter().enumerate() {
            debug!(
                "Relay endpoint {}: name={}, id={}, token_id={}, addresses={:?}",
                i, endpoint.relay_name, endpoint.relay_id, endpoint.token_id, endpoint.addresses
            );
        }

        // Connect to relays in parallel using JoinSet
        let mut join_set = tokio::task::JoinSet::new();
        let num_endpoints = relay_data
            .endpoints
            .len()
            .min(self.config.parallel_connections);

        for i in 0..num_endpoints {
            let relay_data = relay_data.clone();
            let config = self.config.relay_config.clone();
            let endpoint_name = relay_data.endpoints[i].relay_name.clone();

            join_set.spawn(async move {
                debug!("Attempting to connect to relay: {}", endpoint_name);
                let start = Instant::now();
                let conn = RelayConnection::new(config).await?;

                // Create a subset of relay data with just this endpoint
                let mut single_relay_data = relay_data.clone();
                single_relay_data.endpoints = vec![relay_data.endpoints[i].clone()];

                let connected = conn.connect(&single_relay_data).await?;
                let rtt = start.elapsed();

                info!(
                    "Connected to relay {} at {} (RTT: {:?})",
                    connected.relay_name, connected.remote_addr, rtt
                );

                Ok::<_, RelayError>((conn, connected, rtt))
            });
        }

        // Collect successful connections with timeout
        let mut relays = self.connected_relays.lock().await;
        relays.clear();

        let deadline = Instant::now() + self.config.selection_timeout;

        while let Ok(Some(result)) = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline),
            join_set.join_next(),
        )
        .await
        {
            match result {
                Ok(Ok((conn, connected, rtt))) => {
                    relays.push((conn, connected, rtt));
                }
                Ok(Err(e)) => {
                    warn!("Relay connection failed: {}", e);
                }
                Err(e) => {
                    warn!("Relay connection task panicked: {}", e);
                }
            }
        }

        if relays.is_empty() {
            *self.state.write().await = TransportState::Failed;
            warn!("All relay connections failed");
            return Err(TransportError::NoRelaysConnected);
        }

        // Select best relay (lowest latency)
        let best_idx = relays
            .iter()
            .enumerate()
            .min_by_key(|(_, (_, _, rtt))| *rtt)
            .map(|(i, _)| i)
            .unwrap();

        *self.active_relay_idx.lock().await = Some(best_idx);
        *self.state.write().await = TransportState::Connected;

        let (_, connected, rtt) = &relays[best_idx];
        Ok(ActiveRelay {
            relay: connected.clone(),
            latency: *rtt,
        })
    }

    /// Get the active relay info.
    pub async fn active_relay(&self) -> Option<ActiveRelay> {
        let relays = self.connected_relays.lock().await;
        let idx = (*self.active_relay_idx.lock().await)?;

        relays.get(idx).map(|(_, connected, rtt)| ActiveRelay {
            relay: connected.clone(),
            latency: *rtt,
        })
    }

    /// Get all connected relays with latencies (for relaylatency stanza).
    pub async fn relay_latencies(&self) -> Vec<RelayLatency> {
        let relays = self.connected_relays.lock().await;
        relays
            .iter()
            .map(|(_, connected, rtt)| RelayLatency {
                relay_name: connected.relay_name.clone(),
                relay_id: connected.relay_id,
                rtt: *rtt,
                remote_addr: connected.remote_addr,
            })
            .collect()
    }

    /// Select a specific relay by its relay_id.
    ///
    /// This is used after receiving RELAY_ELECTION to switch to the server-elected relay.
    /// Returns true if the relay was found and selected, false otherwise.
    pub async fn select_relay_by_id(&self, relay_id: u32) -> bool {
        let relays = self.connected_relays.lock().await;

        // Find the relay with the matching ID
        let found_idx = relays
            .iter()
            .enumerate()
            .find(|(_, (_, connected, _))| connected.relay_id == relay_id)
            .map(|(i, _)| i);

        if let Some(idx) = found_idx {
            let relay_name = &relays[idx].1.relay_name;
            info!(
                "Selected relay {} (id={}) as active relay per RELAY_ELECTION",
                relay_name, relay_id
            );
            *self.active_relay_idx.lock().await = Some(idx);
            true
        } else {
            warn!(
                "RELAY_ELECTION specified relay_id={} but we're not connected to it (connected: {:?})",
                relay_id,
                relays
                    .iter()
                    .map(|(_, c, _)| (c.relay_id, &c.relay_name))
                    .collect::<Vec<_>>()
            );
            false
        }
    }

    /// Send data through the active relay.
    pub async fn send(&self, data: &[u8]) -> Result<usize, TransportError> {
        let relays = self.connected_relays.lock().await;
        let idx = self
            .active_relay_idx
            .lock()
            .await
            .ok_or(TransportError::NotConnected)?;

        let (conn, _, _) = relays.get(idx).ok_or(TransportError::NotConnected)?;

        conn.send(data).await.map_err(TransportError::Relay)
    }

    /// Receive data from the active relay.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, TransportError> {
        let relays = self.connected_relays.lock().await;
        let idx = self
            .active_relay_idx
            .lock()
            .await
            .ok_or(TransportError::NotConnected)?;

        let (conn, _, _) = relays.get(idx).ok_or(TransportError::NotConnected)?;

        conn.recv(buf).await.map_err(TransportError::Relay)
    }

    /// Send keepalive to all connected relays to maintain bindings.
    ///
    /// The WhatsApp relay has a short timeout (~4 seconds), so keepalives
    /// must be sent periodically until the peer accepts.
    pub async fn send_keepalives(&self) -> Result<(), TransportError> {
        let relays = self.connected_relays.lock().await;

        if relays.is_empty() {
            return Ok(());
        }

        debug!("Sending keepalives to {} connected relays", relays.len());

        let mut errors = Vec::new();
        for (conn, relay_info, _) in relays.iter() {
            if let Err(e) = conn.send_keepalive().await {
                warn!("Keepalive failed for {}: {}", relay_info.relay_name, e);
                errors.push(e);
            } else {
                debug!("Keepalive sent to {}", relay_info.relay_name);
            }
        }

        // Only fail if ALL keepalives failed
        if errors.len() == relays.len() && !relays.is_empty() {
            return Err(TransportError::Relay(errors.remove(0)));
        }

        Ok(())
    }

    /// Close the transport.
    pub async fn close(&self) {
        *self.state.write().await = TransportState::Closed;
        self.connected_relays.lock().await.clear();
        *self.active_relay_idx.lock().await = None;
    }

    /// Measure latency to a specific relay (for relaylatency response).
    pub async fn measure_relay_latency(
        relay_data: &RelayData,
        endpoint_idx: usize,
    ) -> Result<RelayLatency, TransportError> {
        let endpoint = relay_data
            .endpoints
            .get(endpoint_idx)
            .ok_or(TransportError::InvalidEndpoint)?;

        let config = RelayConnectionConfig::default();
        let conn = RelayConnection::new(config)
            .await
            .map_err(TransportError::Relay)?;

        // Create subset with just this endpoint
        let mut single_relay_data = relay_data.clone();
        single_relay_data.endpoints = vec![endpoint.clone()];

        let start = Instant::now();
        let connected = conn
            .connect(&single_relay_data)
            .await
            .map_err(TransportError::Relay)?;
        let rtt = start.elapsed();

        Ok(RelayLatency {
            relay_name: connected.relay_name,
            relay_id: connected.relay_id,
            rtt,
            remote_addr: connected.remote_addr,
        })
    }
}

/// Errors from media transport.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Transport not connected")]
    NotConnected,
    #[error("No relays connected successfully")]
    NoRelaysConnected,
    #[error("Connection timeout")]
    Timeout,
    #[error("Invalid endpoint index")]
    InvalidEndpoint,
    #[error("Relay error: {0}")]
    Relay(#[from] RelayError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_creation() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);
        assert_eq!(transport.state().await, TransportState::Idle);
    }

    #[tokio::test]
    async fn test_transport_no_relays() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        // Empty relay data
        let relay_data = RelayData::default();
        let result = transport.connect(&relay_data).await;

        assert!(result.is_err());
    }
}
