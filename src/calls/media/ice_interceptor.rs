//! Relay UDP connection for WhatsApp WebRTC transport.
//!
//! WhatsApp Web uses a real RTCPeerConnection with manipulated SDP that sets
//! ice-ufrag to the relay auth_token and ice-pwd to the relay_key. The browser's
//! ICE stack sends STUN Binding Requests with proper credentials to the relay,
//! and the relay responds with valid STUN Binding Responses (including
//! MESSAGE-INTEGRITY). ICE succeeds naturally, then DTLS and SCTP follow.
//!
//! This module provides a simple UDP socket wrapper implementing webrtc-rs's
//! `Conn` trait so it can be used with `UDPMuxDefault`. All packets are
//! forwarded directly to/from the relay — no interception or spoofing.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use webrtc::util;

/// Classify a packet by its first byte for logging.
fn packet_type(buf: &[u8]) -> &'static str {
    match buf.first() {
        Some(0..=3) => "STUN",
        Some(20..=63) => "DTLS",
        _ => "OTHER",
    }
}

/// DTLS content type from first byte (only valid when packet_type is "DTLS").
fn dtls_content_type(b: u8) -> &'static str {
    match b {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        25 => "Heartbeat",
        _ => "Unknown",
    }
}

/// A UDP connection to a WhatsApp relay server.
///
/// Implements the `Conn` trait from webrtc-util so it can be used
/// with `UDPMuxDefault` for WebRTC transport. All packets are
/// forwarded directly — the relay handles STUN authentication
/// using the credentials from the manipulated SDP.
pub struct RelayUdpConn {
    /// The underlying UDP socket.
    socket: Arc<UdpSocket>,
    /// Remote address (relay server).
    remote_addr: SocketAddr,
    /// Local address.
    local_addr: SocketAddr,
    /// Whether connection is closed.
    closed: Arc<Mutex<bool>>,
    /// Packet counters for summary logging.
    sent_count: AtomicU64,
    recv_count: AtomicU64,
}

impl RelayUdpConn {
    /// Create a new UDP connection to a relay server.
    pub async fn new(relay_addr: SocketAddr) -> io::Result<Self> {
        let bind_addr = if relay_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        info!(
            "Relay UDP: {} -> {} (direct pass-through)",
            local_addr, relay_addr
        );

        Ok(Self {
            socket: Arc::new(socket),
            remote_addr: relay_addr,
            local_addr,
            closed: Arc::new(Mutex::new(false)),
            sent_count: AtomicU64::new(0),
            recv_count: AtomicU64::new(0),
        })
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the remote (relay) address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get a reference to the underlying socket (for pre-flight checks before UDPMux takes over).
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Send a bare STUN Binding Request to test relay reachability.
    /// This should be called BEFORE the conn is passed to UDPMux.
    /// Returns Ok(Some(response_bytes)) if relay responds, Ok(None) if timeout.
    pub async fn probe_relay(&self) -> io::Result<Option<Vec<u8>>> {
        // Minimal STUN Binding Request: 20-byte header, no attributes
        let mut probe = [0u8; 20];
        probe[0] = 0x00;
        probe[1] = 0x01; // Binding Request (0x0001)
        // probe[2..4] = 0x0000 (Message Length = 0)
        probe[4] = 0x21;
        probe[5] = 0x12;
        probe[6] = 0xA4;
        probe[7] = 0x42; // Magic Cookie
        // Transaction ID (bytes 8-19) - use nanosecond timestamp
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        probe[8..16].copy_from_slice(&ts.to_be_bytes());
        // probe[16..20] stay as zeros

        let sent = self.socket.send_to(&probe, self.remote_addr).await?;
        info!(
            "Relay probe: sent bare STUN Binding Request ({} bytes) to {}",
            sent, self.remote_addr
        );

        let mut buf = [0u8; 1500];
        match tokio::time::timeout(Duration::from_secs(2), self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                info!(
                    "Relay probe: RESPONSE {} bytes from {} (first 20: {:02x?})",
                    len,
                    from,
                    &buf[..len.min(20)]
                );
                Ok(Some(buf[..len].to_vec()))
            }
            Ok(Err(e)) => {
                warn!("Relay probe: recv error: {}", e);
                Err(e)
            }
            Err(_) => {
                warn!(
                    "Relay probe: NO RESPONSE within 2s from {} — relay may be unreachable or ignoring unauthenticated STUN",
                    self.remote_addr
                );
                Ok(None)
            }
        }
    }

    fn log_send(&self, buf: &[u8]) {
        let n = self.sent_count.fetch_add(1, Ordering::Relaxed) + 1;
        let ptype = packet_type(buf);
        if ptype == "DTLS" {
            info!(
                "Relay TX #{}: {} {} ({} bytes) -> {}",
                n,
                ptype,
                dtls_content_type(buf[0]),
                buf.len(),
                self.remote_addr
            );
        } else if ptype == "STUN" {
            // Log STUN packets with first bytes at debug level for diagnostics
            debug!(
                "Relay TX #{}: STUN ({} bytes) -> {} | header: {:02x?}",
                n,
                buf.len(),
                self.remote_addr,
                &buf[..buf.len().min(20)]
            );
        } else {
            debug!(
                "Relay TX #{}: {} ({} bytes) -> {}",
                n,
                ptype,
                buf.len(),
                self.remote_addr
            );
        }
        trace!(
            "Relay TX #{} full first 40 bytes: {:02x?}",
            n,
            &buf[..buf.len().min(40)]
        );
    }

    fn log_recv(&self, buf: &[u8], from: SocketAddr) {
        let n = self.recv_count.fetch_add(1, Ordering::Relaxed) + 1;
        let ptype = packet_type(buf);
        if ptype == "DTLS" {
            info!(
                "Relay RX #{}: {} {} ({} bytes) <- {}",
                n,
                ptype,
                dtls_content_type(buf[0]),
                buf.len(),
                from
            );
        } else {
            debug!(
                "Relay RX #{}: {} ({} bytes) <- {}",
                n,
                ptype,
                buf.len(),
                from
            );
        }
        trace!(
            "Relay RX #{} first 20 bytes: {:02x?}",
            n,
            &buf[..buf.len().min(20)]
        );
    }
}

#[async_trait]
impl util::Conn for RelayUdpConn {
    async fn connect(&self, addr: SocketAddr) -> util::Result<()> {
        debug!("Relay UDP: connect({}) - no-op for UDP", addr);
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> util::Result<usize> {
        let (len, from) = self.socket.recv_from(buf).await?;
        self.log_recv(&buf[..len], from);
        Ok(len)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        let (len, from) = self.socket.recv_from(buf).await?;
        self.log_recv(&buf[..len], from);
        Ok((len, from))
    }

    async fn send(&self, buf: &[u8]) -> util::Result<usize> {
        self.log_send(buf);
        let sent = self.socket.send_to(buf, self.remote_addr).await?;
        Ok(sent)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> util::Result<usize> {
        self.log_send(buf);
        let sent = self.socket.send_to(buf, target).await?;
        Ok(sent)
    }

    fn local_addr(&self) -> util::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }

    async fn close(&self) -> util::Result<()> {
        let sent = self.sent_count.load(Ordering::Relaxed);
        let recv = self.recv_count.load(Ordering::Relaxed);
        info!(
            "Relay UDP closed: {} -> {} (sent={}, recv={})",
            self.local_addr, self.remote_addr, sent, recv
        );
        *self.closed.lock().await = true;
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
