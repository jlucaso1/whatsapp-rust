//! ICE Interceptor for WhatsApp relay connections.
//!
//! WhatsApp's relay servers don't respond to standard ICE STUN Binding requests.
//! They expect DTLS to be established first. This interceptor fakes STUN Binding
//! responses so that webrtc-rs thinks ICE succeeded and proceeds with DTLS.
//!
//! # How it works
//!
//! 1. webrtc-rs sends STUN Binding Request to relay
//! 2. We intercept it and generate a fake STUN Binding Response
//! 3. webrtc-rs thinks ICE succeeded
//! 4. webrtc-rs proceeds to DTLS handshake (which we forward to real relay)
//! 5. DTLS completes, DataChannel opens

use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use log::{debug, info, warn};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};
use webrtc::util;

/// STUN message type constants
const STUN_BINDING_REQUEST: u16 = 0x0001;
const STUN_BINDING_RESPONSE: u16 = 0x0101;
const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN attribute types
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_FINGERPRINT: u16 = 0x8028;

/// DTLS content types (first byte of packet)
const DTLS_CHANGE_CIPHER_SPEC: u8 = 20;
const DTLS_ALERT: u8 = 21;
const DTLS_HANDSHAKE: u8 = 22;
const DTLS_APPLICATION_DATA: u8 = 23;

/// Check if a packet is a STUN message (starts with 0x00 or 0x01, has magic cookie)
fn is_stun_message(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }
    // STUN messages have first two bits as 00
    if data[0] & 0xC0 != 0 {
        return false;
    }
    // Check magic cookie at bytes 4-7
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    cookie == STUN_MAGIC_COOKIE
}

/// Check if a packet is a STUN Binding Request
fn is_stun_binding_request(data: &[u8]) -> bool {
    if !is_stun_message(data) {
        return false;
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    msg_type == STUN_BINDING_REQUEST
}

/// Check if a packet is DTLS (should be forwarded to relay)
fn is_dtls_packet(data: &[u8]) -> bool {
    if data.is_empty() {
        return false;
    }
    matches!(
        data[0],
        DTLS_CHANGE_CIPHER_SPEC | DTLS_ALERT | DTLS_HANDSHAKE | DTLS_APPLICATION_DATA
    )
}

/// Generate a fake STUN Binding Response for a given request.
///
/// This creates a minimal valid STUN Binding Success Response with:
/// - Same transaction ID as request
/// - XOR-MAPPED-ADDRESS pointing to the source address
/// - FINGERPRINT attribute
fn generate_fake_binding_response(request: &[u8], source_addr: SocketAddr) -> Option<Vec<u8>> {
    if request.len() < 20 {
        return None;
    }

    // Extract transaction ID (bytes 8-19)
    let transaction_id = &request[8..20];

    // Build response
    let mut response = Vec::with_capacity(48);

    // Message Type: Binding Success Response (0x0101)
    response.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());

    // Message Length: placeholder (will fill later)
    let length_pos = response.len();
    response.extend_from_slice(&0u16.to_be_bytes());

    // Magic Cookie
    response.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

    // Transaction ID (12 bytes)
    response.extend_from_slice(transaction_id);

    // XOR-MAPPED-ADDRESS attribute
    let xor_mapped_addr = encode_xor_mapped_address(source_addr, transaction_id);
    response.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
    response.extend_from_slice(&(xor_mapped_addr.len() as u16).to_be_bytes());
    response.extend_from_slice(&xor_mapped_addr);

    // Pad to 4-byte boundary if needed
    while response.len() % 4 != 0 {
        response.push(0);
    }

    // Calculate message length (excluding 20-byte header)
    let msg_length = (response.len() - 20) as u16;
    response[length_pos..length_pos + 2].copy_from_slice(&msg_length.to_be_bytes());

    // Add FINGERPRINT attribute
    // First calculate CRC32 of message so far
    let crc = crc32_stun(&response) ^ 0x5354554E; // XOR with "STUN"
    response.extend_from_slice(&ATTR_FINGERPRINT.to_be_bytes());
    response.extend_from_slice(&4u16.to_be_bytes()); // Length = 4
    response.extend_from_slice(&crc.to_be_bytes());

    // Update message length to include FINGERPRINT
    let final_length = (response.len() - 20) as u16;
    response[length_pos..length_pos + 2].copy_from_slice(&final_length.to_be_bytes());

    Some(response)
}

/// Encode XOR-MAPPED-ADDRESS attribute value
fn encode_xor_mapped_address(addr: SocketAddr, transaction_id: &[u8]) -> Vec<u8> {
    let mut value = Vec::with_capacity(8);

    // Reserved byte
    value.push(0x00);

    match addr {
        SocketAddr::V4(v4) => {
            // Family: IPv4 (0x01)
            value.push(0x01);

            // X-Port: port XOR'd with first 2 bytes of magic cookie
            let xport = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            value.extend_from_slice(&xport.to_be_bytes());

            // X-Address: IP XOR'd with magic cookie
            let ip_bytes = v4.ip().octets();
            let magic_bytes = STUN_MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                value.push(ip_bytes[i] ^ magic_bytes[i]);
            }
        }
        SocketAddr::V6(v6) => {
            // Family: IPv6 (0x02)
            value.push(0x02);

            // X-Port
            let xport = addr.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
            value.extend_from_slice(&xport.to_be_bytes());

            // X-Address: IP XOR'd with magic cookie + transaction ID
            let ip_bytes = v6.ip().octets();
            let mut xor_key = [0u8; 16];
            xor_key[0..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
            xor_key[4..16].copy_from_slice(transaction_id);

            for i in 0..16 {
                value.push(ip_bytes[i] ^ xor_key[i]);
            }
        }
    }

    value
}

/// Simple CRC32 for STUN FINGERPRINT (IEEE polynomial)
fn crc32_stun(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// A UDP connection wrapper that intercepts STUN Binding requests.
pub struct InterceptedUdpConn {
    /// The underlying UDP socket
    socket: Arc<UdpSocket>,
    /// Remote address (relay)
    remote_addr: SocketAddr,
    /// Local address
    local_addr: SocketAddr,
    /// Queue of fake responses to inject
    fake_responses: Arc<Mutex<VecDeque<(Vec<u8>, SocketAddr)>>>,
    /// Notifier to wake up recv when fake responses are queued
    fake_response_notify: Arc<Notify>,
    /// Whether connection is closed
    closed: Arc<Mutex<bool>>,
}

impl InterceptedUdpConn {
    /// Create a new intercepted UDP connection to a relay.
    pub async fn new(relay_addr: SocketAddr) -> io::Result<Self> {
        // Bind to any port
        let bind_addr = if relay_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        info!(
            "ICE Interceptor: Created socket {} -> {} (will fake STUN binding responses)",
            local_addr, relay_addr
        );

        Ok(Self {
            socket: Arc::new(socket),
            remote_addr: relay_addr,
            local_addr,
            fake_responses: Arc::new(Mutex::new(VecDeque::new())),
            fake_response_notify: Arc::new(Notify::new()),
            closed: Arc::new(Mutex::new(false)),
        })
    }

    /// Get the local address
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the remote (relay) address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }
}

// Implement the Conn trait from webrtc-util
#[async_trait]
impl util::Conn for InterceptedUdpConn {
    async fn connect(&self, addr: SocketAddr) -> util::Result<()> {
        debug!("ICE Interceptor: connect({}) - no-op for UDP", addr);
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> util::Result<usize> {
        loop {
            // First check if we have fake responses queued
            {
                let mut queue = self.fake_responses.lock().await;
                if let Some((data, _from)) = queue.pop_front() {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    info!(
                        "ICE Interceptor: Delivering fake STUN response ({} bytes)",
                        len
                    );
                    return Ok(len);
                }
            }

            // Wait for EITHER socket data OR notification of fake response
            tokio::select! {
                result = self.socket.recv(buf) => {
                    let len = result?;
                    debug!(
                        "ICE Interceptor: recv {} bytes (first byte: 0x{:02x})",
                        len,
                        buf.get(0).unwrap_or(&0)
                    );
                    return Ok(len);
                }
                _ = self.fake_response_notify.notified() => {
                    // Fake response was queued, loop back to check queue
                    debug!("ICE Interceptor: Woken up by fake response notification");
                    continue;
                }
            }
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        loop {
            // First check if we have fake responses queued
            {
                let mut queue = self.fake_responses.lock().await;
                if let Some((data, from)) = queue.pop_front() {
                    let len = data.len().min(buf.len());
                    buf[..len].copy_from_slice(&data[..len]);
                    info!(
                        "ICE Interceptor: Delivering fake STUN response ({} bytes) from {}",
                        len, from
                    );
                    return Ok((len, from));
                }
            }

            // Wait for EITHER socket data OR notification of fake response
            tokio::select! {
                result = self.socket.recv_from(buf) => {
                    let (len, from) = result?;
                    debug!(
                        "ICE Interceptor: recv_from {} bytes from {} (first byte: 0x{:02x})",
                        len,
                        from,
                        buf.get(0).unwrap_or(&0)
                    );
                    return Ok((len, from));
                }
                _ = self.fake_response_notify.notified() => {
                    // Fake response was queued, loop back to check queue
                    debug!("ICE Interceptor: Woken up by fake response notification (recv_from)");
                    continue;
                }
            }
        }
    }

    async fn send(&self, buf: &[u8]) -> util::Result<usize> {
        self.send_to(buf, self.remote_addr).await
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> util::Result<usize> {
        // Check if this is a STUN Binding Request
        if is_stun_binding_request(buf) {
            info!(
                "ICE Interceptor: Intercepted STUN Binding Request ({} bytes) to {}",
                buf.len(),
                target
            );

            // Generate fake response
            if let Some(response) = generate_fake_binding_response(buf, self.local_addr) {
                info!(
                    "ICE Interceptor: Generated fake STUN Binding Response ({} bytes)",
                    response.len()
                );

                // Queue the fake response to be returned on next recv
                {
                    let mut queue = self.fake_responses.lock().await;
                    queue.push_back((response, target));
                }

                // Wake up any recv() waiting for data
                self.fake_response_notify.notify_waiters();

                // Return success (pretend we sent it)
                return Ok(buf.len());
            } else {
                warn!("ICE Interceptor: Failed to generate fake response, forwarding original");
            }
        }

        // For DTLS and other packets, forward to real relay
        if is_dtls_packet(buf) {
            debug!(
                "ICE Interceptor: Forwarding DTLS packet ({} bytes, type=0x{:02x}) to {}",
                buf.len(),
                buf[0],
                target
            );
        } else if is_stun_message(buf) {
            let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
            debug!(
                "ICE Interceptor: Forwarding STUN message ({} bytes, type=0x{:04x}) to {}",
                buf.len(),
                msg_type,
                target
            );
        } else {
            debug!(
                "ICE Interceptor: Forwarding unknown packet ({} bytes, first=0x{:02x}) to {}",
                buf.len(),
                buf.get(0).unwrap_or(&0),
                target
            );
        }

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
        *self.closed.lock().await = true;
        debug!("ICE Interceptor: Connection closed");
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_stun_message() {
        // Valid STUN Binding Request
        let mut valid = vec![0u8; 20];
        valid[0] = 0x00;
        valid[1] = 0x01;
        valid[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        assert!(is_stun_message(&valid));

        // DTLS packet (starts with 0x16)
        let dtls = vec![0x16, 0xfe, 0xff];
        assert!(!is_stun_message(&dtls));

        // Too short
        let short = vec![0x00, 0x01];
        assert!(!is_stun_message(&short));
    }

    #[test]
    fn test_is_dtls_packet() {
        assert!(is_dtls_packet(&[DTLS_HANDSHAKE]));
        assert!(is_dtls_packet(&[DTLS_APPLICATION_DATA]));
        assert!(!is_dtls_packet(&[0x00])); // STUN
        assert!(!is_dtls_packet(&[]));
    }

    #[test]
    fn test_generate_fake_response() {
        // Create a minimal STUN Binding Request
        let mut request = vec![0u8; 20];
        request[0] = 0x00;
        request[1] = 0x01; // Binding Request
        request[2] = 0x00;
        request[3] = 0x00; // Length = 0
        request[4..8].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        // Transaction ID (12 bytes)
        for i in 8..20 {
            request[i] = i as u8;
        }

        let source = "192.168.1.100:12345".parse().unwrap();
        let response = generate_fake_binding_response(&request, source).unwrap();

        // Verify it's a valid STUN Binding Response
        assert!(response.len() >= 20);
        assert_eq!(response[0], 0x01);
        assert_eq!(response[1], 0x01); // Binding Success Response

        // Verify transaction ID matches
        assert_eq!(&response[8..20], &request[8..20]);
    }

    #[test]
    fn test_crc32() {
        // Test CRC32 with known value
        let data = b"123456789";
        let crc = crc32_stun(data);
        assert_eq!(crc, 0xCBF43926); // Standard CRC32 check value
    }
}
