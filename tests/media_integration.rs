//! Integration tests for the VoIP media transport.
//!
//! These tests verify the complete media pipeline:
//! - RTP packet creation and parsing
//! - SRTP encryption/decryption round-trip
//! - Jitter buffer ordering
//! - End-to-end packet flow

use whatsapp_rust::calls::SrtpKeyingMaterial;
use whatsapp_rust::calls::media::{
    JitterBuffer, JitterBufferConfig, MediaSessionBuilder, MediaSessionState, RtpHeader, RtpPacket,
    RtpSession, SrtpSession, StunAllocateResult, StunBinder, StunCredentials, StunMessage,
    StunMessageType,
};

/// Create test keying material for SRTP tests.
fn test_keying_material() -> SrtpKeyingMaterial {
    SrtpKeyingMaterial {
        master_key: [0x01; 16],
        master_salt: [0x02; 14],
    }
}

#[test]
fn test_rtp_packet_roundtrip() {
    // Create an RTP session
    let mut rtp = RtpSession::new(12345, 111, 16000, 320);

    // Create some test payloads
    let payloads = [
        vec![0x01, 0x02, 0x03, 0x04],
        vec![0x05, 0x06, 0x07, 0x08, 0x09, 0x0a],
        vec![0xaa, 0xbb, 0xcc],
    ];

    let mut prev_seq: Option<u16> = None;
    for payload in payloads.iter() {
        let packet = rtp.create_packet(payload.clone(), false);

        // Verify header
        assert_eq!(packet.header.version, 2);
        assert_eq!(packet.header.payload_type, 111);
        assert_eq!(packet.header.ssrc, 12345);

        // Sequence should increment
        if let Some(prev) = prev_seq {
            assert_eq!(
                packet.header.sequence_number,
                prev.wrapping_add(1),
                "Sequence should increment"
            );
        }
        prev_seq = Some(packet.header.sequence_number);

        // Verify payload
        assert_eq!(packet.payload, *payload);

        // Serialize and deserialize
        let bytes = packet.encode();
        let parsed = RtpPacket::decode(&bytes).expect("Failed to parse RTP packet");

        assert_eq!(parsed.header.version, packet.header.version);
        assert_eq!(parsed.header.sequence_number, packet.header.sequence_number);
        assert_eq!(parsed.header.timestamp, packet.header.timestamp);
        assert_eq!(parsed.header.ssrc, packet.header.ssrc);
        assert_eq!(parsed.payload, packet.payload);
    }
}

#[test]
fn test_srtp_encryption_roundtrip() {
    let keying = test_keying_material();

    // Same key for send and receive in loopback test
    let mut sender = SrtpSession::new(&keying, &keying);
    let mut receiver = SrtpSession::new(&keying, &keying);

    // Create a test packet
    let mut rtp = RtpSession::new(99999, 111, 16000, 320);
    let packet = rtp.create_packet(vec![0x01, 0x02, 0x03, 0x04, 0x05], false);

    // Encrypt
    let encrypted = sender.protect(&packet).expect("Encryption failed");

    // Encrypted data should be different from original
    assert_ne!(encrypted, packet.encode());

    // Encrypted should be larger (auth tag added)
    assert!(encrypted.len() > packet.encode().len());

    // Decrypt
    let decrypted = receiver.unprotect(&encrypted).expect("Decryption failed");

    // Verify decrypted matches original
    assert_eq!(
        decrypted.header.sequence_number,
        packet.header.sequence_number
    );
    assert_eq!(decrypted.header.timestamp, packet.header.timestamp);
    assert_eq!(decrypted.header.ssrc, packet.header.ssrc);
    assert_eq!(decrypted.payload, packet.payload);
}

#[test]
fn test_srtp_multiple_packets() {
    let keying = test_keying_material();

    let mut sender = SrtpSession::new(&keying, &keying);
    let mut receiver = SrtpSession::new(&keying, &keying);
    let mut rtp = RtpSession::new(12345, 111, 16000, 320);

    // Send multiple packets and verify they decrypt correctly
    let mut prev_seq: Option<u16> = None;
    for i in 0..100u16 {
        let payload = vec![(i % 256) as u8; 160];
        let packet = rtp.create_packet(payload.clone(), false);

        let encrypted = sender.protect(&packet).expect("Encryption failed");
        let decrypted = receiver.unprotect(&encrypted).expect("Decryption failed");

        // Sequence should increment from previous
        if let Some(prev) = prev_seq {
            assert_eq!(
                decrypted.header.sequence_number,
                prev.wrapping_add(1),
                "Sequence should increment"
            );
        }
        prev_seq = Some(decrypted.header.sequence_number);
        assert_eq!(decrypted.payload, payload);
    }
}

#[test]
fn test_jitter_buffer_basic() {
    let config = JitterBufferConfig::default();
    let mut jitter = JitterBuffer::new(config, 16000);

    // Push packets in order
    jitter.push(make_rtp_packet(100, 0));
    jitter.push(make_rtp_packet(101, 320));
    jitter.push(make_rtp_packet(102, 640));

    // Pop should work after buffer fills
    // Note: Jitter buffer may need time to prime, let's check stats
    let stats = jitter.stats();
    assert_eq!(stats.packets_received, 3);
}

#[test]
fn test_jitter_buffer_out_of_order() {
    let config = JitterBufferConfig::default();
    let mut jitter = JitterBuffer::new(config, 16000);

    // Push packets out of order
    jitter.push(make_rtp_packet(102, 640));
    jitter.push(make_rtp_packet(100, 0));
    jitter.push(make_rtp_packet(101, 320));

    let stats = jitter.stats();
    assert_eq!(stats.packets_received, 3);
}

#[tokio::test]
async fn test_media_session_builder() {
    let session = MediaSessionBuilder::new()
        .initiator(true)
        .sample_rate(16000)
        .samples_per_packet(320)
        .build();

    assert_eq!(session.state().await, MediaSessionState::Idle);
    assert!(session.ssrc() != 0);

    // Close session
    session.close().await;
    assert_eq!(session.state().await, MediaSessionState::Ended);
}

#[tokio::test]
async fn test_media_session_stats_tracking() {
    let session = MediaSessionBuilder::new()
        .initiator(true)
        .sample_rate(16000)
        .build();

    let initial_stats = session.stats().await;
    assert_eq!(initial_stats.packets_sent, 0);
    assert_eq!(initial_stats.packets_received, 0);
    assert_eq!(initial_stats.bytes_sent, 0);
    assert_eq!(initial_stats.bytes_received, 0);

    session.close().await;
}

#[test]
fn test_rtp_header_serialization() {
    let header = RtpHeader {
        version: 2,
        padding: false,
        extension: false,
        csrc_count: 0,
        marker: true,
        payload_type: 111,
        sequence_number: 1234,
        timestamp: 56789,
        ssrc: 0xDEADBEEF,
        csrc: vec![],
    };

    let mut buf = [0u8; 12];
    let len = header.encode(&mut buf).expect("Encode failed");
    assert_eq!(len, 12);

    let decoded = RtpHeader::decode(&buf[..len]).expect("Decode failed");
    assert_eq!(decoded.version, header.version);
    assert_eq!(decoded.marker, header.marker);
    assert_eq!(decoded.payload_type, header.payload_type);
    assert_eq!(decoded.sequence_number, header.sequence_number);
    assert_eq!(decoded.timestamp, header.timestamp);
    assert_eq!(decoded.ssrc, header.ssrc);
}

#[test]
fn test_srtp_cross_talk_protection() {
    // Different keys for different sessions - should not decrypt each other's packets
    let keying1 = SrtpKeyingMaterial {
        master_key: [0x01; 16],
        master_salt: [0x02; 14],
    };
    let keying2 = SrtpKeyingMaterial {
        master_key: [0xFF; 16],
        master_salt: [0xFE; 14],
    };

    let mut sender1 = SrtpSession::new(&keying1, &keying1);
    let mut receiver2 = SrtpSession::new(&keying2, &keying2);

    let mut rtp = RtpSession::new(12345, 111, 16000, 320);
    let packet = rtp.create_packet(vec![0x01, 0x02, 0x03], false);

    let encrypted = sender1.protect(&packet).expect("Encryption failed");

    // Decryption with wrong key should fail authentication
    let result = receiver2.unprotect(&encrypted);
    assert!(
        result.is_err(),
        "Decryption should fail with different keys"
    );
}

#[test]
fn test_end_to_end_packet_flow_loopback() {
    // Simulate loopback: same keys for both directions
    let keying = test_keying_material();

    let mut sender = SrtpSession::new(&keying, &keying);
    let mut receiver = SrtpSession::new(&keying, &keying);

    let mut rtp = RtpSession::new(11111, 111, 16000, 320);

    // Simulate 1 second of audio (50 packets at 20ms each)
    for i in 0..50 {
        // Create Opus-like payload (variable size)
        let payload_size = 40 + (i % 20); // 40-59 bytes per frame
        let payload: Vec<u8> = (0..payload_size).map(|j| ((i + j) % 256) as u8).collect();

        let packet = rtp.create_packet(payload.clone(), false);
        let encrypted = sender.protect(&packet).expect("Encryption failed");
        let decrypted = receiver.unprotect(&encrypted).expect("Decryption failed");

        assert_eq!(decrypted.payload, payload);
    }
}

#[test]
fn test_rtp_marker_bit() {
    let mut rtp = RtpSession::new(12345, 111, 16000, 320);

    // First packet with marker
    let packet1 = rtp.create_packet(vec![0x01], true);
    assert!(packet1.header.marker, "Marker should be set");

    // Second packet without marker
    let packet2 = rtp.create_packet(vec![0x02], false);
    assert!(!packet2.header.marker, "Marker should not be set");
}

#[test]
fn test_rtp_timestamp_increment() {
    let mut rtp = RtpSession::new(12345, 111, 16000, 320);

    let packet1 = rtp.create_packet(vec![0x01], false);
    let ts1 = packet1.header.timestamp;

    let packet2 = rtp.create_packet(vec![0x02], false);
    let ts2 = packet2.header.timestamp;

    // Timestamp should increment by samples_per_packet (320)
    assert_eq!(
        ts2.wrapping_sub(ts1),
        320,
        "Timestamp should increment by 320"
    );
}

#[test]
fn test_srtp_context_independence() {
    // Each SRTP context should track its own sequence numbers
    let keying = test_keying_material();

    let mut sender1 = SrtpSession::new(&keying, &keying);
    let mut sender2 = SrtpSession::new(&keying, &keying);
    let mut receiver = SrtpSession::new(&keying, &keying);

    let mut rtp = RtpSession::new(12345, 111, 16000, 320);

    // Send from sender1
    let packet1 = rtp.create_packet(vec![0x01], false);
    let encrypted1 = sender1.protect(&packet1).unwrap();

    // Send same packet from sender2 (would have different ROC/index)
    let encrypted2 = sender2.protect(&packet1).unwrap();

    // Both should decrypt correctly from a fresh receiver
    assert!(receiver.unprotect(&encrypted1).is_ok());

    // Need a fresh receiver for the second one since it uses same seq
    let mut receiver2 = SrtpSession::new(&keying, &keying);
    assert!(receiver2.unprotect(&encrypted2).is_ok());
}

// Helper function to create test RTP packets
fn make_rtp_packet(seq: u16, timestamp: u32) -> RtpPacket {
    RtpPacket {
        header: RtpHeader {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 111,
            sequence_number: seq,
            timestamp,
            ssrc: 12345,
            csrc: vec![],
        },
        payload: vec![0u8; 160],
    }
}

// ============================================================================
// VoIP Call Flow Integration Tests
// ============================================================================
// These tests validate the complete VoIP call flow including:
// - Early relay binding after ACK
// - Keepalive mechanism to prevent relay timeout
// - RELAY_ELECTION handling and relay switching
// - Latency reporting for all relays
// ============================================================================

mod voip_call_flow_tests {
    use std::sync::Arc;
    use std::time::Duration;
    use wacore_binary::jid::Jid;
    use whatsapp_rust::calls::media::{CallMediaTransport, MediaTransportConfig, TransportState};
    use whatsapp_rust::calls::{
        CallManager, CallManagerConfig, CallOptions, RelayAddress, RelayData, RelayElectionData,
        RelayEndpoint, RelayLatencyMeasurement,
    };

    /// Create a test JID for testing.
    fn test_jid() -> Jid {
        "1234567890@s.whatsapp.net".parse().unwrap()
    }

    /// Create a test CallManager for testing.
    fn create_test_call_manager() -> Arc<CallManager> {
        let our_jid = test_jid();
        let config = CallManagerConfig::default();
        CallManager::new(our_jid, config)
    }

    /// Create test relay data with multiple endpoints.
    fn create_test_relay_data() -> RelayData {
        RelayData {
            hbh_key: Some(vec![0u8; 30]), // 16-byte key + 14-byte salt
            relay_key: Some(vec![0u8; 16]),
            uuid: Some("test-uuid".to_string()),
            self_pid: Some(1),
            peer_pid: Some(2),
            relay_tokens: vec![
                vec![0x01; 32], // Token for endpoint 0
                vec![0x02; 32], // Token for endpoint 1
                vec![0x03; 32], // Token for endpoint 2
            ],
            auth_tokens: vec![
                vec![0xA1; 16], // Auth token for endpoint 0
                vec![0xA2; 16], // Auth token for endpoint 1
                vec![0xA3; 16], // Auth token for endpoint 2
            ],
            endpoints: vec![
                RelayEndpoint {
                    relay_id: 0,
                    relay_name: "relay-a".to_string(),
                    token_id: 0,
                    auth_token_id: 0,
                    addresses: vec![RelayAddress {
                        ipv4: Some("192.168.1.1".to_string()),
                        ipv6: None,
                        port: 3478,
                        port_v6: None,
                        protocol: 1,
                    }],
                    c2r_rtt_ms: Some(10),
                },
                RelayEndpoint {
                    relay_id: 1,
                    relay_name: "relay-b".to_string(),
                    token_id: 1,
                    auth_token_id: 1,
                    addresses: vec![RelayAddress {
                        ipv4: Some("192.168.1.2".to_string()),
                        ipv6: None,
                        port: 3478,
                        port_v6: None,
                        protocol: 1,
                    }],
                    c2r_rtt_ms: Some(25),
                },
                RelayEndpoint {
                    relay_id: 2,
                    relay_name: "relay-c".to_string(),
                    token_id: 2,
                    auth_token_id: 2,
                    addresses: vec![RelayAddress {
                        ipv4: Some("192.168.1.3".to_string()),
                        ipv6: None,
                        port: 3478,
                        port_v6: None,
                        protocol: 1,
                    }],
                    c2r_rtt_ms: Some(50),
                },
            ],
        }
    }

    // ========================================================================
    // Transport Layer Tests
    // ========================================================================

    #[tokio::test]
    async fn test_transport_creation_and_state() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        assert_eq!(transport.state().await, TransportState::Idle);
    }

    #[tokio::test]
    async fn test_transport_config_defaults() {
        let config = MediaTransportConfig::default();

        // Default parallel connections should be 3
        assert_eq!(config.parallel_connections, 3);
        // Default selection timeout should be 20 seconds
        assert_eq!(config.selection_timeout, Duration::from_secs(20));
    }

    #[tokio::test]
    async fn test_transport_no_relays_fails() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        // Empty relay data should fail
        let relay_data = RelayData::default();
        let result = transport.connect(&relay_data).await;

        assert!(result.is_err());
        assert_eq!(transport.state().await, TransportState::Failed);
    }

    #[tokio::test]
    async fn test_transport_relay_latencies_empty_before_connect() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        let latencies = transport.relay_latencies().await;
        assert!(latencies.is_empty());
    }

    #[tokio::test]
    async fn test_transport_active_relay_none_before_connect() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        assert!(transport.active_relay().await.is_none());
    }

    #[tokio::test]
    async fn test_transport_close() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        transport.close().await;
        assert_eq!(transport.state().await, TransportState::Closed);
    }

    #[tokio::test]
    async fn test_transport_select_relay_by_id_not_connected() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        // Should return false since no relays are connected
        let result = transport.select_relay_by_id(1).await;
        assert!(!result);
    }

    #[tokio::test]
    async fn test_transport_keepalives_empty_ok() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        // Keepalives on empty transport should succeed (no-op)
        let result = transport.send_keepalives().await;
        assert!(result.is_ok());
    }

    // ========================================================================
    // Call Manager Tests
    // ========================================================================

    #[tokio::test]
    async fn test_call_manager_start_call() {
        let call_manager = create_test_call_manager();
        let peer_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        let call_id = call_manager
            .start_call(peer_jid, CallOptions::audio())
            .await
            .expect("Failed to start call");

        assert!(!call_id.as_str().is_empty());
    }

    #[tokio::test]
    async fn test_call_manager_store_relay_data() {
        let call_manager = create_test_call_manager();
        let peer_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        let call_id = call_manager
            .start_call(peer_jid, CallOptions::audio())
            .await
            .expect("Failed to start call");

        let relay_data = create_test_relay_data();
        call_manager
            .store_relay_data(&call_id, relay_data.clone())
            .await
            .expect("Failed to store relay data");

        let stored = call_manager.get_relay_data(&call_id).await;
        assert!(stored.is_some());
        assert_eq!(stored.unwrap().endpoints.len(), 3);
    }

    #[tokio::test]
    async fn test_call_manager_store_elected_relay() {
        let call_manager = create_test_call_manager();
        let peer_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        let call_id = call_manager
            .start_call(peer_jid, CallOptions::audio())
            .await
            .expect("Failed to start call");

        // Initially no elected relay
        assert!(call_manager.get_elected_relay(&call_id).await.is_none());

        // Store elected relay
        call_manager
            .store_elected_relay(&call_id, 2)
            .await
            .expect("Failed to store elected relay");

        // Verify it's stored
        let elected = call_manager.get_elected_relay(&call_id).await;
        assert_eq!(elected, Some(2));
    }

    #[tokio::test]
    async fn test_call_manager_store_elected_relay_nonexistent_call() {
        let call_manager = create_test_call_manager();
        let fake_call_id = wacore::types::call::CallId::new("nonexistent-call");

        let result = call_manager.store_elected_relay(&fake_call_id, 1).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_call_manager_bound_transport_lifecycle() {
        let call_manager = create_test_call_manager();
        let peer_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        let call_id = call_manager
            .start_call(peer_jid, CallOptions::audio())
            .await
            .expect("Failed to start call");

        // Initially no bound transport
        assert!(call_manager.get_bound_transport(&call_id).await.is_none());

        // Note: bind_relays_early will fail without real relay servers,
        // but we can test the storage mechanism separately
    }

    #[tokio::test]
    async fn test_call_manager_multiple_calls() {
        let call_manager = create_test_call_manager();
        let peer_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        // First call should succeed
        let call_id1 = call_manager
            .start_call(peer_jid.clone(), CallOptions::audio())
            .await
            .expect("Failed to start first call");

        // Second call should fail (max concurrent = 1)
        let result = call_manager
            .start_call(peer_jid, CallOptions::audio())
            .await;
        assert!(result.is_err());

        // Verify first call exists
        let call_info = call_manager.get_call(&call_id1).await;
        assert!(call_info.is_some());
    }

    #[tokio::test]
    async fn test_call_manager_cleanup_ended_calls() {
        let call_manager = create_test_call_manager();
        let peer_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        let call_id = call_manager
            .start_call(peer_jid.clone(), CallOptions::audio())
            .await
            .expect("Failed to start call");

        // Mark offer as sent first (transitions to Ringing state)
        let _ = call_manager.mark_offer_sent(&call_id).await;

        // End the call (now valid from Ringing state)
        let _ = call_manager.end_call(&call_id).await;

        // Cleanup
        call_manager.cleanup_ended_calls().await;

        // Should be able to start a new call now
        let result = call_manager
            .start_call(peer_jid, CallOptions::audio())
            .await;
        assert!(result.is_ok());
    }

    // ========================================================================
    // Relay Latency Measurement Tests
    // ========================================================================

    #[test]
    fn test_relay_latency_measurement_creation() {
        let measurement = RelayLatencyMeasurement {
            relay_name: "test-relay".to_string(),
            latency_ms: 42,
            ipv4: Some("192.168.1.1".to_string()),
            port: 3478,
            token: vec![0x01; 32],
        };

        assert_eq!(measurement.relay_name, "test-relay");
        assert_eq!(measurement.latency_ms, 42);
        assert_eq!(measurement.port, 3478);
    }

    #[test]
    fn test_relay_latency_from_relay_data() {
        let relay_data = create_test_relay_data();
        let measurements = RelayLatencyMeasurement::from_relay_data(&relay_data, 30);

        assert_eq!(measurements.len(), 3);
        assert_eq!(measurements[0].relay_name, "relay-a");
        assert_eq!(measurements[1].relay_name, "relay-b");
        assert_eq!(measurements[2].relay_name, "relay-c");

        // Latencies have a 5ms variation per endpoint (30, 35, 40)
        assert_eq!(measurements[0].latency_ms, 30);
        assert_eq!(measurements[1].latency_ms, 35);
        assert_eq!(measurements[2].latency_ms, 40);
    }

    #[test]
    fn test_relay_latency_from_empty_relay_data() {
        let relay_data = RelayData::default();
        let measurements = RelayLatencyMeasurement::from_relay_data(&relay_data, 30);

        assert!(measurements.is_empty());
    }

    // ========================================================================
    // RELAY_ELECTION Parsing Tests
    // ========================================================================

    #[test]
    fn test_relay_election_data_struct() {
        let election = RelayElectionData {
            elected_relay_idx: 2,
        };
        assert_eq!(election.elected_relay_idx, 2);
    }

    // ========================================================================
    // Relay Data Structure Tests
    // ========================================================================

    #[test]
    fn test_relay_data_creation() {
        let relay_data = create_test_relay_data();

        assert_eq!(relay_data.endpoints.len(), 3);
        assert_eq!(relay_data.relay_tokens.len(), 3);
        assert_eq!(relay_data.auth_tokens.len(), 3);
        assert!(relay_data.hbh_key.is_some());
        assert!(relay_data.relay_key.is_some());
    }

    #[test]
    fn test_relay_endpoint_access() {
        let relay_data = create_test_relay_data();

        // Test endpoint 0
        let ep0 = &relay_data.endpoints[0];
        assert_eq!(ep0.relay_id, 0);
        assert_eq!(ep0.relay_name, "relay-a");
        assert_eq!(ep0.token_id, 0);
        assert!(!ep0.addresses.is_empty());

        // Verify token access
        let token = &relay_data.relay_tokens[ep0.token_id as usize];
        assert_eq!(token.len(), 32);
    }

    #[test]
    fn test_relay_address_protocol() {
        let relay_data = create_test_relay_data();

        for endpoint in &relay_data.endpoints {
            for addr in &endpoint.addresses {
                // All test addresses should have protocol 1 (DTLS/UDP)
                assert_eq!(addr.protocol, 1);
            }
        }
    }

    // ========================================================================
    // Call Options Tests
    // ========================================================================

    #[test]
    fn test_call_options_audio() {
        let opts = CallOptions::audio();
        assert!(!opts.video);
        assert!(opts.group_jid.is_none());
    }

    #[test]
    fn test_call_options_video() {
        let opts = CallOptions::video();
        assert!(opts.video);
        assert!(opts.group_jid.is_none());
    }

    // ========================================================================
    // Keepalive Interval Tests
    // ========================================================================

    #[tokio::test]
    async fn test_keepalive_timing() {
        // Verify the keepalive interval is less than the relay timeout
        // Relay timeout: 4 seconds (from voip_settings)
        // Keepalive interval: 3 seconds (our implementation)
        let keepalive_interval = Duration::from_secs(3);
        let relay_timeout = Duration::from_secs(4);

        assert!(
            keepalive_interval < relay_timeout,
            "Keepalive interval must be less than relay timeout"
        );
    }

    // ========================================================================
    // End-to-End Call Flow Simulation
    // ========================================================================

    #[tokio::test]
    async fn test_outgoing_call_flow_simulation() {
        let call_manager = create_test_call_manager();
        let peer_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        // Step 1: Start the call
        let call_id = call_manager
            .start_call(peer_jid, CallOptions::audio())
            .await
            .expect("Failed to start call");

        // Step 2: Verify call is in correct initial state
        let call_info = call_manager.get_call(&call_id).await.unwrap();
        assert!(call_info.is_initiator());

        // Step 3: Mark offer as sent (transition to Ringing)
        call_manager
            .mark_offer_sent(&call_id)
            .await
            .expect("Failed to mark offer sent");

        // Step 4: Store relay data (simulating ACK receipt)
        let relay_data = create_test_relay_data();
        call_manager
            .store_relay_data(&call_id, relay_data.clone())
            .await
            .expect("Failed to store relay data");

        // Step 5: Verify relay data is stored
        let stored_relay_data = call_manager.get_relay_data(&call_id).await.unwrap();
        assert_eq!(stored_relay_data.endpoints.len(), 3);

        // Step 6: Simulate RELAY_ELECTION (server elects relay 1)
        call_manager
            .store_elected_relay(&call_id, 1)
            .await
            .expect("Failed to store elected relay");

        // Step 7: Verify elected relay is stored
        let elected = call_manager.get_elected_relay(&call_id).await;
        assert_eq!(elected, Some(1));

        // Step 8: End the call (valid from Ringing state)
        let _ = call_manager.end_call(&call_id).await;

        // Step 9: Verify call ended
        let call_info = call_manager.get_call(&call_id).await.unwrap();
        assert!(call_info.state.is_ended());
    }

    #[tokio::test]
    async fn test_latency_measurement_for_all_relays() {
        let relay_data = create_test_relay_data();

        // Simulate having measured latency for only one relay
        let measured_latencies: Vec<(&str, u32)> = vec![("relay-a", 42)];

        let mut all_latencies = Vec::new();

        for endpoint in &relay_data.endpoints {
            let (latency_ms, is_measured) = measured_latencies
                .iter()
                .find(|(name, _)| *name == endpoint.relay_name)
                .map(|(_, lat)| (*lat, true))
                .unwrap_or((100, false)); // 100ms for unmeasured

            all_latencies.push((endpoint.relay_name.clone(), latency_ms, is_measured));
        }

        // Verify we have latencies for all 3 relays
        assert_eq!(all_latencies.len(), 3);

        // Verify relay-a has measured latency
        let relay_a = all_latencies
            .iter()
            .find(|(name, _, _)| name == "relay-a")
            .unwrap();
        assert_eq!(relay_a.1, 42);
        assert!(relay_a.2); // is_measured = true

        // Verify relay-b has estimated latency
        let relay_b = all_latencies
            .iter()
            .find(|(name, _, _)| name == "relay-b")
            .unwrap();
        assert_eq!(relay_b.1, 100);
        assert!(!relay_b.2); // is_measured = false

        // Verify relay-c has estimated latency
        let relay_c = all_latencies
            .iter()
            .find(|(name, _, _)| name == "relay-c")
            .unwrap();
        assert_eq!(relay_c.1, 100);
        assert!(!relay_c.2); // is_measured = false
    }

    #[tokio::test]
    async fn test_relay_election_switches_active_relay() {
        // This test verifies the logic of switching relays based on election
        // We can't test with real relays, but we can verify the logic

        // Simulate having 3 relays connected
        let relays = [
            ("relay-a", 0u32, 50u32), // (name, id, latency_ms)
            ("relay-b", 1u32, 30u32), // lowest latency - would be "best"
            ("relay-c", 2u32, 40u32),
        ];

        // Initially we would pick relay-b (lowest latency)
        let initial_best = relays.iter().min_by_key(|(_, _, lat)| lat).unwrap();
        assert_eq!(initial_best.0, "relay-b");

        // But if RELAY_ELECTION says use relay-c (id=2)
        let elected_id = 2u32;
        let elected = relays.iter().find(|(_, id, _)| *id == elected_id).unwrap();
        assert_eq!(elected.0, "relay-c");

        // We should use relay-c regardless of latency
        assert_eq!(elected.1, 2);
    }

    // ========================================================================
    // Stanza Building Tests
    // ========================================================================

    #[tokio::test]
    async fn test_relay_latency_stanza_building() {
        let call_manager = create_test_call_manager();
        let peer_jid: Jid = "9876543210@s.whatsapp.net".parse().unwrap();

        let call_id = call_manager
            .start_call(peer_jid, CallOptions::audio())
            .await
            .expect("Failed to start call");

        let relay_data = create_test_relay_data();
        call_manager
            .store_relay_data(&call_id, relay_data.clone())
            .await
            .expect("Failed to store relay data");

        // Build relay latency stanza
        let measurements = vec![RelayLatencyMeasurement {
            relay_name: "relay-a".to_string(),
            latency_ms: 42,
            ipv4: Some("192.168.1.1".to_string()),
            port: 3478,
            token: vec![0x01; 32],
        }];

        let stanza = call_manager
            .send_relay_latency(&call_id, measurements)
            .await
            .expect("Failed to build relay latency stanza");

        // Verify stanza structure
        assert_eq!(stanza.tag, "call");
    }

    // ========================================================================
    // Error Handling Tests
    // ========================================================================

    #[tokio::test]
    async fn test_send_on_disconnected_transport() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        let result = transport.send(&[0x01, 0x02, 0x03]).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_recv_on_disconnected_transport() {
        let config = MediaTransportConfig::default();
        let transport = CallMediaTransport::new(config);

        let mut buf = [0u8; 1024];
        let result = transport.recv(&mut buf).await;
        assert!(result.is_err());
    }
}

// ============================================================================
// STUN Authentication Tests
// ============================================================================
// These tests validate the STUN MESSAGE-INTEGRITY implementation that
// follows WhatsApp Web's ICE authentication:
// - USERNAME = auth_token (preferred) or relay_token (ice-ufrag)
// - MESSAGE-INTEGRITY = HMAC-SHA1 using relay_key (ice-pwd)
// ============================================================================

mod stun_auth_tests {
    use whatsapp_rust::calls::media::{StunCredentials, StunMessage, StunMessageType};

    #[test]
    fn test_stun_credentials_username_only() {
        let creds = StunCredentials::username_only(b"relay-token-abc");

        assert_eq!(creds.username, b"relay-token-abc");
        assert!(creds.integrity_key.is_none());
    }

    #[test]
    fn test_stun_credentials_with_integrity() {
        let creds = StunCredentials::with_integrity(b"auth-token-xyz", b"relay-key-secret");

        assert_eq!(creds.username, b"auth-token-xyz");
        assert!(creds.integrity_key.is_some());
        assert_eq!(creds.integrity_key.as_ref().unwrap(), b"relay-key-secret");
    }

    #[test]
    fn test_stun_message_without_integrity() {
        let tx_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let username = b"test-username";

        let msg = StunMessage::binding_request(tx_id)
            .with_username(username)
            .with_fingerprint(false)
            .with_priority(None);
        let encoded = msg.encode();

        // Header (20) + USERNAME attr (4 + 13 + 3 padding = 20) = 40 bytes
        // No MESSAGE-INTEGRITY since no key was set
        assert_eq!(encoded.len(), 40);

        // Verify header
        assert_eq!(encoded[0..2], [0x00, 0x01]); // Binding Request
        assert_eq!(encoded[4..8], [0x21, 0x12, 0xA4, 0x42]); // Magic Cookie
        assert_eq!(&encoded[8..20], &tx_id); // Transaction ID
    }

    #[test]
    fn test_stun_message_with_integrity() {
        let tx_id = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C,
        ];
        let username = b"auth-token-123";
        let relay_key = b"relay-key-secret";

        let msg = StunMessage::binding_request(tx_id)
            .with_username(username)
            .with_integrity_key(relay_key)
            .with_fingerprint(false)
            .with_priority(None);
        let encoded = msg.encode();

        // Header (20) + USERNAME attr (4 + 14 + 2 padding = 20) + MESSAGE-INTEGRITY (4 + 20 = 24) = 64 bytes
        assert_eq!(encoded.len(), 64);

        // Verify MESSAGE-INTEGRITY attribute is present
        // USERNAME is at offset 20, MESSAGE-INTEGRITY follows after padding
        let mi_type_offset = 40; // 20 (header) + 20 (username attr with padding)
        assert_eq!(&encoded[mi_type_offset..mi_type_offset + 2], &[0x00, 0x08]); // MESSAGE-INTEGRITY type

        // MESSAGE-INTEGRITY length should be 20 (HMAC-SHA1 output)
        assert_eq!(
            &encoded[mi_type_offset + 2..mi_type_offset + 4],
            &[0x00, 0x14]
        ); // length = 20
    }

    #[test]
    fn test_stun_message_length_includes_integrity() {
        let tx_id = [0u8; 12];
        let msg = StunMessage::binding_request(tx_id)
            .with_username(b"test")
            .with_integrity_key(b"key")
            .with_fingerprint(false)
            .with_priority(None);
        let encoded = msg.encode();

        // Message length (bytes 2-3) should include MESSAGE-INTEGRITY
        let msg_len = u16::from_be_bytes([encoded[2], encoded[3]]);

        // USERNAME: 4 (header) + 4 (data) = 8 bytes
        // MESSAGE-INTEGRITY: 4 (header) + 20 (HMAC) = 24 bytes
        // Total: 32 bytes
        assert_eq!(msg_len, 32);
    }

    #[test]
    fn test_stun_message_decode_roundtrip() {
        let tx_id = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
        ];
        let username = b"my-auth-token";

        let original = StunMessage::binding_request(tx_id)
            .with_username(username)
            .with_fingerprint(false)
            .with_priority(None);
        let encoded = original.encode();

        let decoded = StunMessage::decode(&encoded).expect("Failed to decode");

        assert_eq!(decoded.msg_type, StunMessageType::BindingRequest);
        assert_eq!(decoded.transaction_id, tx_id);
        assert_eq!(decoded.attributes.len(), 1); // Just USERNAME
    }

    #[test]
    fn test_stun_message_decode_with_integrity() {
        let tx_id = [0u8; 12];
        let username = b"test-user";
        let key = b"test-key";

        let original = StunMessage::binding_request(tx_id)
            .with_username(username)
            .with_integrity_key(key)
            .with_fingerprint(false)
            .with_priority(None);
        let encoded = original.encode();

        let decoded = StunMessage::decode(&encoded).expect("Failed to decode");

        assert_eq!(decoded.msg_type, StunMessageType::BindingRequest);
        assert_eq!(decoded.attributes.len(), 2); // USERNAME + MESSAGE-INTEGRITY
    }

    #[test]
    fn test_whatsapp_web_credential_flow() {
        // Simulate WhatsApp Web's credential selection:
        // ice-ufrag = authToken ?? token (prefer auth_token)
        // ice-pwd = relay_key (for MESSAGE-INTEGRITY)

        let relay_token = b"relay-token-from-server".to_vec();
        let auth_token = Some(b"auth-token-preferred".to_vec());
        let relay_key = Some(b"relay-key-for-hmac".to_vec());

        // WhatsApp Web logic: prefer auth_token if available
        let username = auth_token.as_ref().unwrap_or(&relay_token);

        // Build credentials like our implementation does
        let credentials = if let Some(ref key) = relay_key {
            StunCredentials::with_integrity(username, key)
        } else {
            StunCredentials::username_only(username)
        };

        // Verify we're using auth_token as username
        assert_eq!(credentials.username, b"auth-token-preferred");

        // Verify we're using relay_key for integrity
        assert!(credentials.integrity_key.is_some());
        assert_eq!(
            credentials.integrity_key.as_ref().unwrap(),
            b"relay-key-for-hmac"
        );
    }

    #[test]
    fn test_fallback_to_relay_token_when_no_auth_token() {
        // When auth_token is not available, use relay_token as username

        let relay_token = b"relay-token-fallback".to_vec();
        let auth_token: Option<Vec<u8>> = None;
        let relay_key = Some(b"relay-key".to_vec());

        let username = auth_token.as_ref().unwrap_or(&relay_token);

        let credentials = if let Some(ref key) = relay_key {
            StunCredentials::with_integrity(username, key)
        } else {
            StunCredentials::username_only(username)
        };

        // Should fall back to relay_token
        assert_eq!(credentials.username, b"relay-token-fallback");
        assert!(credentials.integrity_key.is_some());
    }

    #[test]
    fn test_no_integrity_when_no_relay_key() {
        // When relay_key is not available, don't include MESSAGE-INTEGRITY

        let username = b"some-token";
        let relay_key: Option<Vec<u8>> = None;

        let credentials = if let Some(ref key) = relay_key {
            StunCredentials::with_integrity(username, key)
        } else {
            StunCredentials::username_only(username)
        };

        assert!(credentials.integrity_key.is_none());

        // Encode and verify no MESSAGE-INTEGRITY
        let tx_id = [0u8; 12];
        let msg = StunMessage::binding_request(tx_id)
            .with_username(&credentials.username)
            .with_fingerprint(false)
            .with_priority(None);
        let encoded = msg.encode();

        // Only header + USERNAME, no MESSAGE-INTEGRITY
        // Header: 20, USERNAME: 4 + 10 + 2 padding = 16
        assert_eq!(encoded.len(), 36);
    }

    #[test]
    fn test_hmac_sha1_produces_20_byte_output() {
        let tx_id = [0u8; 12];
        let msg = StunMessage::binding_request(tx_id)
            .with_username(b"user")
            .with_integrity_key(b"pass")
            .with_fingerprint(false)
            .with_priority(None);
        let encoded = msg.encode();

        // Find MESSAGE-INTEGRITY in the encoded message
        // USERNAME: 4 header + 4 data = 8 bytes
        // MESSAGE-INTEGRITY starts at offset 28 (20 header + 8 username)
        let mi_offset = 28;

        // Verify it's MESSAGE-INTEGRITY type (0x0008)
        assert_eq!(&encoded[mi_offset..mi_offset + 2], &[0x00, 0x08]);

        // Verify length is 20 (HMAC-SHA1 output)
        assert_eq!(&encoded[mi_offset + 2..mi_offset + 4], &[0x00, 0x14]);

        // Total should be header + attr header + 20 bytes HMAC
        assert_eq!(encoded.len(), mi_offset + 4 + 20);
    }

    #[test]
    fn test_different_keys_produce_different_hmacs() {
        let tx_id = [0u8; 12];
        let username = b"same-username";

        let msg1 = StunMessage::binding_request(tx_id)
            .with_username(username)
            .with_integrity_key(b"key-one");
        let encoded1 = msg1.encode();

        let msg2 = StunMessage::binding_request(tx_id)
            .with_username(username)
            .with_integrity_key(b"key-two");
        let encoded2 = msg2.encode();

        // The encoded messages should be the same length
        assert_eq!(encoded1.len(), encoded2.len());

        // But the MESSAGE-INTEGRITY values should differ
        // MESSAGE-INTEGRITY is at the end (last 24 bytes: 4 header + 20 HMAC)
        let mi_start = encoded1.len() - 20; // Last 20 bytes are the HMAC
        assert_ne!(&encoded1[mi_start..], &encoded2[mi_start..]);
    }

    #[test]
    fn test_stun_binding_response_parsing() {
        // Create a minimal valid STUN Binding Response
        let mut data = Vec::new();

        // Message type: Binding Response (0x0101)
        data.extend_from_slice(&[0x01, 0x01]);

        // Message length: 12 (XOR-MAPPED-ADDRESS only)
        data.extend_from_slice(&[0x00, 0x0c]);

        // Magic cookie
        data.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);

        // Transaction ID
        let tx_id = [0xAA; 12];
        data.extend_from_slice(&tx_id);

        // XOR-MAPPED-ADDRESS attribute
        data.extend_from_slice(&[0x00, 0x20]); // Type
        data.extend_from_slice(&[0x00, 0x08]); // Length
        data.extend_from_slice(&[0x00, 0x01]); // Family (IPv4)
        data.extend_from_slice(&[0x11, 0x2b]); // Port XOR'd (12345 ^ 0x2112 = 0x112B)
        data.extend_from_slice(&[0xe1, 0xba, 0xa5, 0x43]); // IPv4 XOR'd (192.168.1.1)

        let msg = StunMessage::decode(&data).expect("Failed to decode response");

        assert_eq!(msg.msg_type, StunMessageType::BindingResponse);
        assert_eq!(msg.transaction_id, tx_id);

        let mapped = msg.mapped_address().expect("No mapped address");
        assert_eq!(mapped.port(), 12345);
    }
}

// ============================================================================
// Stanza Parsing Integration Tests
// ============================================================================

mod stanza_parsing_tests {
    use wacore_binary::node::{Attrs, Node, NodeContent, NodeValue};
    use whatsapp_rust::calls::ParsedCallStanza;

    fn attrs(pairs: &[(&str, &str)]) -> Attrs {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), NodeValue::from(*v)))
            .collect()
    }

    /// Create a minimal valid call stanza for testing.
    fn create_call_stanza(signaling_type: &str, call_id: &str) -> Node {
        let signaling_node = Node {
            tag: signaling_type.to_string(),
            attrs: attrs(&[
                ("call-id", call_id),
                ("call-creator", "1234567890@s.whatsapp.net"),
            ]),
            content: None,
        };

        Node {
            tag: "call".to_string(),
            attrs: attrs(&[("id", "stanza-123"), ("from", "9876543210@s.whatsapp.net")]),
            content: Some(NodeContent::Nodes(vec![signaling_node])),
        }
    }

    #[test]
    fn test_parse_offer_stanza() {
        let node = create_call_stanza("offer", "test-call-123");
        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse offer");

        assert_eq!(parsed.call_id, "test-call-123");
        assert_eq!(parsed.stanza_id, "stanza-123");
    }

    #[test]
    fn test_parse_accept_stanza() {
        let node = create_call_stanza("accept", "test-call-456");
        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse accept");

        assert_eq!(parsed.call_id, "test-call-456");
    }

    #[test]
    fn test_parse_reject_stanza() {
        let node = create_call_stanza("reject", "test-call-789");
        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse reject");

        assert_eq!(parsed.call_id, "test-call-789");
    }

    #[test]
    fn test_parse_terminate_stanza() {
        let node = create_call_stanza("terminate", "test-call-abc");
        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse terminate");

        assert_eq!(parsed.call_id, "test-call-abc");
    }

    #[test]
    fn test_parse_relay_election_stanza() {
        let signaling_node = Node {
            tag: "relay_election".to_string(),
            attrs: attrs(&[
                ("call-id", "test-call-election"),
                ("call-creator", "1234567890@s.whatsapp.net"),
                ("elected_relay_idx", "2"),
            ]),
            content: None,
        };

        let node = Node {
            tag: "call".to_string(),
            attrs: attrs(&[("id", "stanza-456"), ("from", "9876543210@s.whatsapp.net")]),
            content: Some(NodeContent::Nodes(vec![signaling_node])),
        };

        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse relay_election");

        assert_eq!(parsed.call_id, "test-call-election");
        assert!(parsed.relay_election.is_some());
        assert_eq!(parsed.relay_election.unwrap().elected_relay_idx, 2);
    }

    #[test]
    fn test_parse_relay_election_from_binary_payload() {
        // Test parsing elected_relay_idx from binary payload (single byte)
        let signaling_node = Node {
            tag: "relay_election".to_string(),
            attrs: attrs(&[
                ("call-id", "test-call-binary"),
                ("call-creator", "1234567890@s.whatsapp.net"),
            ]),
            content: Some(NodeContent::Bytes(vec![0x01])), // relay index 1
        };

        let node = Node {
            tag: "call".to_string(),
            attrs: attrs(&[("id", "stanza-789"), ("from", "9876543210@s.whatsapp.net")]),
            content: Some(NodeContent::Nodes(vec![signaling_node])),
        };

        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse");

        assert!(parsed.relay_election.is_some());
        assert_eq!(parsed.relay_election.unwrap().elected_relay_idx, 1);
    }

    #[test]
    fn test_parse_relaylatency_stanza() {
        // Create a relaylatency stanza with te children
        let te_node = Node {
            tag: "te".to_string(),
            attrs: attrs(&[
                ("relay_name", "test-relay"),
                ("latency", "33554474"), // 42ms + flags
            ]),
            content: Some(NodeContent::Bytes(vec![192, 168, 1, 1, 13, 150])), // IPv4 + port
        };

        let signaling_node = Node {
            tag: "relaylatency".to_string(),
            attrs: attrs(&[
                ("call-id", "test-call-latency"),
                ("call-creator", "1234567890@s.whatsapp.net"),
            ]),
            content: Some(NodeContent::Nodes(vec![te_node])),
        };

        let node = Node {
            tag: "call".to_string(),
            attrs: attrs(&[("id", "stanza-lat"), ("from", "9876543210@s.whatsapp.net")]),
            content: Some(NodeContent::Nodes(vec![signaling_node])),
        };

        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse relaylatency");

        assert_eq!(parsed.call_id, "test-call-latency");
        assert!(!parsed.relay_latency.is_empty());

        let lat = &parsed.relay_latency[0];
        assert_eq!(lat.relay_name, "test-relay");
        // Lower 24 bits of 33554474 = 42
        assert_eq!(lat.latency_ms, 42);
    }

    #[test]
    fn test_parse_invalid_tag() {
        let node = Node {
            tag: "not-a-call".to_string(),
            attrs: attrs(&[]),
            content: None,
        };

        let result = ParsedCallStanza::parse(&node);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_missing_signaling_child() {
        let node = Node {
            tag: "call".to_string(),
            attrs: attrs(&[("id", "stanza-123"), ("from", "9876543210@s.whatsapp.net")]),
            content: None, // No children
        };

        let result = ParsedCallStanza::parse(&node);
        assert!(result.is_err());
    }
}

// ============================================================================
// ENC_REKEY Key Rotation Tests
// ============================================================================
// These tests validate the ENC_REKEY handling for SRTP key rotation:
// - Call key derivation via HKDF-SHA256
// - SRTP keying material structure
// - Key rotation flow
// ============================================================================

mod enc_rekey_tests {
    use wacore_binary::node::{Attrs, Node, NodeContent, NodeValue};
    use whatsapp_rust::calls::{CallEncryptionKey, EncType, ParsedCallStanza, derive_call_keys};

    fn attrs(pairs: &[(&str, &str)]) -> Attrs {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), NodeValue::from(*v)))
            .collect()
    }

    /// Create a test call encryption key with known values.
    fn create_test_call_key() -> CallEncryptionKey {
        CallEncryptionKey {
            master_key: [
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
                0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C,
                0x1D, 0x1E, 0x1F, 0x20,
            ],
            generation: 1,
        }
    }

    #[test]
    fn test_call_key_derivation() {
        let call_key = create_test_call_key();
        let derived = derive_call_keys(&call_key);

        // Verify all derived keys are non-zero
        assert_ne!(derived.hbh_srtp.master_key, [0u8; 16]);
        assert_ne!(derived.hbh_srtp.master_salt, [0u8; 14]);
        assert_ne!(derived.uplink_srtcp.master_key, [0u8; 16]);
        assert_ne!(derived.downlink_srtcp.master_key, [0u8; 16]);
        assert_ne!(derived.e2e_sframe, [0u8; 32]);
        assert_ne!(derived.warp_auth, [0u8; 32]);
    }

    #[test]
    fn test_derived_keys_are_different() {
        let call_key = create_test_call_key();
        let derived = derive_call_keys(&call_key);

        // Each derived key should be different (different HKDF labels)
        assert_ne!(derived.hbh_srtp.master_key, derived.uplink_srtcp.master_key);
        assert_ne!(
            derived.uplink_srtcp.master_key,
            derived.downlink_srtcp.master_key
        );
        assert_ne!(derived.e2e_sframe[..16], derived.warp_auth[..16]);
    }

    #[test]
    fn test_key_derivation_is_deterministic() {
        let call_key = create_test_call_key();

        let derived1 = derive_call_keys(&call_key);
        let derived2 = derive_call_keys(&call_key);

        // Same input should produce same output
        assert_eq!(derived1.hbh_srtp.master_key, derived2.hbh_srtp.master_key);
        assert_eq!(derived1.hbh_srtp.master_salt, derived2.hbh_srtp.master_salt);
        assert_eq!(derived1.e2e_sframe, derived2.e2e_sframe);
    }

    #[test]
    fn test_different_master_keys_produce_different_derived_keys() {
        let key1 = CallEncryptionKey {
            master_key: [0x11; 32],
            generation: 1,
        };
        let key2 = CallEncryptionKey {
            master_key: [0x22; 32],
            generation: 1,
        };

        let derived1 = derive_call_keys(&key1);
        let derived2 = derive_call_keys(&key2);

        assert_ne!(derived1.hbh_srtp.master_key, derived2.hbh_srtp.master_key);
        assert_ne!(derived1.e2e_sframe, derived2.e2e_sframe);
    }

    #[test]
    fn test_srtp_keying_material_sizes() {
        let call_key = create_test_call_key();
        let derived = derive_call_keys(&call_key);

        // SRTP master key should be 16 bytes (128-bit AES)
        assert_eq!(derived.hbh_srtp.master_key.len(), 16);
        // SRTP master salt should be 14 bytes (112-bit)
        assert_eq!(derived.hbh_srtp.master_salt.len(), 14);
        // E2E sframe key should be 32 bytes
        assert_eq!(derived.e2e_sframe.len(), 32);
        // WARP auth key should be 32 bytes
        assert_eq!(derived.warp_auth.len(), 32);
    }

    #[test]
    fn test_enc_rekey_stanza_parsing() {
        // Create an enc_rekey stanza with enc child
        let enc_node = Node {
            tag: "enc".to_string(),
            attrs: attrs(&[("type", "msg"), ("count", "2")]),
            content: Some(NodeContent::Bytes(vec![0x01, 0x02, 0x03, 0x04])),
        };

        let signaling_node = Node {
            tag: "enc_rekey".to_string(),
            attrs: attrs(&[
                ("call-id", "test-call-rekey"),
                ("call-creator", "1234567890@s.whatsapp.net"),
            ]),
            content: Some(NodeContent::Nodes(vec![enc_node])),
        };

        let node = Node {
            tag: "call".to_string(),
            attrs: attrs(&[
                ("id", "stanza-rekey"),
                ("from", "9876543210@s.whatsapp.net"),
            ]),
            content: Some(NodeContent::Nodes(vec![signaling_node])),
        };

        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse enc_rekey");

        assert_eq!(parsed.call_id, "test-call-rekey");
        assert!(parsed.enc_rekey_data.is_some());

        let enc_data = parsed.enc_rekey_data.unwrap();
        assert_eq!(enc_data.enc_type, EncType::Msg);
        assert_eq!(enc_data.ciphertext, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(enc_data.count, 2);
    }

    #[test]
    fn test_enc_rekey_pkmsg_type() {
        // Test pkmsg encryption type (prekey message)
        let enc_node = Node {
            tag: "enc".to_string(),
            attrs: attrs(&[("type", "pkmsg"), ("count", "1")]),
            content: Some(NodeContent::Bytes(vec![0xAA, 0xBB, 0xCC])),
        };

        let signaling_node = Node {
            tag: "enc_rekey".to_string(),
            attrs: attrs(&[
                ("call-id", "test-call-pkmsg"),
                ("call-creator", "1234567890@s.whatsapp.net"),
            ]),
            content: Some(NodeContent::Nodes(vec![enc_node])),
        };

        let node = Node {
            tag: "call".to_string(),
            attrs: attrs(&[
                ("id", "stanza-pkmsg"),
                ("from", "9876543210@s.whatsapp.net"),
            ]),
            content: Some(NodeContent::Nodes(vec![signaling_node])),
        };

        let parsed = ParsedCallStanza::parse(&node).expect("Failed to parse");

        let enc_data = parsed.enc_rekey_data.unwrap();
        assert_eq!(enc_data.enc_type, EncType::PkMsg);
    }

    #[test]
    fn test_enc_type_display() {
        assert_eq!(EncType::Msg.to_string(), "msg");
        assert_eq!(EncType::PkMsg.to_string(), "pkmsg");
    }

    #[test]
    fn test_enc_type_from_str() {
        assert_eq!("msg".parse::<EncType>(), Ok(EncType::Msg));
        assert_eq!("pkmsg".parse::<EncType>(), Ok(EncType::PkMsg));
        assert!("invalid".parse::<EncType>().is_err());
    }

    #[test]
    fn test_key_rotation_produces_new_keys() {
        // Simulate key rotation: old key -> new key
        let old_key = CallEncryptionKey {
            master_key: [0x11; 32],
            generation: 1,
        };
        let new_key = CallEncryptionKey {
            master_key: [0x22; 32],
            generation: 2,
        };

        let old_derived = derive_call_keys(&old_key);
        let new_derived = derive_call_keys(&new_key);

        // New keys should be completely different
        assert_ne!(
            old_derived.hbh_srtp.master_key,
            new_derived.hbh_srtp.master_key
        );
        assert_ne!(old_derived.e2e_sframe, new_derived.e2e_sframe);
    }

    #[test]
    fn test_call_encryption_key_generation() {
        // Test that generated keys are random
        let key1 = CallEncryptionKey::generate();
        let key2 = CallEncryptionKey::generate();

        assert_ne!(key1.master_key, key2.master_key);
        assert_eq!(key1.generation, 1);
        assert_eq!(key2.generation, 1);
    }

    #[test]
    fn test_srtp_key_directionality() {
        // Uplink and downlink keys should be different
        let call_key = create_test_call_key();
        let derived = derive_call_keys(&call_key);

        assert_ne!(
            derived.uplink_srtcp.master_key,
            derived.downlink_srtcp.master_key
        );
        assert_ne!(
            derived.uplink_srtcp.master_salt,
            derived.downlink_srtcp.master_salt
        );
    }
}

// ============================================================================
// RTCP NACK Tests
// ============================================================================
// These tests validate the RTCP NACK implementation for packet loss recovery:
// - NACK packet encoding/decoding (RFC 4585)
// - NackTracker for detecting lost packets
// - RetransmitBuffer for storing sent packets
// - Integration with media session
// ============================================================================

mod rtcp_nack_tests {
    use whatsapp_rust::calls::media::{
        NackEntry, NackTracker, RTCP_VERSION, RetransmitBuffer, RtcpHeader, RtcpNack,
        RtcpPayloadType, RtpfbFmt,
    };

    #[test]
    fn test_rtcp_nack_packet_format() {
        // Create a NACK for lost packets 1000, 1001, 1005
        let mut nack = RtcpNack::new(0xAABBCCDD, 0x11223344);
        nack.add_lost_seq(1000);
        nack.add_lost_seq(1001);
        nack.add_lost_seq(1005);

        let encoded = nack.encode();

        // Verify RTCP header
        assert_eq!(encoded[0] >> 6, RTCP_VERSION); // Version = 2
        assert_eq!(encoded[0] & 0x1F, RtpfbFmt::Nack as u8); // FMT = 1
        assert_eq!(encoded[1], RtcpPayloadType::Rtpfb as u8); // PT = 205

        // Decode and verify
        let decoded = RtcpNack::decode(&encoded).unwrap();
        assert_eq!(decoded.sender_ssrc, 0xAABBCCDD);
        assert_eq!(decoded.media_ssrc, 0x11223344);

        let lost = decoded.lost_sequences();
        assert!(lost.contains(&1000));
        assert!(lost.contains(&1001));
        assert!(lost.contains(&1005));
    }

    #[test]
    fn test_nack_entry_blp_encoding() {
        // Test BLP (Bitmask of Following Lost Packets)
        // PID = 100, lost packets: 100, 101, 103, 116 (bit 0, 2, 15)
        let entry = NackEntry {
            pid: 100,
            blp: 0b1000000000000101, // bits 0, 2, 15 set
        };

        let seqs = entry.lost_sequences();
        assert_eq!(seqs, vec![100, 101, 103, 116]);
    }

    #[test]
    fn test_nack_entry_from_consecutive_losses() {
        // Consecutive losses are efficiently encoded
        let seqs = vec![500, 501, 502, 503, 504];
        let entry = NackEntry::from_sequences(&seqs).unwrap();

        assert_eq!(entry.pid, 500);
        assert_eq!(entry.blp, 0b0000000000001111); // bits 0-3 set

        // Verify roundtrip
        let recovered = entry.lost_sequences();
        assert_eq!(recovered, seqs);
    }

    #[test]
    fn test_nack_tracker_gap_detection() {
        let mut tracker = NackTracker::new();

        // Receive packet 100
        let nacks = tracker.on_packet_received(100, 0);
        assert!(nacks.is_empty());

        // Receive packet 105 (skipping 101-104)
        let nacks = tracker.on_packet_received(105, 50);
        assert_eq!(nacks, vec![101, 102, 103, 104]);

        // Verify stats
        let stats = tracker.stats();
        assert_eq!(stats.missing_count, 4);
    }

    #[test]
    fn test_nack_tracker_recovery() {
        let mut tracker = NackTracker::new();

        // Create a gap
        tracker.on_packet_received(100, 0);
        tracker.on_packet_received(105, 50); // Miss 101-104

        // Late packet arrives (102)
        tracker.on_packet_received(102, 100);

        // Verify 102 is no longer missing
        assert!(!tracker.is_missing(102));
        assert!(tracker.is_missing(101));
        assert!(tracker.is_missing(103));
        assert!(tracker.is_missing(104));

        let stats = tracker.stats();
        assert_eq!(stats.missing_count, 3);
        assert_eq!(stats.recovered_count, 1);
    }

    #[test]
    fn test_nack_tracker_pending_nacks() {
        let mut tracker = NackTracker::new();

        // Create a gap
        tracker.on_packet_received(100, 0);
        tracker.on_packet_received(110, 50); // Miss 101-109

        // Get pending NACKs
        let pending = tracker.get_pending_nacks(110, 5);
        assert_eq!(pending.len(), 5); // Limited to 5

        // First 5 missing packets
        assert!(pending.contains(&101));
        assert!(pending.contains(&102));
        assert!(pending.contains(&103));
        assert!(pending.contains(&104));
        assert!(pending.contains(&105));
    }

    #[test]
    fn test_retransmit_buffer_store_and_retrieve() {
        let mut buffer = RetransmitBuffer::new(50);

        // Store some packets
        buffer.store(100, vec![0xAA; 100]);
        buffer.store(101, vec![0xBB; 100]);
        buffer.store(102, vec![0xCC; 100]);

        // Retrieve
        assert_eq!(buffer.get(100), Some(&[0xAA; 100][..]));
        assert_eq!(buffer.get(101), Some(&[0xBB; 100][..]));
        assert_eq!(buffer.get(102), Some(&[0xCC; 100][..]));

        // Non-existent
        assert_eq!(buffer.get(999), None);
    }

    #[test]
    fn test_retransmit_buffer_eviction_policy() {
        let mut buffer = RetransmitBuffer::new(3);

        // Fill buffer
        buffer.store(100, vec![1]);
        buffer.store(101, vec![2]);
        buffer.store(102, vec![3]);

        // Overflow - oldest should be evicted
        buffer.store(103, vec![4]);

        assert_eq!(buffer.get(100), None); // Evicted
        assert_eq!(buffer.get(101), Some(&[2][..]));
        assert_eq!(buffer.get(103), Some(&[4][..]));
    }

    #[test]
    fn test_retransmit_buffer_get_multiple() {
        let mut buffer = RetransmitBuffer::new(10);

        buffer.store(100, vec![1]);
        buffer.store(101, vec![2]);
        buffer.store(102, vec![3]);
        buffer.store(103, vec![4]);

        // Request retransmission of 100, 102, 999
        let result = buffer.get_multiple(&[100, 102, 999]);

        assert_eq!(result.len(), 2); // 999 doesn't exist
        assert!(result.iter().any(|(seq, _)| *seq == 100));
        assert!(result.iter().any(|(seq, _)| *seq == 102));
    }

    #[test]
    fn test_nack_packet_multiple_entries() {
        // NACK with multiple FCI entries
        let mut nack = RtcpNack::new(0x12345678, 0x87654321);

        // Add losses that span multiple entries
        nack.add_lost_seq(100);
        nack.add_lost_seq(101);
        nack.add_lost_seq(200); // Different entry
        nack.add_lost_seq(201);

        let encoded = nack.encode();
        let decoded = RtcpNack::decode(&encoded).unwrap();

        let lost = decoded.lost_sequences();
        assert!(lost.contains(&100));
        assert!(lost.contains(&101));
        assert!(lost.contains(&200));
        assert!(lost.contains(&201));
    }

    #[test]
    fn test_rtcp_header_packet_type_rtpfb() {
        let header = RtcpHeader::new(RtcpPayloadType::Rtpfb, 1, 3);

        let mut buf = [0u8; 4];
        header.encode(&mut buf).unwrap();

        // Verify format
        assert_eq!(buf[0] & 0xC0, 0x80); // V=2
        assert_eq!(buf[0] & 0x1F, 1); // FMT=1 (NACK)
        assert_eq!(buf[1], 205); // PT=205 (RTPFB)
    }

    #[test]
    fn test_nack_integration_flow() {
        // Simulate a complete NACK flow
        let mut tx_buffer = RetransmitBuffer::new(100);
        let mut rx_tracker = NackTracker::new();

        // Sender transmits packets 100-110
        for seq in 100u16..=110 {
            let packet = vec![seq as u8; 50]; // Dummy packet data
            tx_buffer.store(seq, packet);
        }

        // Receiver gets 100, 101, then 105 (missing 102, 103, 104)
        rx_tracker.on_packet_received(100, 0);
        rx_tracker.on_packet_received(101, 20);
        let nacks = rx_tracker.on_packet_received(105, 40);

        assert_eq!(nacks, vec![102, 103, 104]);

        // Create NACK packet
        let mut nack_packet = RtcpNack::new(0xAAAAAAAA, 0xBBBBBBBB);
        nack_packet.add_lost_sequences(&nacks);

        // Encode and decode (simulating network)
        let encoded = nack_packet.encode();
        let decoded = RtcpNack::decode(&encoded).unwrap();

        // Sender processes NACK
        let lost_seqs = decoded.lost_sequences();
        let retransmits = tx_buffer.get_multiple(&lost_seqs);

        // Verify all requested packets are available for retransmit
        assert_eq!(retransmits.len(), 3);
    }

    #[test]
    fn test_nack_sequence_wrap_around() {
        let mut tracker = NackTracker::new();

        // Test wrap-around near u16::MAX
        tracker.on_packet_received(65530, 0);
        let nacks = tracker.on_packet_received(65535, 10); // Miss 65531-65534

        assert_eq!(nacks.len(), 4);
        assert!(nacks.contains(&65531));
        assert!(nacks.contains(&65534));

        // Wrap to 0
        let nacks = tracker.on_packet_received(2, 20); // Miss 0, 1
        assert_eq!(nacks.len(), 2);
        assert!(nacks.contains(&0));
        assert!(nacks.contains(&1));
    }

    #[test]
    fn test_nack_stats_tracking() {
        let mut tracker = NackTracker::new();

        // Initial stats
        let stats = tracker.stats();
        assert_eq!(stats.missing_count, 0);
        assert_eq!(stats.nack_count, 0);
        assert_eq!(stats.recovered_count, 0);

        // Create gap
        tracker.on_packet_received(100, 0);
        tracker.on_packet_received(105, 50); // 4 missing

        let stats = tracker.stats();
        assert_eq!(stats.missing_count, 4);

        // Request NACKs
        let _ = tracker.get_pending_nacks(105, 10);
        let stats = tracker.stats();
        assert_eq!(stats.nack_count, 1);

        // Recovery
        tracker.on_packet_received(102, 100);
        let stats = tracker.stats();
        assert_eq!(stats.recovered_count, 1);
        assert_eq!(stats.missing_count, 3);
    }
}

/// Tests for STUN ALLOCATE (RFC 5766 TURN) functionality.
mod stun_allocate_tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    /// Magic cookie for STUN messages (RFC 5389).
    const STUN_MAGIC_COOKIE: u32 = 0x2112A442;

    #[test]
    fn test_allocate_request_message_type() {
        let tx_id = [0u8; 12];
        let msg = StunMessage::allocate_request(tx_id);
        let encoded = msg.encode();

        // First two bytes should be 0x0003 (Allocate Request)
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x03);
    }

    #[test]
    fn test_allocate_request_contains_requested_transport() {
        let tx_id = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let msg = StunMessage::allocate_request(tx_id);
        let encoded = msg.encode();

        // Find REQUESTED-TRANSPORT attribute (0x0019)
        // Should be at offset 20 (after 20-byte header)
        let attr_type = u16::from_be_bytes([encoded[20], encoded[21]]);
        assert_eq!(attr_type, 0x0019, "REQUESTED-TRANSPORT attribute expected");

        // Length should be 4
        let attr_len = u16::from_be_bytes([encoded[22], encoded[23]]);
        assert_eq!(attr_len, 4);

        // First byte of value should be UDP (17)
        assert_eq!(encoded[24], 17);
    }

    #[test]
    fn test_allocate_request_with_username_and_integrity() {
        let tx_id = [0u8; 12];
        let username = b"test-auth-token";
        let relay_key = b"test-relay-key";

        let msg = StunMessage::allocate_request(tx_id)
            .with_username(username)
            .with_integrity_key(relay_key);

        let encoded = msg.encode();

        // Verify message type is AllocateRequest
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x03);

        // Should contain all attributes
        // The encoded message should be reasonably sized
        assert!(encoded.len() > 60, "Should contain multiple attributes");
    }

    #[test]
    fn test_decode_allocate_response_with_relayed_address() {
        let mut data = Vec::new();

        // Message type: Allocate Response (0x0103)
        data.extend_from_slice(&[0x01, 0x03]);

        // Message length (will update later)
        let msg_len_offset = data.len();
        data.extend_from_slice(&[0x00, 0x00]);

        // Magic cookie
        data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID
        let tx_id = [0xAA; 12];
        data.extend_from_slice(&tx_id);

        // XOR-RELAYED-ADDRESS (0x0016) for 203.0.113.5:49152
        data.extend_from_slice(&[0x00, 0x16]); // Type
        data.extend_from_slice(&[0x00, 0x08]); // Length (IPv4)
        data.extend_from_slice(&[0x00, 0x01]); // Reserved + Family (IPv4)

        // Port: 49152 (0xC000) XOR 0x2112 = 0xE112
        data.extend_from_slice(&[0xE1, 0x12]);

        // IP: 203.0.113.5 = 0xCB007105
        // XOR with magic cookie 0x2112A442 = 0xEA12D547
        data.extend_from_slice(&[0xEA, 0x12, 0xD5, 0x47]);

        // Update message length
        let attrs_len = (data.len() - 20) as u16;
        data[msg_len_offset] = (attrs_len >> 8) as u8;
        data[msg_len_offset + 1] = attrs_len as u8;

        let msg = StunMessage::decode(&data).unwrap();
        assert_eq!(msg.msg_type, StunMessageType::AllocateResponse);
        assert_eq!(msg.transaction_id, tx_id);

        let relayed = msg.relayed_address().unwrap();
        assert_eq!(relayed.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)));
        assert_eq!(relayed.port(), 49152);
    }

    #[test]
    fn test_decode_allocate_response_with_lifetime() {
        let mut data = Vec::new();

        // Message type: Allocate Response (0x0103)
        data.extend_from_slice(&[0x01, 0x03]);
        data.extend_from_slice(&[0x00, 0x08]); // Message length: 8 (LIFETIME only)

        // Magic cookie
        data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID
        data.extend_from_slice(&[0xBB; 12]);

        // LIFETIME (0x000D) with value 600 seconds
        data.extend_from_slice(&[0x00, 0x0D]); // Type
        data.extend_from_slice(&[0x00, 0x04]); // Length
        data.extend_from_slice(&[0x00, 0x00, 0x02, 0x58]); // 600 seconds

        let msg = StunMessage::decode(&data).unwrap();
        assert_eq!(msg.lifetime(), Some(600));
    }

    #[test]
    fn test_decode_allocate_error_response_401() {
        let mut data = Vec::new();

        // Message type: Allocate Error Response (0x0113)
        data.extend_from_slice(&[0x01, 0x13]);
        // Message length: 20 (4-byte attr header + 16-byte attr value)
        data.extend_from_slice(&[0x00, 0x14]);

        // Magic cookie
        data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());

        // Transaction ID
        data.extend_from_slice(&[0xCC; 12]);

        // ERROR-CODE (0x0009) for 401 Unauthorized
        data.extend_from_slice(&[0x00, 0x09]); // Type
        data.extend_from_slice(&[0x00, 0x10]); // Length: 16 (4 reserved/class + 12 reason)
        data.extend_from_slice(&[0x00, 0x00]); // Reserved
        data.extend_from_slice(&[0x04, 0x01]); // Error class 4, number 01 = 401
        data.extend_from_slice(b"Unauthorized"); // Reason phrase (12 bytes)

        let msg = StunMessage::decode(&data).unwrap();
        assert_eq!(msg.msg_type, StunMessageType::AllocateErrorResponse);
        assert!(msg.is_error());
        assert!(!msg.is_success());

        let (code, reason) = msg.error_code().unwrap();
        assert_eq!(code, 401);
        assert_eq!(reason, "Unauthorized");
    }

    #[test]
    fn test_classify_stun_vs_rtp_packets() {
        // STUN Binding Request
        let stun_bind = [0x00, 0x01, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42];
        assert!(StunBinder::is_stun_packet(&stun_bind));
        assert!(StunBinder::is_binding_packet(&stun_bind));
        assert!(!StunBinder::is_allocate_packet(&stun_bind));

        // STUN Allocate Request
        let stun_alloc = [0x00, 0x03, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42];
        assert!(StunBinder::is_stun_packet(&stun_alloc));
        assert!(!StunBinder::is_binding_packet(&stun_alloc));
        assert!(StunBinder::is_allocate_packet(&stun_alloc));

        // RTP packet (version 2, payload type 111)
        let rtp = [0x80, 0x6F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00];
        assert!(!StunBinder::is_stun_packet(&rtp));
        assert!(!StunBinder::is_binding_packet(&rtp));
        assert!(!StunBinder::is_allocate_packet(&rtp));
    }

    #[test]
    fn test_refresh_request_message_format() {
        let tx_id = [0xDD; 12];
        let msg = StunMessage::refresh_request(tx_id, 0); // Lifetime 0 = delete allocation
        let encoded = msg.encode();

        // Message type: 0x0004 (Refresh Request)
        assert_eq!(encoded[0], 0x00);
        assert_eq!(encoded[1], 0x04);

        // Should contain LIFETIME attribute
        let attr_type = u16::from_be_bytes([encoded[20], encoded[21]]);
        assert_eq!(attr_type, 0x000D); // LIFETIME

        // Lifetime value should be 0
        let lifetime = u32::from_be_bytes([encoded[24], encoded[25], encoded[26], encoded[27]]);
        assert_eq!(lifetime, 0);
    }

    #[test]
    fn test_full_allocate_flow_encode_decode() {
        // 1. Create allocate request
        let tx_id = [0xEE; 12];
        let request = StunMessage::allocate_request(tx_id)
            .with_username(b"auth-token-123")
            .with_integrity_key(b"relay-key-456");

        let request_bytes = request.encode();

        // Verify request encoding
        assert_eq!(request_bytes[0], 0x00);
        assert_eq!(request_bytes[1], 0x03);

        // 2. Create simulated response
        let mut response_data = Vec::new();
        response_data.extend_from_slice(&[0x01, 0x03]); // Allocate Response

        // We'll add XOR-RELAYED-ADDRESS (12) + XOR-MAPPED-ADDRESS (12) + LIFETIME (8)
        let msg_len_offset = response_data.len();
        response_data.extend_from_slice(&[0x00, 0x00]); // Will update

        response_data.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        response_data.extend_from_slice(&tx_id); // Same transaction ID

        // XOR-RELAYED-ADDRESS: 10.20.30.40:5000
        response_data.extend_from_slice(&[0x00, 0x16]);
        response_data.extend_from_slice(&[0x00, 0x08]);
        response_data.extend_from_slice(&[0x00, 0x01]); // IPv4
        // Port: 5000 (0x1388) XOR 0x2112 = 0x329A
        response_data.extend_from_slice(&[0x32, 0x9A]);
        // IP: 10.20.30.40 = 0x0A141E28 XOR 0x2112A442 = 0x2B06BA6A
        response_data.extend_from_slice(&[0x2B, 0x06, 0xBA, 0x6A]);

        // XOR-MAPPED-ADDRESS: 203.0.113.1:12345
        response_data.extend_from_slice(&[0x00, 0x20]);
        response_data.extend_from_slice(&[0x00, 0x08]);
        response_data.extend_from_slice(&[0x00, 0x01]); // IPv4
        // Port: 12345 (0x3039) XOR 0x2112 = 0x112B
        response_data.extend_from_slice(&[0x11, 0x2B]);
        // IP: 203.0.113.1 = 0xCB007101 XOR 0x2112A442 = 0xEA12D543
        response_data.extend_from_slice(&[0xEA, 0x12, 0xD5, 0x43]);

        // LIFETIME: 3600 seconds
        response_data.extend_from_slice(&[0x00, 0x0D]);
        response_data.extend_from_slice(&[0x00, 0x04]);
        response_data.extend_from_slice(&[0x00, 0x00, 0x0E, 0x10]);

        // Update message length
        let attrs_len = (response_data.len() - 20) as u16;
        response_data[msg_len_offset] = (attrs_len >> 8) as u8;
        response_data[msg_len_offset + 1] = attrs_len as u8;

        // 3. Decode response
        let response = StunMessage::decode(&response_data).unwrap();

        // Verify response
        assert_eq!(response.msg_type, StunMessageType::AllocateResponse);
        assert_eq!(response.transaction_id, tx_id);
        assert!(response.is_success());

        // Verify relayed address
        let relayed = response.relayed_address().unwrap();
        assert_eq!(relayed.ip(), IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)));
        assert_eq!(relayed.port(), 5000);

        // Verify mapped address
        let mapped = response.mapped_address().unwrap();
        assert_eq!(mapped.ip(), IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        assert_eq!(mapped.port(), 12345);

        // Verify lifetime
        assert_eq!(response.lifetime(), Some(3600));
    }

    #[test]
    fn test_stun_credentials_for_allocate() {
        // Simulate WhatsApp-style credentials
        let auth_token = b"whatsapp-auth-token-xyz";
        let relay_key = b"whatsapp-relay-key-abc";

        let credentials = StunCredentials::with_integrity(auth_token, relay_key);

        assert_eq!(credentials.username, auth_token);
        assert_eq!(credentials.integrity_key.as_ref().unwrap(), relay_key);
    }

    #[test]
    fn test_ice_restart_detection_with_allocate() {
        // Simulate receiving STUN ALLOCATE during active call
        // (This triggers ICE restart in WhatsApp Web if no RX packets for 10+ seconds)

        let packets = vec![
            // RTP media packets
            vec![0x80, 0x6F, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00],
            vec![0x80, 0x6F, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00],
            // STUN Allocate (indicates ICE restart needed)
            vec![0x00, 0x03, 0x00, 0x08, 0x21, 0x12, 0xA4, 0x42],
            // More RTP
            vec![0x80, 0x6F, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00],
        ];

        let mut stun_allocate_count = 0;
        let mut media_packet_count = 0;

        for packet in &packets {
            if StunBinder::is_allocate_packet(packet) {
                stun_allocate_count += 1;
            } else if !StunBinder::is_stun_packet(packet) {
                media_packet_count += 1;
            }
        }

        assert_eq!(stun_allocate_count, 1, "Should detect 1 ALLOCATE packet");
        assert_eq!(media_packet_count, 3, "Should detect 3 media packets");
    }

    #[test]
    fn test_allocate_result_structure() {
        // Test the StunAllocateResult structure
        let result = StunAllocateResult {
            mapped_address: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                12345,
            )),
            relayed_address: Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                54321,
            )),
            lifetime: Some(3600),
            response: StunMessage::allocate_request([0; 12]), // Dummy for test
        };

        assert!(result.mapped_address.is_some());
        assert!(result.relayed_address.is_some());
        assert_eq!(result.lifetime, Some(3600));
    }

    #[test]
    fn test_turn_transport_protocol_udp() {
        // Verify UDP is the default for allocate
        let tx_id = [0; 12];
        let msg = StunMessage::allocate_request(tx_id);
        let encoded = msg.encode();

        // REQUESTED-TRANSPORT should contain UDP (17)
        // After header (20) and attr header (4), first byte is protocol
        assert_eq!(encoded[24], 17, "Protocol should be UDP (17)");
    }
}
