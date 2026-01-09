//! Jitter buffer for RTP packet reordering and timing.
//!
//! Handles network jitter by buffering incoming packets and releasing
//! them in order at regular intervals.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use super::rtp::RtpPacket;

/// Configuration for the jitter buffer.
#[derive(Debug, Clone)]
pub struct JitterBufferConfig {
    pub target_delay: Duration,
    pub max_packets: usize,
    pub max_age: Duration,
}

impl Default for JitterBufferConfig {
    fn default() -> Self {
        Self {
            target_delay: Duration::from_millis(60), // 60ms playout delay
            max_packets: 50,                         // ~1 second at 20ms packets
            max_age: Duration::from_millis(500),     // 500ms max age
        }
    }
}

/// A buffered packet with timing info.
#[derive(Debug)]
struct BufferedPacket {
    packet: RtpPacket,
    received_at: Instant,
}

/// Statistics about the jitter buffer.
#[derive(Debug, Clone, Default)]
pub struct JitterStats {
    pub packets_received: u64,
    pub packets_played: u64,
    pub packets_dropped: u64,
    pub packets_reordered: u64,
    pub packets_duplicate: u64,
    pub buffer_depth: usize,
    pub jitter_ms: f64,
}

/// Jitter buffer for smoothing RTP packet delivery.
pub struct JitterBuffer {
    config: JitterBufferConfig,
    buffer: BTreeMap<u16, BufferedPacket>,
    next_seq: Option<u16>,
    first_packet_time: Option<Instant>,
    first_rtp_timestamp: Option<u32>,
    sample_rate: u32,
    stats: JitterStats,
    jitter_estimate: f64,
    last_arrival: Option<Instant>,
    last_timestamp: Option<u32>,
}

impl JitterBuffer {
    pub fn new(config: JitterBufferConfig, sample_rate: u32) -> Self {
        Self {
            config,
            buffer: BTreeMap::new(),
            next_seq: None,
            first_packet_time: None,
            first_rtp_timestamp: None,
            sample_rate,
            stats: JitterStats::default(),
            jitter_estimate: 0.0,
            last_arrival: None,
            last_timestamp: None,
        }
    }

    pub fn opus_16khz() -> Self {
        Self::new(JitterBufferConfig::default(), 16000)
    }

    pub fn push(&mut self, packet: RtpPacket) {
        let now = Instant::now();
        let seq = packet.header.sequence_number;
        let timestamp = packet.header.timestamp;

        self.stats.packets_received += 1;

        // Initialize timing on first packet
        if self.first_packet_time.is_none() {
            self.first_packet_time = Some(now);
            self.first_rtp_timestamp = Some(timestamp);
            self.next_seq = Some(seq);
        }

        // Update jitter estimate (RFC 3550)
        self.update_jitter(now, timestamp);

        // Check for duplicate
        if self.buffer.contains_key(&seq) {
            self.stats.packets_duplicate += 1;
            return;
        }

        // Check if packet is too old (already played out)
        // Only drop packets if we've actually started playback
        if self.stats.packets_played > 0
            && let Some(next) = self.next_seq
        {
            let diff = seq.wrapping_sub(next) as i16;
            if diff < 0 && diff > -1000 {
                // Packet is older than what we've already played
                self.stats.packets_dropped += 1;
                return;
            }
            if diff < 0 {
                self.stats.packets_reordered += 1;
            }
        }

        // Check buffer capacity
        if self.buffer.len() >= self.config.max_packets {
            // Remove oldest packet
            if let Some(oldest_seq) = self.buffer.keys().next().copied() {
                self.buffer.remove(&oldest_seq);
                self.stats.packets_dropped += 1;
            }
        }

        // Add to buffer
        self.buffer.insert(
            seq,
            BufferedPacket {
                packet,
                received_at: now,
            },
        );

        self.stats.buffer_depth = self.buffer.len();
    }

    /// Pop the next packet if ready for playout.
    pub fn pop(&mut self) -> Option<RtpPacket> {
        let now = Instant::now();
        self.cleanup_old_packets(now);

        // Check if we've waited long enough for initial buffering
        let first_time = self.first_packet_time?;
        if now.duration_since(first_time) < self.config.target_delay {
            return None;
        }

        // On first playback, set next_seq to the lowest sequence in buffer
        if self.stats.packets_played == 0
            && let Some(&min_seq) = self.buffer.keys().next()
        {
            self.next_seq = Some(min_seq);
        }

        let next_seq = self.next_seq?;

        // Try to get the next expected packet
        if let Some(buffered) = self.buffer.remove(&next_seq) {
            self.next_seq = Some(next_seq.wrapping_add(1));
            self.stats.packets_played += 1;
            self.stats.buffer_depth = self.buffer.len();
            return Some(buffered.packet);
        }

        // Packet missing - skip ahead if gap is reasonable
        let &available_seq = self.buffer.keys().next()?;
        let gap = available_seq.wrapping_sub(next_seq);

        if gap < 100 {
            self.stats.packets_dropped += gap as u64;
            self.next_seq = Some(available_seq);

            if let Some(buffered) = self.buffer.remove(&available_seq) {
                self.next_seq = Some(available_seq.wrapping_add(1));
                self.stats.packets_played += 1;
                self.stats.buffer_depth = self.buffer.len();
                return Some(buffered.packet);
            }
        }

        None
    }

    fn update_jitter(&mut self, arrival: Instant, timestamp: u32) {
        if let (Some(last_arrival), Some(last_ts)) = (self.last_arrival, self.last_timestamp) {
            let arrival_diff = arrival.duration_since(last_arrival).as_micros() as f64;
            let ts_diff = timestamp.wrapping_sub(last_ts) as f64;
            let expected_diff = (ts_diff / self.sample_rate as f64) * 1_000_000.0;
            let d = (arrival_diff - expected_diff).abs();

            // Exponential moving average (RFC 3550)
            self.jitter_estimate += (d - self.jitter_estimate) / 16.0;
            self.stats.jitter_ms = self.jitter_estimate / 1000.0;
        }

        self.last_arrival = Some(arrival);
        self.last_timestamp = Some(timestamp);
    }

    fn cleanup_old_packets(&mut self, now: Instant) {
        let max_age = self.config.max_age;
        let old_count = self.buffer.len();

        self.buffer
            .retain(|_, buffered| now.duration_since(buffered.received_at) < max_age);

        let removed = old_count - self.buffer.len();
        self.stats.packets_dropped += removed as u64;
        self.stats.buffer_depth = self.buffer.len();
    }

    pub fn stats(&self) -> JitterStats {
        self.stats.clone()
    }

    pub fn depth(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn reset(&mut self) {
        self.buffer.clear();
        self.next_seq = None;
        self.first_packet_time = None;
        self.first_rtp_timestamp = None;
        self.stats = JitterStats::default();
        self.jitter_estimate = 0.0;
        self.last_arrival = None;
        self.last_timestamp = None;
    }
}

impl std::fmt::Debug for JitterBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JitterBuffer")
            .field("config", &self.config)
            .field("buffer_size", &self.buffer.len())
            .field("next_seq", &self.next_seq)
            .field("sample_rate", &self.sample_rate)
            .field("stats", &self.stats)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::calls::media::rtp::RtpHeader;

    fn make_packet(seq: u16, timestamp: u32) -> RtpPacket {
        let header = RtpHeader::new(111, seq, timestamp, 0x12345678);
        RtpPacket::new(header, vec![0u8; 20])
    }

    #[test]
    fn test_jitter_buffer_creation() {
        let buffer = JitterBuffer::opus_16khz();
        assert!(buffer.is_empty());
        assert_eq!(buffer.depth(), 0);
    }

    #[test]
    fn test_jitter_buffer_push_and_pop() {
        let config = JitterBufferConfig {
            target_delay: Duration::from_millis(0), // No initial delay for testing
            ..Default::default()
        };

        let mut buffer = JitterBuffer::new(config, 16000);

        // Push some packets
        buffer.push(make_packet(1000, 16000));
        buffer.push(make_packet(1001, 16320));
        buffer.push(make_packet(1002, 16640));

        assert_eq!(buffer.depth(), 3);

        // Pop should return packets in order
        let p1 = buffer.pop().unwrap();
        assert_eq!(p1.header.sequence_number, 1000);

        let p2 = buffer.pop().unwrap();
        assert_eq!(p2.header.sequence_number, 1001);

        let p3 = buffer.pop().unwrap();
        assert_eq!(p3.header.sequence_number, 1002);

        // Buffer should be empty now
        assert!(buffer.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_reordering() {
        let config = JitterBufferConfig {
            target_delay: Duration::from_millis(0),
            ..Default::default()
        };

        let mut buffer = JitterBuffer::new(config, 16000);

        // Push packets out of order
        buffer.push(make_packet(1002, 16640));
        buffer.push(make_packet(1000, 16000));
        buffer.push(make_packet(1001, 16320));

        // Should pop in order
        assert_eq!(buffer.pop().unwrap().header.sequence_number, 1000);
        assert_eq!(buffer.pop().unwrap().header.sequence_number, 1001);
        assert_eq!(buffer.pop().unwrap().header.sequence_number, 1002);
    }

    #[test]
    fn test_jitter_buffer_duplicate_detection() {
        let config = JitterBufferConfig {
            target_delay: Duration::from_millis(0),
            ..Default::default()
        };

        let mut buffer = JitterBuffer::new(config, 16000);

        buffer.push(make_packet(1000, 16000));
        buffer.push(make_packet(1000, 16000)); // Duplicate

        let stats = buffer.stats();
        assert_eq!(stats.packets_duplicate, 1);
        assert_eq!(buffer.depth(), 1);
    }

    #[test]
    fn test_jitter_buffer_max_packets() {
        let config = JitterBufferConfig {
            max_packets: 5,
            target_delay: Duration::from_millis(0),
            ..Default::default()
        };

        let mut buffer = JitterBuffer::new(config, 16000);

        // Push more than max
        for i in 0..10 {
            buffer.push(make_packet(1000 + i, 16000 + i as u32 * 320));
        }

        // Should only have max_packets
        assert_eq!(buffer.depth(), 5);
    }

    #[test]
    fn test_jitter_buffer_gap_handling() {
        let config = JitterBufferConfig {
            target_delay: Duration::from_millis(0),
            ..Default::default()
        };

        let mut buffer = JitterBuffer::new(config, 16000);

        // Push with a gap (1001 is missing)
        buffer.push(make_packet(1000, 16000));
        buffer.push(make_packet(1002, 16640));
        buffer.push(make_packet(1003, 16960));

        // First packet
        assert_eq!(buffer.pop().unwrap().header.sequence_number, 1000);

        // Next pop should skip 1001 and return 1002
        assert_eq!(buffer.pop().unwrap().header.sequence_number, 1002);
    }

    #[test]
    fn test_jitter_buffer_stats() {
        let config = JitterBufferConfig {
            target_delay: Duration::from_millis(0),
            ..Default::default()
        };

        let mut buffer = JitterBuffer::new(config, 16000);

        buffer.push(make_packet(1000, 16000));
        buffer.push(make_packet(1001, 16320));
        buffer.pop();
        buffer.pop();

        let stats = buffer.stats();
        assert_eq!(stats.packets_received, 2);
        assert_eq!(stats.packets_played, 2);
    }

    #[test]
    fn test_jitter_buffer_reset() {
        let mut buffer = JitterBuffer::opus_16khz();

        buffer.push(make_packet(1000, 16000));
        buffer.push(make_packet(1001, 16320));

        assert!(!buffer.is_empty());

        buffer.reset();

        assert!(buffer.is_empty());
        assert_eq!(buffer.stats().packets_received, 0);
    }

    #[test]
    fn test_jitter_buffer_initial_delay() {
        let config = JitterBufferConfig {
            target_delay: Duration::from_millis(100),
            ..Default::default()
        };

        let mut buffer = JitterBuffer::new(config, 16000);

        buffer.push(make_packet(1000, 16000));

        // Should not return packet immediately (within target delay)
        assert!(buffer.pop().is_none());
    }
}
