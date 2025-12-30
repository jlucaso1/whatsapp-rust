//! RTCP (Real-time Control Protocol) packet handling.
//!
//! Implements RFC 3550 RTCP and RFC 4585 Extended RTP Profile for RTCP-Based Feedback.
//!
//! # Supported Packet Types
//!
//! - RTPFB (205): Transport layer feedback
//!   - FMT=1: Generic NACK - Request retransmission of lost packets
//! - PSFB (206): Payload-specific feedback
//!   - FMT=1: PLI - Picture Loss Indication (for video)
//!
//! # RTCP NACK Format (RFC 4585)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |V=2|P|  FMT=1  |   PT=205      |          length               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of packet sender                        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                  SSRC of media source                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |            PID                |             BLP               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

use std::collections::VecDeque;
use std::io;

/// RTCP version (always 2, same as RTP).
pub const RTCP_VERSION: u8 = 2;

/// RTCP payload types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RtcpPayloadType {
    /// Sender Report (RFC 3550)
    Sr = 200,
    /// Receiver Report (RFC 3550)
    Rr = 201,
    /// Source Description (RFC 3550)
    Sdes = 202,
    /// Goodbye (RFC 3550)
    Bye = 203,
    /// Application-defined (RFC 3550)
    App = 204,
    /// Transport layer feedback (RFC 4585) - includes NACK
    Rtpfb = 205,
    /// Payload-specific feedback (RFC 4585) - includes PLI, FIR
    Psfb = 206,
}

impl TryFrom<u8> for RtcpPayloadType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            200 => Ok(Self::Sr),
            201 => Ok(Self::Rr),
            202 => Ok(Self::Sdes),
            203 => Ok(Self::Bye),
            204 => Ok(Self::App),
            205 => Ok(Self::Rtpfb),
            206 => Ok(Self::Psfb),
            _ => Err(value),
        }
    }
}

/// Feedback Message Type (FMT) for RTPFB (PT=205).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RtpfbFmt {
    /// Generic NACK (RFC 4585)
    Nack = 1,
    /// Transport-wide Congestion Control (draft-holmer-rmcat-transport-wide-cc-extensions)
    Twcc = 15,
}

/// Feedback Message Type (FMT) for PSFB (PT=206).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PsfbFmt {
    /// Picture Loss Indication (RFC 4585)
    Pli = 1,
    /// Slice Loss Indication (RFC 4585)
    Sli = 2,
    /// Reference Picture Selection Indication (RFC 4585)
    Rpsi = 3,
    /// Full Intra Request (RFC 5104)
    Fir = 4,
    /// Application Layer Feedback (REMB uses this)
    Afb = 15,
}

/// RTCP common header (first 4 bytes of every RTCP packet).
#[derive(Debug, Clone)]
pub struct RtcpHeader {
    /// Version (always 2).
    pub version: u8,
    /// Padding flag.
    pub padding: bool,
    /// Reception report count / Feedback message type (FMT).
    pub count_or_fmt: u8,
    /// Payload type.
    pub payload_type: RtcpPayloadType,
    /// Length in 32-bit words minus one.
    pub length: u16,
}

impl RtcpHeader {
    /// Header size in bytes.
    pub const SIZE: usize = 4;

    /// Create a new RTCP header.
    pub fn new(payload_type: RtcpPayloadType, count_or_fmt: u8, length_words: u16) -> Self {
        Self {
            version: RTCP_VERSION,
            padding: false,
            count_or_fmt,
            payload_type,
            length: length_words,
        }
    }

    /// Encode header to bytes.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if buf.len() < Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for RTCP header",
            ));
        }

        // Byte 0: V(2) P(1) RC/FMT(5)
        buf[0] = (self.version << 6) | ((self.padding as u8) << 5) | (self.count_or_fmt & 0x1F);

        // Byte 1: PT
        buf[1] = self.payload_type as u8;

        // Bytes 2-3: Length (big-endian)
        buf[2..4].copy_from_slice(&self.length.to_be_bytes());

        Ok(Self::SIZE)
    }

    /// Decode header from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, io::Error> {
        if buf.len() < Self::SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for RTCP header",
            ));
        }

        let version = (buf[0] >> 6) & 0x03;
        if version != RTCP_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid RTCP version: {}", version),
            ));
        }

        let padding = (buf[0] >> 5) & 0x01 != 0;
        let count_or_fmt = buf[0] & 0x1F;
        let payload_type = RtcpPayloadType::try_from(buf[1]).map_err(|pt| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown RTCP PT: {}", pt),
            )
        })?;
        let length = u16::from_be_bytes([buf[2], buf[3]]);

        Ok(Self {
            version,
            padding,
            count_or_fmt,
            payload_type,
            length,
        })
    }

    /// Total packet size in bytes (header + payload).
    pub fn packet_size(&self) -> usize {
        Self::SIZE + (self.length as usize + 1) * 4 - 4
    }
}

/// A single NACK entry (PID + BLP).
///
/// PID is the sequence number of the first lost packet.
/// BLP is a bitmask where bit i indicates that packet (PID + i + 1) is also lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NackEntry {
    /// Packet ID - sequence number of the first lost packet.
    pub pid: u16,
    /// Bitmask of following lost packets.
    pub blp: u16,
}

impl NackEntry {
    /// Create a NACK entry for a single lost packet.
    pub fn single(seq: u16) -> Self {
        Self { pid: seq, blp: 0 }
    }

    /// Create a NACK entry from a list of lost sequence numbers.
    ///
    /// The first sequence in the list becomes PID, and subsequent sequences
    /// (within 16 of PID) are encoded in BLP.
    pub fn from_sequences(sequences: &[u16]) -> Option<Self> {
        if sequences.is_empty() {
            return None;
        }

        let pid = sequences[0];
        let mut blp: u16 = 0;

        for &seq in &sequences[1..] {
            let diff = seq.wrapping_sub(pid);
            if (1..=16).contains(&diff) {
                blp |= 1 << (diff - 1);
            }
        }

        Some(Self { pid, blp })
    }

    /// Get all lost sequence numbers from this entry.
    pub fn lost_sequences(&self) -> Vec<u16> {
        let mut seqs = vec![self.pid];

        for i in 0..16 {
            if (self.blp >> i) & 1 != 0 {
                seqs.push(self.pid.wrapping_add(i + 1));
            }
        }

        seqs
    }

    /// Encode to bytes (4 bytes).
    pub fn encode(&self, buf: &mut [u8]) -> Result<(), io::Error> {
        if buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for NACK entry",
            ));
        }

        buf[0..2].copy_from_slice(&self.pid.to_be_bytes());
        buf[2..4].copy_from_slice(&self.blp.to_be_bytes());

        Ok(())
    }

    /// Decode from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, io::Error> {
        if buf.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for NACK entry",
            ));
        }

        Ok(Self {
            pid: u16::from_be_bytes([buf[0], buf[1]]),
            blp: u16::from_be_bytes([buf[2], buf[3]]),
        })
    }
}

/// RTCP Generic NACK packet (RFC 4585).
#[derive(Debug, Clone)]
pub struct RtcpNack {
    /// SSRC of the sender of this NACK packet.
    pub sender_ssrc: u32,
    /// SSRC of the media source whose packets are being requested.
    pub media_ssrc: u32,
    /// List of NACK entries.
    pub entries: Vec<NackEntry>,
}

impl RtcpNack {
    /// Create a new NACK packet.
    pub fn new(sender_ssrc: u32, media_ssrc: u32) -> Self {
        Self {
            sender_ssrc,
            media_ssrc,
            entries: Vec::new(),
        }
    }

    /// Add a single lost sequence number.
    pub fn add_lost_seq(&mut self, seq: u16) {
        // Try to add to existing entry if within BLP range
        for entry in &mut self.entries {
            let diff = seq.wrapping_sub(entry.pid);
            if (1..=16).contains(&diff) {
                entry.blp |= 1 << (diff - 1);
                return;
            }
        }

        // Create new entry
        self.entries.push(NackEntry::single(seq));
    }

    /// Add multiple lost sequence numbers.
    pub fn add_lost_sequences(&mut self, sequences: &[u16]) {
        for &seq in sequences {
            self.add_lost_seq(seq);
        }
    }

    /// Get all lost sequence numbers.
    pub fn lost_sequences(&self) -> Vec<u16> {
        let mut seqs = Vec::new();
        for entry in &self.entries {
            seqs.extend(entry.lost_sequences());
        }
        seqs.sort_unstable();
        seqs.dedup();
        seqs
    }

    /// Packet size in bytes.
    pub fn size(&self) -> usize {
        // Header (4) + sender SSRC (4) + media SSRC (4) + entries (4 each)
        RtcpHeader::SIZE + 8 + self.entries.len() * 4
    }

    /// Encode to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.size()];

        // Calculate length in 32-bit words minus 1
        let length_words = (self.size() / 4 - 1) as u16;
        let header = RtcpHeader::new(RtcpPayloadType::Rtpfb, RtpfbFmt::Nack as u8, length_words);

        header.encode(&mut buf[..4]).unwrap();
        buf[4..8].copy_from_slice(&self.sender_ssrc.to_be_bytes());
        buf[8..12].copy_from_slice(&self.media_ssrc.to_be_bytes());

        for (i, entry) in self.entries.iter().enumerate() {
            let offset = 12 + i * 4;
            entry.encode(&mut buf[offset..offset + 4]).unwrap();
        }

        buf
    }

    /// Decode from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, io::Error> {
        if buf.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for RTCP NACK",
            ));
        }

        let header = RtcpHeader::decode(buf)?;
        if header.payload_type != RtcpPayloadType::Rtpfb {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected RTPFB, got {:?}", header.payload_type),
            ));
        }
        if header.count_or_fmt != RtpfbFmt::Nack as u8 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected NACK FMT, got {}", header.count_or_fmt),
            ));
        }

        let sender_ssrc = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let media_ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        // Parse NACK entries
        let num_entries = (header.length as usize + 1) - 2; // Subtract 2 for SSRCs
        let mut entries = Vec::with_capacity(num_entries);

        for i in 0..num_entries {
            let offset = 12 + i * 4;
            if offset + 4 > buf.len() {
                break;
            }
            entries.push(NackEntry::decode(&buf[offset..offset + 4])?);
        }

        Ok(Self {
            sender_ssrc,
            media_ssrc,
            entries,
        })
    }
}

/// Tracks received packets and detects gaps for NACK generation.
#[derive(Debug)]
pub struct NackTracker {
    /// Expected next sequence number.
    expected_seq: Option<u16>,
    /// Missing sequence numbers awaiting NACK.
    missing: VecDeque<MissingPacket>,
    /// Maximum number of missing packets to track.
    max_missing: usize,
    /// Maximum age (in sequence numbers) before giving up on a packet.
    max_age: u16,
    /// Number of NACKs sent.
    nack_count: u64,
    /// Number of recovered packets (received after NACK).
    recovered_count: u64,
}

#[derive(Debug, Clone)]
struct MissingPacket {
    seq: u16,
    /// Number of times we've sent NACK for this packet.
    nack_attempts: u8,
    /// Timestamp when first detected missing.
    first_detected_ms: u64,
}

impl NackTracker {
    /// Create a new NACK tracker.
    pub fn new() -> Self {
        Self {
            expected_seq: None,
            missing: VecDeque::new(),
            max_missing: 100,
            max_age: 1000, // Give up after ~1000 packets (~20 seconds at 50pps)
            nack_count: 0,
            recovered_count: 0,
        }
    }

    /// Record receipt of a packet.
    ///
    /// Returns list of sequence numbers that need to be NACKed.
    pub fn on_packet_received(&mut self, seq: u16, current_time_ms: u64) -> Vec<u16> {
        let mut need_nack = Vec::new();

        match self.expected_seq {
            None => {
                // First packet - initialize
                self.expected_seq = Some(seq.wrapping_add(1));
            }
            Some(expected) => {
                // Calculate signed difference handling wrap-around
                let raw_diff = seq.wrapping_sub(expected);
                let diff = if raw_diff > 32767 {
                    // Negative difference (late packet)
                    raw_diff as i32 - 65536
                } else {
                    raw_diff as i32
                };

                if diff == 0 {
                    // In order - advance expected
                    self.expected_seq = Some(seq.wrapping_add(1));
                } else if diff > 0 && diff < 100 {
                    // Gap detected - packets expected..seq-1 are missing
                    let mut current = expected;
                    while current != seq {
                        if self.missing.len() < self.max_missing {
                            self.missing.push_back(MissingPacket {
                                seq: current,
                                nack_attempts: 0,
                                first_detected_ms: current_time_ms,
                            });
                            need_nack.push(current);
                        }
                        current = current.wrapping_add(1);
                    }
                    self.expected_seq = Some(seq.wrapping_add(1));
                } else if diff < 0 && diff > -100 {
                    // Late packet (was missing, now received)
                    if let Some(pos) = self.missing.iter().position(|m| m.seq == seq) {
                        self.missing.remove(pos);
                        self.recovered_count += 1;
                    }
                }
                // Ignore very old or very far future packets
            }
        }

        need_nack
    }

    /// Get list of packets that need retransmission request.
    ///
    /// This should be called periodically to resend NACKs for still-missing packets.
    pub fn get_pending_nacks(&mut self, current_seq: u16, max_nacks: usize) -> Vec<u16> {
        let mut nacks = Vec::new();

        // Remove packets that are too old
        self.missing.retain(|m| {
            let age = current_seq.wrapping_sub(m.seq);
            age < self.max_age
        });

        // Collect packets for NACK (prioritize by attempts)
        for m in &mut self.missing {
            if nacks.len() >= max_nacks {
                break;
            }
            // Only NACK packets we haven't given up on
            if m.nack_attempts < 8 {
                nacks.push(m.seq);
                m.nack_attempts += 1;
            }
        }

        if !nacks.is_empty() {
            self.nack_count += 1;
        }

        nacks
    }

    /// Check if a sequence number is in the missing list.
    pub fn is_missing(&self, seq: u16) -> bool {
        self.missing.iter().any(|m| m.seq == seq)
    }

    /// Get statistics.
    pub fn stats(&self) -> NackStats {
        NackStats {
            missing_count: self.missing.len(),
            nack_count: self.nack_count,
            recovered_count: self.recovered_count,
        }
    }
}

impl Default for NackTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// NACK statistics.
#[derive(Debug, Clone, Copy)]
pub struct NackStats {
    /// Current number of missing packets.
    pub missing_count: usize,
    /// Total NACKs sent.
    pub nack_count: u64,
    /// Packets recovered after NACK.
    pub recovered_count: u64,
}

/// Retransmission buffer for handling incoming NACKs.
///
/// Stores recently sent packets so they can be retransmitted on NACK request.
#[derive(Debug)]
pub struct RetransmitBuffer {
    /// Circular buffer of (sequence_number, encrypted_packet).
    packets: VecDeque<(u16, Vec<u8>)>,
    /// Maximum number of packets to store.
    max_size: usize,
}

impl RetransmitBuffer {
    /// Create a new retransmit buffer.
    pub fn new(max_size: usize) -> Self {
        Self {
            packets: VecDeque::with_capacity(max_size),
            max_size,
        }
    }

    /// Store a packet for potential retransmission.
    pub fn store(&mut self, seq: u16, packet: Vec<u8>) {
        if self.packets.len() >= self.max_size {
            self.packets.pop_front();
        }
        self.packets.push_back((seq, packet));
    }

    /// Get a packet for retransmission.
    pub fn get(&self, seq: u16) -> Option<&[u8]> {
        self.packets
            .iter()
            .find(|(s, _)| *s == seq)
            .map(|(_, p)| p.as_slice())
    }

    /// Get multiple packets for retransmission.
    pub fn get_multiple(&self, seqs: &[u16]) -> Vec<(u16, &[u8])> {
        seqs.iter()
            .filter_map(|&seq| self.get(seq).map(|p| (seq, p)))
            .collect()
    }

    /// Number of packets in buffer.
    pub fn len(&self) -> usize {
        self.packets.len()
    }

    /// Check if buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtcp_header_encode_decode() {
        let header = RtcpHeader::new(RtcpPayloadType::Rtpfb, 1, 3);

        let mut buf = [0u8; 4];
        header.encode(&mut buf).unwrap();

        let decoded = RtcpHeader::decode(&buf).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.count_or_fmt, 1);
        assert_eq!(decoded.payload_type, RtcpPayloadType::Rtpfb);
        assert_eq!(decoded.length, 3);
    }

    #[test]
    fn test_nack_entry_single() {
        let entry = NackEntry::single(1000);
        assert_eq!(entry.pid, 1000);
        assert_eq!(entry.blp, 0);
        assert_eq!(entry.lost_sequences(), vec![1000]);
    }

    #[test]
    fn test_nack_entry_with_blp() {
        let entry = NackEntry {
            pid: 1000,
            blp: 0b0000000000010101, // bits 0, 2, 4 set
        };

        let seqs = entry.lost_sequences();
        assert_eq!(seqs, vec![1000, 1001, 1003, 1005]);
    }

    #[test]
    fn test_nack_entry_from_sequences() {
        let seqs = vec![1000, 1001, 1003, 1005];
        let entry = NackEntry::from_sequences(&seqs).unwrap();

        assert_eq!(entry.pid, 1000);
        assert_eq!(entry.blp, 0b0000000000010101);
    }

    #[test]
    fn test_nack_entry_encode_decode() {
        let entry = NackEntry {
            pid: 0x1234,
            blp: 0x5678,
        };

        let mut buf = [0u8; 4];
        entry.encode(&mut buf).unwrap();

        let decoded = NackEntry::decode(&buf).unwrap();
        assert_eq!(decoded.pid, 0x1234);
        assert_eq!(decoded.blp, 0x5678);
    }

    #[test]
    fn test_rtcp_nack_encode_decode() {
        let mut nack = RtcpNack::new(0x11111111, 0x22222222);
        nack.add_lost_seq(1000);
        nack.add_lost_seq(1001);
        nack.add_lost_seq(1005);

        let encoded = nack.encode();

        // Verify size: 4 (header) + 4 (sender) + 4 (media) + 4 (1 entry) = 16
        assert_eq!(encoded.len(), 16);

        let decoded = RtcpNack::decode(&encoded).unwrap();
        assert_eq!(decoded.sender_ssrc, 0x11111111);
        assert_eq!(decoded.media_ssrc, 0x22222222);

        let lost = decoded.lost_sequences();
        assert!(lost.contains(&1000));
        assert!(lost.contains(&1001));
        assert!(lost.contains(&1005));
    }

    #[test]
    fn test_nack_tracker_detects_gap() {
        let mut tracker = NackTracker::new();

        // Receive packets in order
        assert!(tracker.on_packet_received(100, 0).is_empty());
        assert!(tracker.on_packet_received(101, 10).is_empty());

        // Skip 102, 103
        let nacks = tracker.on_packet_received(104, 20);
        assert_eq!(nacks, vec![102, 103]);
    }

    #[test]
    fn test_nack_tracker_late_packet() {
        let mut tracker = NackTracker::new();

        tracker.on_packet_received(100, 0);
        let nacks = tracker.on_packet_received(103, 10); // Miss 101, 102
        assert_eq!(nacks, vec![101, 102]);

        // Late packet arrives
        tracker.on_packet_received(101, 20);
        assert!(!tracker.is_missing(101));
        assert!(tracker.is_missing(102));
    }

    #[test]
    fn test_nack_tracker_stats() {
        let mut tracker = NackTracker::new();

        tracker.on_packet_received(100, 0);
        tracker.on_packet_received(105, 10); // Miss 101-104

        let stats = tracker.stats();
        assert_eq!(stats.missing_count, 4);

        // Recover one
        tracker.on_packet_received(102, 20);
        let stats = tracker.stats();
        assert_eq!(stats.missing_count, 3);
        assert_eq!(stats.recovered_count, 1);
    }

    #[test]
    fn test_retransmit_buffer() {
        let mut buffer = RetransmitBuffer::new(10);

        buffer.store(100, vec![1, 2, 3]);
        buffer.store(101, vec![4, 5, 6]);
        buffer.store(102, vec![7, 8, 9]);

        assert_eq!(buffer.get(101), Some(&[4, 5, 6][..]));
        assert_eq!(buffer.get(999), None);
    }

    #[test]
    fn test_retransmit_buffer_eviction() {
        let mut buffer = RetransmitBuffer::new(3);

        buffer.store(100, vec![1]);
        buffer.store(101, vec![2]);
        buffer.store(102, vec![3]);
        buffer.store(103, vec![4]); // Should evict 100

        assert_eq!(buffer.get(100), None);
        assert_eq!(buffer.get(103), Some(&[4][..]));
    }

    #[test]
    fn test_payload_type_values() {
        assert_eq!(RtcpPayloadType::Sr as u8, 200);
        assert_eq!(RtcpPayloadType::Rr as u8, 201);
        assert_eq!(RtcpPayloadType::Rtpfb as u8, 205);
        assert_eq!(RtcpPayloadType::Psfb as u8, 206);
    }

    #[test]
    fn test_rtpfb_fmt_values() {
        assert_eq!(RtpfbFmt::Nack as u8, 1);
        assert_eq!(RtpfbFmt::Twcc as u8, 15);
    }

    #[test]
    fn test_psfb_fmt_values() {
        assert_eq!(PsfbFmt::Pli as u8, 1);
        assert_eq!(PsfbFmt::Fir as u8, 4);
        assert_eq!(PsfbFmt::Afb as u8, 15);
    }
}
