//! RTP (Real-time Transport Protocol) packet handling.
//!
//! Implements RFC 3550 RTP packet encoding/decoding for VoIP media transport.

use std::io;

/// RTP protocol version (always 2).
pub const RTP_VERSION: u8 = 2;

/// Common RTP payload types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum PayloadType {
    /// PCMU (G.711 μ-law) - 8kHz
    Pcmu = 0,
    /// PCMA (G.711 A-law) - 8kHz
    Pcma = 8,
    /// G.722 - 8kHz (actually 16kHz wideband)
    G722 = 9,
    /// Comfort Noise
    Cn = 13,
    /// Dynamic payload type for Opus (typically 111)
    DynamicOpus = 111,
    /// WhatsApp Opus payload type (120)
    WhatsAppOpus = 120,
}

impl TryFrom<u8> for PayloadType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Pcmu),
            8 => Ok(Self::Pcma),
            9 => Ok(Self::G722),
            13 => Ok(Self::Cn),
            111 => Ok(Self::DynamicOpus),
            120 => Ok(Self::WhatsAppOpus),
            _ => Err(value),
        }
    }
}

/// RTP packet header.
#[derive(Debug, Clone)]
pub struct RtpHeader {
    /// RTP version (always 2).
    pub version: u8,
    /// Padding flag.
    pub padding: bool,
    /// Extension flag.
    pub extension: bool,
    /// CSRC count.
    pub csrc_count: u8,
    /// Marker bit.
    pub marker: bool,
    /// Payload type.
    pub payload_type: u8,
    /// Sequence number.
    pub sequence_number: u16,
    /// Timestamp.
    pub timestamp: u32,
    /// Synchronization source identifier.
    pub ssrc: u32,
    /// Contributing source identifiers.
    pub csrc: Vec<u32>,
}

impl RtpHeader {
    /// Create a new RTP header.
    pub fn new(payload_type: u8, sequence_number: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            version: RTP_VERSION,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc: Vec::new(),
        }
    }

    /// Set the marker bit.
    pub fn with_marker(mut self, marker: bool) -> Self {
        self.marker = marker;
        self
    }

    /// Set the extension flag.
    pub fn with_extension(mut self, extension: bool) -> Self {
        self.extension = extension;
        self
    }

    /// Header size in bytes (12 + 4*csrc_count).
    pub fn size(&self) -> usize {
        12 + (self.csrc_count as usize) * 4
    }

    /// Encode header to bytes.
    pub fn encode(&self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if buf.len() < self.size() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "buffer too small for RTP header",
            ));
        }

        // Byte 0: V(2) P(1) X(1) CC(4)
        buf[0] = (self.version << 6)
            | ((self.padding as u8) << 5)
            | ((self.extension as u8) << 4)
            | (self.csrc_count & 0x0F);

        // Byte 1: M(1) PT(7)
        buf[1] = ((self.marker as u8) << 7) | (self.payload_type & 0x7F);

        // Bytes 2-3: Sequence number (big-endian)
        buf[2..4].copy_from_slice(&self.sequence_number.to_be_bytes());

        // Bytes 4-7: Timestamp (big-endian)
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());

        // Bytes 8-11: SSRC (big-endian)
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());

        // CSRC list
        for (i, csrc) in self.csrc.iter().enumerate() {
            let offset = 12 + i * 4;
            buf[offset..offset + 4].copy_from_slice(&csrc.to_be_bytes());
        }

        Ok(self.size())
    }

    /// Decode header from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, io::Error> {
        if buf.len() < 12 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for RTP header",
            ));
        }

        let version = (buf[0] >> 6) & 0x03;
        if version != RTP_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid RTP version: {}", version),
            ));
        }

        let padding = (buf[0] >> 5) & 0x01 != 0;
        let extension = (buf[0] >> 4) & 0x01 != 0;
        let csrc_count = buf[0] & 0x0F;

        let marker = (buf[1] >> 7) & 0x01 != 0;
        let payload_type = buf[1] & 0x7F;

        let sequence_number = u16::from_be_bytes([buf[2], buf[3]]);
        let timestamp = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let ssrc = u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]);

        let header_size = 12 + (csrc_count as usize) * 4;
        if buf.len() < header_size {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "buffer too small for CSRC list",
            ));
        }

        let mut csrc = Vec::with_capacity(csrc_count as usize);
        for i in 0..csrc_count as usize {
            let offset = 12 + i * 4;
            csrc.push(u32::from_be_bytes([
                buf[offset],
                buf[offset + 1],
                buf[offset + 2],
                buf[offset + 3],
            ]));
        }

        Ok(Self {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc,
        })
    }
}

/// Complete RTP packet (header + payload).
#[derive(Debug, Clone)]
pub struct RtpPacket {
    /// RTP header.
    pub header: RtpHeader,
    /// Payload data.
    pub payload: Vec<u8>,
}

impl RtpPacket {
    /// Create a new RTP packet.
    pub fn new(header: RtpHeader, payload: Vec<u8>) -> Self {
        Self { header, payload }
    }

    /// Total packet size.
    pub fn size(&self) -> usize {
        self.header.size() + self.payload.len()
    }

    /// Encode packet to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; self.size()];
        let header_size = self.header.encode(&mut buf).unwrap();
        buf[header_size..].copy_from_slice(&self.payload);
        buf
    }

    /// Decode packet from bytes.
    pub fn decode(buf: &[u8]) -> Result<Self, io::Error> {
        let header = RtpHeader::decode(buf)?;
        let payload = buf[header.size()..].to_vec();
        Ok(Self { header, payload })
    }
}

/// RTP session state for sending/receiving.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RtpSession {
    ssrc: u32,
    payload_type: u8,
    sequence_number: u16,
    sample_rate: u32,
    timestamp: u32,
    samples_per_packet: u32,
}

impl RtpSession {
    /// Create a new RTP session.
    pub fn new(ssrc: u32, payload_type: u8, sample_rate: u32, samples_per_packet: u32) -> Self {
        Self {
            ssrc,
            payload_type,
            sequence_number: rand::random(),
            sample_rate,
            timestamp: rand::random(),
            samples_per_packet,
        }
    }

    /// Create an RTP session for Opus at 16kHz (WhatsApp voice).
    pub fn opus_16khz(ssrc: u32) -> Self {
        // Opus at 16kHz, 20ms packets = 320 samples
        Self::new(ssrc, PayloadType::DynamicOpus as u8, 16000, 320)
    }

    /// Create an RTP session for WhatsApp Web VoIP.
    ///
    /// Uses PT=120 and extension header like WhatsApp Web does.
    pub fn whatsapp_opus(ssrc: u32) -> Self {
        // WhatsApp uses PT=120, 16kHz, 20ms packets = 320 samples
        Self::new(ssrc, PayloadType::WhatsAppOpus as u8, 16000, 320)
    }

    /// Create the next RTP packet with the given payload.
    pub fn create_packet(&mut self, payload: Vec<u8>, marker: bool) -> RtpPacket {
        let header = RtpHeader::new(
            self.payload_type,
            self.sequence_number,
            self.timestamp,
            self.ssrc,
        )
        .with_marker(marker);

        // Advance sequence and timestamp
        self.sequence_number = self.sequence_number.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(self.samples_per_packet);

        RtpPacket::new(header, payload)
    }

    /// Get the current SSRC.
    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    /// Get the current sequence number.
    pub fn sequence_number(&self) -> u16 {
        self.sequence_number
    }

    /// Get the current timestamp.
    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_header_encode_decode() {
        let header = RtpHeader::new(111, 12345, 0xABCDEF00, 0x12345678);

        let mut buf = [0u8; 12];
        let size = header.encode(&mut buf).unwrap();
        assert_eq!(size, 12);

        let decoded = RtpHeader::decode(&buf).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.payload_type, 111);
        assert_eq!(decoded.sequence_number, 12345);
        assert_eq!(decoded.timestamp, 0xABCDEF00);
        assert_eq!(decoded.ssrc, 0x12345678);
    }

    #[test]
    fn test_rtp_header_marker_bit() {
        let header = RtpHeader::new(111, 0, 0, 0).with_marker(true);

        let mut buf = [0u8; 12];
        header.encode(&mut buf).unwrap();

        let decoded = RtpHeader::decode(&buf).unwrap();
        assert!(decoded.marker);
    }

    #[test]
    fn test_rtp_packet_roundtrip() {
        let header = RtpHeader::new(111, 1000, 160000, 0xDEADBEEF);
        let payload = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let packet = RtpPacket::new(header, payload.clone());

        let encoded = packet.encode();
        assert_eq!(encoded.len(), 12 + 8);

        let decoded = RtpPacket::decode(&encoded).unwrap();
        assert_eq!(decoded.header.sequence_number, 1000);
        assert_eq!(decoded.header.timestamp, 160000);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_rtp_session_creates_packets() {
        let mut session = RtpSession::opus_16khz(0x12345678);

        let packet1 = session.create_packet(vec![0; 20], false);
        let seq1 = packet1.header.sequence_number;
        let ts1 = packet1.header.timestamp;

        let packet2 = session.create_packet(vec![0; 20], false);
        let seq2 = packet2.header.sequence_number;
        let ts2 = packet2.header.timestamp;

        // Sequence number increments by 1
        assert_eq!(seq2, seq1.wrapping_add(1));

        // Timestamp increments by samples_per_packet (320 for 20ms at 16kHz)
        assert_eq!(ts2, ts1.wrapping_add(320));
    }

    #[test]
    fn test_rtp_header_invalid_version() {
        let mut buf = [0u8; 12];
        buf[0] = 0x00; // Version 0 instead of 2

        let result = RtpHeader::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_rtp_header_with_csrc() {
        let mut header = RtpHeader::new(111, 0, 0, 0);
        header.csrc_count = 2;
        header.csrc = vec![0x11111111, 0x22222222];

        let mut buf = [0u8; 20]; // 12 + 8 for 2 CSRCs
        let size = header.encode(&mut buf).unwrap();
        assert_eq!(size, 20);

        let decoded = RtpHeader::decode(&buf).unwrap();
        assert_eq!(decoded.csrc_count, 2);
        assert_eq!(decoded.csrc, vec![0x11111111, 0x22222222]);
    }
}
