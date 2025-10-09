/// WhatsApp protocol framing logic
///
/// This module handles the encoding and decoding of WhatsApp frames.
/// Each frame consists of a 3-byte big-endian length prefix followed by the payload.

use bytes::{Buf, Bytes, BytesMut};
use log::trace;

pub const FRAME_LENGTH_SIZE: usize = 3;
pub const FRAME_MAX_SIZE: usize = 2 << 23;

/// Encodes a payload into a WhatsApp frame with length prefix.
/// Optionally prepends a header (used for the initial connection frame).
pub fn encode_frame(payload: &[u8], header: Option<&[u8]>) -> Result<Vec<u8>, anyhow::Error> {
    let payload_len = payload.len();
    
    if payload_len >= FRAME_MAX_SIZE {
        return Err(anyhow::anyhow!(
            "Frame is too large (max: {}, got: {})",
            FRAME_MAX_SIZE,
            payload_len
        ));
    }

    let header_len = header.map(|h| h.len()).unwrap_or(0);
    let prefix_len = header_len + FRAME_LENGTH_SIZE;
    
    let mut data = Vec::with_capacity(prefix_len + payload_len);
    data.resize(prefix_len, 0);
    data.extend_from_slice(payload);

    // Write header if provided
    if let Some(header_data) = header {
        data[0..header_len].copy_from_slice(header_data);
    }

    // Write 3-byte big-endian length
    let len_bytes = u32::to_be_bytes(payload_len as u32);
    data[header_len..prefix_len].copy_from_slice(&len_bytes[1..]);

    Ok(data)
}

/// A frame decoder that buffers incoming data and extracts complete frames.
pub struct FrameDecoder {
    buffer: BytesMut,
}

impl FrameDecoder {
    pub fn new() -> Self {
        Self {
            buffer: BytesMut::new(),
        }
    }

    /// Feeds raw data into the decoder.
    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    /// Attempts to decode the next complete frame from the buffer.
    /// Returns Some(frame_payload) if a complete frame is available, None otherwise.
    pub fn decode_frame(&mut self) -> Option<Bytes> {
        if self.buffer.len() < FRAME_LENGTH_SIZE {
            return None;
        }

        // Read 3-byte big-endian length
        let frame_len = ((self.buffer[0] as usize) << 16)
            | ((self.buffer[1] as usize) << 8)
            | (self.buffer[2] as usize);

        if self.buffer.len() >= FRAME_LENGTH_SIZE + frame_len {
            self.buffer.advance(FRAME_LENGTH_SIZE);
            let frame_data = self.buffer.split_to(frame_len).freeze();
            trace!("<-- Decoded frame: {} bytes", frame_data.len());
            Some(frame_data)
        } else {
            None
        }
    }
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_frame_no_header() {
        let payload = vec![1, 2, 3, 4, 5];
        let encoded = encode_frame(&payload, None).unwrap();
        
        // Check length prefix (3 bytes, big-endian)
        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 0);
        assert_eq!(encoded[2], 5);
        
        // Check payload
        assert_eq!(&encoded[3..], &payload[..]);
    }

    #[test]
    fn test_encode_frame_with_header() {
        let payload = vec![1, 2, 3];
        let header = vec![0xAA, 0xBB];
        let encoded = encode_frame(&payload, Some(&header)).unwrap();
        
        // Check header
        assert_eq!(&encoded[0..2], &header[..]);
        
        // Check length prefix
        assert_eq!(encoded[2], 0);
        assert_eq!(encoded[3], 0);
        assert_eq!(encoded[4], 3);
        
        // Check payload
        assert_eq!(&encoded[5..], &payload[..]);
    }

    #[test]
    fn test_frame_decoder() {
        let mut decoder = FrameDecoder::new();
        
        // Feed incomplete frame
        decoder.feed(&[0, 0, 5, 1, 2]);
        assert!(decoder.decode_frame().is_none());
        
        // Feed rest of frame
        decoder.feed(&[3, 4, 5]);
        let frame = decoder.decode_frame().unwrap();
        assert_eq!(&frame[..], &[1, 2, 3, 4, 5]);
        
        // No more frames
        assert!(decoder.decode_frame().is_none());
    }

    #[test]
    fn test_frame_decoder_multiple_frames() {
        let mut decoder = FrameDecoder::new();
        
        // Feed two complete frames at once
        decoder.feed(&[0, 0, 2, 0xAA, 0xBB, 0, 0, 3, 0xCC, 0xDD, 0xEE]);
        
        let frame1 = decoder.decode_frame().unwrap();
        assert_eq!(&frame1[..], &[0xAA, 0xBB]);
        
        let frame2 = decoder.decode_frame().unwrap();
        assert_eq!(&frame2[..], &[0xCC, 0xDD, 0xEE]);
        
        assert!(decoder.decode_frame().is_none());
    }

    #[test]
    fn test_encode_frame_too_large() {
        let large_payload = vec![0u8; FRAME_MAX_SIZE];
        let result = encode_frame(&large_payload, None);
        assert!(result.is_err());
    }
}
