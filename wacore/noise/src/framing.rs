use bytes::{Buf, Bytes, BytesMut};
use log::trace;

pub const FRAME_LENGTH_SIZE: usize = 3;
pub const FRAME_MAX_SIZE: usize = 2 << 23;

/// Encodes a payload into a WhatsApp frame, writing directly into `out`.
/// The `out` buffer is cleared before use, allowing buffer reuse.
pub fn encode_frame_into(
    payload: &[u8],
    header: Option<&[u8]>,
    out: &mut Vec<u8>,
) -> Result<(), anyhow::Error> {
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
    let total_len = prefix_len + payload_len;

    out.clear();
    out.reserve(total_len);

    if let Some(header_data) = header {
        out.extend_from_slice(header_data);
    }

    let len_bytes = u32::to_be_bytes(payload_len as u32);
    out.extend_from_slice(&len_bytes[1..]);
    out.extend_from_slice(payload);

    Ok(())
}

/// Encodes a payload into a WhatsApp frame with length prefix.
/// For performance-critical paths, prefer `encode_frame_into`.
pub fn encode_frame(payload: &[u8], header: Option<&[u8]>) -> Result<Vec<u8>, anyhow::Error> {
    let header_len = header.map(|h| h.len()).unwrap_or(0);
    let prefix_len = header_len + FRAME_LENGTH_SIZE;
    let mut data = Vec::with_capacity(prefix_len + payload.len());
    encode_frame_into(payload, header, &mut data)?;
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

    pub fn feed(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn decode_frame(&mut self) -> Option<Bytes> {
        if self.buffer.len() < FRAME_LENGTH_SIZE {
            return None;
        }

        let frame_len = ((self.buffer[0] as usize) << 16)
            | ((self.buffer[1] as usize) << 8)
            | (self.buffer[2] as usize);

        if frame_len > FRAME_MAX_SIZE {
            trace!(
                "Frame length {} exceeds maximum size {}, dropping invalid frame",
                frame_len, FRAME_MAX_SIZE
            );
            self.buffer.advance(FRAME_LENGTH_SIZE);
            return None;
        }

        if self.buffer.len() >= FRAME_LENGTH_SIZE + frame_len {
            self.buffer.advance(FRAME_LENGTH_SIZE);
            let frame_data = self.buffer.split_to(frame_len).freeze();
            trace!("<-- Decoded frame: {} bytes", frame_data.len());
            Some(frame_data)
        } else {
            None
        }
    }

    /// Returns the number of bytes currently buffered waiting for more data.
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// Clears the internal buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
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
        let encoded = encode_frame(&payload, None).expect("frame operation should succeed");

        assert_eq!(encoded[0], 0);
        assert_eq!(encoded[1], 0);
        assert_eq!(encoded[2], 5);
        assert_eq!(&encoded[3..], &payload[..]);
    }

    #[test]
    fn test_encode_frame_with_header() {
        let payload = vec![1, 2, 3];
        let header = vec![0xAA, 0xBB];
        let encoded =
            encode_frame(&payload, Some(&header)).expect("frame operation should succeed");

        assert_eq!(&encoded[0..2], &header[..]);
        assert_eq!(encoded[2], 0);
        assert_eq!(encoded[3], 0);
        assert_eq!(encoded[4], 3);
        assert_eq!(&encoded[5..], &payload[..]);
    }

    #[test]
    fn test_frame_decoder() {
        let mut decoder = FrameDecoder::new();

        decoder.feed(&[0, 0, 5, 1, 2]);
        assert!(decoder.decode_frame().is_none());

        decoder.feed(&[3, 4, 5]);
        let frame = decoder
            .decode_frame()
            .expect("frame operation should succeed");
        assert_eq!(&frame[..], &[1, 2, 3, 4, 5]);

        assert!(decoder.decode_frame().is_none());
    }

    #[test]
    fn test_frame_decoder_multiple_frames() {
        let mut decoder = FrameDecoder::new();

        decoder.feed(&[0, 0, 2, 0xAA, 0xBB, 0, 0, 3, 0xCC, 0xDD, 0xEE]);

        let frame1 = decoder
            .decode_frame()
            .expect("frame operation should succeed");
        assert_eq!(&frame1[..], &[0xAA, 0xBB]);

        let frame2 = decoder
            .decode_frame()
            .expect("frame operation should succeed");
        assert_eq!(&frame2[..], &[0xCC, 0xDD, 0xEE]);

        assert!(decoder.decode_frame().is_none());
    }

    #[test]
    fn test_encode_frame_too_large() {
        let large_payload = vec![0u8; FRAME_MAX_SIZE];
        let result = encode_frame(&large_payload, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_encode_frame_into_reuses_buffer() {
        let mut buffer = Vec::with_capacity(100);
        let original_ptr = buffer.as_ptr();

        let payload1 = vec![1, 2, 3, 4, 5];
        encode_frame_into(&payload1, None, &mut buffer).expect("frame operation should succeed");
        assert_eq!(&buffer[3..], &payload1[..]);

        let payload2 = vec![6, 7, 8];
        encode_frame_into(&payload2, None, &mut buffer).expect("frame operation should succeed");
        assert_eq!(&buffer[3..], &payload2[..]);

        assert_eq!(buffer.as_ptr(), original_ptr);
    }

    #[test]
    fn test_encode_frame_into_with_header() {
        let mut buffer = Vec::new();
        let payload = vec![1, 2, 3];
        let header = vec![0xAA, 0xBB];
        encode_frame_into(&payload, Some(&header), &mut buffer)
            .expect("frame operation should succeed");

        assert_eq!(&buffer[0..2], &header[..]);
        assert_eq!(buffer[2], 0);
        assert_eq!(buffer[3], 0);
        assert_eq!(buffer[4], 3);
        assert_eq!(&buffer[5..], &payload[..]);
    }
}
