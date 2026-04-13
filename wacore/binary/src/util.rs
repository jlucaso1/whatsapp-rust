use crate::error::{BinaryError, Result};
use bytes::{Buf, Bytes, BytesMut};
use flate2::read::ZlibDecoder;
use std::borrow::Cow;
use std::io::Read;

pub fn unpack(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    if data.is_empty() {
        return Err(BinaryError::EmptyData);
    }
    let data_type = data[0];
    let data = &data[1..];

    if (data_type & 2) > 0 {
        let mut decoder = ZlibDecoder::new(data);
        // Pre-allocate with estimated decompressed size (typically 4-8x compressed)
        // Min 256 bytes for small inputs, max 64KB to limit allocation for large inputs
        let estimated_size = (data.len() * 4).clamp(256, 64 * 1024);
        let mut decompressed = Vec::with_capacity(estimated_size);
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| BinaryError::Zlib(e.to_string()))?;
        Ok(Cow::Owned(decompressed))
    } else {
        Ok(Cow::Borrowed(data))
    }
}

/// Unpack a network payload into an owned buffer.
///
/// This is the hot-path variant used after frame decryption. For compressed
/// payloads we still allocate a decompression buffer, but for uncompressed
/// payloads we strip the leading format byte in place and reuse the existing
/// `Vec<u8>` allocation.
pub fn unpack_owned(mut data: Vec<u8>) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(BinaryError::EmptyData);
    }
    let data_type = data[0];

    if (data_type & 2) > 0 {
        let mut decoder = ZlibDecoder::new(&data[1..]);
        // Pre-allocate with estimated decompressed size (typically 4-8x compressed)
        // Min 256 bytes for small inputs, max 64KB to limit allocation for large inputs
        let estimated_size = ((data.len() - 1) * 4).clamp(256, 64 * 1024);
        let mut decompressed = Vec::with_capacity(estimated_size);
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| BinaryError::Zlib(e.to_string()))?;
        Ok(decompressed)
    } else {
        let unpacked_len = data.len() - 1;
        data.copy_within(1.., 0);
        data.truncate(unpacked_len);
        Ok(data)
    }
}

/// Unpack a network payload into an owned `Bytes` buffer.
///
/// This variant preserves ownership of the frame buffer across the receive
/// pipeline. Uncompressed payloads reuse the existing `BytesMut` allocation
/// and freeze it without copying. Compressed payloads still allocate a
/// decompression buffer, which is then wrapped as `Bytes`.
pub fn unpack_bytes(mut data: BytesMut) -> Result<Bytes> {
    if data.is_empty() {
        return Err(BinaryError::EmptyData);
    }
    let data_type = data[0];

    if (data_type & 2) > 0 {
        let mut decoder = ZlibDecoder::new(&data[1..]);
        let estimated_size = ((data.len() - 1) * 4).clamp(256, 64 * 1024);
        let mut decompressed = Vec::with_capacity(estimated_size);
        decoder
            .read_to_end(&mut decompressed)
            .map_err(|e| BinaryError::Zlib(e.to_string()))?;
        Ok(Bytes::from(decompressed))
    } else {
        data.advance(1);
        Ok(data.freeze())
    }
}
