use crate::error::{BinaryError, Result};
use bytes::{Buf, Bytes, BytesMut};
use flate2::read::ZlibDecoder;
use std::borrow::Cow;
use std::io::Read;

/// Protocol frames larger than 16 MiB after decompression are rejected.
/// WhatsApp messages are typically small; this guards against malicious
/// or corrupt compressed payloads that would expand into huge allocations.
const MAX_DECOMPRESSED_SIZE: u64 = 16 * 1024 * 1024;

fn decompress_zlib(compressed: &[u8]) -> Result<Vec<u8>> {
    let estimated = (compressed.len() * 4).clamp(256, 64 * 1024);
    let mut out = Vec::with_capacity(estimated);
    ZlibDecoder::new(compressed)
        .take(MAX_DECOMPRESSED_SIZE)
        .read_to_end(&mut out)
        .map_err(|e| BinaryError::Zlib(e.to_string()))?;
    Ok(out)
}

pub fn unpack(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    if data.is_empty() {
        return Err(BinaryError::EmptyData);
    }
    let data_type = data[0];
    let data = &data[1..];

    if (data_type & 2) > 0 {
        Ok(Cow::Owned(decompress_zlib(data)?))
    } else {
        Ok(Cow::Borrowed(data))
    }
}

/// Unpack a network payload into an owned `Bytes` buffer.
///
/// Uncompressed payloads reuse the existing `BytesMut` allocation
/// and freeze it without copying. Compressed payloads allocate a
/// decompression buffer which is then wrapped as `Bytes`.
pub fn unpack_bytes(mut data: BytesMut) -> Result<Bytes> {
    if data.is_empty() {
        return Err(BinaryError::EmptyData);
    }
    let data_type = data[0];

    if (data_type & 2) > 0 {
        Ok(Bytes::from(decompress_zlib(&data[1..])?))
    } else {
        data.advance(1);
        Ok(data.freeze())
    }
}
