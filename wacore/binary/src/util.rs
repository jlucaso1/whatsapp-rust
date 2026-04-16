use crate::error::{BinaryError, Result};
use crate::zlib_pool::decompress_zlib_pooled;
use bytes::{Buf, Bytes, BytesMut};
use std::borrow::Cow;

/// Protocol frames larger than 16 MiB after decompression are rejected.
const MAX_DECOMPRESSED_SIZE: u64 = 16 * 1024 * 1024;

fn decompress_zlib(compressed: &[u8]) -> Result<Vec<u8>> {
    decompress_zlib_pooled(compressed, MAX_DECOMPRESSED_SIZE)
        .map_err(|e| BinaryError::Zlib(e.to_string()))
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
