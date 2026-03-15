use bytes::Bytes;
use flate2::read::ZlibDecoder;
use prost::Message;
use std::io::Read;
use thiserror::Error;
use waproto::whatsapp as wa;

#[derive(Debug, Error)]
pub enum HistorySyncError {
    #[error("Failed to decompress history sync data: {0}")]
    DecompressionError(#[from] std::io::Error),
    #[error("Failed to decode HistorySync protobuf: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("Malformed protobuf: {0}")]
    MalformedProtobuf(String),
}

#[derive(Debug, Default)]
pub struct HistorySyncResult {
    pub own_pushname: Option<String>,

    pub conversations_processed: usize,
}

mod wire_type {
    pub const VARINT: u32 = 0;
    pub const FIXED64: u32 = 1;
    pub const LENGTH_DELIMITED: u32 = 2;
    pub const FIXED32: u32 = 5;
}

/// Decompress and process a history sync blob.
///
/// **Memory strategy**: Decompresses the entire blob into a single `Bytes` buffer,
/// then extracts conversation fields as zero-copy `Bytes::slice()` sub-views.
/// This trades a slightly higher peak (full decompressed blob in memory) for
/// **zero per-conversation heap allocations** — each conversation is just an
/// Arc refcount increment on the shared buffer.
///
/// After decompression, the compressed input is dropped immediately, so peak
/// memory = max(compressed, decompressed) + small overhead, not both.
pub fn process_history_sync<F>(
    compressed_data: Vec<u8>,
    own_user: Option<&str>,
    mut on_conversation_bytes: Option<F>,
) -> Result<HistorySyncResult, HistorySyncError>
where
    F: FnMut(Bytes),
{
    // Decompress into a single contiguous buffer.
    // Pre-allocate with estimated 4x ratio, clamped to reasonable bounds.
    let estimated = (compressed_data.len() * 4).clamp(256, 8 * 1024 * 1024);
    let mut decompressed = Vec::with_capacity(estimated);
    {
        let mut decoder = ZlibDecoder::new(compressed_data.as_slice());
        decoder.read_to_end(&mut decompressed)?;
    }
    // Drop compressed data immediately — no longer needed.
    drop(compressed_data);

    // Wrap in Bytes so we can hand out zero-copy slices.
    let buf = Bytes::from(decompressed);
    let mut pos = 0;
    let mut result = HistorySyncResult::default();

    while pos < buf.len() {
        let (tag, bytes_read) = read_varint(&buf[pos..])?;
        pos += bytes_read;

        let field_number = (tag >> 3) as u32;
        let wire_type_raw = (tag & 0x7) as u32;

        match field_number {
            // field 2 = conversations (repeated, length-delimited)
            2 if wire_type_raw == wire_type::LENGTH_DELIMITED => {
                let (len, vlen) = read_varint(&buf[pos..])?;
                pos += vlen;
                let len = len as usize;

                if pos + len > buf.len() {
                    return Err(HistorySyncError::MalformedProtobuf(format!(
                        "conversation field overflows buffer: pos={pos}, len={len}, buf={}",
                        buf.len()
                    )));
                }

                if let Some(ref mut callback) = on_conversation_bytes {
                    // Zero-copy slice — just an Arc refcount increment.
                    callback(buf.slice(pos..pos + len));
                    result.conversations_processed += 1;
                }
                pos += len;
            }

            // field 7 = pushnames (repeated, length-delimited)
            7 if own_user.is_some()
                && result.own_pushname.is_none()
                && wire_type_raw == wire_type::LENGTH_DELIMITED =>
            {
                let (len, vlen) = read_varint(&buf[pos..])?;
                pos += vlen;
                let len = len as usize;

                if pos + len > buf.len() {
                    return Err(HistorySyncError::MalformedProtobuf(format!(
                        "pushname field overflows buffer: pos={pos}, len={len}, buf={}",
                        buf.len()
                    )));
                }

                if let Ok(pn) = wa::Pushname::decode(&buf[pos..pos + len])
                    && let Some(ref id) = pn.id
                    && Some(id.as_str()) == own_user
                    && let Some(name) = pn.pushname
                {
                    result.own_pushname = Some(name);
                }
                pos += len;
            }

            _ => {
                pos = skip_field(wire_type_raw, &buf, pos)?;
            }
        }
    }

    Ok(result)
}

/// Read a protobuf varint from `data`, returning (value, bytes_consumed).
#[inline]
fn read_varint(data: &[u8]) -> Result<(u64, usize), HistorySyncError> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
        if shift >= 64 {
            return Err(HistorySyncError::MalformedProtobuf(
                "varint too long".into(),
            ));
        }
    }
    Err(HistorySyncError::MalformedProtobuf(
        "unexpected end of data in varint".into(),
    ))
}

/// Skip a protobuf field based on wire type, returning the new position.
#[inline]
fn skip_field(wire_type: u32, buf: &[u8], pos: usize) -> Result<usize, HistorySyncError> {
    match wire_type {
        wire_type::VARINT => {
            let (_, vlen) = read_varint(&buf[pos..])?;
            Ok(pos + vlen)
        }
        wire_type::FIXED64 => Ok(pos + 8),
        wire_type::LENGTH_DELIMITED => {
            let (len, vlen) = read_varint(&buf[pos..])?;
            Ok(pos + vlen + len as usize)
        }
        wire_type::FIXED32 => Ok(pos + 4),
        _ => {
            log::warn!("Unknown wire type {wire_type} in history sync, cannot skip");
            Err(HistorySyncError::MalformedProtobuf(format!(
                "unknown wire type {wire_type}"
            )))
        }
    }
}
