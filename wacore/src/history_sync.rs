use bytes::Bytes;
use flate2::read::ZlibDecoder;
use prost::Message;
use protobuf::CodedInputStream;
use std::io::BufReader;
use thiserror::Error;
use waproto::whatsapp as wa;

const STREAMING_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug, Error)]
pub enum HistorySyncError {
    #[error("Failed to decompress history sync data: {0}")]
    DecompressionError(#[from] std::io::Error),
    #[error("Failed to decode HistorySync protobuf: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
    #[error("Streaming protobuf error: {0}")]
    StreamingProtobufError(#[from] protobuf::Error),
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

pub fn process_history_sync<F>(
    compressed_data: &[u8],
    own_user: Option<&str>,
    mut on_conversation_bytes: Option<F>,
) -> Result<HistorySyncResult, HistorySyncError>
where
    F: FnMut(Bytes),
{
    let decoder = ZlibDecoder::new(compressed_data);
    let mut buf_reader = BufReader::with_capacity(STREAMING_BUFFER_SIZE, decoder);
    let mut cis = CodedInputStream::from_buf_read(&mut buf_reader);

    cis.set_recursion_limit(100);

    let mut result = HistorySyncResult::default();

    while let Some(tag) = cis.read_raw_tag_or_eof()? {
        let field_number = tag >> 3;
        let wire_type_raw = tag & 0x7;

        match field_number {
            2 if wire_type_raw == wire_type::LENGTH_DELIMITED => {
                if let Some(ref mut callback) = on_conversation_bytes {
                    let raw_bytes = Bytes::from(cis.read_bytes()?);
                    callback(raw_bytes);
                    result.conversations_processed += 1;
                } else {
                    let len = cis.read_raw_varint32()?;
                    cis.skip_raw_bytes(len)?;
                }
            }

            7 if own_user.is_some()
                && result.own_pushname.is_none()
                && wire_type_raw == wire_type::LENGTH_DELIMITED =>
            {
                let raw_bytes = cis.read_bytes()?;

                if let Ok(pn) = wa::Pushname::decode(raw_bytes.as_slice())
                    && let Some(ref id) = pn.id
                    && Some(id.as_str()) == own_user
                    && let Some(name) = pn.pushname
                {
                    result.own_pushname = Some(name);
                }
            }

            _ => {
                skip_field_by_wire_type(&mut cis, wire_type_raw)?;
            }
        }
    }

    Ok(result)
}

fn skip_field_by_wire_type(
    cis: &mut CodedInputStream<'_>,
    wire_type: u32,
) -> Result<(), HistorySyncError> {
    match wire_type {
        wire_type::VARINT => {
            cis.read_raw_varint64()?;
        }
        wire_type::FIXED64 => {
            cis.read_raw_little_endian64()?;
        }
        wire_type::LENGTH_DELIMITED => {
            let len = cis.read_raw_varint32()?;
            cis.skip_raw_bytes(len)?;
        }
        wire_type::FIXED32 => {
            cis.read_raw_little_endian32()?;
        }
        _ => {
            log::warn!("Unknown wire type {wire_type} in history sync, skipping");
        }
    }
    Ok(())
}
