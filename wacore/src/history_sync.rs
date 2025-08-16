use core::future::Future;
use flate2::read::ZlibDecoder;
use prost::Message;
use prost::encoding::{decode_key, decode_varint};
use std::io::{Cursor, Read};
use thiserror::Error;
use waproto::whatsapp as wa;

#[derive(Debug, Error)]
pub enum HistorySyncError {
    #[error("Failed to decompress history sync data: {0}")]
    DecompressionError(#[from] std::io::Error),
    #[error("Failed to decode HistorySync protobuf: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
}

/// Original convenience API: decode the whole HistorySync message into memory.
/// Keep for backwards compatibility but prefer `process_history_sync_stream`.
pub fn process_history_sync_blob(
    compressed_data: &[u8],
) -> Result<wa::HistorySync, HistorySyncError> {
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut uncompressed = Vec::new();
    decoder.read_to_end(&mut uncompressed)?;

    let history_sync = wa::HistorySync::decode(uncompressed.as_slice())?;

    Ok(history_sync)
}

/// Stream-parse a HistorySync blob and invoke `conversation_handler` for each
/// `wa::Conversation` found. This avoids allocating the full `wa::HistorySync`
/// with a large `Vec<Conversation>`.
pub async fn process_history_sync_stream<FConv, FConvFut, FPn, FPnFut>(
    compressed_data: &[u8],
    mut conversation_handler: FConv,
    mut pushname_handler: FPn,
) -> Result<(), HistorySyncError>
where
    FConv: FnMut(wa::Conversation) -> FConvFut,
    FConvFut: Future<Output = ()>,
    FPn: FnMut(wa::Pushname) -> FPnFut,
    FPnFut: Future<Output = ()>,
{
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut uncompressed = Vec::new();
    decoder.read_to_end(&mut uncompressed)?;

    let mut cursor = Cursor::new(uncompressed.as_slice());
    let total_len = uncompressed.len();

    while (cursor.position() as usize) < total_len {
        // Read key (field number + wire type)
        let (field_number, wire_type) =
            decode_key(&mut cursor).map_err(HistorySyncError::ProtobufDecodeError)?;

        match field_number {
            // field 1 = sync_type (varint)
            1 => {
                // consume varint
                let _ =
                    decode_varint(&mut cursor).map_err(HistorySyncError::ProtobufDecodeError)?;
            }
            // field 2 = conversations (length-delimited, repeated)
            2 => {
                let len = decode_varint(&mut cursor)
                    .map_err(HistorySyncError::ProtobufDecodeError)?
                    as usize;
                let pos = cursor.position() as usize;

                // bounds check
                if pos + len > total_len {
                    return Err(HistorySyncError::ProtobufDecodeError(
                        prost::DecodeError::new("message length out of bounds"),
                    ));
                }

                // Decode just this single Conversation from the slice
                let conv_slice = &uncompressed[pos..pos + len];
                match wa::Conversation::decode(conv_slice) {
                    Ok(conv) => conversation_handler(conv).await,
                    Err(e) => return Err(HistorySyncError::ProtobufDecodeError(e)),
                }

                // advance cursor
                cursor.set_position((pos + len) as u64);
            }
            // field 7 = pushnames (length-delimited, repeated)
            7 => {
                let len = decode_varint(&mut cursor).map_err(HistorySyncError::ProtobufDecodeError)? as usize;
                let pos = cursor.position() as usize;
                if pos + len > total_len {
                    return Err(HistorySyncError::ProtobufDecodeError(prost::DecodeError::new("pushname length out of bounds")));
                }
                let slice = &uncompressed[pos..pos + len];
                match wa::Pushname::decode(slice) {
                    Ok(pn) => pushname_handler(pn).await,
                    Err(e) => return Err(HistorySyncError::ProtobufDecodeError(e)),
                }
                cursor.set_position((pos + len) as u64);
            }
            // unknown/other fields: skip based on wire type
            _ => {
                match wire_type {
                    prost::encoding::WireType::Varint => {
                        let _ = decode_varint(&mut cursor)
                            .map_err(HistorySyncError::ProtobufDecodeError)?;
                    }
                    prost::encoding::WireType::LengthDelimited => {
                        let l = decode_varint(&mut cursor)
                            .map_err(HistorySyncError::ProtobufDecodeError)?
                            as usize;
                        let pos = cursor.position() as usize;
                        if pos + l > total_len {
                            return Err(HistorySyncError::ProtobufDecodeError(
                                prost::DecodeError::new("length-delimited skip out of bounds"),
                            ));
                        }
                        cursor.set_position((pos + l) as u64);
                    }
                    prost::encoding::WireType::ThirtyTwoBit => {
                        // 4 bytes
                        let pos = cursor.position() as usize;
                        cursor.set_position((pos + 4) as u64);
                    }
                    prost::encoding::WireType::SixtyFourBit => {
                        // 8 bytes
                        let pos = cursor.position() as usize;
                        cursor.set_position((pos + 8) as u64);
                    }
                    _ => {
                        return Err(HistorySyncError::ProtobufDecodeError(
                            prost::DecodeError::new("unsupported wire type"),
                        ));
                    }
                }
            }
        }
    }

    Ok(())
}
