use core::future::Future;
use flate2::read::ZlibDecoder;
use prost::Message;
use prost::encoding::{decode_key, decode_varint};
use std::io::Read;
use thiserror::Error;
use waproto::whatsapp as wa;

#[derive(Debug, Error)]
pub enum HistorySyncError {
    #[error("Failed to decompress history sync data: {0}")]
    DecompressionError(#[from] std::io::Error),
    #[error("Failed to decode HistorySync protobuf: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
}
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

    let mut buf: &[u8] = uncompressed.as_slice();
    let total_len = buf.len();

    while !buf.is_empty() {
        let (field_number, wire_type) =
            decode_key(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?;

        match field_number {
            1 => {
                let _ = decode_varint(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?;
            }
            2 => {
                let len = decode_varint(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?
                    as usize;
                let pos = total_len - buf.len();

                if pos + len > total_len {
                    return Err(HistorySyncError::ProtobufDecodeError(
                        prost::DecodeError::new("message length out of bounds"),
                    ));
                }

                let conv_slice = &uncompressed[pos..pos + len];
                match wa::Conversation::decode(conv_slice) {
                    Ok(conv) => conversation_handler(conv).await,
                    Err(e) => return Err(HistorySyncError::ProtobufDecodeError(e)),
                }

                // advance the buf by len bytes
                buf = &buf[len..];
            }
            7 => {
                let len = decode_varint(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?
                    as usize;
                let pos = total_len - buf.len();
                if pos + len > total_len {
                    return Err(HistorySyncError::ProtobufDecodeError(
                        prost::DecodeError::new("pushname length out of bounds"),
                    ));
                }
                let slice = &uncompressed[pos..pos + len];
                match wa::Pushname::decode(slice) {
                    Ok(pn) => pushname_handler(pn).await,
                    Err(e) => return Err(HistorySyncError::ProtobufDecodeError(e)),
                }
                buf = &buf[len..];
            }
            _ => match wire_type {
                prost::encoding::WireType::Varint => {
                    let _ =
                        decode_varint(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?;
                }
                prost::encoding::WireType::LengthDelimited => {
                    let l = decode_varint(&mut buf)
                        .map_err(HistorySyncError::ProtobufDecodeError)?
                        as usize;
                    let pos = total_len - buf.len();
                    if pos + l > total_len {
                        return Err(HistorySyncError::ProtobufDecodeError(
                            prost::DecodeError::new("length-delimited skip out of bounds"),
                        ));
                    }
                    buf = &buf[l..];
                }
                prost::encoding::WireType::ThirtyTwoBit => {
                    if buf.len() < 4 {
                        return Err(HistorySyncError::ProtobufDecodeError(
                            prost::DecodeError::new("insufficient bytes for 32-bit field"),
                        ));
                    }
                    buf = &buf[4..];
                }
                prost::encoding::WireType::SixtyFourBit => {
                    if buf.len() < 8 {
                        return Err(HistorySyncError::ProtobufDecodeError(
                            prost::DecodeError::new("insufficient bytes for 64-bit field"),
                        ));
                    }
                    buf = &buf[8..];
                }
                _ => {
                    return Err(HistorySyncError::ProtobufDecodeError(
                        prost::DecodeError::new("unsupported wire type"),
                    ));
                }
            },
        }
    }

    Ok(())
}
