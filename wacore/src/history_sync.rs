use bytes::{Buf, BytesMut};
use core::future::Future;
use flate2::read::ZlibDecoder;
use prost::Message;
use prost::encoding::{WireType, decode_key, decode_varint};
use std::io::{BufReader, Read};
use thiserror::Error;
use waproto::whatsapp as wa;

#[derive(Debug, Error)]
pub enum HistorySyncError {
    #[error("Failed to decompress history sync data: {0}")]
    DecompressionError(#[from] std::io::Error),
    #[error("Failed to decode HistorySync protobuf: {0}")]
    ProtobufDecodeError(#[from] prost::DecodeError),
}

/// Processes a streaming, compressed history sync blob without buffering the entire decompressed
/// data into memory. Instead, it reads the decompressed stream in chunks and parses Protobuf
/// messages as they become available.
///
/// This function accepts any `Read` source (e.g., an HTTP response stream or file handle),
/// decompresses it on-the-fly, and parses messages incrementally.
pub async fn process_history_sync_stream<R, FConv, FConvFut, FPn, FPnFut>(
    compressed_reader: R,
    mut conversation_handler: FConv,
    mut pushname_handler: FPn,
) -> Result<(), HistorySyncError>
where
    R: Read,
    FConv: FnMut(wa::Conversation) -> FConvFut,
    FConvFut: Future<Output = ()>,
    FPn: FnMut(wa::Pushname) -> FPnFut,
    FPnFut: Future<Output = ()>,
{
    // Wrap the compressed reader in a decompressor
    let decoder = ZlibDecoder::new(compressed_reader);
    let mut reader = BufReader::new(decoder);

    // Use BytesMut as our buffer for efficient slicing and management
    let mut buffer = BytesMut::with_capacity(8192); // 8KB initial capacity
    let mut temp_read_buf = [0u8; 4096]; // Temporary buffer for reading from the stream

    loop {
        // Try to read more data from the decompressed stream
        let bytes_read = reader.read(&mut temp_read_buf)?;
        if bytes_read > 0 {
            buffer.extend_from_slice(&temp_read_buf[..bytes_read]);
        }

        // Process as many complete messages as possible from the buffer
        loop {
            if buffer.is_empty() {
                break; // Need more data from the stream
            }

            // Create a temporary slice to peek at the next message without consuming it yet
            let mut peek_buf = &buffer[..];
            let original_len = peek_buf.len();

            // Try to decode the field key (field number + wire type)
            let (field_number, wire_type) = match decode_key(&mut peek_buf) {
                Ok(key) => key,
                Err(_) if bytes_read == 0 => return Ok(()), // Clean end of stream
                Err(_) => break,                            // Incomplete key; need more data
            };

            // Handle the field based on its wire type
            match wire_type {
                WireType::Varint => {
                    // Varint field (like sync_type which is field 1)
                    match decode_varint(&mut peek_buf) {
                        Ok(_) => {
                            // Successfully decoded, advance buffer
                            let consumed = original_len - peek_buf.len();
                            buffer.advance(consumed);
                        }
                        Err(_) => break, // Not enough data for varint
                    }
                }
                WireType::LengthDelimited => {
                    // Length-delimited field (like Conversation and Pushname)
                    let len = match decode_varint(&mut peek_buf) {
                        Ok(len) => len as usize,
                        Err(_) => break, // Incomplete length; need more data
                    };

                    // Calculate the header size (field key + varint length)
                    let header_len = original_len - peek_buf.len();

                    // Check if we have the complete message
                    if peek_buf.len() < len {
                        break; // Not enough data for the full message body
                    }

                    // We have a complete message; consume it from the buffer
                    buffer.advance(header_len);
                    let msg_bytes = buffer.split_to(len);

                    // Parse and handle the message based on field number
                    match field_number {
                        2 => {
                            // Field 2 is a Conversation message
                            match wa::Conversation::decode(&msg_bytes[..]) {
                                Ok(conv) => conversation_handler(conv).await,
                                Err(e) => return Err(HistorySyncError::ProtobufDecodeError(e)),
                            }
                        }
                        7 => {
                            // Field 7 is a Pushname message
                            match wa::Pushname::decode(&msg_bytes[..]) {
                                Ok(pn) => pushname_handler(pn).await,
                                Err(e) => return Err(HistorySyncError::ProtobufDecodeError(e)),
                            }
                        }
                        _ => {
                            // Unknown field; already skipped by splitting buffer
                        }
                    }
                }
                WireType::ThirtyTwoBit => {
                    // Fixed 32-bit field
                    if peek_buf.len() < 4 {
                        break; // Not enough data
                    }
                    let consumed = original_len - (peek_buf.len() - 4);
                    buffer.advance(consumed);
                }
                WireType::SixtyFourBit => {
                    // Fixed 64-bit field
                    if peek_buf.len() < 8 {
                        break; // Not enough data
                    }
                    let consumed = original_len - (peek_buf.len() - 8);
                    buffer.advance(consumed);
                }
                WireType::StartGroup | WireType::EndGroup => {
                    // Groups are deprecated in proto3 and rarely used.
                    // In proto2, groups need recursive parsing which we don't support here.
                    // For now, we'll treat them as unknown fields and skip.
                    // This shouldn't occur in WhatsApp's protocol.
                    return Err(HistorySyncError::ProtobufDecodeError(
                        prost::DecodeError::new("Unsupported wire type: Group"),
                    ));
                }
            }
        }

        // If we couldn't read any more data and the buffer is empty or incomplete, we're done
        if bytes_read == 0 {
            break;
        }
    }

    Ok(())
}
