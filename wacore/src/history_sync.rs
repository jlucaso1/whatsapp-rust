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

/// Configuration for what to extract from history sync data.
/// By default, nothing is extracted to minimize memory usage.
/// Users can opt-in to receive specific data types.
pub struct HistorySyncOptions<'a, F> {
    /// If set, conversations will be parsed and passed to this callback.
    /// The callback receives each conversation one at a time for streaming processing.
    pub on_conversation: Option<F>,
    /// The user ID to match for extracting own pushname.
    /// If None, pushname extraction is skipped.
    pub own_user_for_pushname: Option<&'a str>,
}

impl<'a, F> Default for HistorySyncOptions<'a, F> {
    fn default() -> Self {
        Self {
            on_conversation: None,
            own_user_for_pushname: None,
        }
    }
}

/// Result of processing history sync data.
#[derive(Default)]
pub struct HistorySyncResult {
    /// The user's own pushname if found and requested.
    pub own_pushname: Option<String>,
    /// Number of conversations processed (only counted if callback was provided).
    pub conversations_processed: usize,
}

/// Process history sync data with configurable options.
///
/// This function allows users to opt-in to processing different data types.
/// By default, it does minimal work. Users can:
/// - Provide a callback to receive conversations (one at a time, streaming)
/// - Provide their user ID to extract their own pushname
///
/// # Memory Efficiency
/// - Without callbacks: Only decompresses and scans, minimal allocations
/// - With conversation callback: Parses conversations one at a time, doesn't accumulate
///
/// # Example
/// ```ignore
/// // Minimal - just extract own pushname
/// let result = process_history_sync(&data, HistorySyncOptions {
///     own_user_for_pushname: Some("1234567890"),
///     ..Default::default()
/// })?;
///
/// // Full - also process conversations
/// let result = process_history_sync(&data, HistorySyncOptions {
///     on_conversation: Some(|conv| {
///         println!("Got conversation: {:?}", conv.id);
///     }),
///     own_user_for_pushname: Some("1234567890"),
/// })?;
/// ```
pub fn process_history_sync<F>(
    compressed_data: &[u8],
    options: HistorySyncOptions<'_, F>,
) -> Result<HistorySyncResult, HistorySyncError>
where
    F: FnMut(wa::Conversation),
{
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut uncompressed = Vec::new();
    decoder.read_to_end(&mut uncompressed)?;

    let mut buf = uncompressed.as_slice();
    let total_len = uncompressed.len();

    let mut result = HistorySyncResult::default();
    let mut on_conversation = options.on_conversation;
    let want_conversations = on_conversation.is_some();
    let want_pushname = options.own_user_for_pushname.is_some();

    while !buf.is_empty() {
        let (field_number, wire_type) =
            decode_key(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?;

        match field_number {
            1 => {
                // sync_type - varint, skip
                let _ = decode_varint(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?;
            }
            2 if want_conversations => {
                // conversations field - only parse if user wants them
                let len = decode_varint(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?
                    as usize;
                let pos = total_len - buf.len();

                if pos + len > total_len {
                    return Err(HistorySyncError::ProtobufDecodeError(
                        prost::DecodeError::new("message length out of bounds"),
                    ));
                }
                let conv_slice = &uncompressed[pos..pos + len];
                if let Ok(conv) = wa::Conversation::decode(conv_slice) {
                    if let Some(ref mut callback) = on_conversation {
                        callback(conv);
                        result.conversations_processed += 1;
                    }
                }
                buf = &uncompressed[(pos + len)..];
            }
            7 if want_pushname && result.own_pushname.is_none() => {
                // pushnames field - only parse if user wants their pushname and we haven't found it
                let len = decode_varint(&mut buf).map_err(HistorySyncError::ProtobufDecodeError)?
                    as usize;
                let pos = total_len - buf.len();
                if pos + len > total_len {
                    return Err(HistorySyncError::ProtobufDecodeError(
                        prost::DecodeError::new("pushname length out of bounds"),
                    ));
                }
                let slice = &uncompressed[pos..pos + len];

                if let Ok(pn) = wa::Pushname::decode(slice)
                    && let Some(ref id) = pn.id
                    && Some(id.as_str()) == options.own_user_for_pushname
                    && let Some(name) = pn.pushname
                {
                    result.own_pushname = Some(name);
                }
                buf = &uncompressed[(pos + len)..];
            }
            _ => {
                // Skip all other fields
                match wire_type {
                    prost::encoding::WireType::Varint => {
                        let _ = decode_varint(&mut buf)
                            .map_err(HistorySyncError::ProtobufDecodeError)?;
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
                        buf = &uncompressed[(pos + l)..];
                    }
                    prost::encoding::WireType::ThirtyTwoBit => {
                        let pos = total_len - buf.len();
                        buf = &uncompressed[(pos + 4)..];
                    }
                    prost::encoding::WireType::SixtyFourBit => {
                        let pos = total_len - buf.len();
                        buf = &uncompressed[(pos + 8)..];
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

    Ok(result)
}

/// Convenience function for the common case: just extract own pushname.
/// This is the most memory-efficient option when you don't need conversations.
pub fn extract_own_pushname(
    compressed_data: &[u8],
    own_user: &str,
) -> Result<Option<String>, HistorySyncError> {
    let result = process_history_sync::<fn(wa::Conversation)>(
        compressed_data,
        HistorySyncOptions {
            on_conversation: None,
            own_user_for_pushname: Some(own_user),
        },
    )?;
    Ok(result.own_pushname)
}
