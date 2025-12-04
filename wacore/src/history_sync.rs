use bytes::Bytes;
use flate2::read::ZlibDecoder;
use prost::Message;
use protobuf::CodedInputStream;
use std::io::BufReader;
use thiserror::Error;
use waproto::whatsapp as wa;

/// Buffer size for streaming decompression (64KB)
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

/// Result from history sync processing.
#[derive(Debug, Default)]
pub struct HistorySyncResult {
    /// Own pushname if found.
    pub own_pushname: Option<String>,

    /// Number of conversations processed.
    pub conversations_processed: usize,
}

/// Wire type constants for protobuf
mod wire_type {
    pub const VARINT: u32 = 0;
    pub const FIXED64: u32 = 1;
    pub const LENGTH_DELIMITED: u32 = 2;
    pub const FIXED32: u32 = 5;
}

/// Process history sync data with streaming.
///
/// This function chains streaming decompression with incremental protobuf
/// parsing, ensuring memory usage is bounded (~1-2MB) regardless of input size.
///
/// # How it works
///
/// 1. `ZlibDecoder` decompresses data on-demand as bytes are requested
/// 2. `BufReader` provides buffered reading (64KB buffer)
/// 3. `CodedInputStream` parses protobuf fields incrementally
/// 4. Each conversation's raw bytes are passed to callback as `Bytes` (zero-copy)
///
/// # Memory Profile
///
/// | Component | Size |
/// |-----------|------|
/// | ZlibDecoder buffer | ~32KB |
/// | BufReader buffer | ~64KB |
/// | CodedInputStream | ~8KB |
/// | Current raw bytes | ~1-50KB |
/// | **Total peak** | **~200KB-1MB** |
///
/// # Arguments
///
/// * `compressed_data` - The zlib-compressed history sync blob
/// * `own_user` - Optional user JID to extract own pushname
/// * `on_conversation_bytes` - Callback invoked with `Bytes` for each conversation.
///   If `None`, conversations are skipped entirely. Uses `Bytes` for zero-copy cloning.
///
/// # Example
///
/// ```ignore
/// use wacore::history_sync::process_history_sync;
/// use bytes::Bytes;
///
/// let result = process_history_sync(
///     &compressed_data,
///     Some("1234567890"),
///     Some(|raw_bytes: Bytes| {
///         // raw_bytes can be wrapped in LazyConversation::from_bytes() for deferred parsing
///         println!("Got conversation bytes: {} bytes", raw_bytes.len());
///     }),
/// )?;
///
/// println!("Processed {} conversations", result.conversations_processed);
/// if let Some(name) = result.own_pushname {
///     println!("Own pushname: {}", name);
/// }
/// ```
pub fn process_history_sync<F>(
    compressed_data: &[u8],
    own_user: Option<&str>,
    mut on_conversation_bytes: Option<F>,
) -> Result<HistorySyncResult, HistorySyncError>
where
    F: FnMut(Bytes),
{
    // Set up streaming pipeline:
    // compressed_data -> ZlibDecoder -> BufReader -> CodedInputStream
    let decoder = ZlibDecoder::new(compressed_data);
    let mut buf_reader = BufReader::with_capacity(STREAMING_BUFFER_SIZE, decoder);
    let mut cis = CodedInputStream::from_buf_read(&mut buf_reader);

    // Increase recursion limit for deeply nested messages
    cis.set_recursion_limit(100);

    let mut result = HistorySyncResult::default();

    // Parse fields incrementally until EOF
    while let Some(tag) = cis.read_raw_tag_or_eof()? {
        // Extract field number and wire type from tag
        let field_number = tag >> 3;
        let wire_type_raw = tag & 0x7;

        match field_number {
            // Field 2: conversations (repeated, length-delimited)
            2 if wire_type_raw == wire_type::LENGTH_DELIMITED => {
                if let Some(ref mut callback) = on_conversation_bytes {
                    // Read raw bytes for this conversation - no parsing here!
                    // Parsing is deferred to the caller via LazyConversation
                    // Convert Vec<u8> to Bytes for zero-copy reference counting
                    let raw_bytes = Bytes::from(cis.read_bytes()?);
                    callback(raw_bytes);
                    result.conversations_processed += 1;
                } else {
                    // No callback - skip conversation entirely without allocating
                    let len = cis.read_raw_varint32()?;
                    cis.skip_raw_bytes(len)?;
                }
            }

            // Field 7: pushnames (repeated, length-delimited)
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

            // All other fields: skip without parsing
            _ => {
                skip_field_by_wire_type(&mut cis, wire_type_raw)?;
            }
        }
    }

    Ok(result)
}

/// Skip a field based on its wire type without allocating
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
            // Use skip_raw_bytes to avoid allocating a Vec<u8>
            let len = cis.read_raw_varint32()?;
            cis.skip_raw_bytes(len)?;
        }
        wire_type::FIXED32 => {
            cis.read_raw_little_endian32()?;
        }
        _ => {
            // Unknown wire type - shouldn't happen with valid protobuf
            log::warn!("Unknown wire type {wire_type} in history sync, skipping");
        }
    }
    Ok(())
}
