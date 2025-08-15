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
}

/// Process a compressed history sync blob by decompressing and parsing it.
///
/// Takes raw compressed bytes and returns a parsed HistorySync protobuf structure.
/// This function encapsulates the platform-agnostic logic for processing history sync data.
pub fn process_history_sync_blob(
    compressed_data: &[u8],
) -> Result<wa::HistorySync, HistorySyncError> {
    // Decompress the data using Zlib
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut uncompressed = Vec::new();
    decoder.read_to_end(&mut uncompressed)?;

    // Parse the protobuf
    let history_sync = wa::HistorySync::decode(uncompressed.as_slice())?;

    Ok(history_sync)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::ZlibEncoder;
    use std::io::Write;

    #[test]
    fn test_process_history_sync_blob_success() {
        // Create a minimal HistorySync protobuf for testing
        let history_sync = wa::HistorySync {
            sync_type: wa::history_sync::HistorySyncType::Recent as i32,
            conversations: vec![],
            pushnames: vec![],
            ..Default::default()
        };

        // Encode to bytes
        let encoded = history_sync.encode_to_vec();

        // Compress with zlib
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&encoded).unwrap();
        let compressed = encoder.finish().unwrap();

        // Test the function
        let result = process_history_sync_blob(&compressed);
        assert!(result.is_ok());

        let parsed = result.unwrap();
        assert_eq!(
            parsed.sync_type(),
            wa::history_sync::HistorySyncType::Recent
        );
        assert_eq!(parsed.conversations.len(), 0);
        assert_eq!(parsed.pushnames.len(), 0);
    }

    #[test]
    fn test_process_history_sync_blob_invalid_compression() {
        let invalid_data = b"invalid zlib data";
        let result = process_history_sync_blob(invalid_data);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HistorySyncError::DecompressionError(_)
        ));
    }

    #[test]
    fn test_process_history_sync_blob_invalid_protobuf() {
        // Create valid zlib compressed data but invalid protobuf
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"invalid protobuf data").unwrap();
        let compressed = encoder.finish().unwrap();

        let result = process_history_sync_blob(&compressed);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            HistorySyncError::ProtobufDecodeError(_)
        ));
    }
}
