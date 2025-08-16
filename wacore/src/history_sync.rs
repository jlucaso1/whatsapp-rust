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

pub fn process_history_sync_blob(
    compressed_data: &[u8],
) -> Result<wa::HistorySync, HistorySyncError> {
    let mut decoder = ZlibDecoder::new(compressed_data);
    let mut uncompressed = Vec::new();
    decoder.read_to_end(&mut uncompressed)?;

    let history_sync = wa::HistorySync::decode(uncompressed.as_slice())?;

    Ok(history_sync)
}
