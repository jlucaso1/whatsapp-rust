use core::future::Future;
use prost::Message;
use prost::encoding::{decode_key, decode_varint};
use std::io::Cursor;
use thiserror::Error;
use waproto::whatsapp as wa;

#[derive(Debug, Error)]
pub enum SnapshotStreamError {
    #[error("Protobuf decode error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),
    #[error("Malformed protobuf: {0}")]
    Malformed(&'static str),
}

/// Stream parse a SyncdSnapshot, invoking `record_handler` for each record without
/// allocating the full `wa::SyncdSnapshot` in memory. Returns (version, key_id, mac).
pub async fn process_snapshot_stream<FRec, FRecFut>(
    data: &[u8],
    mut record_handler: FRec,
) -> Result<(Option<wa::SyncdVersion>, Option<wa::KeyId>, Option<Vec<u8>>), SnapshotStreamError>
where
    FRec: FnMut(wa::SyncdRecord) -> FRecFut,
    FRecFut: Future<Output = ()>,
{
    let mut cursor = Cursor::new(data);
    let total_len = data.len();
    let mut version: Option<wa::SyncdVersion> = None;
    let mut key_id: Option<wa::KeyId> = None;
    let mut mac: Option<Vec<u8>> = None;

    while (cursor.position() as usize) < total_len {
        let (field_number, wire_type) = decode_key(&mut cursor)?;
        match field_number {
            1 => {
                // version
                let len = decode_varint(&mut cursor)? as usize;
                let pos = cursor.position() as usize;
                if pos + len > total_len {
                    return Err(SnapshotStreamError::Malformed(
                        "version length out of bounds",
                    ));
                }
                let slice = &data[pos..pos + len];
                version = Some(wa::SyncdVersion::decode(slice)?);
                cursor.set_position((pos + len) as u64);
            }
            2 => {
                // record repeated
                let len = decode_varint(&mut cursor)? as usize;
                let pos = cursor.position() as usize;
                if pos + len > total_len {
                    return Err(SnapshotStreamError::Malformed(
                        "record length out of bounds",
                    ));
                }
                let slice = &data[pos..pos + len];
                match wa::SyncdRecord::decode(slice) {
                    Ok(rec) => record_handler(rec).await,
                    Err(e) => return Err(SnapshotStreamError::ProtobufDecode(e)),
                }
                cursor.set_position((pos + len) as u64);
            }
            3 => {
                // mac bytes
                let len = decode_varint(&mut cursor)? as usize;
                let pos = cursor.position() as usize;
                if pos + len > total_len {
                    return Err(SnapshotStreamError::Malformed("mac length out of bounds"));
                }
                mac = Some(data[pos..pos + len].to_vec());
                cursor.set_position((pos + len) as u64);
            }
            4 => {
                // key_id
                let len = decode_varint(&mut cursor)? as usize;
                let pos = cursor.position() as usize;
                if pos + len > total_len {
                    return Err(SnapshotStreamError::Malformed(
                        "key_id length out of bounds",
                    ));
                }
                let slice = &data[pos..pos + len];
                key_id = Some(wa::KeyId::decode(slice)?);
                cursor.set_position((pos + len) as u64);
            }
            _ => {
                use prost::encoding::WireType;
                match wire_type {
                    prost::encoding::WireType::Varint => {
                        let _ = decode_varint(&mut cursor)?;
                    }
                    prost::encoding::WireType::LengthDelimited => {
                        let l = decode_varint(&mut cursor)? as usize;
                        let pos = cursor.position() as usize;
                        if pos + l > total_len {
                            return Err(SnapshotStreamError::Malformed("ld skip out of bounds"));
                        }
                        cursor.set_position((pos + l) as u64);
                    }
                    WireType::ThirtyTwoBit => {
                        let pos = cursor.position() as usize;
                        cursor.set_position((pos + 4) as u64);
                    }
                    WireType::SixtyFourBit => {
                        let pos = cursor.position() as usize;
                        cursor.set_position((pos + 8) as u64);
                    }
                    _ => return Err(SnapshotStreamError::Malformed("unsupported wire type")),
                }
            }
        }
    }

    Ok((version, key_id, mac))
}
